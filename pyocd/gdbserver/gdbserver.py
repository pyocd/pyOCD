# pyOCD debugger
# Copyright (c) 2006-2020 Arm Limited
# Copyright (c) 2021 Chris Reed
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import threading
from struct import unpack
from time import sleep
import sys
import six
import io
from xml.etree.ElementTree import (Element, SubElement, tostring)

from ..core import exceptions
from ..core.target import Target
from ..flash.loader import FlashLoader
from ..utility.cmdline import convert_vector_catch
from ..utility.conversion import (hex_to_byte_list, hex_encode, hex_decode, hex8_to_u32le)
from ..utility.compatibility import (iter_single_bytes, to_bytes_safe, to_str_safe)
from ..utility.server import StreamServer
from ..trace.swv import SWVReader
from ..utility.sockets import ListenerSocket
from .syscall import GDBSyscallIOHandler
from ..debug import semihost
from .context_facade import GDBDebugContextFacade
from .symbols import GDBSymbolProvider
from ..rtos import RTOS
from . import signals
from . import gdbserver_commands # lgtm[py/unused-import]
from .packet_io import (
    checksum,
    ConnectionClosedException,
    GDBServerPacketIOThread,
    )
from ..commands.execution_context import CommandExecutionContext
from ..commands.commander import ToolExitException

LOG = logging.getLogger(__name__)

TRACE_MEM = LOG.getChild("trace.mem")
TRACE_MEM.setLevel(logging.CRITICAL)

def unescape(data):
    """! @brief De-escapes binary data from Gdb.
    
    @param data Bytes-like object with possibly escaped values.
    @return List of integers in the range 0-255, with all escaped bytes de-escaped.
    """
    data_idx = 0

    # unpack the data into binary array
    str_unpack = str(len(data)) + 'B'
    data = unpack(str_unpack, data)
    data = list(data)

    # check for escaped characters
    while data_idx < len(data):
        if data[data_idx] == 0x7d:
            data.pop(data_idx)
            data[data_idx] = data[data_idx] ^ 0x20
        data_idx += 1

    return data

def escape(data):
    """! @brief Escape binary data to be sent to Gdb.
    
    @param data Bytes-like object containing raw binary.
    @return Bytes object with the characters in '#$}*' escaped as required by Gdb.
    """
    result = b''
    for c in iter_single_bytes(data):
        if c in b'#$}*':
            result += b'}' + six.int2byte(six.byte2int(c) ^ 0x20)
        else:
            result += c
    return result

class GDBError(exceptions.Error):
    """! @brief Error communicating with GDB."""
    pass

class GDBServer(threading.Thread):
    """! @brief GDB remote server thread.
    
    This class start a GDB server listening a gdb connection on a specific port.
    It implements the RSP (Remote Serial Protocol).
    """

    ## Notification event for the gdbserver beginnning to listen on its RSP port.
    GDBSERVER_START_LISTENING_EVENT = 'gdbserver-start-listening'
    
    ## Timer delay for sending the notification that the server is listening.
    START_LISTENING_NOTIFY_DELAY = 0.03 # 30 ms
    
    def __init__(self, session, core=None):
        super(GDBServer, self).__init__()
        self.session = session
        self.board = session.board
        if core is None:
            self.core = 0
            self.target = self.board.target
        else:
            self.core = core
            self.target = self.board.target.cores[core]
        self.name = "gdb-server-core%d" % self.core
        self.abstract_socket = None

        self.port = session.options.get('gdbserver_port')
        if self.port != 0:
            self.port += self.core
        self.telnet_port = session.options.get('telnet_port')
        if self.telnet_port != 0:
            self.telnet_port += self.core

        self.vector_catch = session.options.get('vector_catch')
        self.target.set_vector_catch(convert_vector_catch(self.vector_catch))
        self.step_into_interrupt = session.options.get('step_into_interrupt')
        self.persist = session.options.get('persist')
        self.enable_semihosting = session.options.get('enable_semihosting')
        self.semihost_console_type = session.options.get('semihost_console_type') # Not subscribed.
        self.semihost_use_syscalls = session.options.get('semihost_use_syscalls') # Not subscribed.
        self.serve_local_only = session.options.get('serve_local_only') # Not subscribed.
        self.report_core = session.options.get('report_core_number')
        # Subscribe to changes for those of the above options that make sense to change at runtime.
        self.session.options.subscribe(self._option_did_change, [
                'vector_catch',
                'step_into_interrupt',
                'persist',
                'enable_semihosting',
                'report_core_number',
                ])

        self.packet_size = 2048
        self.packet_io = None
        self.gdb_features = []
        self.non_stop = False
        self._is_extended_remote = False
        self.is_target_running = (self.target.get_state() == Target.State.RUNNING)
        self.flash_loader = None
        self.shutdown_event = threading.Event()
        self.detach_event = threading.Event()
        if core is None:
            self.target_context = self.board.target.get_target_context()
        else:
            self.target_context = self.board.target.get_target_context(core=core)
        self.target_facade = GDBDebugContextFacade(self.target_context)
        self.thread_provider = None
        self.did_init_thread_providers = False
        self.current_thread_id = 0
        self.first_run_after_reset_or_flash = True

        self.abstract_socket = ListenerSocket(self.port, self.packet_size)
        if not self.serve_local_only:
            # We really should be binding to explicit interfaces, not all available.
            self.abstract_socket.host = ''
        self.abstract_socket.init()
        # Read back bound port in case auto-assigned (port 0)
        self.port = self.abstract_socket.port

        # Coarse grain lock to synchronize SWO with other activity
        self.lock = threading.Lock()

        self.session.subscribe(self.event_handler, Target.Event.POST_RESET)

        # Init semihosting and telnet console.
        if self.semihost_use_syscalls:
            semihost_io_handler = GDBSyscallIOHandler(self)
        else:
            # Use internal IO handler.
            semihost_io_handler = semihost.InternalSemihostIOHandler()

        if self.semihost_console_type == 'telnet':
            self.telnet_server = StreamServer(self.telnet_port, self.serve_local_only, "Semihost",
                False, extra_info=("core %d" % self.core))
            console_file = self.telnet_server
            semihost_console = semihost.ConsoleIOHandler(self.telnet_server)
        else:
            LOG.info("Semihosting will be output to console")
            console_file = sys.stdout
            self.telnet_server = None
            semihost_console = semihost_io_handler
        self.semihost = semihost.SemihostAgent(self.target_context, io_handler=semihost_io_handler, console=semihost_console)
        
        #
        # If SWV is enabled, create a SWVReader thread. Note that we only do
        # this if the core is 0: SWV is not a per-core construct, and can't
        # be meaningfully read by multiple threads concurrently.
        #
        self._swv_reader = None

        if session.options.get("enable_swv") and core == 0:
            if "swv_system_clock" not in session.options:
                LOG.warning("Cannot enable SWV due to missing swv_system_clock option")
            else:
                sys_clock = int(session.options.get("swv_system_clock"))
                swo_clock = int(session.options.get("swv_clock"))
                self._swv_reader = SWVReader(session, self.core, self.lock)
                self._swv_reader.init(sys_clock, swo_clock, console_file)
        
        self._init_remote_commands()

        # pylint: disable=invalid-name
        
        # Command handler table.
        #
        # The dict keys are the first character of the incoming command from gdb. Values are a
        # bi-tuple. The first element is the handler method, and the second element is the start
        # offset of the command string passed to the handler.
        #
        # Start offset values:
        #  0 - Special case: handler method does not take any parameters.
        #  1 - Strip off leading "$" from command.
        #  2 - Strip leading "$" plus character matched through this table.
        #  3+ - Supported, but not very useful.
        #
        self.COMMANDS = {
        #       CMD    HANDLER                   START    DESCRIPTION
                b'!' : (self.extended_remote,    0   ), # Enable extended remote mode.
                b'?' : (self.stop_reason_query,  0   ), # Stop reason query.
                b'c' : (self.resume,             1   ), # Continue (at addr)
                b'C' : (self.resume,             1   ), # Continue with signal.
                b'D' : (self.detach,             1   ), # Detach.
                b'g' : (self.get_registers,      0   ), # Read general registers.
                b'G' : (self.set_registers,      2   ), # Write general registers.
                b'H' : (self.set_thread,         2   ), # Set thread for subsequent operations.
                b'k' : (self.kill,               0   ), # Kill.
                b'm' : (self.get_memory,         2   ), # Read memory.
                b'M' : (self.write_memory_hex,   2   ), # Write memory (hex).
                b'p' : (self.read_register,      2   ), # Read register.
                b'P' : (self.write_register,     2   ), # Write register.
                b'q' : (self.handle_query,       2   ), # General query.
                b'Q' : (self.handle_general_set, 2   ), # General set.
                b'R' : (self.restart,            1   ), # Extended remote restart command.
                b's' : (self.step,               1   ), # Single step.
                b'S' : (self.step,               1   ), # Step with signal.
                b'T' : (self.is_thread_alive,    1   ), # Thread liveness query.
                b'v' : (self.v_command,          2   ), # v command.
                b'X' : (self.write_memory,       2   ), # Write memory (binary).
                b'z' : (self.breakpoint,         1   ), # Insert breakpoint/watchpoint.
                b'Z' : (self.breakpoint,         1   ), # Remove breakpoint/watchpoint.
            }

        # Commands that kill the connection to gdb.
        self.DETACH_COMMANDS = (b'D', b'k')

        # pylint: enable=invalid-name

        self.setDaemon(True)

    def _init_remote_commands(self):
        """! @brief Initialize the remote command processor infrastructure."""
        # Create command execution context. The output stream will default to stdout
        # but we'll change it to a fresh StringIO prior to running each command.
        #
        # Note we also modify the selected_core property so it is initially set to the gdbserver's core.
        self._command_context = CommandExecutionContext()
        self._command_context.selected_core = self.target
        self._command_context.attach_session(self.session)
        
        # Add the gdbserver command group.
        self._command_context.command_set.add_command_group('gdbserver')

    def stop(self):
        if self.is_alive():
            self.shutdown_event.set()
            while self.is_alive():
                pass
            LOG.info("GDB server thread killed")

    def _cleanup(self):
        LOG.debug("GDB server cleaning up")
        if self.packet_io:
            self.packet_io.stop()
            self.packet_io = None
        if self.semihost:
            self.semihost.cleanup()
            self.semihost = None
        if self.telnet_server:
            self.telnet_server.stop()
            self.telnet_server = None
        if self._swv_reader:
            self._swv_reader.stop()
            self._swv_reader = None
        self.abstract_socket.cleanup()

    def _cleanup_for_next_connection(self):
        self.non_stop = False
        self.thread_provider = None
        self.did_init_thread_providers = False
        self.current_thread_id = 0

    def run(self):
        LOG.info('GDB server started on port %d (core %d)', self.port, self.core)

        while True:
            try:
                self.detach_event.clear()

                # Notify listeners that the server is running after a short delay.
                #
                # This timer prevents a race condition where the notification is sent before the server is
                # actually listening. It's not a 100% guarantee, though.
                notify_timer = threading.Timer(self.START_LISTENING_NOTIFY_DELAY, self.session.notify,
                        args=(self.GDBSERVER_START_LISTENING_EVENT, self))
                notify_timer.start()

                while not self.shutdown_event.isSet() and not self.detach_event.isSet():
                    connected = self.abstract_socket.connect()
                    if connected != None:
                        self.packet_io = GDBServerPacketIOThread(self.abstract_socket)
                        break

                if self.shutdown_event.isSet():
                    self._cleanup()
                    return

                if self.detach_event.isSet():
                    continue
        
                # Make sure the target is halted. Otherwise gdb gets easily confused.
                self.target.halt()

                LOG.info("Client connected to port %d!", self.port)
                self._run_connection()
                LOG.info("Client disconnected from port %d!", self.port)
                self._cleanup_for_next_connection()

            except Exception as e:
                LOG.error("Unexpected exception: %s", e, exc_info=self.session.log_tracebacks)

    def _run_connection(self):
        while True:
            try:
                if self.shutdown_event.isSet():
                    self._cleanup()
                    return

                if self.detach_event.isSet():
                    break

                if self.packet_io.interrupt_event.isSet():
                    if self.non_stop:
                        self.target.halt()
                        self.is_target_running = False
                        self.send_stop_notification()
                    else:
                        LOG.error("Got unexpected ctrl-c, ignoring")
                    self.packet_io.interrupt_event.clear()

                if self.non_stop and self.is_target_running:
                    try:
                        if self.target.get_state() == Target.State.HALTED:
                            LOG.debug("state halted")
                            self.is_target_running = False
                            self.send_stop_notification()
                    except Exception as e:
                        LOG.error("Unexpected exception: %s", e, exc_info=self.session.log_tracebacks)

                # read command
                try:
                    packet = self.packet_io.receive(block=not self.non_stop)
                except ConnectionClosedException:
                    break

                if self.shutdown_event.isSet():
                    self._cleanup()
                    return

                if self.detach_event.isSet():
                    break

                if self.non_stop and packet is None:
                    sleep(0.1)
                    continue

                if len(packet) != 0:
                    # decode and prepare resp
                    resp, detach = self.handle_message(packet)

                    if resp is not None:
                        # send resp
                        self.packet_io.send(resp)

                    if detach:
                        self.abstract_socket.close()
                        self.packet_io.stop()
                        self.packet_io = None
                        if self.persist:
                            self._cleanup_for_next_connection()
                            break
                        else:
                            self.shutdown_event.set()
                            return

            except Exception as e:
                LOG.error("Unexpected exception: %s", e, exc_info=self.session.log_tracebacks)

    def handle_message(self, msg):
        try:
            assert msg[0:1] == b'$', "invalid first char of message != $"

            try:
                handler, msgStart = self.COMMANDS[msg[1:2]]
            except (KeyError, IndexError):
                LOG.error("Unknown RSP packet: %s", msg)
                return self.create_rsp_packet(b""), 0

            self.lock.acquire()
            if msgStart == 0:
                reply = handler()
            else:
                reply = handler(msg[msgStart:])
            self.lock.release()

            detach = msg[1:2] in self.DETACH_COMMANDS
            return reply, detach

        except Exception as e:
            self.lock.release()
            LOG.error("Unhandled exception in handle_message: %s", e, exc_info=self.session.log_tracebacks)
            return self.create_rsp_packet(b"E01"), 0

    def extended_remote(self):
        self._is_extended_remote = True
        return self.create_rsp_packet(b"OK")

    def detach(self, data):
        LOG.info("Client detached")
        resp = b"OK"
        return self.create_rsp_packet(resp)

    def kill(self):
        LOG.debug("GDB kill")
        # Keep target halted and leave vector catches if in persistent mode.
        if not self.persist:
            self.board.target.set_vector_catch(Target.VectorCatch.NONE)
            self.board.target.resume()
    
    def restart(self, data):
        self.target.reset_and_halt()
        # No reply.

    def breakpoint(self, data):
        # handle breakpoint/watchpoint commands
        split = data.split(b'#')[0].split(b',')
        addr = int(split[1], 16)
        LOG.debug("GDB breakpoint %s%d @ %x" % (data[0:1], int(data[1:2]), addr))

        # handle software breakpoint Z0/z0
        if data[1:2] == b'0':
            if data[0:1] == b'Z':
                if not self.target.set_breakpoint(addr, Target.BreakpointType.SW):
                    return self.create_rsp_packet(b'E01') #EPERM
            else:
                self.target.remove_breakpoint(addr)
            return self.create_rsp_packet(b"OK")

        # handle hardware breakpoint Z1/z1
        if data[1:2] == b'1':
            if data[0:1] == b'Z':
                if self.target.set_breakpoint(addr, Target.BreakpointType.HW) is False:
                    return self.create_rsp_packet(b'E01') #EPERM
            else:
                self.target.remove_breakpoint(addr)
            return self.create_rsp_packet(b"OK")

        # handle hardware watchpoint Z2/z2/Z3/z3/Z4/z4
        if data[1:2] == b'2':
            # Write-only watch
            watchpoint_type = Target.WatchpointType.WRITE
        elif data[1:2] == b'3':
            # Read-only watch
            watchpoint_type = Target.WatchpointType.READ
        elif data[1:2] == b'4':
            # Read-Write watch
            watchpoint_type = Target.WatchpointType.READ_WRITE
        else:
            return self.create_rsp_packet(b'E01') #EPERM

        size = int(split[2], 16)
        if data[0:1] == b'Z':
            if self.target.set_watchpoint(addr, size, watchpoint_type) is False:
                return self.create_rsp_packet(b'E01') #EPERM
        else:
            self.target.remove_watchpoint(addr, size, watchpoint_type)
        return self.create_rsp_packet(b"OK")

    def set_thread(self, data):
        if not self.is_threading_enabled():
            return self.create_rsp_packet(b'OK')

        LOG.debug("set_thread:%s", data)
        op = data[0:1]
        thread_id = int(data[1:-3], 16)
        if not (thread_id in (0, -1) or self.thread_provider.is_valid_thread_id(thread_id)):
            return self.create_rsp_packet(b'E01')

        if op == b'c':
            pass
        elif op == b'g':
            if thread_id == -1:
                self.target_facade.set_context(self.target_context)
            else:
                if thread_id == 0:
                    thread = self.thread_provider.current_thread
                    thread_id = thread.unique_id
                else:
                    thread = self.thread_provider.get_thread(thread_id)
                self.target_facade.set_context(thread.context)
        else:
            return self.create_rsp_packet(b'E01')

        self.current_thread_id = thread_id
        return self.create_rsp_packet(b'OK')

    def is_thread_alive(self, data):
        threadId = int(data[1:-3], 16)

        if self.is_threading_enabled():
            isAlive = self.thread_provider.is_valid_thread_id(threadId)
        else:
            isAlive = (threadId == 1)

        if isAlive:
            return self.create_rsp_packet(b'OK')
        else:
            self.validate_debug_context()
            return self.create_rsp_packet(b'E00')

    def validate_debug_context(self):
        if self.is_threading_enabled():
            currentThread = self.thread_provider.current_thread
            if self.current_thread_id != currentThread.unique_id:
                self.target_facade.set_context(currentThread.context)
                self.current_thread_id = currentThread.unique_id
        else:
            if self.current_thread_id != 1:
                LOG.debug("Current thread %x is no longer valid, switching context to target", self.current_thread_id)
                self.target_facade.set_context(self.target_context)
                self.current_thread_id = 1

    def stop_reason_query(self):
        # In non-stop mode, if no threads are stopped we need to reply with OK.
        if self.non_stop and self.is_target_running:
            return self.create_rsp_packet(b"OK")

        return self.create_rsp_packet(self.get_t_response())

    def _get_resume_step_addr(self, data):
        if data is None:
            return None
        data = data.split(b'#')[0]
        if b';' not in data:
            return None
        # c[;addr]
        if data[0:1] in (b'c', b's'):
            addr = int(data[2:], base=16)
        # Csig[;addr]
        elif data[0:1] in (b'C', b'S'):
            addr = int(data[1:].split(b';')[1], base=16)
        return addr

    def resume(self, data):
#         addr = self._get_resume_step_addr(data)
        self.target.resume()
        LOG.debug("target resumed")

        if self.first_run_after_reset_or_flash:
            self.first_run_after_reset_or_flash = False
            if self.thread_provider is not None:
                self.thread_provider.read_from_target = True

        val = b''

        while True:
            if self.shutdown_event.isSet():
                self.packet_io.interrupt_event.clear()
                return self.create_rsp_packet(val)

            self.lock.release()

            # Wait for a ctrl-c to be received.
            if self.packet_io.interrupt_event.wait(0.01):
                self.lock.acquire()
                LOG.debug("receive CTRL-C")
                self.packet_io.interrupt_event.clear()
                self.target.halt()
                val = self.get_t_response(forceSignal=signals.SIGINT)
                break

            self.lock.acquire()

            try:
                if self.target.get_state() == Target.State.HALTED:
                    # Handle semihosting
                    if self.enable_semihosting:
                        was_semihost = self.semihost.check_and_handle_semihost_request()

                        if was_semihost:
                            self.target.resume()
                            continue

                    pc = self.target_context.read_core_register('pc')
                    LOG.debug("state halted; pc=0x%08x", pc)
                    val = self.get_t_response()
                    break
            except exceptions.Error as e:
                try:
                    self.target.halt()
                except exceptions.Error:
                    pass
                LOG.warning('Exception while target was running: %s', e, exc_info=self.session.log_tracebacks)
                val = ('S%02x' % self.target_facade.get_signal_value()).encode()
                break

        return self.create_rsp_packet(val)

    def step(self, data, start=0, end=0):
        #addr = self._get_resume_step_addr(data)
        LOG.debug("GDB step: %s (start=0x%x, end=0x%x)", data, start, end)
        
        # Use the step hook to check for an interrupt event.
        def step_hook():
            # Note we don't clear the interrupt event here!
            return self.packet_io.interrupt_event.is_set()
        self.target.step(not self.step_into_interrupt, start, end, hook_cb=step_hook)
        
        # Clear and handle an interrupt.
        if self.packet_io.interrupt_event.is_set():
            LOG.debug("Received Ctrl-C during step")
            self.packet_io.interrupt_event.clear()
            response = self.get_t_response(forceSignal=signals.SIGINT)
        else:
            response = self.get_t_response()
        
        return self.create_rsp_packet(response)

    def halt(self):
        self.target.halt()
        return self.create_rsp_packet(self.get_t_response())

    def send_stop_notification(self, forceSignal=None):
        data = self.get_t_response(forceSignal=forceSignal)
        packet = b'%Stop:' + data + b'#' + checksum(data)
        self.packet_io.send(packet)

    def v_command(self, data):
        cmd = data.split(b'#')[0]

        # Flash command.
        if cmd.startswith(b'Flash'):
            return self.flash_op(data)

        # v_cont capabilities query.
        elif b'Cont?' == cmd:
            return self.create_rsp_packet(b"vCont;c;C;s;S;r;t")

        # v_cont, thread action command.
        elif cmd.startswith(b'Cont'):
            return self.v_cont(cmd)

        # vStopped, part of thread stop state notification sequence.
        elif b'Stopped' in cmd:
            # Because we only support one thread for now, we can just reply OK to vStopped.
            return self.create_rsp_packet(b"OK")

        return self.create_rsp_packet(b"")

    # Example: $v_cont;s:1;c#c1
    def v_cont(self, cmd):
        ops = cmd.split(b';')[1:] # split and remove 'Cont' from list
        if not ops:
            return self.create_rsp_packet(b"OK")

        if self.is_threading_enabled():
            thread_actions = {}
            threads = self.thread_provider.get_threads()
            for k in threads:
                thread_actions[k.unique_id] = None
            currentThread = self.thread_provider.get_current_thread_id()
        else:
            thread_actions = { 1 : None } # our only thread
            currentThread = 1
        default_action = None

        for op in ops:
            args = op.split(b':')
            action = args[0]
            if len(args) > 1:
                thread_id = int(args[1], 16)
                if thread_id == -1 or thread_id == 0:
                    thread_id = currentThread
                thread_actions[thread_id] = action
            else:
                default_action = action

        LOG.debug("thread_actions=%s; default_action=%s", repr(thread_actions), default_action)

        # Only the current thread is supported at the moment.
        if thread_actions[currentThread] is None:
            if default_action is None:
                return self.create_rsp_packet(b'E01')
            thread_actions[currentThread] = default_action

        if thread_actions[currentThread][0:1] in (b'c', b'C'):
            if self.non_stop:
                self.target.resume()
                self.is_target_running = True
                return self.create_rsp_packet(b"OK")
            else:
                return self.resume(None)
        elif thread_actions[currentThread][0:1] in (b's', b'S', b'r'):
            start = 0
            end = 0
            if thread_actions[currentThread][0:1] == b'r':
                start, end = [int(addr, base=16) for addr in thread_actions[currentThread][1:].split(b',')]
	
            if self.non_stop:
                self.target.step(not self.step_into_interrupt, start, end)
                self.packet_io.send(self.create_rsp_packet(b"OK"))
                self.send_stop_notification()
                return None
            else:
                return self.step(None, start, end)
        elif thread_actions[currentThread] == b't':
            # Must ignore t command in all-stop mode.
            if not self.non_stop:
                return self.create_rsp_packet(b"")
            self.packet_io.send(self.create_rsp_packet(b"OK"))
            self.target.halt()
            self.is_target_running = False
            self.send_stop_notification(forceSignal=0)
        else:
            LOG.error("Unsupported v_cont action '%s'" % thread_actions[1:2])

    def flash_op(self, data):
        ops = data.split(b':')[0]
        LOG.debug("flash op: %s", ops)

        if ops == b'FlashErase':
            return self.create_rsp_packet(b"OK")

        elif ops == b'FlashWrite':
            write_addr = int(data.split(b':')[1], 16)
            LOG.debug("flash write addr: 0x%x", write_addr)
            # search for second ':' (beginning of data encoded in the message)
            second_colon = 0
            idx_begin = 0
            while second_colon != 2:
                if data[idx_begin:idx_begin+1] == b':':
                    second_colon += 1
                idx_begin += 1

            # Get flash loader if there isn't one already
            if self.flash_loader is None:
                self.flash_loader = FlashLoader(self.session)

            # Add data to flash loader
            self.flash_loader.add_data(write_addr, unescape(data[idx_begin:len(data) - 3]))

            return self.create_rsp_packet(b"OK")

        # we need to flash everything
        elif b'FlashDone' in ops :
            # Only program if we received data.
            if self.flash_loader is not None:
                try:
                    # Write all buffered flash contents.
                    self.flash_loader.commit()
                finally:
                    # Set flash loader to None so that on the next flash command a new
                    # object is used.
                    self.flash_loader = None

            self.first_run_after_reset_or_flash = True
            if self.thread_provider is not None:
                self.thread_provider.read_from_target = False

            return self.create_rsp_packet(b"OK")

        return None

    def get_memory(self, data):
        split = data.split(b',')
        addr = int(split[0], 16)
        length = split[1].split(b'#')[0]
        length = int(length, 16)

        TRACE_MEM.debug("GDB getMem: addr=%x len=%x", addr, length)

        try:
            mem = self.target_context.read_memory_block8(addr, length)
            # Flush so an exception is thrown now if invalid memory was accesses
            self.target_context.flush()
            val = hex_encode(bytearray(mem))
        except exceptions.TransferError as e:
            LOG.debug("get_memory failed at 0x%x: %s", addr, str(e))
            val = b'E01' #EPERM
        return self.create_rsp_packet(val)

    def write_memory_hex(self, data):
        split = data.split(b',')
        addr = int(split[0], 16)

        split = split[1].split(b':')
        length = int(split[0], 16)

        split = split[1].split(b'#')
        data = hex_to_byte_list(split[0])

        TRACE_MEM.debug("GDB writeMemHex: addr=%x len=%x", addr, length)

        try:
            if length > 0:
                self.target_context.write_memory_block8(addr, data)
                # Flush so an exception is thrown now if invalid memory was accessed
                self.target_context.flush()
            resp = b"OK"
        except exceptions.TransferError as e:
            LOG.debug("write_memory_hex failed at 0x%x: %s", addr, str(e))
            resp = b'E01' #EPERM

        return self.create_rsp_packet(resp)

    def write_memory(self, data):
        split = data.split(b',')
        addr = int(split[0], 16)
        length = int(split[1].split(b':')[0], 16)

        TRACE_MEM.debug("GDB writeMem: addr=%x len=%x", addr, length)

        idx_begin = data.index(b':') + 1
        data = data[idx_begin:len(data) - 3]
        data = unescape(data)

        try:
            if length > 0:
                self.target_context.write_memory_block8(addr, data)
                # Flush so an exception is thrown now if invalid memory was accessed
                self.target_context.flush()
            resp = b"OK"
        except exceptions.TransferError as e:
            LOG.debug("write_memory failed at 0x%x: %s", addr, str(e))
            resp = b'E01' #EPERM

        return self.create_rsp_packet(resp)

    def read_register(self, which):
        return self.create_rsp_packet(self.target_facade.gdb_get_register(which))

    def write_register(self, data):
        reg = int(data.split(b'=')[0], 16)
        val = data.split(b'=')[1].split(b'#')[0]
        self.target_facade.set_register(reg, val)
        return self.create_rsp_packet(b"OK")

    def get_registers(self):
        return self.create_rsp_packet(self.target_facade.get_register_context())

    def set_registers(self, data):
        self.target_facade.set_register_context(data)
        return self.create_rsp_packet(b"OK")

    def handle_query(self, msg):
        query = msg.split(b':')
        LOG.debug('GDB received query: %s', query)

        if query is None:
            LOG.error('GDB received query packet malformed')
            return None

        if query[0] == b'Supported':
            # Save features sent by gdb.
            self.gdb_features = query[1].split(b';')

            # Build our list of features.
            features = [b'qXfer:features:read+', b'QStartNoAckMode+', b'qXfer:threads:read+', b'QNonStop+']
            features.append(b'PacketSize=' + six.b(hex(self.packet_size))[2:])
            if self.target_facade.get_memory_map_xml() is not None:
                features.append(b'qXfer:memory-map:read+')
            resp = b';'.join(features)
            return self.create_rsp_packet(resp)

        elif query[0] == b'Xfer':

            if query[1] == b'features' and query[2] == b'read' and \
               query[3] == b'target.xml':
                data = query[4].split(b',')
                resp = self.handle_query_xml(b'read_feature', int(data[0], 16), int(data[1].split(b'#')[0], 16))
                return self.create_rsp_packet(resp)

            elif query[1] == b'memory-map' and query[2] == b'read':
                data = query[4].split(b',')
                resp = self.handle_query_xml(b'memory_map', int(data[0], 16), int(data[1].split(b'#')[0], 16))
                return self.create_rsp_packet(resp)

            elif query[1] == b'threads' and query[2] == b'read':
                data = query[4].split(b',')
                resp = self.handle_query_xml(b'threads', int(data[0], 16), int(data[1].split(b'#')[0], 16))
                return self.create_rsp_packet(resp)

            else:
                LOG.debug("Unsupported qXfer request: %s:%s:%s:%s", query[1], query[2], query[3], query[4])
                return None

        elif query[0].startswith(b'C'):
            if not self.is_threading_enabled():
                return self.create_rsp_packet(b"QC1")
            else:
                self.validate_debug_context()
                return self.create_rsp_packet(("QC%x" % self.current_thread_id).encode())

        elif query[0].find(b'Attached') != -1:
            return self.create_rsp_packet(b"1")

        elif query[0].find(b'TStatus') != -1:
            return self.create_rsp_packet(b"")

        elif query[0].find(b'Tf') != -1:
            return self.create_rsp_packet(b"")

        elif b'Offsets' in query[0]:
            resp = b"Text=0;Data=0;Bss=0"
            return self.create_rsp_packet(resp)

        elif b'Symbol' in query[0]:
            if self.did_init_thread_providers:
                return self.create_rsp_packet(b"OK")
            return self.init_thread_providers()

        elif query[0].startswith(b'Rcmd,'):
            cmd = hex_decode(query[0][5:].split(b'#')[0])
            return self.handle_remote_command(cmd)

        else:
            return self.create_rsp_packet(b"")

    def init_thread_providers(self):
        if not self.session.options.get('rtos.enable'):
            LOG.debug("Skipping RTOS load because it was disabled.")
            return self.create_rsp_packet(b"OK")
        
        forced_rtos_name = self.session.options.get('rtos.name')
        
        symbol_provider = GDBSymbolProvider(self)

        for rtosName, rtosClass in RTOS.items():
            if (forced_rtos_name is not None) and (rtosName != forced_rtos_name):
                continue
            try:
                LOG.info("Attempting to load %s", rtosName)
                rtos = rtosClass(self.target)
                if rtos.init(symbol_provider):
                    LOG.info("%s loaded successfully", rtosName)
                    self.thread_provider = rtos
                    break
            except exceptions.Error as e:
                LOG.error("Error during symbol lookup: " + str(e), exc_info=self.session.log_tracebacks)

        self.did_init_thread_providers = True

        # Done with symbol processing.
        return self.create_rsp_packet(b"OK")

    def get_symbol(self, name):
        # Send the symbol request.
        request = self.create_rsp_packet(b'qSymbol:' + hex_encode(name))
        self.packet_io.send(request)

        # Read a packet.
        packet = self.packet_io.receive()

        # Parse symbol value reply packet.
        packet = packet[1:-3]
        if not packet.startswith(b'qSymbol:'):
            raise GDBError("Got unexpected response from gdb when asking for symbol value")
        packet = packet[8:]
        symValue, symName = packet.split(b':')

        symName = hex_decode(symName)
        if symName != name:
            raise GDBError("Symbol value reply from gdb has unexpected symbol name")
        if symValue:
            symValue = hex8_to_u32le(symValue)
        else:
            return None
        return symValue

    def handle_remote_command(self, cmd):
        """! @brief Pass remote commands to the commander command processor."""
        # Convert the command line to a string.
        cmd = to_str_safe(cmd)
        LOG.debug('Remote command: %s', cmd)

        # Create a new stream to collect the command output.
        stream = io.StringIO()
        self._command_context.output_stream = stream
        
        # TODO run this in a separate thread so we can cancel the command with ^C from gdb?
        try:
            # Run command and collect output.
            self._command_context.process_command_line(cmd)
        except exceptions.CommandError as err:
            stream.write("Error: %s\n" % err)
        except ToolExitException:
            stream.write("Error: cannot exit gdbserver\n")
        except exceptions.TransferError as err:
            stream.write("Transfer failed: %s\n" % err)
            LOG.error("Transfer failure while executing remote command '%s': %s", cmd, err,
                    exc_info=self.session.log_tracebacks)
        except Exception as err:
            stream.write("Unexpected error: %s\n" % err)
            LOG.error("Exception while executing remote command '%s': %s", cmd, err,
                    exc_info=self.session.log_tracebacks)
        
        # Convert back to bytes, hex encode, then return the response packet.
        output = stream.getvalue()
        if not output:
            output = "OK\n"
        response = hex_encode(to_bytes_safe(output))

        # Disconnect the stream.
        self._command_context.output_stream = None
            
        return self.create_rsp_packet(response)

    def handle_general_set(self, msg):
        feature = msg.split(b'#')[0]
        LOG.debug("GDB general set: %s", feature)

        if feature == b'StartNoAckMode':
            # Disable acks after the reply and ack.
            self.packet_io.set_send_acks(False)
            return self.create_rsp_packet(b"OK")

        elif feature.startswith(b'NonStop'):
            enable = feature.split(b':')[1]
            self.non_stop = (enable == b'1')
            return self.create_rsp_packet(b"OK")

        else:
            return self.create_rsp_packet(b"")

    def handle_query_xml(self, query, offset, size):
        LOG.debug('GDB query %s: offset: %s, size: %s', query, offset, size)
        xml = ''
        if query == b'memory_map':
            xml = self.target_facade.get_memory_map_xml()
        elif query == b'read_feature':
            xml = self.target_facade.get_target_xml()
        elif query == b'threads':
            xml = self.get_threads_xml()
        else:
            raise GDBError("Invalid XML query (%s)" % query)

        size_xml = len(xml)

        prefix = b'm'

        if offset > size_xml:
            raise GDBError('GDB: xml offset > size for %s!', query)

        if size > (self.packet_size - 4):
            size = self.packet_size - 4

        nbBytesAvailable = size_xml - offset

        if size > nbBytesAvailable:
            prefix = b'l'
            size = nbBytesAvailable

        resp = prefix + escape(xml[offset:offset + size])

        return resp


    def create_rsp_packet(self, data):
        resp = b'$' + data + b'#' + checksum(data)
        return resp

    def syscall(self, op):
        op = to_bytes_safe(op)
        LOG.debug("GDB server syscall: %s", op)
        request = self.create_rsp_packet(b'F' + op)
        self.packet_io.send(request)

        while not self.packet_io.interrupt_event.is_set():
            # Read a packet.
            packet = self.packet_io.receive(False)
            if packet is None:
                sleep(0.1)
                continue

            # Check for file I/O response.
            if packet[0:1] == b'$' and packet[1:2] == b'F':
                LOG.debug("Syscall: got syscall response " + packet)
                args = packet[2:packet.index(b'#')].split(b',')
                result = int(args[0], base=16)
                errno = int(args[1], base=16) if len(args) > 1 else 0
                ctrl_c = args[2] if len(args) > 2 else b''
                if ctrl_c == b'C':
                    self.packet_io.interrupt_event.set()
                    self.packet_io.drop_reply = True
                return result, errno

            # decode and prepare resp
            resp, detach = self.handle_message(packet)

            if resp is not None:
                # send resp
                self.packet_io.send(resp)

            if detach:
                self.detach_event.set()
                LOG.warning("GDB server received detach request while waiting for file I/O completion")
                break

        return -1, 0

    def get_t_response(self, forceSignal=None):
        self.validate_debug_context()
        response = self.target_facade.get_t_response(forceSignal)

        # Append thread
        if not self.is_threading_enabled():
            response += b"thread:1;"
        else:
            if self.current_thread_id in (-1, 0, 1):
                response += ("thread:%x;" % self.thread_provider.current_thread.unique_id).encode()
            else:
                response += ("thread:%x;" % self.current_thread_id).encode()

        # Optionally append core
        if self.report_core:
            response += ("core:%x;" % self.core).encode()
        LOG.debug("Tresponse=%s", response)
        return response

    def get_threads_xml(self):
        root = Element('threads')

        if not self.is_threading_enabled():
            t = SubElement(root, 'thread', id="1")
            if self.report_core:
                t.set("core", str(self.core))
            if self.is_target_in_reset():
                t.text = "Reset"
            else:
                t.text = self.exception_name()
        else:
            threads = self.thread_provider.get_threads()
            for thread in threads:
                hexId = "%x" % thread.unique_id
                t = SubElement(root, 'thread', id=hexId, name=thread.name)
                if self.report_core:
                    t.set("core", str(self.core))
                t.text = thread.description

        return b'<?xml version="1.0"?><!DOCTYPE feature SYSTEM "threads.dtd">' + tostring(root)

    def is_threading_enabled(self):
        return (self.thread_provider is not None) and self.thread_provider.is_enabled \
            and (self.thread_provider.current_thread is not None)

    def is_target_in_reset(self):
        return self.target.get_state() == Target.State.RESET

    def exception_name(self):
        try:
            ipsr = self.target_context.read_core_register('ipsr')
            return self.target_context.core.exception_number_to_name(ipsr)
        except exceptions.Error:
            return None

    def event_handler(self, notification):
        if notification.event == Target.Event.POST_RESET:
            # Invalidate threads list if flash is reprogrammed.
            LOG.debug("Received POST_RESET event")
            self.first_run_after_reset_or_flash = True
            if self.thread_provider is not None:
                self.thread_provider.read_from_target = False

    def _option_did_change(self, notification):
        """! @brief Handle an option changing at runtime.
        
        For option notifications, the event is the name of the option and the `data` attribute is an
        OptionChangeInfo object with `new_value` and `old_value` attributes.
        """
        if notification.event == 'vector_catch':
            self.target.set_vector_catch(convert_vector_catch(notification.data.new_value))
        elif notification.event == 'step_into_interrupt':
            self.step_into_interrupt = notification.data.new_value
        elif notification.event == 'persist':
            self.persist = notification.data.new_value
        elif notification.event == 'enable_semihosting':
            self.enable_semihosting = notification.data.new_value
            LOG.info("Semihosting %s", ('enabled' if self.enable_semihosting else 'disabled'))
        elif notification.event == 'report_core_number':
            self.report_core = notification.data.new_value

