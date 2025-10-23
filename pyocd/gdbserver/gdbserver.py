# pyOCD debugger
# Copyright (c) 2006-2020,2025 Arm Limited
# Copyright (c) 2021-2022 Chris Reed
# Copyright (c) 2022 Clay McClure
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
from time import sleep
import sys
import io
from xml.etree.ElementTree import (Element, SubElement, tostring)
from typing import (Dict, List, Optional, Tuple)

from ..core import exceptions
from ..core.target import Target
from ..flash.loader import FlashLoader
from ..utility.cmdline import convert_vector_catch
from ..utility.conversion import (hex_to_byte_list, hex_encode, hex_decode, hex8_to_u32le)
from ..utility.compatibility import (to_bytes_safe, to_str_safe)
from ..utility.server import StreamServer
from ..utility.timeout import Timeout
from ..trace.swv import SWVReader
from ..utility.rtt_server import RTTServer
from ..utility.sockets import ConnectedSocket, ListenerSocket
from ..utility.sockets import ClientSocket
from .syscall import GDBSyscallIOHandler
from ..debug import semihost
from .context_facade import GDBDebugContextFacade
from .symbols import GDBSymbolProvider
from ..rtos import RTOS
from . import signals
from .packet_io import (
    checksum,
    ConnectionClosedException,
    GDBServerPacketIOThread,
    )
from ..commands.execution_context import CommandExecutionContext
from ..commands.commander import ToolExitException

# Import this module, even though it's not used below, to ensure the gdbserver commands get loaded.
from . import gdbserver_commands # noqa

LOG = logging.getLogger(__name__)

TRACE_MEM = LOG.getChild("trace.mem")
TRACE_MEM.setLevel(logging.CRITICAL)

# When a client thread sets the active index, this filter will
# prepend "Client<index>: " to log messages emitted on that thread.
class _ClientLogFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self._tls = threading.local()

    def set_client(self, index: int) -> None:
        self._tls.client_index = index

    def clear_client(self) -> None:
        self._tls.client_index = None

    def filter(self, record: logging.LogRecord) -> bool:
        idx = getattr(self._tls, 'client_index', None)
        if idx is not None:
            try:
                msg = record.getMessage()
            except Exception:
                msg = str(record.msg)
            record.msg = "Client %d: %s" % (idx, msg)
            record.args = ()
        return True

# Single shared filter instance for this module's logger.
_client_log_filter = _ClientLogFilter()
LOG.addFilter(_client_log_filter)
TRACE_MEM.addFilter(_client_log_filter)

def unescape(data: bytes) -> List[int]:
    """@brief De-escapes binary data from Gdb.

    @param data Bytes-like object with possibly escaped values.
    @return List of integers in the range 0-255, with all escaped bytes de-escaped.
    """
    data_idx = 0

    # unpack the data into binary array
    result = list(data)

    # check for escaped characters
    while data_idx < len(result):
        if result[data_idx] == 0x7d:
            result.pop(data_idx)
            result[data_idx] = result[data_idx] ^ 0x20
        data_idx += 1

    return result

## Tuple of int values of characters that must be escaped.
_GDB_ESCAPED_CHARS = tuple(b'#$}*')

def escape(data):
    """@brief Escape binary data to be sent to Gdb.

    @param data Bytes-like object containing raw binary.
    @return Bytes object with the characters in '#$}*' escaped as required by Gdb.
    """
    result: List[int] = []
    for c in data:
        if c in _GDB_ESCAPED_CHARS:
            # Escape by prefixing with '}' and xor'ing the char with 0x20.
            result += [0x7d, c ^ 0x20]
        else:
            result.append(c)
    return bytes(result)

class GDBClientSession(threading.Thread):
    """@brief GDB client session thread.

    This class represents a per-connection GDB client session. It manages the state and communication
    for a single GDB client connected to the server. The session delegates command handling to the
    GDBServer, which owns the target and coordinates access among multiple clients.
    """
    def __init__(self, server: 'GDBServer', connected_socket: 'ConnectedSocket', index: int):
        super().__init__(daemon=True)
        self.name = "gdb-client-%d" % index
        self.index: int = index
        self._server: GDBServer = server
        self._connected_socket: ConnectedSocket = connected_socket
        self._packet_io = None
        self.is_extended_remote: bool = False
        self.non_stop: bool = False
        self.is_attached_to_target: bool = False
        self.is_socket_connected: bool = True
        self.gdb_features = []
        self.target_facade = GDBDebugContextFacade(server.target_context)
        self.shutdown_event = threading.Event()


    def run(self) -> None:
        # Set the log filter to include the client index in messages from this thread.
        _client_log_filter.set_client(self.index)

        LOG.debug("Thread started")
        try:
            self._packet_io = GDBServerPacketIOThread(self._connected_socket, self.index)
        except Exception as e:
            LOG.error("Error starting packet I/O thread: %s", e, exc_info=self._server.session.log_tracebacks)
            return

        self.shutdown_event.clear()
        self.is_attached_to_target = True

        try:
            while not self.shutdown_event.is_set() and not self._server.shutdown_event.is_set():
                try:
                    if self.is_interrupted():
                        if self.non_stop:
                            self._server.target.halt()
                            self._server.is_target_running = False
                            self._server.send_stop_notification(self)
                        else:
                            LOG.warning("Unexpected Ctrl-C ignored in all-stop mode")
                        self.interrupt_clear()

                    if self.non_stop and self._server.is_target_running:
                        try:
                            if self._server.target.get_state() == Target.State.HALTED:
                                LOG.debug("Target halted")
                                self._server.is_target_running = False
                                self._server.send_stop_notification(self)
                        except Exception as e:
                            LOG.error("Unexpected exception: %s", e, exc_info=self._server.session.log_tracebacks)

                    # read command
                    try:
                        packet = self.receive(block=not self.non_stop)
                    except ConnectionClosedException:
                        LOG.debug("Connection closed")
                        break

                    if self._server.shutdown_event.is_set():
                        break

                    if self.non_stop and packet is None:
                        sleep(0.1)
                        continue

                    if packet is not None and len(packet) != 0:
                        # decode and prepare resp
                        resp = self._server.handle_message(self, packet)

                        if resp is not None:
                            # send resp
                            self.send(resp)

                except Exception as e:
                    LOG.error("Unexpected exception: %s", e, exc_info=self._server.session.log_tracebacks)
        finally:
            LOG.debug("Thread stopping")

            try:
                self.cleanup()
            except Exception as e:
                LOG.error("Error cleaning up session: %s", e, exc_info=self._server.session.log_tracebacks)

            # Notify server that session detached.
            try:
                self._server.notify_client_detached(self)
            except Exception as e:
                LOG.error("Failed to notify server of client detachment: %s",
                        e, exc_info=self._server.session.log_tracebacks)

            _client_log_filter.clear_client()
            LOG.info("Client %d disconnected", self.index)

    # packet_io wrapper methods
    def send(self, data):
        return self._packet_io.send(data)

    def receive(self, block=True):
        return self._packet_io.receive(block)

    def interrupt_clear(self):
        self._packet_io.interrupt_event.clear()

    def is_interrupted(self):
        return self._packet_io.interrupt_event.is_set()

    def set_interrupt(self):
        self._packet_io.interrupt_event.set()

    def set_drop_reply(self, value=True):
        self._packet_io.drop_reply = value

    def set_send_acks(self, enable):
        self._packet_io.set_send_acks(enable)

    def wait_for_interrupt(self, timeout=None):
        return self._packet_io.interrupt_event.wait(timeout)

    # Cleanup resources
    def cleanup(self):
        """
        Gracefully stop the packet I/O handler and close the connected socket.
        """
        try:
            if  self._packet_io is not None:
                self._packet_io.stop()
        except Exception as e:
            LOG.debug("Error stopping packet I/O thread: %s", e, exc_info=self._server.session.log_tracebacks)

        try:
            if  self._connected_socket is not None:
                self._connected_socket.close()
        except Exception as e:
            LOG.debug("Error closing socket: %s", e, exc_info=self._server.session.log_tracebacks)
        finally:
            self.is_socket_connected = False


    def stop(self, timeout: float = 1.0) -> None:
        self.shutdown_event.set()

        # Only attempt to join if not in the same thread
        current_thread = threading.current_thread()
        if current_thread is not self:
            self.join(timeout)

class GDBServer(threading.Thread):
    """@brief GDB remote server thread.

    This class start a GDB server listening a gdb connection on a specific port.
    It implements the RSP (Remote Serial Protocol).
    """

    ## Notification event for the gdbserver beginnning to listen on its RSP port.
    GDBSERVER_START_LISTENING_EVENT = 'gdbserver-start-listening'

    ## Timer delay for sending the notification that the server is listening.
    START_LISTENING_NOTIFY_DELAY = 0.03 # 30 ms

    def __init__(self, session, core=None, port=None):
        super().__init__(daemon=True)
        self.session = session
        self.board = session.board
        if core is None:
            self.core = 0
            self.target = self.board.target
        else:
            self.core = core
            self.target = self.board.target.cores[core]
        self.name = "gdb-server-core%d" % self.core

        if port is None:
            self.port = session.options.get('gdbserver_port')
            if self.port != 0:
                self.port += self.core
        else:
            self.port = port

        self.client_sessions: List[GDBClientSession] = []
        # Lock to protect access to the sessions list
        self.client_sessions_lock = threading.Lock()
        self.client_last_index = 0

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
        self.soft_bkpt_as_hard = session.options.get('soft_bkpt_as_hard')

        # Subscribe to changes for those of the above options that make sense to change at runtime.
        self.session.options.subscribe(self._option_did_change, [
                'vector_catch',
                'step_into_interrupt',
                'persist',
                'enable_semihosting',
                'report_core_number',
                'soft_bkpt_as_hard',
                ])

        self.packet_size = 2048
        self.is_target_running = (self.target.get_state() == Target.State.RUNNING)
        self.flash_loader = None
        self.shutdown_event = threading.Event()
        if core is None:
            self.target_context = self.board.target.get_target_context()
        else:
            self.target_context = self.board.target.get_target_context(core=core)
        self.thread_provider = None
        self.did_init_thread_providers = False
        self.first_run_after_reset_or_flash = True

        # Listening socket - same port for all clients
        self.listen_socket = ListenerSocket(self.port, self.packet_size)
        if not self.serve_local_only:
            # We really should be binding to explicit interfaces, not all available.
            self.listen_socket.host = ''
        self.listen_socket.init()
        # Read back bound port in case auto-assigned (port 0)
        self.port = self.listen_socket.port

        # Coarse grain lock to synchronize SWO with other activity
        self.lock = threading.RLock()

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
            LOG.info("Semihosting output to console")
            console_file = sys.stdout
            self.telnet_server = None
            semihost_console = semihost_io_handler
        self.semihost = semihost.SemihostAgent(self.target_context, io_handler=semihost_io_handler, console=semihost_console)
        self._semihosting_client = None

        # Start with RTT disabled
        self.rtt_server: Optional[RTTServer] = None

        #
        # If SWV is enabled, create a SWVReader thread. Note that we only do
        # this if the core is 0: SWV is not a per-core construct, and can't
        # be meaningfully read by multiple threads concurrently.
        #
        self._swv_reader = None

        if session.options.get("enable_swv") and core == 0:
            if "swv_system_clock" not in session.options:
                LOG.warning("SWV not enabled; swv_system_clock option missing")
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

        # pylint: enable=invalid-name

    def _init_remote_commands(self):
        """@brief Initialize the remote command processor infrastructure."""
        # Create command execution context. The output stream will default to stdout
        # but we'll change it to a fresh StringIO prior to running each command.
        #
        # Note we also modify the selected_core property so it is initially set to the gdbserver's core.
        self._command_context = CommandExecutionContext()
        self._command_context.selected_core = self.target
        self._command_context.attach_session(self.session)

        # Add the gdbserver command group.
        self._command_context.command_set.add_command_group('gdbserver')

    def stop(self, wait=True):
        if self.is_alive():
            self.shutdown_event.set()
            if wait:
                LOG.debug("GDB server on port %d shutdown event; waiting for thread exit", self.port)
                self.join()
            else:
                LOG.debug("GDB server on port %d shutdown event", self.port)
            LOG.info("GDB server on port %d stopped", self.port)


    def _cleanup_client_sessions(self):
        # Stop and clean client sessions
        with self.client_sessions_lock:
            clients = list(self.client_sessions)
        for client in clients:
            client.stop()
            with self.client_sessions_lock:
                if client in self.client_sessions:
                    self.client_sessions.remove(client)

    def _cleanup(self):
        LOG.debug("GDB server on port %d cleaning up", self.port)
        self._cleanup_client_sessions()
        if self.semihost:
            self.semihost.cleanup()
            self.semihost = None
        if self.telnet_server:
            self.telnet_server.stop()
            self.telnet_server = None
        if self._swv_reader:
            self._swv_reader.stop()
            self._swv_reader = None
        if self.rtt_server:
            self.rtt_server.stop()
            self.rtt_server = None
        self.listen_socket.close()

    def run(self):
        LOG.info("GDB server listening on port %d (core %d)", self.port, self.core)

        # Notify listeners that the server is running after a short delay.
        #
        # This timer prevents a race condition where the notification is sent before the server is
        # actually listening. It's not a 100% guarantee, though.
        notify_timer = threading.Timer(self.START_LISTENING_NOTIFY_DELAY, self.session.notify,
                args=(self.GDBSERVER_START_LISTENING_EVENT, self))
        notify_timer.start()

        # Main GDB server loop: listens for incoming GDB client connections.
        try:
            while not self.shutdown_event.is_set():
                # Wait for a GDB client to connect to the TCP socket.
                try:
                    connected_socket = self.listen_socket.accept(0.001)
                    if connected_socket:
                        remote_address = connected_socket.get_remote_address()
                except Exception as e:
                    LOG.error("Error accepting socket connection on port %d: %s", self.port, e, exc_info=self.session.log_tracebacks)
                    connected_socket = None

                if connected_socket is None:
                    sleep(0.1)
                    continue

                client = None
                try:
                    with self.client_sessions_lock:
                        self.client_last_index += 1
                        index = self.client_last_index
                    # Open client session
                    client = GDBClientSession(self, connected_socket, index)
                    with self.client_sessions_lock:
                        self.client_sessions.append(client)

                    # Make sure the target is halted. Otherwise gdb gets easily confused.
                    self.target.halt()

                        # Start the per-client handler thread (server.run_session() will be invoked there).
                    client.start()
                    if remote_address:
                        LOG.info("Client %d connected on port %d from remote address %s", index, self.port, remote_address)
                    else:
                        LOG.info("Client %d connected on port %d (remote=unknown)", index, self.port)

                except Exception as e:
                    LOG.error("Error starting client session on port %d: %s", self.port, e, exc_info=self.session.log_tracebacks)

                    try:
                        if client is not None:
                            if client.is_alive():
                                client.stop()
                            else:
                                client.cleanup()

                            # Remove from session list if present
                            with self.client_sessions_lock:
                                if client in self.client_sessions:
                                    self.client_sessions.remove(client)
                        else:
                            # client not created -> close accepted socket
                            try:
                                connected_socket.close()
                            except Exception:
                                pass

                    except Exception as e:
                        LOG.error("Error cleaning up client session on port %d: %s", self.port, e, exc_info=self.session.log_tracebacks)
        finally:
            LOG.debug("GDB server on port %d exiting", self.port)
            self._cleanup()

    def notify_client_detached(self, client: GDBClientSession):
        """
        Called when a client session detaches from target
        """
        with self.client_sessions_lock:
            # Mark client detached from program
            client.is_attached_to_target = False

            if client is self._semihosting_client:
                self._semihosting_client = None

            # Client is detached from the target. If its socket connection is closed, remove it from the session list.
            if client in self.client_sessions and not client.is_socket_connected:
                LOG.debug("Removing from session list")
                self.client_sessions.remove(client)

            # Resume target if no client is attached to program
            if not any(c.is_attached_to_target for c in self.client_sessions):
                self.thread_provider = None
                self.did_init_thread_providers = False

                # Resume target when no clients are connected
                try:
                    # First check if it's halted
                    if self.target.get_state() == Target.State.HALTED:
                        self.target.resume()
                except Exception as e:
                    LOG.error("Error resuming target after client detached: %s",
                              e, exc_info=self.session.log_tracebacks)
                self.is_target_running = (self.target.get_state() == Target.State.RUNNING)

            # Decide server lifecycle on connected sessions
            if not self.client_sessions and not self.persist:
                self.shutdown_event.set()

    def handle_message(self, client, msg):
        try:
            assert msg[0:1] == b'$', "invalid first char of message != $"

            try:
                handler, msgStart = self.COMMANDS[msg[1:2]]
            except (KeyError, IndexError):
                LOG.error("Unknown RSP command (%s)", to_str_safe(msg[1:2]))
                return self.create_rsp_packet(b"")

            with self.lock:
                if msgStart == 0:
                    reply = handler(client)
                else:
                    reply = handler(client, msg[msgStart:])

            return reply

        except Exception as e:
            LOG.error("Unhandled exception processing RSP command (%s): %s",
                    to_str_safe(msg[1:2]), e, exc_info=self.session.log_tracebacks)
            return self.create_rsp_packet(b"E01")

    def extended_remote(self, client):
        LOG.debug("Command: Extended mode")
        client.is_extended_remote = True
        return self.create_rsp_packet(b"OK")

    def detach(self, client, data):
        LOG.debug("Command: Detach")
        # In extended-remote mode, detach should detach from the program but not close the connection. gdb assumes
        # the server connection is still valid.
        try:
            if client.is_extended_remote:
                self.notify_client_detached(client)
            else:
                # In normal mode, close the connection and stop the client thread
                client.stop()
        except Exception as e:
            LOG.error("Command: Detach: Error = %s", e, exc_info=self.session.log_tracebacks)
        # Ensure we return OK to gdb even if an error occurred.
        return self.create_rsp_packet(b"OK")

    def kill(self, client):
        LOG.debug("Command: Kill")
        if not client.is_extended_remote:
            # In normal mode, close the connection and stop the client thread
            try:
                client.stop()
            except Exception as e:
                LOG.error("Command: Kill: Error stopping client: %s", e, exc_info=self.session.log_tracebacks)
        # No reply for 'k' command.

    def restart(self, client, data):
        LOG.debug("Command: Restart")
        try:
            client.is_attached_to_target = True
            self.target.reset_and_halt()
        except Exception as e:
            LOG.error("Command: Restart: Error resetting and halting target: %s", e, exc_info=self.session.log_tracebacks)
        # No reply for 'R' command.

    def breakpoint(self, client, data):
        # handle breakpoint/watchpoint commands
        split = data.split(b'#')[0].split(b',')
        addr = int(split[1], 16)

        # handle software breakpoint Z0/z0
        if data[1:2] == b'0':
            if data[0:1] == b'Z':
                bkpt_type = Target.BreakpointType.HW if self.soft_bkpt_as_hard else Target.BreakpointType.SW
                LOG.debug("Command: Set software breakpoint (addr=0x%08x)", addr)
                if not self.target.set_breakpoint(addr, bkpt_type):
                    LOG.debug("Command: Set software breakpoint (addr=0x%08x): Failed", addr)
                    return self.create_rsp_packet(b'E01') #EPERM
            else:
                LOG.debug("Command: Clear software breakpoint (addr=0x%08x)", addr)
                self.target.remove_breakpoint(addr)
            return self.create_rsp_packet(b"OK")

        # handle hardware breakpoint Z1/z1
        if data[1:2] == b'1':
            if data[0:1] == b'Z':
                LOG.debug("Command: Set hardware breakpoint (addr=0x%08x)", addr)
                if self.target.set_breakpoint(addr, Target.BreakpointType.HW) is False:
                    LOG.debug("Command: Set hardware breakpoint (addr=0x%08x): Failed", addr)
                    return self.create_rsp_packet(b'E01') #EPERM
            else:
                LOG.debug("Command: Clear hardware breakpoint (addr=0x%08x)", addr)
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
            LOG.debug("Command: Set/Clear Break/Watchpoint: Invalid command=%s", to_str_safe(data[0:2]))
            return self.create_rsp_packet(b'E01') #EPERM

        _WP_NAMES = {
            Target.WatchpointType.WRITE: "Write",
            Target.WatchpointType.READ: "Read",
            Target.WatchpointType.READ_WRITE: "Access",
        }

        size = int(split[2], 16)
        if data[0:1] == b'Z':
            LOG.debug("Command: Set %s watchpoint (addr=0x%08x)", _WP_NAMES[watchpoint_type], addr)
            if self.target.set_watchpoint(addr, size, watchpoint_type) is False:
                LOG.debug("Command: Set %s watchpoint (addr=0x%08x): Failed", _WP_NAMES[watchpoint_type], addr)
                return self.create_rsp_packet(b'E01') #EPERM
        else:
            LOG.debug("Command: Clear %s watchpoint (addr=0x%08x)", _WP_NAMES[watchpoint_type], addr)
            self.target.remove_watchpoint(addr, size, watchpoint_type)
        return self.create_rsp_packet(b"OK")

    def set_thread(self, client, data):
        op = data[0:1]
        thread_id = int(data[1:-3], 16)
        LOG.debug("Command: Set thread (threadId=%s, operation=%s)",
                  ("0x%08x" % thread_id) if thread_id >= 0 else str(thread_id), to_str_safe(op))

        if not self.is_threading_enabled():
            LOG.debug("Command: Set thread: Threading not enabled")
            return self.create_rsp_packet(b'OK')

        if not (thread_id in (0, -1) or self.thread_provider.is_valid_thread_id(thread_id)):
            LOG.debug("Command: Set thread (threadId=0x%08x): Invalid threadId", thread_id)
            return self.create_rsp_packet(b'E01')

        if op == b'c':
            pass
        elif op == b'g':
            if thread_id == -1:
                client.target_facade.set_context(self.target_context)
            else:
                if thread_id == 0:
                    thread = self.thread_provider.current_thread
                    thread_id = thread.unique_id
                else:
                    thread = self.thread_provider.get_thread(thread_id)
                client.target_facade.set_context(thread.context)
        else:
            LOG.debug("Command: Set thread (threadId=%s, operation=%s): Invalid thread operation",
                      ("0x%08x" % thread_id) if thread_id >= 0 else str(thread_id), to_str_safe(op))
            return self.create_rsp_packet(b'E01')

        return self.create_rsp_packet(b'OK')

    def is_thread_alive(self, client, data):
        threadId = int(data[1:-3], 16)

        if self.is_threading_enabled():
            isAlive = self.thread_provider.is_valid_thread_id(threadId)
        else:
            isAlive = (threadId == 1)

        if isAlive:
            LOG.debug("Command: Is thread alive (threadId=0x%08x): OK", threadId)
            return self.create_rsp_packet(b'OK')
        else:
            LOG.debug("Command: Is thread alive (threadId=0x%08x): Not Alive (E00)", threadId)
            return self.create_rsp_packet(b'E00')

    def stop_reason_query(self, client):
        LOG.debug("Command: Stop reason query")

        # In non-stop mode, if no threads are stopped we need to reply with OK.
        if client.non_stop and self.is_target_running:
            return self.create_rsp_packet(b"OK")

        return self.create_rsp_packet(self.get_t_response(client))

    def _get_resume_step_addr(self, data):
        data = data.split(b'#')[0]
        if b';' not in data:
            return None
        # c[;addr]
        if data[0:1] in (b'c', b's'):
            addr = int(data[2:], base=16)
        # Csig[;addr]
        elif data[0:1] in (b'C', b'S'):
            addr = int(data[1:].split(b';')[1], base=16)
        # else:
        #     # Address is currently igonored - no need to log error
        #     LOG.error("Invalid step address received from gdb")
        return addr

    def resume(self, client, data):
        if data and data[0:1] in (b'c', b'C'):
            addr = self._get_resume_step_addr(data)
            if addr:
                LOG.debug("Command: Continue (addr=%d): Address is ignored", addr)
            else:
                LOG.debug("Command: Continue")

        self.target.resume()
        LOG.debug("Target resumed")

        if self.first_run_after_reset_or_flash:
            self.first_run_after_reset_or_flash = False
            if self.thread_provider is not None:
                self.thread_provider.read_from_target = True

        val = b''

        # Timeout used only if the target starts returning faults. The is_running property of this timeout
        # also serves as a flag that a fault occurred and we're attempting to retry.
        fault_retry_timeout = Timeout(self.session.options.get('debug.status_fault_retry_timeout'))

        while fault_retry_timeout.check():
            if self.shutdown_event.is_set():
                client.interrupt_clear()
                return self.create_rsp_packet(val)

            self.lock.release()

            # Wait for a ctrl-c to be received.
            if client.wait_for_interrupt(0.01):
                self.lock.acquire()
                LOG.debug("Ctrl-C received, halting target")
                client.interrupt_clear()

                # Be careful about reading the target state. If we previously got a fault (the timeout
                # is running) then ignore the error. In all cases we still return SIGINT.
                try:
                    self.target.halt()
                    val = self.get_t_response(client, forceSignal=signals.SIGINT)
                except exceptions.TransferError as e:
                    # Note: if the target is not actually halted, gdb can get confused from this point on.
                    # But there's not much we can do if we're getting faults attempting to control it.
                    if not fault_retry_timeout.is_running:
                        LOG.error("Error reading target status after halt: %s", e, exc_info=self.session.log_tracebacks)
                    val = ('S%02x' % signals.SIGINT).encode()
                break

            self.lock.acquire()

            try:
                state = self.target.get_state()

                if self.rtt_server:
                    self.rtt_server.poll()

                # If we were able to successfully read the target state after previously receiving a fault,
                # then clear the timeout.
                if fault_retry_timeout.is_running:
                    LOG.info("Target control re-established.")
                    fault_retry_timeout.clear()

                if state == Target.State.HALTED:
                    # Handle semihosting
                    if self.enable_semihosting and self._semihosting_client is None:
                        self._semihosting_client = client
                        self.lock.release()
                        try:
                            was_semihost = self.semihost.check_and_handle_semihost_request()
                        finally:
                            self.lock.acquire()
                            self._semihosting_client = None

                        if was_semihost:
                            self.target.resume()
                            continue

                    pc = self.target_context.read_core_register('pc')
                    LOG.debug("Target halted at pc=0x%08x", pc)
                    val = self.get_t_response(client)
                    break
            except exceptions.TransferError as e:
                # If we get any sort of transfer error or fault while checking target status, then start
                # a timeout running. Upon a later successful status check, the timeout is cleared. In the event
                # that the timeout expires, this loop is exited and an error raised to gdb.
                if not fault_retry_timeout.is_running:
                    LOG.warning("Transfer error while checking target status; retrying: %s", e,
                            exc_info=self.session.log_tracebacks)
                fault_retry_timeout.start()
            except exceptions.Error as e:
                try:
                    self.target.halt()
                except exceptions.Error:
                    pass
                LOG.warning("Error while target running: %s", e, exc_info=self.session.log_tracebacks)
                # This exception was not a transfer error, so reading the target state should be ok.
                val = ('S%02x' % client.target_facade.get_signal_value()).encode()
                break

        # Check if we exited the above loop due to a timeout after a fault.
        if fault_retry_timeout.did_time_out:
            LOG.error("Timeout re-establishing target control.")
            val = ('S%02x' % signals.SIGSEGV).encode()

        return self.create_rsp_packet(val)

    def step(self, client, data, start=0, end=0):
        if data and data[0:1] in (b's', b'S'):
            addr = self._get_resume_step_addr(data)
            if addr:
                LOG.debug("Command: Step (addr=%d): Address is ignored", addr)
            else:
                LOG.debug("Command: Step")

        # Use the step hook to check for an interrupt event.
        def step_hook():
            # Note we don't clear the interrupt event here!
            return client.is_interrupted()
        self.target.step(not self.step_into_interrupt, start, end, hook_cb=step_hook)

        # Clear and handle an interrupt.
        if client.is_interrupted():
            LOG.debug("Ctrl-C received during step")
            client.interrupt_clear()
            response = self.get_t_response(client, forceSignal=signals.SIGINT)
        else:
            response = self.get_t_response(client)

        return self.create_rsp_packet(response)

    def send_stop_notification(self, client, forceSignal=None):
        LOG.debug("Notification: Stop")
        data = self.get_t_response(client, forceSignal=forceSignal)
        packet = b'%Stop:' + data + b'#' + checksum(data)
        client.send(packet)

    def v_command(self, client, data):
        cmd = data.split(b'#')[0]

        # Flash command.
        if cmd.startswith(b'Flash'):
            return self.flash_op(data)

        # vCont capabilities query.
        elif b'Cont?' == cmd:
            response = b"vCont;c;C;s;S;r;t"
            LOG.debug("Command: Request list of actions supported by 'vCont': %s", to_str_safe(response))
            return self.create_rsp_packet(response)

        # vCont, thread action command.
        elif cmd.startswith(b'Cont'):
            return self.v_cont(client, cmd)

        # vStopped, part of thread stop state notification sequence.
        elif b'Stopped' in cmd:
            # Because we only support one thread for now, we can just reply OK to vStopped.
            LOG.debug("Command: vStopped notification")
            return self.create_rsp_packet(b"OK")

        LOG.debug("Command: v%s: Unknown command", to_str_safe(cmd))
        return self.create_rsp_packet(b"")

    # Example: $vCont;s:1;c#c1
    def v_cont(self, client, cmd):
        ops = cmd.split(b';')[1:] # split and remove 'Cont' from list
        if not ops:
            LOG.debug("Command: vCont: No operations")
            return self.create_rsp_packet(b"OK")

        # Maps the thread unique ID to an action char (byte).
        thread_actions: Dict[int, Optional[bytes]] = {}

        if self.is_threading_enabled():
            threads = self.thread_provider.get_threads()
            for k in threads:
                thread_actions[k.unique_id] = None
            currentThread = self.thread_provider.get_current_thread_id()
        else:
            thread_actions[1] = None # our only thread
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

        # Only the current thread is supported at the moment.
        if thread_actions[currentThread] is None:
            if default_action is None:
                LOG.debug("Command: vCont (threadId=0x%08x): No action for current thread", currentThread)
                return self.create_rsp_packet(b'E01')
            thread_actions[currentThread] = default_action

        if thread_actions[currentThread][0:1] in (b'c', b'C'):
            LOG.debug("Command: vCont (threadId=0x%08x, action=continue)", currentThread)
            if client.non_stop:
                self.target.resume()
                self.is_target_running = True
                return self.create_rsp_packet(b"OK")
            else:
                return self.resume(client, None)
        elif thread_actions[currentThread][0:1] in (b's', b'S', b'r'):
            start = 0
            end = 0
            if thread_actions[currentThread][0:1] == b'r':
                start, end = [int(addr, base=16) for addr in thread_actions[currentThread][1:].split(b',')]
                LOG.debug("Command: vCont (threadId=0x%08x, action=step, start=0x%08x, end=0x%08x)", currentThread, start, end)
            else:
                LOG.debug("Command: vCont (threadId=0x%08x, action=step)", currentThread)

            if client.non_stop:
                self.target.step(not self.step_into_interrupt, start, end)
                client.send(self.create_rsp_packet(b"OK"))
                self.send_stop_notification(client)
                return None
            else:
                return self.step(client, None, start, end)
        elif thread_actions[currentThread] == b't':
            LOG.debug("Command: vCont (threadId=0x%08x, action=stop)", currentThread)
            # Must ignore t command in all-stop mode.
            if not client.non_stop:
                return self.create_rsp_packet(b"")
            client.send(self.create_rsp_packet(b"OK"))
            self.target.halt()
            self.is_target_running = False
            self.send_stop_notification(client, forceSignal=0)
        else:
            LOG.error("Command: vCont (threadId=0x%08x, action='%s'): Unsupported action", currentThread, to_str_safe(thread_actions[currentThread]))

    def flash_op(self, data):
        ops = data.split(b':')[0]

        # Select current core
        if self.board.target.selected_core != self.core:
            self.board.target.selected_core = self.core

        if ops == b'FlashErase':
            LOG.debug("Command: Flash erase")
            return self.create_rsp_packet(b"OK")

        elif ops == b'FlashWrite':
            write_addr = int(data.split(b':')[1], 16)
            LOG.debug("Command: Flash write (addr=0x%08x)", write_addr)
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
            LOG.debug("Command: Flash done")
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

    def get_memory(self, client, data):
        split = data.split(b',')
        addr = int(split[0], 16)
        length = split[1].split(b'#')[0]
        length = int(length, 16)

        TRACE_MEM.debug("Command: Read memory (addr=0x%08x, len=%d)", addr, length)

        try:
            mem = self.target_context.read_memory_block8(addr, length)
            # Flush so an exception is thrown now if invalid memory was accesses
            self.target_context.flush()
            val = hex_encode(bytearray(mem))
        except exceptions.TransferError as e:
            LOG.debug("Command: Read memory (addr=0x%08x, len=%d): Error = %s", addr, length, str(e))
            val = b'E01' #EPERM
        return self.create_rsp_packet(val)

    def write_memory_hex(self, client, data):
        split = data.split(b',')
        addr = int(split[0], 16)

        split = split[1].split(b':')
        length = int(split[0], 16)

        split = split[1].split(b'#')
        data = hex_to_byte_list(split[0])

        TRACE_MEM.debug("Command: Write memory hex (addr=0x%08x, len=%d)", addr, length)

        try:
            if length > 0:
                self.target_context.write_memory_block8(addr, data)
                # Flush so an exception is thrown now if invalid memory was accessed
                self.target_context.flush()
            resp = b"OK"
        except exceptions.TransferError as e:
            LOG.debug("Command: Write memory hex (addr=0x%08x, len=%d): Error = %s", addr, length, str(e))
            resp = b'E01' #EPERM

        return self.create_rsp_packet(resp)

    def write_memory(self, client, data):
        split = data.split(b',')
        addr = int(split[0], 16)
        length = int(split[1].split(b':')[0], 16)

        idx_begin = data.index(b':') + 1
        data = data[idx_begin:len(data) - 3]
        data = unescape(data)

        TRACE_MEM.debug("Command: Write memory (addr=0x%08x, len=%d)", addr, length)

        try:
            if length > 0:
                self.target_context.write_memory_block8(addr, data)
                # Flush so an exception is thrown now if invalid memory was accessed
                self.target_context.flush()
            resp = b"OK"
        except exceptions.TransferError as e:
            LOG.debug("Command: Write memory (addr=0x%08x, len=%d): Error = %s", addr, length, str(e))
            resp = b'E01' #EPERM

        return self.create_rsp_packet(resp)

    def read_register(self, client, which):
        TRACE_MEM.debug("Command: Read register (reg_num=0x%x)", which)
        return self.create_rsp_packet(client.target_facade.get_register(which))

    def write_register(self, client, data):
        reg = int(data.split(b'=')[0], 16)
        val = data.split(b'=')[1].split(b'#')[0]
        TRACE_MEM.debug("Command: Write register (reg_num=0x%x, value=%s)", reg, to_str_safe(val))
        client.target_facade.set_register(reg, val)
        return self.create_rsp_packet(b"OK")

    def get_registers(self, client):
        TRACE_MEM.debug("Command: Read general registers")
        return self.create_rsp_packet(client.target_facade.get_register_context())

    def set_registers(self, client, data):
        TRACE_MEM.debug("Command: Write general registers (registers_data=%s)", to_str_safe(data))
        client.target_facade.set_register_context(data)
        return self.create_rsp_packet(b"OK")

    def handle_query(self, client, msg):
        query = msg.split(b':')

        if query is None:
            LOG.error("Command: General query: Malformed packet received")
            return None

        if query[0] == b'Supported':
            # Save features sent by gdb.
            client.gdb_features = query[1].split(b';')

            # Build our list of features.
            features = [b'qXfer:features:read+', b'QStartNoAckMode+', b'qXfer:threads:read+', b'QNonStop+']
            features.append(b'PacketSize=' + (hex(self.packet_size).encode())[2:])
            if client.target_facade.get_memory_map_xml() is not None:
                features.append(b'qXfer:memory-map:read+')
            resp = b';'.join(features)
            LOG.debug("Command: Query supported features (gdb features=%s): %s", client.gdb_features, features)
            return self.create_rsp_packet(resp)

        elif query[0] == b'Xfer':
            # qXfer:<object>:read:<annex>:<offset>,<length>
            if query[2] == b'read':
                data = query[4].split(b',')
                resp = self.handle_query_xml(client, query[1], query[3], int(data[0], 16), int(data[1].split(b'#')[0], 16))
                return self.create_rsp_packet(resp)
            else:
                LOG.debug("Command: Query Xfer:%s:%s: Unsupported request", to_str_safe(query[1]), to_str_safe(query[2]))
                # Must return an empty packet for an unrecognized qXfer.
                return self.create_rsp_packet(b"")

        elif query[0] == b'C':
            if not self.is_threading_enabled():
                thread_id = 1
            else:
                thread_id = self.thread_provider.get_current_thread_id()
            LOG.debug("Command: Query current thread ID: 0x%08x", thread_id)
            return self.create_rsp_packet(("QC%x" % thread_id).encode())

        elif query[0].find(b'Attached') != -1:
            LOG.debug("Command: Query attached: 1")
            return self.create_rsp_packet(b"1")

        elif query[0].find(b'TStatus') != -1:
            LOG.debug("Command: Query TStatus: Not supported")
            return self.create_rsp_packet(b"")

        elif query[0].find(b'Tf') != -1:
            LOG.debug("Command: Query Tf: Not supported")
            return self.create_rsp_packet(b"")

        elif b'Offsets' in query[0]:
            resp = b"Text=0;Data=0;Bss=0"
            LOG.debug("Command: Query offsets: %s", to_str_safe(resp))
            return self.create_rsp_packet(resp)

        elif b'Symbol' in query[0]:
            LOG.debug("Command: Query Symbol")
            if self.did_init_thread_providers:
                return self.create_rsp_packet(b"OK")
            return self.init_thread_providers(client)

        elif query[0].startswith(b'Rcmd,'):
            cmd = hex_decode(query[0][5:].split(b'#')[0])
            return self.handle_remote_command(cmd)

        else:
            LOG.debug("Command: Query %s: Not supported",  to_str_safe(query[0]))
            return self.create_rsp_packet(b"")

    def init_thread_providers(self, client):
        if not self.session.options.get('rtos.enable'):
            LOG.debug("RTOS loading disabled by option")
            return self.create_rsp_packet(b"OK")

        forced_rtos_name = self.session.options.get('rtos.name')
        if forced_rtos_name and (forced_rtos_name not in RTOS.keys()):
            LOG.error("Specified RTOS plugin '%s' not found", to_str_safe(forced_rtos_name))
            return self.create_rsp_packet(b"OK")

        symbol_provider = GDBSymbolProvider(self, client)

        LOG.debug("Attempting to load RTOS plugins")
        for rtos_name, rtos_class in RTOS.items():
            if (forced_rtos_name is not None) and (rtos_name != forced_rtos_name):
                continue
            try:
                LOG.debug("Attempting to load %s", rtos_name)
                rtos = rtos_class(self.target)
                if rtos.init(symbol_provider):
                    LOG.info("Loaded %s RTOS plugin", rtos_name)
                    self.thread_provider = rtos
                    break
                elif forced_rtos_name is not None:
                    LOG.error("Specified RTOS '%s' failed to load", rtos_name)
            except exceptions.Error as e:
                LOG.error("Error during RTOS symbol lookup: %s", e, exc_info=self.session.log_tracebacks)

        self.did_init_thread_providers = True

        # Done with symbol processing.
        return self.create_rsp_packet(b"OK")

    def get_symbol(self, client, name: bytes) -> Optional[int]:
        try:
            # Send the symbol request.
            request = self.create_rsp_packet(b'qSymbol:' + hex_encode(name))
            client.send(request)

            # Read a packet.
            try:
                packet = client.receive()
            except ConnectionClosedException:
                LOG.error("Connection closed during gdb symbol lookup")
                client.is_socket_connected = False
                return None
            assert packet is not None

            # Parse symbol value reply packet.
            packet = packet[1:-3]
            if not packet.startswith(b'qSymbol:'):
                LOG.error("Unexpected response from gdb for symbol value request")
                return None
            packet = packet[8:]
            sym_value, sym_name = packet.split(b':')

            sym_name = hex_decode(sym_name)
            if sym_name != name:
                LOG.error("Symbol value reply from gdb has unexpected symbol name (expected '%s', received '%s')",
                        to_str_safe(name), to_str_safe(sym_name))
                return None
            if sym_value:
                sym_value = hex8_to_u32le(sym_value)
            else:
                return None
            return sym_value
        except Exception as e:
            LOG.error("Error getting symbol value from gdb: %s", e, exc_info=self.session.log_tracebacks)
            return None

    def handle_remote_command(self, cmd):
        """@brief Pass remote commands to the commander command processor."""
        # Convert the command line to a string.
        cmd = to_str_safe(cmd)
        LOG.debug("Command: Remote (cmd=%s)", cmd)

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
            LOG.error("Command: Remote (cmd=%s): Transfer error = %s", cmd, err,
                    exc_info=self.session.log_tracebacks)
        except Exception as err:
            stream.write("Unexpected error: %s\n" % err)
            LOG.error("Command: Remote (cmd=%s): Unexpected error = %s", cmd, err,
                    exc_info=self.session.log_tracebacks)

        # Convert back to bytes, hex encode, then return the response packet.
        output = stream.getvalue()
        if not output:
            output = "OK\n"
        response = hex_encode(to_bytes_safe(output))

        # Disconnect the stream.
        self._command_context.output_stream = None

        return self.create_rsp_packet(response)

    def handle_general_set(self, client, msg):
        feature = msg.split(b'#')[0]

        if feature == b'StartNoAckMode':
            # Disable acks after the reply and ack.
            client.set_send_acks(False)
            LOG.debug("Command: General set StartNoAckMode")
            return self.create_rsp_packet(b"OK")

        elif feature.startswith(b'NonStop'):
            enable = feature.split(b':')[1]
            client.non_stop = (enable == b'1')
            LOG.debug("Command: General set NonStop=%s", (enable == b'1'))
            return self.create_rsp_packet(b"OK")

        else:
            LOG.debug("Command: General set %s not supported", to_str_safe(feature))
            return self.create_rsp_packet(b"")

    def handle_query_xml(self, client, query: bytes, annex: bytes, offset: int, size: int) -> bytes:
        requested_size = size

        # For each query object, we check the annex and return E00 for invalid values. Only 'features'
        # has a non-empty annex.
        if query == b'memory-map':
            if annex != b'':
                LOG.debug("Command: Query Xfer:memory-map:read (annex=%s, offset=%d, size=%d): Annex not empty", to_str_safe(annex), offset, size)
                return b"E00"
            xml = client.target_facade.get_memory_map_xml()
        elif query == b'features':
            if annex == b'target.xml':
                xml = client.target_facade.get_target_xml()
            else:
                LOG.debug("Command: Query Xfer:features:read (annex=%s, offset=%d, size=%d): Unsupported annex", to_str_safe(annex), offset, size)
                return b"E00"
        elif query == b'threads':
            if annex != b'':
                LOG.debug("Command: Query Xfer:threads:read (annex=%s, offset=%d, size=%d): Annex not empty", to_str_safe(annex), offset, size)
                return b"E00"
            xml = self.get_threads_xml()
        else:
            # Unrecognised query object, so return empty packet.
            LOG.debug("Command: Query Xfer:%s:read (annex=%s, offset=%d, size=%d): Unsupported XML query", to_str_safe(query), to_str_safe(annex), offset,size)
            return b""

        size_xml = len(xml)

        prefix = b'm'

        if offset > size_xml:
            LOG.error("Command: Query Xfer:%s:read (annex=%s, offset=%d, size=%d): Offset out of bounds", to_str_safe(query), to_str_safe(annex), offset, size)
            return b"E16" # EINVAL

        if size > (self.packet_size - 4):
            size = self.packet_size - 4

        nbBytesAvailable = size_xml - offset

        if size > nbBytesAvailable:
            prefix = b'l'
            size = nbBytesAvailable

        resp = prefix + escape(xml[offset:offset + size])

        LOG.debug("Command: Query Xfer:%s:read (annex=%s, offset=%d, size=%d): %s", to_str_safe(query), to_str_safe(annex), offset, requested_size, to_str_safe(xml[offset:offset + size]))
        return resp

    def create_rsp_packet(self, data):
        resp = b'$' + data + b'#' + checksum(data)
        return resp

    def syscall(self, op: str) -> Tuple[int, int]:
        client = self._semihosting_client

        LOG.debug("Syscall request: %s", op)
        request = self.create_rsp_packet(b'F' + op.encode())
        client.send(request)

        while not client.shutdown_event.is_set() and not client.is_interrupted():
            # Read a packet.
            try:
                packet = client.receive(False)
            except ConnectionClosedException:
                LOG.error("Connection closed during syscall")
                client.is_socket_connected = False
                break
            if packet is None:
                sleep(0.1)
                continue

            # Check for file I/O response.
            if packet[0:1] == b'$' and packet[1:2] == b'F':
                LOG.debug("Syscall response received: %r", packet)
                args = packet[2:packet.index(b'#')].split(b',')
                result = int(args[0], base=16)
                errno = int(args[1], base=16) if len(args) > 1 else 0
                ctrl_c = args[2] if len(args) > 2 else b''
                if ctrl_c == b'C':
                    client.set_interrupt()
                    client.set_drop_reply(True)
                return result, errno

            # decode and prepare resp
            resp = self.handle_message(client, packet)

            if resp is not None:
                # send resp
                client.send(resp)

            # check if detach
            if packet[1:2] == b'D':
                LOG.warning("Detach received during syscall")
                break

        return -1, 0

    def get_t_response(self, client, forceSignal=None):
        if self.is_threading_enabled():
            currentThread = self.thread_provider.current_thread
            currentThreadId = currentThread.unique_id
            client.target_facade.set_context(currentThread.context)
        else:
            currentThreadId = 1
            client.target_facade.set_context(self.target_context)

        response  = client.target_facade.get_t_response(forceSignal)
        response += ("thread:%x;" % currentThreadId).encode()

        # Optionally append core
        if self.report_core:
            response += ("core:%x;" % self.core).encode()
        LOG.debug("Stop reply: %s", to_str_safe(response))
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
            and (self.thread_provider.get_actual_current_thread_id() is not None)

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
            LOG.debug("POST_RESET event received")
            self.first_run_after_reset_or_flash = True
            if self.thread_provider is not None:
                self.thread_provider.read_from_target = False

    def _option_did_change(self, notification):
        """@brief Handle an option changing at runtime.

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
            LOG.info("Semihosting %s", ("enabled" if self.enable_semihosting else "disabled"))
        elif notification.event == 'report_core_number':
            self.report_core = notification.data.new_value
        elif notification.event == 'soft_bkpt_as_hard':
            self.soft_bkpt_as_hard = notification.data.new_value
