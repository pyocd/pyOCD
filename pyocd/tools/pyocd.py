#!/usr/bin/env python
# pyOCD debugger
# Copyright (c) 2015-2018 Arm Limited
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

from __future__ import print_function
import argparse
import logging
import os
import sys
import optparse
from optparse import make_option
import six
import prettytable
import traceback

# Attempt to import readline.
try:
    import readline
except ImportError:
    pass

from .. import __version__
from .. import (utility, coresight)
from ..core.helpers import ConnectHelper
from ..core import (exceptions, session)
from ..target.family import target_kinetis
from ..probe.pydapaccess import DAPAccess
from ..probe.debug_probe import DebugProbe
from ..coresight.ap import MEM_AP
from ..core.target import Target
from ..flash.loader import (FlashEraser, FlashLoader)
from ..gdbserver.gdbserver import GDBServer
from ..utility import mask
from ..utility.cmdline import convert_session_options
from ..utility.hex import (format_hex_width, dump_hex_data)

# Make disasm optional.
try:
    import capstone
    isCapstoneAvailable = True # pylint: disable=invalid-name
except ImportError:
    isCapstoneAvailable = False # pylint: disable=invalid-name

LOG = logging.getLogger(__name__)

LEVELS = {
        'debug':logging.DEBUG,
        'info':logging.INFO,
        'warning':logging.WARNING,
        'error':logging.ERROR,
        'critical':logging.CRITICAL
        }

CORE_STATUS_DESC = {
        Target.TARGET_HALTED : "Halted",
        Target.TARGET_RUNNING : "Running",
        Target.TARGET_RESET : "Reset",
        Target.TARGET_SLEEPING : "Sleeping",
        Target.TARGET_LOCKUP : "Lockup",
        }

VC_NAMES_MAP = {
        Target.CATCH_HARD_FAULT : "hard fault",
        Target.CATCH_BUS_FAULT : "bus fault",
        Target.CATCH_MEM_FAULT : "memory fault",
        Target.CATCH_INTERRUPT_ERR : "interrupt error",
        Target.CATCH_STATE_ERR : "state error",
        Target.CATCH_CHECK_ERR : "check error",
        Target.CATCH_COPROCESSOR_ERR : "coprocessor error",
        Target.CATCH_CORE_RESET : "core reset",
        }

HPROT_BIT_DESC = {
        0: ("instruction fetch", "data access"),
        1: ("user", "privileged"),
        2: ("non-bufferable", "bufferable"),
        3: ("non-cacheable", "cacheable/modifiable"),
        4: ("no cache lookup", "lookup in cache"),
        5: ("no cache allocate", "allocate in cache"),
        6: ("non-shareable", "shareable"),
        }

## Default SWD clock in Hz.
DEFAULT_CLOCK_FREQ_HZ = 1000000

## Command info and help.
COMMAND_INFO = {
        'list' : {
            'aliases' : [],
            'args' : "",
            'help' : "Show available targets"
            },
        'erase' : {
            'aliases' : [],
            'args' : "ADDR [COUNT]",
            'help' : "Erase internal flash sectors"
            },
        'unlock' :  {
            'aliases' : [],
            'args' : "",
            'help' : "Unlock security on the target"
            },
        'status' : {
            'aliases' : ['stat'],
            'args' : "",
            'help' : "Show the target's current state"
            },
        'reg' : {
            'aliases' : [],
            'args' : "[-f] [REG]",
            'help' : "Print all or one register"
            },
        'wreg' : {
            'aliases' : [],
            'args' : "REG VALUE",
            'help' : "Set the value of a register"
            },
        'reset' : {
            'aliases' : [],
            'args' : "[-h/--halt]",
            'help' : "Reset the target"
            },
        'savemem' : {
            'aliases' : [],
            'args' : "ADDR LEN FILENAME",
            "help" : "Save a range of memory to a binary file"
            },
        'loadmem' : {
            'aliases' : [],
            'args' : "ADDR FILENAME",
            "help" : "Load a binary file to an address in memory (RAM or flash)"
            },
        'read8' : {
            'aliases' : ['read', 'r', 'rb'],
            'args' : "ADDR [LEN]",
            'help' : "Read 8-bit bytes"
            },
        'read16' : {
            'aliases' : ['r16', 'rh'],
            'args' : "ADDR [LEN]",
            'help' : "Read 16-bit halfwords"
            },
        'read32' : {
            'aliases' : ['r32', 'rw'],
            'args' : "ADDR [LEN]",
            'help' : "Read 32-bit words"
            },
        'write8' : {
            'aliases' : ['write', 'w', 'wb'],
            'args' : "ADDR DATA...",
            'help' : "Write 8-bit bytes to memory (RAM or flash)"
            },
        'write16' : {
            'aliases' : ['w16', 'wh'],
            'args' : "ADDR DATA...",
            'help' : "Write 16-bit halfwords to memory (RAM or flash)"
            },
        'write32' : {
            'aliases' : ['w32', 'ww'],
            'args' : "ADDR DATA...",
            'help' : "Write 32-bit words to memory (RAM or flash)"
            },
        'go' : {
            'aliases' : ['g'],
            'args' : "",
            'help' : "Resume execution of the target"
            },
        'step' : {
            'aliases' : ['s'],
            'args' : "",
            'help' : "Step one instruction"
            },
        'halt' : {
            'aliases' : ['h'],
            'args' : "",
            'help' : "Halt the target"
            },
        'break' : {
            'aliases' : [],
            'args' : "ADDR",
            'help' : "Set a breakpoint address"
            },
        'rmbreak' : {
            'aliases' : [],
            'args' : "ADDR",
            'help' : "Remove a breakpoint"
            },
        'lsbreak' : {
            'aliases' : [],
            'args' : "",
            'help' : "List breakpoints"
            },
        'help' : {
            'aliases' : ['?'],
            'args' : "[CMD]",
            'help' : "Show help for commands"
            },
        'disasm' : {
            'aliases' : ['d'],
            'args' : "[-c/--center] ADDR [LEN]",
            'help' : "Disassemble instructions at an address",
            'extra_help' : "Only available if the capstone library is installed."
            },
        'exit' : {
            'aliases' : ['quit'],
            'args' : "",
            'help' : "Quit pyocd-tool"
            },
        'core' : {
            'aliases' : [],
            'args' : "[NUM]",
            'help' : "Select CPU core by number or print selected core"
            },
        'readdp' : {
            'aliases' : ['rdp'],
            'args' : "ADDR",
            'help' : "Read DP register"
            },
        'writedp' : {
            'aliases' : ['wdp'],
            'args' : "ADDR DATA",
            'help' : "Write DP register"
            },
        'readap' : {
            'aliases' : ['rap'],
            'args' : "[APSEL] ADDR",
            'help' : "Read AP register"
            },
        'writeap' : {
            'aliases' : ['wap'],
            'args' : "[APSEL] ADDR DATA",
            'help' : "Write AP register"
            },
        'reinit' : {
            'aliases' : [],
            'args' : "",
            'help' : "Reinitialize the target object"
            },
        'show' : {
            'aliases' : [],
            'args' : "INFO",
            'help' : "Report info about the target",
            },
        'set' : {
            'aliases' : [],
            'args' : "NAME VALUE",
            'help' : "Set an option value",
            'extra_help' : "Available info names: vc, vectorcatch.",
            },
        'initdp' : {
            'aliases' : [],
            'args' : "",
            'help' : "Init DP and power up debug.",
            },
        'makeap' : {
            'aliases' : [],
            'args' : "APSEL",
            'help' : "Creates a new AP object for the given APSEL.",
            'extra_help' : "The type of AP, MEM-AP or generic, is autodetected.",
            },
        'where' : {
            'aliases' : [],
            'args' : "[ADDR]",
            'help' : "Show symbol, file, and line for address.",
            'extra_help' : "The symbol name, source file path, and line number are displayed for the specified address. If no address is given then current PC is used. An ELF file must have been specified with the --elf option.",
            },
        'symbol' : {
            'aliases' : [],
            'args' : "NAME",
            'help' : "Show a symbol's value.",
            'extra_help' : "An ELF file must have been specified with the --elf option.",
            },
        'gdbserver' : {
            'aliases' : [],
            'args' : "ACTION",
            'help' : "Start or stop the gdbserver.",
            'extra_help' : "The action argument should be either 'start' or 'stop'. Use the 'gdbserver_port' and 'telnet_port' user options to control the ports the gdbserver uses.",
            },
        }

INFO_HELP = {
        'map' : {
            'aliases' : [],
            'help' : "Target memory map.",
            },
        'peripherals' : {
            'aliases' : [],
            'help' : "List of target peripheral instances.",
            },
        'uid' : {
            'aliases' : [],
            'help' : "Target's unique ID",
            },
        'cores' : {
            'aliases' : [],
            'help' : "Information about CPU cores in the target.",
            },
        'target' : {
            'aliases' : [],
            'help' : "General target information.",
            },
        'fault' : {
            'aliases' : [],
            'help' : "Fault status information.",
            'extra_help' : "By default, only asserted fields are shown. Add -a to command to show all fields.",
            },
        'vector-catch' : {
            'aliases' : ['vc'],
            'help' : "Show current vector catch settings.",
            },
        'step-into-interrupt' : {
            'aliases' : ['si'],
            'help' : "Display whether interrupts are enabled when single stepping."
            },
        'nreset' : {
            'aliases' : [],
            'help' : "Current nRESET signal state.",
            },
        'option' : {
            'aliases' : [],
            'help' : "Show the current value of one or more user options.",
            },
        'mem-ap' : {
            'aliases' : [],
            'help' : "Display the currently selected MEM-AP used for memory read/write commands."
            },
        'hnonsec' : {
            'aliases' : [],
            'help' : "Display the current HNONSEC value used by the selected MEM-AP."
            },
        'hprot' : {
            'aliases' : [],
            'help' : "Display the current HPROT value used by the selected MEM-AP."
            },
        }

OPTION_HELP = {
        'vector-catch' : {
            'aliases' : ['vc'],
            'help' : "Control enabled vector catch sources.",
            'extra_help' : "Value is a concatenation of one letter per enabled source in any order, or 'all' or 'none'. (h=hard fault, b=bus fault, m=mem fault, i=irq err, s=state err, c=check err, p=nocp, r=reset, a=all, n=none).",
            },
        'step-into-interrupt' : {
            'aliases' : ['si'],
            'help' : "Set whether to enable or disable interrupts when single stepping. Set to 1 to enable."
            },
        'nreset' : {
            'aliases' : [],
            'help' : "Set nRESET signal state. Accepts a value of 0 or 1."
            },
        'log' : {
            'aliases' : [],
            'help' : "Set log level to one of debug, info, warning, error, critical"
            },
        'clock' : {
            'aliases' : [],
            'help' : "Set SWD or JTAG clock frequency in kilohertz."
            },
        'option' : {
            'aliases' : [],
            'help' : "Change the value of one or more user options.",
            'extra_help' : "Each parameter should follow the form OPTION=VALUE.",
            },
        'mem-ap' : {
            'aliases' : [],
            'help' : "Select the MEM-AP used for memory read/write commands."
            },
        'hnonsec' : {
            'aliases' : [],
            'help' : "Set the current HNONSEC value used by the selected MEM-AP."
            },
        'hprot' : {
            'aliases' : [],
            'help' : "Set the current HPROT value used by the selected MEM-AP."
            },
        }

ALL_COMMANDS = list(COMMAND_INFO.keys())
ALL_COMMANDS.extend(a for d in COMMAND_INFO.values() for a in d['aliases'])
ALL_COMMANDS.sort()

class ToolError(Exception):
    pass

class ToolExitException(Exception):
    pass

def cmdoptions(opts):
    def process_opts(fn):
        parser = optparse.OptionParser(add_help_option=False)
        for opt in opts:
            parser.add_option(opt)
        def foo(inst, args):
            namespace, other_args = parser.parse_args(args)
            return fn(inst, namespace, other_args)
        return foo
    return process_opts

class PyOCDConsole(object):
    PROMPT = '>>> '

    def __init__(self, tool):
        self.tool = tool
        self.last_command = ''

    def run(self):
        try:
            while True:
                try:
                    line = six.moves.input(self.PROMPT)
                    line = line.strip()
                    if line:
                        self.process_command_line(line)
                        self.last_command = line
                    elif self.last_command:
                        self.process_command(self.last_command)
                except KeyboardInterrupt:
                    print()
        except EOFError:
            # Print a newline when we get a Ctrl-D on a Posix system.
            # Windows exits with a Ctrl-Z+Return, so there is no need for this.
            if os.name != "nt":
                print()

    def process_command_line(self, line):
        for cmd in line.split(';'):
            self.process_command(cmd)

    def process_command(self, cmd):
        try:
            firstChar = (cmd.strip())[0]
            if firstChar in '$!':
                cmd = cmd[1:].strip()
                if firstChar == '$':
                    self.tool.handle_python(cmd)
                elif firstChar == '!':
                    os.system(cmd)
                return

            args = utility.cmdline.split_command_line(cmd)
            cmd = args[0].lower()
            args = args[1:]

            # Handle register name as command.
            if cmd in coresight.cortex_m.CORE_REGISTER:
                self.tool.handle_reg([cmd])
                return

            # Check for valid command.
            if cmd not in self.tool.command_list:
                print("Error: unrecognized command '%s'" % cmd)
                return

            # Run command.
            handler = self.tool.command_list[cmd]
            handler(args)
        except ValueError:
            print("Error: invalid argument")
            if session.Session.get_current().log_tracebacks:
                traceback.print_exc()
        except exceptions.TransferError as e:
            print("Error:", e)
            if session.Session.get_current().log_tracebacks:
                traceback.print_exc()
        except ToolError as e:
            print("Error:", e)
        except ToolExitException:
            raise
        except Exception as e:
            print("Unexpected exception:", e)
            if session.Session.get_current().log_tracebacks:
                traceback.print_exc()

class PyOCDCommander(object):
    def __init__(self, args, cmds=None):
        # Read command-line arguments.
        self.args = args
        self.cmds = cmds

        self.session = None
        self.board = None
        self.target = None
        self.probe = None
        self.selected_ap = 0
        self.did_erase = False
        self.exit_code = 0
        self.step_into_interrupt = False
        self.elf = None
        self._peripherals = {}
        self._loaded_peripherals = False
        self._gdbserver = None
        
        self.command_list = {
                'list' :    self.handle_list,
                'erase' :   self.handle_erase,
                'unlock' :  self.handle_unlock,
                'status' :  self.handle_status,
                'stat' :    self.handle_status,
                'reg' :     self.handle_reg,
                'wreg' :    self.handle_write_reg,
                'reset' :   self.handle_reset,
                'savemem' : self.handle_savemem,
                'loadmem' : self.handle_loadmem,
                'read' :    self.handle_read8,
                'read8' :   self.handle_read8,
                'read16' :  self.handle_read16,
                'read32' :  self.handle_read32,
                'r' :       self.handle_read8,
                'rb' :      self.handle_read8,
                'r16' :     self.handle_read16,
                'rh' :      self.handle_read16,
                'r32' :     self.handle_read32,
                'rw' :      self.handle_read32,
                'write' :   self.handle_write8,
                'write8' :  self.handle_write8,
                'write16' : self.handle_write16,
                'write32' : self.handle_write32,
                'w' :       self.handle_write8,
                'wb' :      self.handle_write8,
                'w16' :     self.handle_write16,
                'wh' :      self.handle_write16,
                'w32' :     self.handle_write32,
                'ww' :      self.handle_write32,
                'go' :      self.handle_go,
                'g' :       self.handle_go,
                'step' :    self.handle_step,
                's' :       self.handle_step,
                'halt' :    self.handle_halt,
                'h' :       self.handle_halt,
                'break' :   self.handle_breakpoint,
                'rmbreak' : self.handle_remove_breakpoint,
                'lsbreak' : self.handle_list_breakpoints,
                'disasm' :  self.handle_disasm,
                'd' :       self.handle_disasm,
                'exit' :    self.handle_exit,
                'quit' :    self.handle_exit,
                'core' :    self.handle_core,
                'readdp' :  self.handle_readdp,
                'writedp' : self.handle_writedp,
                'readap' :  self.handle_readap,
                'writeap' : self.handle_writeap,
                'rdp' :     self.handle_readdp,
                'wdp' :     self.handle_writedp,
                'rap' :     self.handle_readap,
                'wap' :     self.handle_writeap,
                'reinit' :  self.handle_reinit,
                'show' :    self.handle_show,
                'set' :     self.handle_set,
                'help' :    self.handle_help,
                'where' :   self.handle_where,
                '?' :       self.handle_help,
                'initdp' :  self.handle_initdp,
                'makeap' :  self.handle_makeap,
                'symbol' :  self.handle_symbol,
                'gdbserver':self.handle_gdbserver,
            }
        self.info_list = {
                'map' :                 self.handle_show_map,
                'peripherals' :         self.handle_show_peripherals,
                'uid' :                 self.handle_show_unique_id,
                'cores' :               self.handle_show_cores,
                'target' :              self.handle_show_target,
                'fault' :               self.handle_show_fault,
                'vector-catch' :        self.handle_show_vectorcatch,
                'vc' :                  self.handle_show_vectorcatch,
                'step-into-interrupt' : self.handle_show_step_interrupts,
                'si' :                  self.handle_show_step_interrupts,
                'nreset' :              self.handle_show_nreset,
                'option' :              self.handle_show_option,
                'mem-ap' :              self.handle_show_ap,
                'hnonsec' :             self.handle_show_hnonsec,
                'hprot' :               self.handle_show_hprot,
            }
        self.option_list = {
                'vector-catch' :        self.handle_set_vectorcatch,
                'vc' :                  self.handle_set_vectorcatch,
                'step-into-interrupt' : self.handle_set_step_interrupts,
                'si' :                  self.handle_set_step_interrupts,
                'nreset' :              self.handle_set_nreset,
                'log' :                 self.handle_set_log,
                'clock' :               self.handle_set_clock,
                'option' :              self.handle_set_option,
                'mem-ap' :              self.handle_set_ap,
                'hnonsec' :             self.handle_set_hnonsec,
                'hprot' :               self.handle_set_hprot,
            }

    def run(self):
        try:
            # If no commands, enter interactive mode.
            if self.cmds is None:
                if not self.connect():
                    return self.exit_code
                
                # Print connected message, unless not initing.
                if not self.args.no_init:
                    try:
                        # If the target is locked, we can't read the CPU state.
                        if self.target.is_locked():
                            status = "locked"
                        else:
                            try:
                                status = CORE_STATUS_DESC[self.target.get_state()]
                            except KeyError:
                                status = "<no core>"

                        # Say what we're connected to.
                        print("Connected to %s [%s]: %s" % (self.target.part_number,
                            status, self.board.unique_id))
                    except exceptions.TransferFaultError:
                        pass

                # Run the command line.
                console = PyOCDConsole(self)
                console.run()
                
            # Otherwise, run the list of commands we were given and exit. We only connect when
            # there is a command that requires a connection (most do).
            else:
                didConnect = False

                for args in self.cmds:
                    # Extract the command name.
                    cmd = args.pop(0).lower()
                    
                    # Handle certain commands without connecting.
                    if cmd == 'list':
                        self.handle_list([])
                        continue
                    elif cmd == 'help':
                        self.handle_help(args)
                        continue
                    # For others, connect first.
                    elif not didConnect:
                        if not self.connect():
                            return self.exit_code
                        didConnect = True
                
                    # Invoke action handler.
                    result = self.command_list[cmd](args)
                    if result is not None:
                        self.exit_code = result
                        break

        except ToolExitException:
            self.exit_code = 0
        except ValueError:
            print("Error: invalid argument")
            if session.Session.get_current().log_tracebacks:
                traceback.print_exc()
        except exceptions.TransferError:
            print("Error: transfer failed")
            if session.Session.get_current().log_tracebacks:
                traceback.print_exc()
            self.exit_code = 2
        except ToolError as e:
            print("Error:", e)
            self.exit_code = 1
        finally:
            if self.session is not None:
                self.session.close()

        return self.exit_code

    def connect(self):
        if (self.args.frequency is not None) and (self.args.frequency != DEFAULT_CLOCK_FREQ_HZ):
            print("Setting SWD clock to %d kHz" % (self.args.frequency // 1000))

        options = convert_session_options(self.args.options)
        
        # Set connect mode. If --halt is set then the connect mode is halt. If connect_mode is
        # set through -O then use that. Otherwise default to attach.
        if self.args.halt:
            connect_mode = 'halt'
        elif 'connect_mode' in options:
            connect_mode = None
        else:
            connect_mode = 'attach'
        
        # Connect to board.
        self.session = ConnectHelper.session_with_chosen_probe(
                        blocking=(not self.args.no_wait),
                        project_dir=self.args.project_dir,
                        config_file=self.args.config,
                        user_script=self.args.script,
                        no_config=self.args.no_config,
                        pack=self.args.pack,
                        unique_id=self.args.unique_id,
                        target_override=self.args.target_override,
                        connect_mode=connect_mode,
                        frequency=self.args.frequency,
                        options=options,
                        option_defaults=dict(
                            auto_unlock=False,
                            resume_on_disconnect=False,
                            ))
        if self.session is None:
            self.exit_code = 3
            return False
        self.board = self.session.board
        try:
            self.session.open(init_board=not self.args.no_init)
        except exceptions.TransferFaultError as e:
            if not self.board.target.is_locked():
                print("Transfer fault while initing board: %s" % e)
                if session.Session.get_current().log_tracebacks:
                    traceback.print_exc()
                self.exit_code = 1
                return False
        except Exception as e:
            print("Exception while initing board: %s" % e)
            if session.Session.get_current().log_tracebacks:
                traceback.print_exc()
            self.exit_code = 1
            return False

        self.target = self.board.target
        self.probe = self.session.probe

        # Select the first core's MEM-AP by default.
        if not self.args.no_init:
            try:
                self.selected_ap = self.target.selected_core.ap.ap_num
            except IndexError:
                for ap_num in sorted(self.target.aps.keys()):
                    if isinstance(self.target.aps[ap_num], MEM_AP):
                        self.selected_ap = ap_num
                        break

        # Set elf file if provided.
        if self.args.elf:
            self.target.elf = self.args.elf
            self.elf = self.target.elf
        else:
            self.elf = None

        # Handle a device with flash security enabled.
        if not self.args.no_init and self.target.is_locked():
            print("Warning: Target is locked, limited operations available. Use unlock command to mass erase and unlock.")
        
        return True
    
    @property
    def peripherals(self):
        if self.target.svd_device and not self._loaded_peripherals:
            for p in self.target.svd_device.peripherals:
                self._peripherals[p.name.lower()] = p
            self._loaded_peripherals = True
        return self._peripherals

    def handle_list(self, args):
        ConnectHelper.list_connected_probes()

    def handle_status(self, args):
        if self.target.is_locked():
            print("Security:       Locked")
        else:
            print("Security:       Unlocked")
        if isinstance(self.target, target_kinetis.Kinetis):
            print("MDM-AP Status:  0x%08x" % self.target.mdm_ap.read_reg(target_kinetis.MDM_STATUS))
        if not self.target.is_locked():
            for i, c in enumerate(self.target.cores):
                core = self.target.cores[c]
                print("Core %d status:  %s" % (i, CORE_STATUS_DESC[core.get_state()]))

    def handle_reg(self, args):
        # If there are no args, print all register values.
        if len(args) < 1:
            self.dump_registers()
            return

        if len(args) == 2 and args[0].lower() == '-f':
            del args[0]
            show_fields = True
        else:
            show_fields = False

        reg = args[0].lower()
        if reg in coresight.cortex_m.CORE_REGISTER:
            value = self.target.read_core_register(reg)
            if isinstance(value, six.integer_types):
                print("%s = 0x%08x (%d)" % (reg, value, value))
            elif type(value) is float:
                print("%s = %g" % (reg, value))
            else:
                raise ToolError("Unknown register value type")
        else:
            subargs = reg.split('.')
            if subargs[0] in self.peripherals:
                p = self.peripherals[subargs[0]]
                if len(subargs) > 1:
                    r = [x for x in p.registers if x.name.lower() == subargs[1]]
                    if len(r):
                        self._dump_peripheral_register(p, r[0], True)
                    else:
                        raise ToolError("invalid register '%s' for %s" % (subargs[1], p.name))
                else:
                    for r in p.registers:
                        self._dump_peripheral_register(p, r, show_fields)
            else:
                raise ToolError("invalid peripheral '%s'" % (subargs[0]))

    def handle_write_reg(self, args):
        if len(args) < 1:
            raise ToolError("No register specified")
        if len(args) < 2:
            raise ToolError("No value specified")

        reg = args[0].lower()
        if reg in coresight.cortex_m.CORE_REGISTER:
            if (reg.startswith('s') and reg != 'sp') or reg.startswith('d'):
                value = float(args[1])
            else:
                value = self.convert_value(args[1])
            self.target.write_core_register(reg, value)
        else:
            value = self.convert_value(args[1])
            subargs = reg.split('.')
            if len(subargs) < 2:
                raise ToolError("no register specified")
            if subargs[0] in self.peripherals:
                p = self.peripherals[subargs[0]]
                r = [x for x in p.registers if x.name.lower() == subargs[1]]
                if len(r):
                    r = r[0]
                    addr = p.base_address + r.address_offset
                    if len(subargs) == 2:
                        print("writing 0x%x to 0x%x:%d (%s)" % (value, addr, r.size, r.name))
                        self.target.write_memory(addr, value, r.size)
                    elif len(subargs) == 3:
                        f = [x for x in r.fields if x.name.lower() == subargs[2]]
                        if len(f):
                            f = f[0]
                            msb = f.bit_offset + f.bit_width - 1
                            lsb = f.bit_offset
                            originalValue = self.target.read_memory(addr, r.size)
                            value = mask.bfi(originalValue, msb, lsb, value)
                            print("writing 0x%x to 0x%x[%d:%d]:%d (%s.%s)" % (value, addr, msb, lsb, r.size, r.name, f.name))
                            self.target.write_memory(addr, value, r.size)
                    else:
                        raise ToolError("too many dots")
                    self._dump_peripheral_register(p, r, True)
                else:
                    raise ToolError("invalid register '%s' for %s" % (subargs[1], p.name))
            else:
                raise ToolError("invalid peripheral '%s'" % (subargs[0]))

    @cmdoptions([make_option('-h', "--halt", action="store_true")])
    def handle_reset(self, args, other):
        print("Resetting target")
        if args.halt:
            self.target.reset_and_halt()

            status = self.target.get_state()
            if status != Target.TARGET_HALTED:
                print("Failed to halt device on reset")
            else:
                print("Successfully halted device on reset")
        else:
            self.target.reset()

    def handle_set_nreset(self, args):
        if len(args) != 1:
            print("Missing reset state")
            return
        state = int(args[0], base=0)
        print("nRESET = %d" % (state))
        self.probe.assert_reset((state == 0))

    @cmdoptions([make_option('-c', "--center", action="store_true")])
    def handle_disasm(self, args, other):
        if len(other) == 0:
            print("Error: no address specified")
            return 1
        addr = self.convert_value(other[0])
        if len(other) < 2:
            count = 6
        else:
            count = self.convert_value(other[1])

        if args.center:
            addr -= count // 2

        # Since we're disassembling, make sure the Thumb bit is cleared.
        addr &= ~1

        # Print disasm of data.
        data = self.target.read_memory_block8(addr, count)
        self.print_disasm(bytes(bytearray(data)), addr)

    def handle_read8(self, args):
        return self.do_read(args, 8)

    def handle_read16(self, args):
        return self.do_read(args, 16)

    def handle_read32(self, args):
        return self.do_read(args, 32)

    def handle_write8(self, args):
        return self.do_write(args, 8)

    def handle_write16(self, args):
        return self.do_write(args, 16)

    def handle_write32(self, args):
        return self.do_write(args, 32)

    def handle_savemem(self, args):
        if len(args) < 3:
            print("Error: missing argument")
            return 1
        addr = self.convert_value(args[0])
        count = self.convert_value(args[1])
        filename = args[2]

        region = self.session.target.memory_map.get_region_for_address(addr)
        flash_init_required =  region is not None and region.is_flash and not region.is_powered_on_boot and region.flash is not None
        if flash_init_required:
            region.flash.init(region.flash.Operation.VERIFY)

        data = bytearray(self.target.aps[self.selected_ap].read_memory_block8(addr, count))

        if flash_init_required:
            region.flash.cleanup()

        with open(filename, 'wb') as f:
            f.write(data)
            print("Saved %d bytes to %s" % (count, filename))

    def handle_loadmem(self, args):
        if len(args) < 2:
            print("Error: missing argument")
            return 1
        addr = self.convert_value(args[0])
        filename = args[1]

        with open(filename, 'rb') as f:
            data = bytearray(f.read())
            if self.is_flash_write(addr, 8, data):
                FlashLoader.program_binary_data(self.session, addr, data)
            else:
                self.target.aps[self.selected_ap].write_memory_block8(addr, data)
            print("Loaded %d bytes to 0x%08x" % (len(data), addr))

    def do_read(self, args, width):
        if len(args) == 0:
            print("Error: no address specified")
            return 1
        addr = self.convert_value(args[0])
        if len(args) < 2:
            count = width // 8
        else:
            count = self.convert_value(args[1])

        if width == 8:
            data = self.target.aps[self.selected_ap].read_memory_block8(addr, count)
            byteData = data
        elif width == 16:
            byteData = self.target.aps[self.selected_ap].read_memory_block8(addr, count)
            data = utility.conversion.byte_list_to_u16le_list(byteData)
        elif width == 32:
            byteData = self.target.aps[self.selected_ap].read_memory_block8(addr, count)
            data = utility.conversion.byte_list_to_u32le_list(byteData)

        # Print hex dump of output.
        dump_hex_data(data, addr, width=width)

    def do_write(self, args, width):
        if len(args) == 0:
            print("Error: no address specified")
            return 1
        addr = self.convert_value(args[0])
        if len(args) <= 1:
            print("Error: no data for write")
            return 1
        else:
            data = [self.convert_value(d) for d in args[1:]]

        if width == 8:
            pass
        elif width == 16:
            data = utility.conversion.u16le_list_to_byte_list(data)
        elif width == 32:
            data = utility.conversion.u32le_list_to_byte_list(data)

        if self.is_flash_write(addr, width, data):
            # Look up flash region.
            region = self.session.target.memory_map.get_region_for_address(addr)
            if not region:
                print("address 0x%08x is not within a memory region" % addr)
                return 1
            if not region.is_flash:
                print("address 0x%08x is not in flash" % addr)
                return 1
            assert region.flash is not None
            
            # Program phrase to flash.
            region.flash.init(region.flash.Operation.PROGRAM)
            region.flash.program_phrase(addr, data)
            region.flash.cleanup()
        else:
            self.target.aps[self.selected_ap].write_memory_block8(addr, data)
            self.target.flush()

    def handle_erase(self, args):
        if len(args) < 1:
            raise ToolError("invalid arguments")
        addr = self.convert_value(args[0])
        if len(args) < 2:
            count = 1
        else:
            count = self.convert_value(args[1])
        
        eraser = FlashEraser(self.session, FlashEraser.Mode.SECTOR)
        while count:
            # Look up the flash region so we can get the page size.
            region = self.session.target.memory_map.get_region_for_address(addr)
            if not region:
                print("address 0x%08x is not within a memory region" % addr)
                break
            if not region.is_flash:
                print("address 0x%08x is not in flash" % addr)
                break
            
            # Erase this page.
            eraser.erase([addr])
            
            # Next page.
            count -= 1
            addr += region.blocksize

    def handle_unlock(self, args):
        # Currently the same as erase.
        if not self.did_erase:
            self.target.mass_erase()

    def handle_go(self, args):
        self.target.resume()
        status = self.target.get_state()
        if status == Target.TARGET_RUNNING:
            print("Successfully resumed device")
        else:
            print("Failed to resume device")

    def handle_step(self, args):
        self.target.step(disable_interrupts=not self.step_into_interrupt)
        addr = self.target.read_core_register('pc')
        if isCapstoneAvailable:
            addr &= ~1
            data = self.target.read_memory_block8(addr, 4)
            self.print_disasm(bytes(bytearray(data)), addr, maxInstructions=1)
        else:
            print("PC = 0x%08x" % (addr))

    def handle_halt(self, args):
        self.target.halt()

        status = self.target.get_state()
        if status != Target.TARGET_HALTED:
            print("Failed to halt device")
            return 1
        else:
            print("Successfully halted device")

    def handle_breakpoint(self, args):
        if len(args) < 1:
            raise ToolError("no breakpoint address provided")
        addr = self.convert_value(args[0])
        if self.target.set_breakpoint(addr):
            self.target.selected_core.bp_manager.flush()
            print("Set breakpoint at 0x%08x" % addr)
        else:
            print("Failed to set breakpoint at 0x%08x" % addr)

    def handle_remove_breakpoint(self, args):
        if len(args) < 1:
            raise ToolError("no breakpoint address provided")
        addr = self.convert_value(args[0])
        try:
            type = self.target.get_breakpoint_type(addr)
            self.target.remove_breakpoint(addr)
            self.target.selected_core.bp_manager.flush()
            print("Removed breakpoint at 0x%08x" % addr)
        except:
            print("Failed to remove breakpoint at 0x%08x" % addr)

    def handle_list_breakpoints(self, args):
        availableBpCount = self.target.selected_core.available_breakpoint_count
        print("%d hardware breakpoints available" % availableBpCount)
        bps = self.target.selected_core.bp_manager.get_breakpoints()
        if not len(bps):
            print("No breakpoints installed")
        else:
            for i, addr in enumerate(bps):
                print("%d: 0x%08x" % (i, addr))

    def handle_set_log(self, args):
        if len(args) < 1:
            print("Error: no log level provided")
            return 1
        if args[0].lower() not in LEVELS:
            print("Error: log level must be one of {%s}" % ','.join(LEVELS.keys()))
            return 1
        logging.getLogger().setLevel(LEVELS[args[0].lower()])

    def handle_set_clock(self, args):
        if len(args) < 1:
            print("Error: no clock frequency provided")
            return 1
        try:
            freq_Hz = self.convert_value(args[0]) * 1000
        except:
            print("Error: invalid frequency")
            return 1
        self.probe.set_clock(freq_Hz)
        if self.probe.wire_protocol == DebugProbe.Protocol.SWD:
            swd_jtag = 'SWD'
        elif self.probe.wire_protocol == DebugProbe.Protocol.JTAG:
            swd_jtag = 'JTAG'
        else:
            swd_jtag = '??'

        if freq_Hz >= 1000000:
            nice_freq = "%.2f MHz" % (freq_Hz / 1000000)
        elif freq_Hz > 1000:
            nice_freq = "%.2f kHz" % (freq_Hz / 1000)
        else:
            nice_freq = "%d Hz" % freq_Hz

        print("Changed %s frequency to %s" % (swd_jtag, nice_freq))

    def handle_exit(self, args):
        raise ToolExitException()

    def handle_python(self, args):
        try:
            import pyocd
            env = {
                    'session' : self.session,
                    'board' : self.board,
                    'target' : self.target,
                    'probe' : self.probe,
                    'link' : self.probe, # Old name
                    'dp' : self.target.dp,
                    'aps' : self.target.dp.aps,
                    'elf' : self.elf,
                    'map' : self.target.memory_map,
                    'pyocd' : pyocd,
                }
            result = eval(args, globals(), env)
            if result is not None:
                if isinstance(result, six.integer_types):
                    print("0x%08x (%d)" % (result, result))
                else:
                    print(result)
        except Exception as e:
            print("Exception while executing expression:", e)
            if session.Session.get_current().log_tracebacks:
                traceback.print_exc()

    def handle_core(self, args):
        if len(args) < 1:
            print("Core %d is selected" % self.target.selected_core.core_number)
            return
        core = int(args[0], base=0)
        self.target.select_core(core)
        print("Selected core %d" % core)

    def handle_readdp(self, args):
        if len(args) < 1:
            print("Missing DP address")
            return
        addr = self.convert_value(args[0])
        result = self.target.dp.read_reg(addr)
        print("DP register 0x%x = 0x%08x" % (addr, result))

    def handle_writedp(self, args):
        if len(args) < 1:
            print("Missing DP address")
            return
        if len(args) < 2:
            print("Missing value")
            return
        addr = self.convert_value(args[0])
        data = self.convert_value(args[1])
        self.target.dp.write_reg(addr, data)

    def handle_readap(self, args):
        if len(args) < 1:
            print("Missing AP address")
            return
        if len(args) == 1:
            addr = self.convert_value(args[0])
        elif len(args) == 2:
            addr = (self.convert_value(args[0]) << 24) | self.convert_value(args[1])
        result = self.target.dp.read_ap(addr)
        print("AP register 0x%x = 0x%08x" % (addr, result))

    def handle_writeap(self, args):
        if len(args) < 1:
            print("Missing AP address")
            return
        if len(args) < 2:
            print("Missing value")
            return
        if len(args) == 2:
            addr = self.convert_value(args[0])
            data_arg = 1
        elif len(args) == 3:
            addr = (self.convert_value(args[0]) << 24) | self.convert_value(args[1])
            data_arg = 2
        data = self.convert_value(args[data_arg])
        self.target.dp.write_ap(addr, data)

    def handle_initdp(self, args):
        self.target.dp.init()
        self.target.dp.power_up_debug()

    def handle_makeap(self, args):
        if len(args) < 1:
            print("Missing APSEL")
            return
        apsel = self.convert_value(args[0])
        if apsel in self.target.aps:
            print("AP with APSEL=%d already exists" % apsel)
            return
        exists = coresight.ap.AccessPort.probe(self.target.dp, apsel)
        if not exists:
            print("Error: no AP with APSEL={} exists".format(apsel))
            return
        ap = coresight.ap.AccessPort.create(self.target.dp, apsel)
        self.target.dp.aps[apsel] = ap # Same mutable list is target.aps
        print("AP#{:d} IDR = {:#010x}".format(apsel, ap.idr))

    def handle_where(self, args):
        if self.elf is None:
            print("No ELF available")
            return
        
        if len(args) >= 1:
            addr = self.convert_value(args[0])
        else:
            addr = self.target.read_core_register('pc')
        
        lineInfo = self.elf.address_decoder.get_line_for_address(addr)
        if lineInfo is not None:
            path = os.path.join(lineInfo.dirname, lineInfo.filename).decode()
            line = lineInfo.line
            pathline = "{}:{}".format(path, line)
        else:
            pathline = "<unknown file>"
        
        fnInfo = self.elf.address_decoder.get_function_for_address(addr)
        if fnInfo is not None:
            name = fnInfo.name.decode()
        else:
            name = "<unknown symbol>"
        
        print("{addr:#10x} : {fn} : {pathline}".format(addr=addr, fn=name, pathline=pathline))

    def handle_symbol(self, args):
        if self.elf is None:
            print("No ELF available")
            return
        if len(args) < 1:
            raise ToolError("missing symbol name argument")
        name = args[0]
        
        sym = self.elf.symbol_decoder.get_symbol_for_name(name)
        if sym is not None:
            if sym.type == 'STT_FUNC':
                name += "()"
            print("{name}: {addr:#10x} {sz:#x}".format(name=name, addr=sym.address, sz=sym.size))
        else:
            print("No symbol named '{}' was found".format(name))

    def handle_gdbserver(self, args):
        if len(args) < 1:
            raise ToolError("missing action argument")
        action = args[0].lower()
        if action == 'start':
            if self._gdbserver is None:
                self._gdbserver = GDBServer(self.session, core=self.target.selected_core.core_number)
            else:
                print("gdbserver is already running")
        elif action == 'stop':
            if self._gdbserver is not None:
                self._gdbserver.stop()
                self._gdbserver = None
            else:
                print("gdbserver is not running")
        else:
            print("Invalid action")

    def handle_reinit(self, args):
        self.target.init()

    def handle_show(self, args):
        if len(args) < 1:
            raise ToolError("missing info name argument")
        infoName = args[0]
        try:
            self.info_list[infoName](args[1:])
        except KeyError:
            raise ToolError("unknown info name '%s'" % infoName)

    def handle_show_unique_id(self, args):
        print("Unique ID:    %s" % self.board.unique_id)

    def handle_show_target(self, args):
        print("Target:       %s" % self.target.part_number)
        print("DAP IDCODE:   0x%08x" % self.target.dp.dpidr)

    def handle_show_cores(self, args):
        if self.target.is_locked():
            print("Target is locked")
        else:
            print("Cores:        %d" % len(self.target.cores))
            for i, c in enumerate(self.target.cores):
                core = self.target.cores[c]
                print("Core %d type:  %s" % (i, coresight.cortex_m.CORE_TYPE_NAME[core.core_type]))

    def handle_show_map(self, args):
        pt = prettytable.PrettyTable(["Region", "Start", "End", "Size", "Access", "Sector", "Page"])
        pt.align = 'l'
        pt.border = False
        for region in self.target.get_memory_map():
            pt.add_row([
                region.name,
                "0x%08x" % region.start,
                "0x%08x" % region.end,
                "0x%08x" % region.length,
                region.access,
                ("0x%08x" % region.sector_size) if region.is_flash else '-',
                ("0x%08x" % region.page_size) if region.is_flash else '-',
                ])
        print(pt)

    def handle_show_peripherals(self, args):
        for periph in sorted(self.peripherals.values(), key=lambda x:x.base_address):
            print("0x%08x: %s" % (periph.base_address, periph.name))

    def handle_show_fault(self, args):
        showAll = ('-a' in args)
        
        CFSR = 0xe000ed28
        HFSR = 0xe000ed2c
        DFSR = 0xe000ed30
        MMFAR = 0xe000ed34
        BFAR = 0xe000ed38
        AFSR = 0xe000ed3c
        
        MMFSR_fields = [
                ('IACCVIOL', 0),
                ('DACCVIOL', 1),
                ('MUNSTKERR', 3),
                ('MSTKERR', 4),
#                 ('MMARVALID', 7),
            ]
        BFSR_fields = [
                ('IBUSERR', 0),
                ('PRECISERR', 1),
                ('IMPRECISERR', 2),
                ('UNSTKERR', 3),
                ('STKERR', 4),
                ('LSPERR', 5),
#                 ('BFARVALID', 7),
            ]
        UFSR_fields = [
                ('UNDEFINSTR', 0),
                ('INVSTATE', 1),
                ('INVPC', 2),
                ('NOCP', 3),
                ('STKOF', 4),
                ('UNALIGNED', 8),
                ('DIVBYZERO', 9),
            ]
        HFSR_fields = [
                ('VECTTBL', 1),
                ('FORCED', 30),
                ('DEBUGEVT', 31),
            ]
        DFSR_fields = [
                ('HALTED', 0),
                ('BKPT', 1),
                ('DWTTRAP', 2),
                ('VCATCH', 3),
                ('EXTERNAL', 4),
            ]
        
        def print_fields(regname, value, fields, showAll):
            if value == 0 and not showAll:
                return
            print("  %s = 0x%08x" % (regname, value))
            for name, bitpos in fields:
                bit = (value >> bitpos) & 1
                if showAll or bit != 0:
                    print("    %s = 0x%x" % (name, bit))
        
        cfsr = self.target.read32(CFSR)
        mmfsr = cfsr & 0xff
        bfsr = (cfsr >> 8) & 0xff
        ufsr = (cfsr >> 16) & 0xffff
        hfsr = self.target.read32(HFSR)
        dfsr = self.target.read32(DFSR)
        mmfar = self.target.read32(MMFAR)
        bfar = self.target.read32(BFAR)
        
        print_fields('MMFSR', mmfsr, MMFSR_fields, showAll)
        if showAll or mmfsr & (1 << 7): # MMFARVALID
            print("  MMFAR = 0x%08x" % (mmfar))
        print_fields('BFSR', bfsr, BFSR_fields, showAll)
        if showAll or bfsr & (1 << 7): # BFARVALID
            print("  BFAR = 0x%08x" % (bfar))
        print_fields('UFSR', ufsr, UFSR_fields, showAll)
        print_fields('HFSR', hfsr, HFSR_fields, showAll)
        print_fields('DFSR', dfsr, DFSR_fields, showAll)

    def handle_show_nreset(self, args):
        rst = int(not self.probe.is_reset_asserted())
        print("nRESET = {}".format(rst))

    def handle_show_option(self, args):
        if len(args) < 1:
            raise ToolError("missing user option name argument")
        for name in args:
            if name in self.session.options:
                value = self.session.options[name]
                print("Option '%s' = %s" % (name, value))
            else:
                print("No option with name '%s'" % name)

    def handle_show_ap(self, args):
        print("MEM-AP #{} is selected".format(self.selected_ap))

    def handle_show_hnonsec(self, args):
        print("MEM-AP #{} HNONSEC = {} ({})".format(
            self.selected_ap,
            self.target.aps[self.selected_ap].hnonsec,
            ("nonsecure" if self.target.aps[self.selected_ap].hnonsec else "secure")))

    def handle_show_hprot(self, args):
        hprot = self.target.aps[self.selected_ap].hprot
        print("MEM-AP #{} HPROT = {:#x}".format(
            self.selected_ap,
            hprot))
        desc = ""
        for bitnum in range(7):
            bitvalue = (hprot >> bitnum) & 1
            desc += "    HPROT[{}] = {:#x} ({})\n".format(
                bitnum,
                bitvalue,
                HPROT_BIT_DESC[bitnum][bitvalue])
        print(desc, end='')

    def handle_set(self, args):
        if len(args) < 1:
            raise ToolError("missing option name argument")
        name = args[0]
        try:
            self.option_list[name](args[1:])
        except KeyError:
            raise ToolError("unkown option name '%s'" % name)

    def handle_show_vectorcatch(self, args):
        catch = self.target.get_vector_catch()

        print("Vector catch:")
        for mask in sorted(VC_NAMES_MAP.keys()):
            name = VC_NAMES_MAP[mask]
            s = "ON" if (catch & mask) else "OFF"
            print("  {:3} {}".format(s, name))

    def handle_set_vectorcatch(self, args):
        if len(args) == 0:
            print("Missing vector catch setting")
            return
    
        try:
            self.target.set_vector_catch(utility.cmdline.convert_vector_catch(args[0]))
        except ValueError as e:
            print(e)

    def handle_show_step_interrupts(self, args):
        print("Interrupts while stepping:", ("enabled" if self.step_into_interrupt else "disabled"))

    def handle_set_step_interrupts(self, args):
        if len(args) == 0:
            print("Missing argument")
            return
        
        self.step_into_interrupt = (args[0] in ('1', 'true', 'yes', 'on'))

    def handle_set_ap(self, args):
        if len(args) == 0:
            print("Missing argument")
            return
            
        ap_num = int(args[0], base=0)
        if ap_num not in self.target.aps:
            print("Invalid AP number {}".format(ap_num))
            return
        ap = self.target.aps[ap_num]
        if not isinstance(ap, MEM_AP):
            print("AP #{} is not a MEM-AP".format(ap_num))
            return
        self.selected_ap = ap_num

    def handle_set_hnonsec(self, args):
        if len(args) == 0:
            print("Missing argument")
            return
        value = int(args[0], base=0)
        self.target.aps[self.selected_ap].hnonsec = value

    def handle_set_hprot(self, args):
        if len(args) == 0:
            print("Missing argument")
            return
        value = int(args[0], base=0)
        self.target.aps[self.selected_ap].hprot = value

    def handle_help(self, args):
        if not args:
            self._list_commands("Commands", COMMAND_INFO, "{cmd:<25} {args:<20} {help}")
            print("""
All register names are also available as commands that print the register's value.
Any ADDR or LEN argument will accept a register name.
Prefix line with $ to execute a Python expression.
Prefix line with ! to execute a shell command.""")
            print()
            self._list_commands("Info", INFO_HELP, "{cmd:<25} {help}")
            print()
            self._list_commands("Options", OPTION_HELP, "{cmd:<25} {help}")
        else:
            cmd = args[0].lower()
            try:
                subcmd = args[1].lower()
            except IndexError:
                subcmd = None
            
            def print_help(cmd, commandList, usageFormat):
                for name, info in commandList.items():
                    if cmd == name or cmd in info['aliases']:
                        print(("Usage: " + usageFormat).format(cmd=name, **info))
                        if len(info['aliases']):
                            print("Aliases:", ", ".join(info['aliases']))
                        print(info['help'])
                        if 'extra_help' in info:
                            print(info['extra_help'])
            
            if subcmd is None:
                print_help(cmd, COMMAND_INFO, "{cmd} {args}")
                if cmd == "show":
                    print()
                    self._list_commands("Info", INFO_HELP, "{cmd:<25} {help}")
                elif cmd == "set":
                    print()
                    self._list_commands("Options", OPTION_HELP, "{cmd:<25} {help}")
            elif cmd == 'show':
                print_help(subcmd, INFO_HELP, "show {cmd}")
            elif cmd == 'set':
                print_help(subcmd, OPTION_HELP, "set {cmd} VALUE")
            else:
                print("Error: invalid arguments")

    def handle_set_option(self, args):
        if len(args) < 1:
            raise ToolError("missing user option setting")
        opts = convert_session_options(args)
        self.session.options.update(opts)

    def _list_commands(self, title, commandList, helpFormat):
        print(title + ":\n" + ("-" * len(title)))
        for cmd in sorted(commandList.keys()):
            info = commandList[cmd]
            aliases = ', '.join(sorted([cmd] + info['aliases']))
            print(helpFormat.format(cmd=aliases, **info))

    def is_flash_write(self, addr, width, data):
        mem_map = self.board.target.get_memory_map()
        region = mem_map.get_region_for_address(addr)
        if (region is None) or (not region.is_flash):
            return False

        if width == 8:
            l = len(data)
        elif width == 16:
            l = len(data) * 2
        elif width == 32:
            l = len(data) * 4

        return region.contains_range(addr, length=l)

    def convert_value(self, arg):
        """! @brief Convert an argument to a 32-bit integer.
        
        Handles the usual decimal, binary, and hex numbers with the appropriate prefix.
        Also recognizes register names and address dereferencing. Dereferencing using the
        ARM assembler syntax. To dereference, put the value in brackets, i.e. '[r0]' or
        '[0x1040]'. You can also use put an offset in the brackets after a comma, such as
        '[r3,8]'. The offset can be positive or negative, and any supported base.
        """
        deref = (arg[0] == '[')
        if deref:
            arg = arg[1:-1]
            offset = 0
            if ',' in arg:
                arg, offset = arg.split(',')
                arg = arg.strip()
                offset = int(offset.strip(), base=0)

        value = None
        if arg.lower() in coresight.cortex_m.CORE_REGISTER:
            value = self.target.read_core_register(arg.lower())
            print("%s = 0x%08x" % (arg.lower(), value))
        else:
            subargs = arg.lower().split('.')
            if subargs[0] in self.peripherals and len(subargs) > 1:
                p = self.peripherals[subargs[0]]
                r = [x for x in p.registers if x.name.lower() == subargs[1]]
                if len(r):
                    value = p.base_address + r[0].address_offset
                else:
                    raise ToolError("invalid register '%s' for %s" % (subargs[1], p.name))
            elif self.elf is not None:
                sym = self.elf.symbol_decoder.get_symbol_for_name(arg)
                if sym is not None:
                    value = sym.address

        if value is None:
            arg = arg.lower().replace('_', '')
            value = int(arg, base=0)

        if deref:
            value = utility.conversion.byte_list_to_u32le_list(self.target.read_memory_block8(value + offset, 4))[0]
            print("[%s,%d] = 0x%08x" % (arg, offset, value))

        return value

    def dump_registers(self):
        # Registers organized into columns for display.
        regs = ['r0', 'r6', 'r12',
                'r1', 'r7', 'sp',
                'r2', 'r8', 'lr',
                'r3', 'r9', 'pc',
                'r4', 'r10', 'xpsr',
                'r5', 'r11', 'primask']

        for i, reg in enumerate(regs):
            regValue = self.target.read_core_register(reg)
            print("{:>8} {:#010x} ".format(reg + ':', regValue), end=' ')
            if i % 3 == 2:
                print()

    def _dump_peripheral_register(self, periph, reg, show_fields):
        size = reg.size or 32
        addr = periph.base_address + reg.address_offset
        value = self.target.read_memory(addr, size)
        value_str = format_hex_width(value, size)
        print("%s.%s @ %08x = %s" % (periph.name, reg.name, addr, value_str))

        if show_fields:
            for f in reg.fields:
                if f.is_reserved:
                    continue
                msb = f.bit_offset + f.bit_width - 1
                lsb = f.bit_offset
                f_value = mask.bfx(value, msb, lsb)
                v_enum = None
                if f.enumerated_values:
                    for v in f.enumerated_values:
                        if v.value == f_value:
                            v_enum = v
                            break
                if f.bit_width == 1:
                    bits_str = "%d" % lsb
                else:
                    bits_str = "%d:%d" % (msb, lsb)
                f_value_str = "%x" % f_value
                digits = (f.bit_width + 3) // 4
                f_value_str = "0" * (digits - len(f_value_str)) + f_value_str
                f_value_bin_str = bin(f_value)[2:]
                f_value_bin_str = "0" * (f.bit_width - len(f_value_bin_str)) + f_value_bin_str
                if v_enum:
                    f_value_enum_str = " %s: %s" % (v.name, v_enum.description)
                else:
                    f_value_enum_str = ""
                print("  %s[%s] = %s (%s)%s" % (f.name, bits_str, f_value_str, f_value_bin_str, f_value_enum_str))

    def print_disasm(self, code, startAddr, maxInstructions=None):
        if not isCapstoneAvailable:
            print("Warning: Disassembly is not available because the Capstone library is not installed. "
                  "To install Capstone, run 'pip install capstone'.")
            return

        if self.target.is_halted():
            pc = self.target.read_core_register('pc') & ~1
        else:
            pc = -1
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

        addrLine = 0
        text = ''
        n = 0
        for i in md.disasm(code, startAddr):
            hexBytes = ''
            for b in i.bytes:
                hexBytes += '%02x' % b
            pc_marker = '*' if (pc == i.address) else ' '
            text += "{addr:#010x}:{pc_marker} {bytes:<10}{mnemonic:<8}{args}\n".format(addr=i.address, pc_marker=pc_marker, bytes=hexBytes, mnemonic=i.mnemonic, args=i.op_str)
            n += 1
            if (maxInstructions is not None) and (n >= maxInstructions):
                break

        print(text)

class PyOCDTool(object):
    def get_args(self):
        debug_levels = list(LEVELS.keys())

        epi = "Available commands:\n" + ', '.join(ALL_COMMANDS)

        parser = argparse.ArgumentParser(description='Target inspection utility', epilog=epi)
        parser.add_argument('--version', action='version', version=__version__)
        parser.add_argument('-j', '--dir', metavar="PATH", dest="project_dir",
            help="Set the project directory. Defaults to the directory where pyocd was run.")
        parser.add_argument('--config', metavar="PATH", default=None, help="Use a YAML config file.")
        parser.add_argument("--no-config", action="store_true", default=None, help="Do not use a configuration file.")
        parser.add_argument('--script', metavar="PATH",
            help="Use the specified user script. Defaults to pyocd_user.py.")
        parser.add_argument("--pack", metavar="PATH", help="Path to a CMSIS Device Family Pack")
        parser.add_argument("-H", "--halt", action="store_true", default=None, help="Halt core upon connect.")
        parser.add_argument("-N", "--no-init", action="store_true", help="Do not init debug system.")
        parser.add_argument('-k', "--clock", metavar='KHZ', default=(DEFAULT_CLOCK_FREQ_HZ // 1000), type=int, help="Set SWD speed in kHz. (Default 1 MHz.)")
        parser.add_argument('-b', "--board", action='store', dest="unique_id", metavar='ID', help="Use the specified board. Only a unique part of the board ID needs to be provided.")
        parser.add_argument('-t', "--target", action='store', metavar='TARGET', help="Override target.")
        parser.add_argument('-e', "--elf", metavar="PATH", help="Optionally specify ELF file being debugged.")
        parser.add_argument("-d", "--debug", dest="debug_level", choices=debug_levels, default='warning', help="Set the level of system logging output. Supported choices are: " + ", ".join(debug_levels), metavar="LEVEL")
        parser.add_argument("cmd", nargs='?', default=None, help="Command")
        parser.add_argument("args", nargs='*', help="Arguments for the command.")
        parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
        parser.add_argument("-O", "--option", dest="options", metavar="OPTION", action="append", help="Set session option of form 'OPTION=VALUE'.")
        parser.add_argument("-W", "--no-wait", action="store_true", help="Do not wait for a probe to be connected if none are available.")
        parser.add_argument("--no-deprecation-warning", action="store_true", help="Do not warn about pyocd-tool being deprecated.")
        return parser.parse_args()

    def configure_logging(self):
        level = LEVELS.get(self.args.debug_level, logging.WARNING)
        logging.basicConfig(level=level)

    def run(self):
        # Read command-line arguments.
        self.args = self.get_args()
        
        if self.args.cmd is not None:
            self.cmd = [[self.args.cmd] + self.args.args]
        else:
            self.cmd = None

        # Set logging level
        self.configure_logging()
        DAPAccess.set_args(self.args.daparg)
        
        if not self.args.no_deprecation_warning:
            LOG.warning("pyocd-tool is deprecated; please use the new combined pyocd tool.")
        
        # Convert args to new names.
        self.args.target_override = self.args.target
        self.args.frequency = self.args.clock * 1000

        commander = PyOCDCommander(self.args, self.cmd)
        return commander.run()


def main():
    sys.exit(PyOCDTool().run())


if __name__ == '__main__':
    main()
