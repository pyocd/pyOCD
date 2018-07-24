#!/usr/bin/env python
"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

from __future__ import print_function
import argparse
import logging
import os
import sys
import optparse
from optparse import make_option
import traceback
import six

# Attempt to import readline.
try:
    import readline
except ImportError:
    pass

from .. import __version__
from .. import (utility, coresight)
from ..board import MbedBoard
from ..target.family import target_kinetis
from ..pyDAPAccess import DAPAccess
from ..core.target import Target
from ..utility import mask

# Make disasm optional.
try:
    import capstone
    isCapstoneAvailable = True
except ImportError:
    isCapstoneAvailable = False

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

DP_REGS_MAP = {
        0x0 : DAPAccess.REG.DP_0x0,
        0x4 : DAPAccess.REG.DP_0x4,
        0x8 : DAPAccess.REG.DP_0x8,
        0xc : DAPAccess.REG.DP_0xC
        }

## Default SWD clock in kHz.
DEFAULT_CLOCK_FREQ_KHZ = 1000

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
            "help" : "Load a binary file to an address in memory"
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
            'help' : "Write 8-bit bytes"
            },
        'write16' : {
            'aliases' : ['w16', 'wh'],
            'args' : "ADDR DATA...",
            'help' : "Write 16-bit halfwords"
            },
        'write32' : {
            'aliases' : ['w32', 'ww'],
            'args' : "ADDR DATA...",
            'help' : "Write 32-bit words"
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
            'help' : "Read DP register"
            },
        'readap' : {
            'aliases' : ['rap'],
            'args' : "[APSEL] ADDR",
            'help' : "Read AP register"
            },
        'writeap' : {
            'aliases' : ['wap'],
            'args' : "[APSEL] ADDR DATA",
            'help' : "Read AP register"
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
            'args' : "APSEL [mem]",
            'help' : "Creates a new AP object for the given APSEL and optional type.",
            'extra_help' : "Either a generic AP or a MEM-AP will be created depending on whether 'mem' is passed for the second, optional parameter.",
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
        }

def hex_width(value, width):
    if width == 8:
        return "%02x" % value
    elif width == 16:
        return "%04x" % value
    elif width == 32:
        return "%08x" % value
    else:
        raise ToolError("unrecognized register width (%d)" % width)

def dumpHexData(data, startAddress=0, width=8):
    i = 0
    while i < len(data):
        print("%08x: " % (startAddress + (i * (width // 8))), end=' ')

        while i < len(data):
            d = data[i]
            i += 1
            if width == 8:
                print("%02x" % d, end=' ')
                if i % 4 == 0:
                    print("", end=' ')
                if i % 16 == 0:
                    break
            elif width == 16:
                print("%04x" % d, end=' ')
                if i % 8 == 0:
                    break
            elif width == 32:
                print("%08x" % d, end=' ')
                if i % 4 == 0:
                    break
        print()

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
            traceback.print_exc()
        except DAPAccess.TransferError as e:
            print("Error:", e)
            traceback.print_exc()
        except ToolError as e:
            print("Error:", e)
        except ToolExitException:
            raise
        except Exception as e:
            print("Unexpected exception:", e)
            traceback.print_exc()

class PyOCDTool(object):
    def __init__(self):
        self.board = None
        self.exitCode = 0
        self.step_into_interrupt = False
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
                '?' :       self.handle_help,
                'initdp' :  self.handle_initdp,
                'makeap' :  self.handle_makeap,
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
            }
        self.option_list = {
                'vector-catch' :        self.handle_set_vectorcatch,
                'vc' :                  self.handle_set_vectorcatch,
                'step-into-interrupt' : self.handle_set_step_interrupts,
                'si' :                  self.handle_set_step_interrupts,
                'nreset' :              self.handle_set_nreset,
                'log' :                 self.handle_set_log,
                'clock' :               self.handle_set_clock,
            }

    def get_args(self):
        debug_levels = list(LEVELS.keys())

        epi = "Available commands:\n" + ', '.join(sorted(self.command_list.keys()))

        parser = argparse.ArgumentParser(description='Target inspection utility', epilog=epi)
        parser.add_argument('--version', action='version', version=__version__)
        parser.add_argument("-H", "--halt", action="store_true", help="Halt core upon connect.")
        parser.add_argument("-N", "--no-init", action="store_true", help="Do not init debug system.")
        parser.add_argument('-k', "--clock", metavar='KHZ', default=DEFAULT_CLOCK_FREQ_KHZ, type=int, help="Set SWD speed in kHz. (Default 1 MHz.)")
        parser.add_argument('-b', "--board", action='store', metavar='ID', help="Use the specified board. Only a unique part of the board ID needs to be provided.")
        parser.add_argument('-t', "--target", action='store', metavar='TARGET', help="Override target.")
        parser.add_argument("-d", "--debug", dest="debug_level", choices=debug_levels, default='warning', help="Set the level of system logging output. Supported choices are: " + ", ".join(debug_levels), metavar="LEVEL")
        parser.add_argument("cmd", nargs='?', default=None, help="Command")
        parser.add_argument("args", nargs='*', help="Arguments for the command.")
        parser.add_argument("-da", "--daparg", dest="daparg", nargs='+', help="Send setting to DAPAccess layer.")
        return parser.parse_args()

    def configure_logging(self):
        level = LEVELS.get(self.args.debug_level, logging.WARNING)
        logging.basicConfig(level=level)

    def run(self):
        try:
            # Read command-line arguments.
            self.args = self.get_args()
            self.cmd = self.args.cmd
            if self.cmd:
                self.cmd = self.cmd.lower()

            # Set logging level
            self.configure_logging()
            DAPAccess.set_args(self.args.daparg)

            # Check for a valid command.
            if self.cmd and self.cmd not in self.command_list:
                print("Error: unrecognized command '%s'" % self.cmd)
                return 1

            # Handle certain commands without connecting.
            if self.cmd == 'list':
                self.handle_list([])
                return 0
            elif self.cmd == 'help':
                self.handle_help(self.args.args)
                return 0

            if self.args.clock != DEFAULT_CLOCK_FREQ_KHZ:
                print("Setting SWD clock to %d kHz" % self.args.clock)

            # Connect to board.
            self.board = MbedBoard.chooseBoard(board_id=self.args.board, target_override=self.args.target, init_board=False, frequency=(self.args.clock * 1000))
            if self.board is None:
                return 1
            self.board.target.setAutoUnlock(False)
            self.board.target.setHaltOnConnect(self.args.halt)
            try:
                if not self.args.no_init:
                    self.board.init()
            except DAPAccess.TransferFaultError as e:
                if not self.board.target.isLocked():
                    print("Transfer fault while initing board: %s" % e)
                    traceback.print_exc()
                    self.exitCode = 1
                    return self.exitCode
            except Exception as e:
                print("Exception while initing board: %s" % e)
                traceback.print_exc()
                self.exitCode = 1
                return self.exitCode

            self.target = self.board.target
            self.link = self.board.link
            self.flash = self.board.flash

            self._peripherals = {}
            self._loaded_peripherals = False

            # Handle a device with flash security enabled.
            self.didErase = False
            if not self.args.no_init and self.target.isLocked() and self.cmd != 'unlock':
                print("Warning: Target is locked, limited operations available. Use unlock command to mass erase and unlock.")

            # If no command, enter interactive mode.
            if not self.cmd:
                if not self.args.no_init:
                    try:
                        # Say what we're connected to.
                        print("Connected to %s [%s]: %s" % (self.target.part_number,
                            CORE_STATUS_DESC[self.target.getState()], self.board.getUniqueID()))
                    except DAPAccess.TransferFaultError:
                        pass

                # Run the command line.
                console = PyOCDConsole(self)
                console.run()
            else:
                # Invoke action handler.
                result = self.command_list[self.cmd](self.args.args)
                if result is not None:
                    self.exitCode = result

        except ToolExitException:
            self.exitCode = 0
        except ValueError:
            print("Error: invalid argument")
        except DAPAccess.TransferError:
            print("Error: transfer failed")
            traceback.print_exc()
            self.exitCode = 2
        except ToolError as e:
            print("Error:", e)
            self.exitCode = 1
        finally:
            if self.board != None:
                # Pass false to prevent target resume.
                self.board.uninit(False)

        return self.exitCode
    
    @property
    def peripherals(self):
        if self.target.svd_device and not self._loaded_peripherals:
            for p in self.target.svd_device.peripherals:
                self._peripherals[p.name.lower()] = p
            self._loaded_peripherals = True
        return self._peripherals

    def handle_list(self, args):
        MbedBoard.listConnectedBoards()

    def handle_status(self, args):
        if self.target.isLocked():
            print("Security:       Locked")
        else:
            print("Security:       Unlocked")
        if isinstance(self.target, target_kinetis.Kinetis):
            print("MDM-AP Status:  0x%08x" % self.target.mdm_ap.read_reg(target_kinetis.MDM_STATUS))
        if not self.target.isLocked():
            for i, c in enumerate(self.target.cores):
                core = self.target.cores[c]
                print("Core %d status:  %s" % (i, CORE_STATUS_DESC[core.getState()]))

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
            value = self.target.readCoreRegister(reg)
            if type(value) in six.integer_types:
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
            if reg.startswith('s') and reg != 'sp':
                value = float(args[1])
            else:
                value = self.convert_value(args[1])
            self.target.writeCoreRegister(reg, value)
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
                        self.target.writeMemory(addr, value, r.size)
                    elif len(subargs) == 3:
                        f = [x for x in r.fields if x.name.lower() == subargs[2]]
                        if len(f):
                            f = f[0]
                            msb = f.bit_offset + f.bit_width - 1
                            lsb = f.bit_offset
                            originalValue = self.target.readMemory(addr, r.size)
                            value = mask.bfi(originalValue, msb, lsb, value)
                            print("writing 0x%x to 0x%x[%d:%d]:%d (%s.%s)" % (value, addr, msb, lsb, r.size, r.name, f.name))
                            self.target.writeMemory(addr, value, r.size)
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
            self.target.resetStopOnReset()

            status = self.target.getState()
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
        self.target.dp.assert_reset((state == 0))

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
        data = self.target.readBlockMemoryUnaligned8(addr, count)
        self.print_disasm(str(bytearray(data)), addr)

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

        data = bytearray(self.target.readBlockMemoryUnaligned8(addr, count))

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
            self.target.writeBlockMemoryUnaligned8(addr, data)
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
            data = self.target.readBlockMemoryUnaligned8(addr, count)
            byteData = data
        elif width == 16:
            byteData = self.target.readBlockMemoryUnaligned8(addr, count)
            data = utility.conversion.byteListToU16leList(byteData)
        elif width == 32:
            byteData = self.target.readBlockMemoryUnaligned8(addr, count)
            data = utility.conversion.byteListToU32leList(byteData)

        # Print hex dump of output.
        dumpHexData(data, addr, width=width)

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
            data = utility.conversion.u16leListToByteList(data)
        elif width == 32:
            data = utility.conversion.u32leListToByteList(data)

        if self.isFlashWrite(addr, width, data):
            self.target.flash.init()
            self.target.flash.programPhrase(addr, data)
        else:
            self.target.writeBlockMemoryUnaligned8(addr, data)
            self.target.flush()

    def handle_erase(self, args):
        if len(args) < 1:
            raise ToolError("invalid arguments")
        addr = self.convert_value(args[0])
        if len(args) < 2:
            count = 1
        else:
            count = self.convert_value(args[1])
        self.flash.init()
        while count:
            info = self.flash.getPageInfo(addr)
            self.flash.erasePage(info.base_addr)
            print("Erased page 0x%08x" % info.base_addr)
            count -= 1
            addr += info.size

    def handle_unlock(self, args):
        # Currently the same as erase.
        if not self.didErase:
            self.target.massErase()

    def handle_go(self, args):
        self.target.resume()
        status = self.target.getState()
        if status == Target.TARGET_RUNNING:
            print("Successfully resumed device")
        else:
            print("Failed to resume device")

    def handle_step(self, args):
        self.target.step(disable_interrupts=not self.step_into_interrupt)
        addr = self.target.readCoreRegister('pc')
        if isCapstoneAvailable:
            addr &= ~1
            data = self.target.readBlockMemoryUnaligned8(addr, 4)
            self.print_disasm(str(bytearray(data)), addr, maxInstructions=1)
        else:
            print("PC = 0x%08x" % (addr))

    def handle_halt(self, args):
        self.target.halt()

        status = self.target.getState()
        if status != Target.TARGET_HALTED:
            print("Failed to halt device")
            return 1
        else:
            print("Successfully halted device")

    def handle_breakpoint(self, args):
        if len(args) < 1:
            raise ToolError("no breakpoint address provided")
        addr = self.convert_value(args[0])
        if self.target.setBreakpoint(addr):
            self.target.selected_core.bp_manager.flush()
            print("Set breakpoint at 0x%08x" % addr)
        else:
            print("Failed to set breakpoint at 0x%08x" % addr)

    def handle_remove_breakpoint(self, args):
        if len(args) < 1:
            raise ToolError("no breakpoint address provided")
        addr = self.convert_value(args[0])
        try:
            type = self.target.getBreakpointType(addr)
            self.target.removeBreakpoint(addr)
            self.target.selected_core.bp_manager.flush()
            print("Removed breakpoint at 0x%08x" % addr)
        except:
            print("Failed to remove breakpoint at 0x%08x" % addr)

    def handle_list_breakpoints(self, args):
        availableBpCount = self.target.selected_core.availableBreakpoint()
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
        self.link.set_clock(freq_Hz)
        if self.link.get_swj_mode() == DAPAccess.PORT.SWD:
            swd_jtag = 'SWD'
        else:
            swd_jtag = 'JTAG'

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
            env = {
                    'board' : self.board,
                    'target' : self.target,
                    'link' : self.link,
                    'flash' : self.flash,
                    'dp' : self.target.dp,
                }
            result = eval(args, globals(), env)
            if result is not None:
                if type(result) in six.integer_types:
                    print("0x%08x (%d)" % (result, result))
                else:
                    print(result)
        except Exception as e:
            print("Exception while executing expression:", e)
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
        addr_int = self.convert_value(args[0])
        addr = DP_REGS_MAP[addr_int]
        result = self.target.dp.read_reg(addr)
        print("DP register 0x%x = 0x%08x" % (addr_int, result))

    def handle_writedp(self, args):
        if len(args) < 1:
            print("Missing DP address")
            return
        if len(args) < 2:
            print("Missing value")
            return
        addr_int = self.convert_value(args[0])
        addr = DP_REGS_MAP[addr_int]
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
        result = self.target.dp.readAP(addr)
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
        self.target.dp.writeAP(addr, data)

    def handle_initdp(self, args):
        self.target.dp.init()
        self.target.dp.power_up_debug()

    def handle_makeap(self, args):
        if len(args) < 1:
            print("Missing APSEL")
            return
        apsel = self.convert_value(args[0])
        makeMemAp = (len(args) == 2 and args[1].lower() == 'mem')
        if apsel in self.target.aps:
            print("AP with APSEL=%d already exists" % apsel)
            return
        if makeMemAp:
            ap = coresight.ap.MEM_AP(self.target.dp, apsel)
        else:
            ap = coresight.ap.AccessPort(self.target.dp, apsel)
        ap.init(bus_accessible=False)
        self.target.aps[apsel] = ap

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
        print("Unique ID:    %s" % self.board.getUniqueID())

    def handle_show_target(self, args):
        print("Target:       %s" % self.target.part_number)
        print("DAP IDCODE:   0x%08x" % self.target.readIDCode())

    def handle_show_cores(self, args):
        if self.target.isLocked():
            print("Target is locked")
        else:
            print("Cores:        %d" % len(self.target.cores))
            for i, c in enumerate(self.target.cores):
                core = self.target.cores[c]
                print("Core %d type:  %s" % (i, coresight.cortex_m.CORE_TYPE_NAME[core.core_type]))

    def handle_show_map(self, args):
        print("Region          Start         End                 Size    Blocksize")
        for region in self.target.getMemoryMap():
            print("{:<15} {:#010x}    {:#010x}    {:#10x}    {}".format(region.name, region.start, region.end, region.length, region.blocksize if region.isFlash else '-'))

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

    def handle_set(self, args):
        if len(args) < 1:
            raise ToolError("missing option name argument")
        name = args[0]
        try:
            self.option_list[name](args[1:])
        except KeyError:
            raise ToolError("unkown option name '%s'" % name)

    def handle_show_vectorcatch(self, args):
        catch = self.target.getVectorCatch()

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
            self.target.setVectorCatch(utility.cmdline.convert_vector_catch(args[0]))
        except ValueError as e:
            print(e)

    def handle_show_step_interrupts(self, args):
        print("Interrupts while stepping:", ("enabled" if self.step_into_interrupt else "disabled"))

    def handle_set_step_interrupts(self, args):
        if len(args) == 0:
            print("Missing argument")
            return
        
        self.step_into_interrupt = (args[0] in ('1', 'true', 'yes', 'on'))

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

    def _list_commands(self, title, commandList, helpFormat):
        print(title + ":\n" + ("-" * len(title)))
        for cmd in sorted(commandList.keys()):
            info = commandList[cmd]
            aliases = ', '.join(sorted([cmd] + info['aliases']))
            print(helpFormat.format(cmd=aliases, **info))

    def isFlashWrite(self, addr, width, data):
        mem_map = self.board.target.getMemoryMap()
        region = mem_map.getRegionForAddress(addr)
        if (region is None) or (not region.isFlash):
            return False

        if width == 8:
            l = len(data)
        elif width == 16:
            l = len(data) * 2
        elif width == 32:
            l = len(data) * 4

        return region.containsRange(addr, length=l)

    ## @brief Convert an argument to a 32-bit integer.
    #
    # Handles the usual decimal, binary, and hex numbers with the appropriate prefix.
    # Also recognizes register names and address dereferencing. Dereferencing using the
    # ARM assembler syntax. To dereference, put the value in brackets, i.e. '[r0]' or
    # '[0x1040]'. You can also use put an offset in the brackets after a comma, such as
    # '[r3,8]'. The offset can be positive or negative, and any supported base.
    def convert_value(self, arg):
        arg = arg.lower().replace('_', '')
        deref = (arg[0] == '[')
        if deref:
            arg = arg[1:-1]
            offset = 0
            if ',' in arg:
                arg, offset = arg.split(',')
                arg = arg.strip()
                offset = int(offset.strip(), base=0)

        if arg in coresight.cortex_m.CORE_REGISTER:
            value = self.target.readCoreRegister(arg)
            print("%s = 0x%08x" % (arg, value))
        else:
            subargs = arg.split('.')
            if subargs[0] in self.peripherals and len(subargs) > 1:
                p = self.peripherals[subargs[0]]
                r = [x for x in p.registers if x.name.lower() == subargs[1]]
                if len(r):
                    value = p.base_address + r[0].address_offset
                else:
                    raise ToolError("invalid register '%s' for %s" % (subargs[1], p.name))
            else:
                value = int(arg, base=0)

        if deref:
            value = utility.conversion.byteListToU32leList(self.target.readBlockMemoryUnaligned8(value + offset, 4))[0]
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
            regValue = self.target.readCoreRegister(reg)
            print("{:>8} {:#010x} ".format(reg + ':', regValue), end=' ')
            if i % 3 == 2:
                print()

    def _dump_peripheral_register(self, periph, reg, show_fields):
        addr = periph.base_address + reg.address_offset
        value = self.target.readMemory(addr, reg.size)
        value_str = hex_width(value, reg.size)
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
            print("Warning: Disassembly is not available because the Capstone library is not installed")
            return

        pc = self.target.readCoreRegister('pc') & ~1
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


def main():
    sys.exit(PyOCDTool().run())


if __name__ == '__main__':
    main()
