# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
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
import prettytable

from .. import coresight
from ..core import exceptions
from ..probe.debug_probe import DebugProbe
from ..coresight.ap import MEM_AP
from ..core.target import Target
from ..utility.cmdline import (
    convert_session_options,
    convert_frequency,
    convert_vector_catch,
    )
from .base import ValueBase

LOG = logging.getLogger(__name__)

VC_NAMES_MAP = {
        Target.VectorCatch.HARD_FAULT: "hard fault",
        Target.VectorCatch.BUS_FAULT: "bus fault",
        Target.VectorCatch.MEM_FAULT: "memory fault",
        Target.VectorCatch.INTERRUPT_ERR: "interrupt error",
        Target.VectorCatch.STATE_ERR: "state error",
        Target.VectorCatch.CHECK_ERR: "check error",
        Target.VectorCatch.COPROCESSOR_ERR: "coprocessor error",
        Target.VectorCatch.CORE_RESET: "core reset",
        Target.VectorCatch.SECURE_FAULT: "secure fault",
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

class UniqueIdValue(ValueBase):
    INFO = {
            'names': ['probe-uid', 'uid'],
            'group': 'standard',
            'category': 'probe',
            'access': 'r',
            'help': "Target's unique ID.",
            }

    def display(self, args):
        self.context.writei("Unique ID:    %s", self.context.board.unique_id)

class TargetValue(ValueBase):
    INFO = {
            'names': ['target'],
            'group': 'standard',
            'category': 'target',
            'access': 'r',
            'help': "General target information.",
            }

    def display(self, args):
        self.context.writei("Target:       %s", self.context.target.part_number)
        self.context.writei("DAP IDCODE:   0x%08x", self.context.target.dp.dpidr.idr)

class CoresValue(ValueBase):
    INFO = {
            'names': ['cores'],
            'group': 'standard',
            'category': 'target',
            'access': 'r',
            'help': "Information about CPU cores in the target.",
            }

    def display(self, args):
        if self.context.target.is_locked():
            self.context.write("Target is locked")
        else:
            self.context.writei("Cores:        %d", len(self.context.target.cores))
            for i, core in self.context.target.cores.items():
                self.context.writei("Core %d type:  %s%s", i,
                        coresight.core_ids.CORE_TYPE_NAME[core.core_type],
                        " (selected)" if ((self.context.selected_core is not None) \
                                            and (self.context.selected_core.core_number == i)) else "")

class APsValue(ValueBase):
    INFO = {
            'names': ['aps'],
            'group': 'standard',
            'category': 'target',
            'access': 'r',
            'help': "List discovered Access Ports.",
            }

    def display(self, args):
        if self.context.target.is_locked():
            self.context.write("Target is locked")
        else:
            self.context.writei("%d APs:", len(self.context.target.aps))
            for addr, ap in sorted(self.context.target.aps.items(), key=lambda x: x[0]):
                self.context.writei("%s: %s%s", addr, ap.type_name,
                        " (selected)" if (self.context.selected_ap_address == addr) else "")

class MemoryMapValue(ValueBase):
    INFO = {
            'names': ['map'],
            'group': 'standard',
            'category': 'target',
            'access': 'r',
            'help': "Target memory map.",
            }

    def display(self, args):
        if self.context.selected_core is None:
            self.context.write("No core is selected")
            return

        pt = prettytable.PrettyTable(["Region", "Type", "Start", "End", "Size", "Access", "Sector", "Page"])
        pt.align = 'l'
        pt.border = False
        for region in self.context.selected_core.get_memory_map():
            pt.add_row([
                region.name,
                region.type.name.capitalize(),
                "0x%08x" % region.start,
                "0x%08x" % region.end,
                "0x%08x" % region.length,
                region.access,
                ("0x%08x" % region.sector_size) if region.is_flash else '-',
                ("0x%08x" % region.page_size) if region.is_flash else '-',
                ])
        self.context.write(pt)

class PeripheralsValue(ValueBase):
    INFO = {
            'names': ['peripherals'],
            'group': 'standard',
            'category': 'target',
            'access': 'r',
            'help': "List of target peripheral instances.",
            }

    def display(self, args):
        for periph in sorted(self.context.peripherals.values(), key=lambda x:x.base_address):
            self.context.writei("0x%08x: %s", periph.base_address, periph.name)

class FaultValue(ValueBase):
    INFO = {
            'names': ['fault'],
            'group': 'standard',
            'category': 'exceptions',
            'access': 'r',
            'show_usage': "[-a]",
            'help': "Fault status information.",
            'extra_help': "By default, only asserted fields are shown. Add -a to command to show all fields.",
            }

    def display(self, args):
        showAll = ('-a' in args)
        
        CFSR = 0xe000ed28
        HFSR = 0xe000ed2c
        DFSR = 0xe000ed30
        MMFAR = 0xe000ed34
        BFAR = 0xe000ed38
#         AFSR = 0xe000ed3c
        
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
            self.context.writei("  %s = 0x%08x", regname, value)
            for name, bitpos in fields:
                bit = (value >> bitpos) & 1
                if showAll or bit != 0:
                    self.context.writei("    %s = 0x%x", name, bit)
        
        if self.context.selected_core is None:
            self.context.write("No core is selected")
            return

        cfsr = self.context.selected_core.read32(CFSR)
        mmfsr = cfsr & 0xff
        bfsr = (cfsr >> 8) & 0xff
        ufsr = (cfsr >> 16) & 0xffff
        hfsr = self.context.selected_core.read32(HFSR)
        dfsr = self.context.selected_core.read32(DFSR)
        mmfar = self.context.selected_core.read32(MMFAR)
        bfar = self.context.selected_core.read32(BFAR)
        
        print_fields('MMFSR', mmfsr, MMFSR_fields, showAll)
        if showAll or mmfsr & (1 << 7): # MMFARVALID
            self.context.writei("  MMFAR = 0x%08x", mmfar)
        print_fields('BFSR', bfsr, BFSR_fields, showAll)
        if showAll or bfsr & (1 << 7): # BFARVALID
            self.context.writei("  BFAR = 0x%08x", bfar)
        print_fields('UFSR', ufsr, UFSR_fields, showAll)
        print_fields('HFSR', hfsr, HFSR_fields, showAll)
        print_fields('DFSR', dfsr, DFSR_fields, showAll)

class NresetValue(ValueBase):
    INFO = {
            'names': ['nreset'],
            'group': 'standard',
            'category': 'target',
            'access': 'rw',
            'help': "Current nRESET signal state.",
            'extra_help': "Accepts a value of 0 or 1.",
            }

    def display(self, args):
        rst = int(not self.context.probe.is_reset_asserted())
        self.context.writef("nRESET = {}", rst)

    def modify(self, args):
        if len(args) != 1:
            raise exceptions.CommandError("missing reset state")
        state = int(args[0], base=0)
        self.context.writef("nRESET = {}", state)
        
        # Use the probe to assert reset if the DP doesn't exist for some reason, otherwise
        # use the DP so reset notifications are sent.
        if self.context.target.dp is None:
            self.context.probe.assert_reset((state == 0))
        else:
            self.context.target.dp.assert_reset((state == 0))

class SessionOptionValue(ValueBase):
    INFO = {
            'names': ['option'],
            'group': 'standard',
            'category': 'options',
            'access': 'rw',
            'show_usage': "NAME+",
            'set_usage': "NAME[=VALUE]+",
            'help': "The current value of one or more session options.",
            'extra_help': "When setting, each argument should follow the form \"NAME[=VALUE]\".",
            }

    def display(self, args):
        if len(args) < 1:
            raise exceptions.CommandError("missing session option name argument")
        for name in args:
            try:
                value = self.context.session.options[name]
                self.context.writei("Option '%s' = %s", name, value)
            except KeyError:
                self.context.writei("No option with name '%s'", name)

    def modify(self, args):
        if len(args) < 1:
            raise exceptions.CommandError("missing session option setting")
        opts = convert_session_options(args)
        self.context.session.options.update(opts)

class MemApValue(ValueBase):
    INFO = {
            'names': ['mem-ap'],
            'group': 'standard',
            'category': 'memory',
            'access': 'rw',
            'help': "The currently selected MEM-AP used for memory read/write commands.",
            'extra_help': "When the selected core is changed by the 'core' command, the selected "
                "MEM-AP is changed to match. This overrides a user-selected MEM-AP if different "
                "from the AP for the newly selected core.",
            }

    def display(self, args):
        if self.context.selected_ap is None:
            self.context.write("No MEM-AP is selected")
            return
        self.context.writef("{} is selected", self.context.selected_ap.short_description)

    def modify(self, args):
        if len(args) == 0:
            raise exceptions.CommandError("missing argument")
            
        ap_num = int(args[0], base=0)
        if self.context.target.dp.adi_version == coresight.dap.ADIVersion.ADIv5:
            ap_addr = coresight.ap.APv1Address(ap_num)
        elif self.context.target.dp.adi_version == coresight.dap.ADIVersion.ADIv6:
            ap_addr = coresight.ap.APv2Address(ap_num)
        if ap_addr not in self.context.target.aps:
            self.context.writef("Invalid AP number {:#x}", ap_num)
            return
        ap = self.context.target.aps[ap_addr]
        if not isinstance(ap, MEM_AP):
            self.context.writef("{} is not a MEM-AP", ap.short_description)
            return
        self.context.selected_ap_address = ap_addr

class HnonsecValue(ValueBase):
    INFO = {
            'names': ['hnonsec'],
            'group': 'standard',
            'category': 'memory',
            'access': 'rw',
            'help': "The current HNONSEC value used by the selected MEM-AP.",
            }

    def display(self, args):
        if self.context.selected_ap is None:
            self.context.write("No MEM-AP is selected")
            return
        self.context.writef("{} HNONSEC = {} ({})",
            self.context.selected_ap.short_description,
            self.context.selected_ap.hnonsec,
            ("nonsecure" if self.context.selected_ap.hnonsec else "secure"))

    def modify(self, args):
        if len(args) == 0:
            raise exceptions.CommandError("missing argument")
        if self.context.selected_ap is None:
            self.context.write("No MEM-AP is selected")
            return
        value = int(args[0], base=0)
        self.context.selected_ap.hnonsec = value

class HprotValue(ValueBase):
    INFO = {
            'names': ['hprot'],
            'group': 'standard',
            'category': 'memory',
            'access': 'rw',
            'help': "The current HPROT value used by the selected MEM-AP.",
            }

    def display(self, args):
        if self.context.selected_ap is None:
            self.context.write("No MEM-AP is selected")
            return
        hprot = self.context.selected_ap.hprot
        self.context.writef("{} HPROT = {:#x}",
            self.context.selected_ap.short_description,
            hprot)
        desc = ""
        for bitnum in range(7):
            bitvalue = (hprot >> bitnum) & 1
            desc += "    HPROT[{}] = {:#x} ({})\n".format(
                bitnum,
                bitvalue,
                HPROT_BIT_DESC[bitnum][bitvalue])
        self.context.write(desc, end='')

    def modify(self, args):
        if len(args) == 0:
            raise exceptions.CommandError("missing argument")
        if self.context.selected_ap is None:
            self.context.write("No MEM-AP is selected")
            return
        value = int(args[0], base=0)
        self.context.selected_ap.hprot = value

class TargetGraphValue(ValueBase):
    INFO = {
            'names': ['graph'],
            'group': 'standard',
            'category': 'target',
            'access': 'r',
            'help': "Print the target object graph.",
            }

    def display(self, args):
        self.context.board.dump()
    
class LockedValue(ValueBase):
    INFO = {
            'names': ['locked'],
            'group': 'standard',
            'category': 'target',
            'access': 'r',
            'help': "Report whether the target is locked.",
            }

    def display(self, args):
        if self.context.target.is_locked():
            self.context.write("Taget is locked")
        else:
            self.context.write("Taget is unlocked")

class RegisterGroupsValue(ValueBase):
    INFO = {
            'names': ['register-groups'],
            'group': 'standard',
            'category': 'registers',
            'access': 'r',
            'help': "Display available register groups for the selected core.",
            }

    def display(self, args):
        if self.context.selected_core is None:
            self.context.write("No core is selected")
            return
        for g in sorted(self.context.selected_core.core_registers.groups):
            self.context.write(g)

class VectorCatchValue(ValueBase):
    INFO = {
            'names': ['vector-catch', 'vc'],
            'group': 'standard',
            'category': 'exceptions',
            'access': 'rw',
            'help': "Show current vector catch settings.",
            'extra_help': "When setting, the alue is a concatenation of one letter per enabled source in "
                "any order, or 'all' or 'none'. (h=hard fault, b=bus fault, m=mem fault, i=irq err, s=state "
                "err, c=check err, p=nocp, r=reset, a=all, n=none).",
            }

    def display(self, args):
        if self.context.selected_core is None:
            self.context.write("No core is selected")
            return

        catch = self.context.selected_core.get_vector_catch()

        self.context.write("Vector catch:")
        for mask in sorted(VC_NAMES_MAP.keys()):
            name = VC_NAMES_MAP[mask]
            s = "ON" if (catch & mask) else "OFF"
            self.context.writef("  {:3} {}", s, name)

    def modify(self, args):
        if len(args) == 0:
            raise exceptions.CommandError("missing vector catch setting")

        if self.context.selected_core is None:
            self.context.write("No core is selected")
            return
    
        try:
            self.context.selected_core.set_vector_catch(convert_vector_catch(args[0]))
        except ValueError as e:
            self.context.write(e)

class StepIntoInterruptsValue(ValueBase):
    INFO = {
            'names': ['step-into-interrupts', 'si'],
            'group': 'standard',
            'category': 'options',
            'access': 'rw',
            'help': "Display whether interrupts are enabled when single stepping.",
            'extra_help': "Set to 1 to enable.",
            }

    def display(self, args):
        self.context.writei("Interrupts while stepping: %s",
            ("enabled" if self.context.session.options['step_into_interrupt'] else "disabled"))

    def modify(self, args):
        if len(args) == 0:
            raise exceptions.CommandError("missing argument")
        value = (args[0] in ('1', 'true', 'yes', 'on'))
        self.context.session.options['step_into_interrupt'] = value

class LogLevelValue(ValueBase):
    INFO = {
            'names': ['log'],
            'group': 'standard',
            'category': 'miscellaneous',
            'access': 'w',
            'set_usage': "LEVEL [MODULE+]",
            'help': "Set log level to one of 'debug', 'info', 'warning', 'error', 'critical'.",
            'extra_help': "If pyocd module names are provided as arguments after the log level then "
                            "only those modules will have their log level changed."
            }

    LEVELS = {
            'debug': logging.DEBUG,
            'info': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'critical': logging.CRITICAL,
            }

    def display(self, args):
        pass

    def modify(self, args):
        if len(args) < 1:
            raise exceptions.CommandError("no log level provided")
        level_name = args[0].lower()
        if level_name not in self.LEVELS:
            raise exceptions.CommandError("log level must be one of {%s}" % ','.join(self.LEVELS.keys()))
        level = self.LEVELS[level_name]
        if len(args) == 1:
            logging.getLogger().setLevel(level)
        else:
            for module_name in args[1:]:
                # Check if there is already a logger with this name.
                #
                # This is guarded with a check that the root logger has a 'manager' attribute, and the
                # the Manager object has a 'loggerDict' attribute. Both attributes are undocumented, so
                # a check is necessary to prevent failure in case the logging code changes.
                if hasattr(logging.root, 'manager'):
                    manager = logging.root.manager
                    if hasattr(manager, 'loggerDict') and (module_name not in manager.loggerDict):
                        self.context.writef("No logger exists with the name {}", module_name)
                        continue
                logging.getLogger(module_name).setLevel(level)

class ClockFrequencyValue(ValueBase):
    INFO = {
            'names': ['frequency'],
            'group': 'standard',
            'category': 'options',
            'access': 'w',
            'help': "Set SWD or JTAG clock frequency in Hertz.",
            'extra_help': "A case-insensitive metric scale suffix of either 'k' or 'm' is allowed, as well "
                "as a trailing \"Hz\". There must be no space between the frequency and the suffix. For "
                "example, \"2.5MHz\" sets the clock to 2.5 MHz.",
            }

    def display(self, args):
        pass

    def modify(self, args):
        if len(args) < 1:
            raise exceptions.CommandError("no clock frequency provided")
        try:
            freq_Hz = convert_frequency(args[0])
        except:
            raise exceptions.CommandError("invalid frequency")
        self.context.probe.set_clock(freq_Hz)
        if self.context.probe.wire_protocol == DebugProbe.Protocol.SWD:
            swd_jtag = 'SWD'
        elif self.context.probe.wire_protocol == DebugProbe.Protocol.JTAG:
            swd_jtag = 'JTAG'
        else:
            swd_jtag = '??'

        if freq_Hz >= 1000000:
            nice_freq = "%.2f MHz" % (freq_Hz / 1000000)
        elif freq_Hz > 1000:
            nice_freq = "%.2f kHz" % (freq_Hz / 1000)
        else:
            nice_freq = "%d Hz" % freq_Hz

        self.context.writei("Changed %s frequency to %s", swd_jtag, nice_freq)

