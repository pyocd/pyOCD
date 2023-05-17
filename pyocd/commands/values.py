# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
# Copyright (c) 2021-2023 Chris Reed
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

from __future__ import annotations

import logging
import prettytable
from typing import (cast, TYPE_CHECKING)

from .. import coresight
from ..core import exceptions
from ..probe.debug_probe import DebugProbe
from ..coresight.ap import MEM_AP
from ..core.target import Target
from ..core.core_target import CoreTarget
from ..utility.cmdline import (
    convert_one_session_option,
    convert_frequency,
    convert_vector_catch,
    convert_reset_type,
    )
from ..utility.mask import msb
from .base import ValueBase

if TYPE_CHECKING:
    from ..core.memory_map import MemoryMap
    from ..utility.graph import GraphNode

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
        self.context.write(f"Target type:  {self.context.session.options.get('target_override')}")
        self.context.write(f"Vendor:       {self.context.target.vendor}")
        self.context.write(f"Part number:  {self.context.target.part_number}")
        self.context.write(f"DAP IDCODE:   {self.context.target.dp.dpidr.idr:#010x}")

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
            pt = prettytable.PrettyTable(["Number", "Name", "Type"])
            pt.align = 'l'
            pt.border = False

            for i, core in self.context.target.cores.items():
                pt.add_row([
                    (
                        ("*" if ((self.context.selected_core is not None)
                                and (self.context.selected_core.core_number == i))
                            else " ")
                        + str(i)
                    ),
                    cast(CoreTarget, core).node_name,
                    core.name,
                ])

            self.context.write(str(pt))
            self.context.write("(Currently selected core is marked with a '*'.)")

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

        def add_rows(indent: int, pt: prettytable.PrettyTable, map: "MemoryMap") -> None:
            for region in map:
                pt.add_row([
                    ('  ' * indent) + region.name,
                    region.type.name.capitalize(),
                    "0x%08x" % region.start,
                    "0x%08x" % region.end,
                    "0x%08x" % region.length,
                    region.access,
                    ("0x%08x" % region.sector_size) if region.is_flash else '-',
                    ("0x%08x" % region.page_size) if region.is_flash else '-',
                    ])
                if region.has_subregions:
                    add_rows(indent + 2, pt, region.submap)

        add_rows(0, pt, self.context.selected_core.memory_map)

        self.context.write(str(pt))

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

class AccessiblePinsValue(ValueBase):
    INFO = {
            'names': ['accessible-pins'],
            'group': 'standard',
            'category': 'probe',
            'access': 'rw',
            'help': "Display which debug probe pins can be read and written with the 'pins' value.",
            }

    def display(self, args):
        if DebugProbe.Capability.PIN_ACCESS not in self.context.probe.capabilities:
            raise exceptions.CommandError("debug probe does not support pin access")

        # Display accessibility of protocol pins.
        r_pins, w_pins = self.context.probe.get_accessible_pins(DebugProbe.PinGroup.PROTOCOL_PINS)

        def pin_desc(mask: int) -> str:
            desc = ""
            if r_pins & mask:
                desc += "r"
            if w_pins & mask:
                desc += "w"
            if desc == "":
                desc = "n/a"
            return desc

        self.context.write(f"Protocol pins:")
        self.context.write(f"  SWCLK/TCK = {pin_desc(DebugProbe.ProtocolPin.SWCLK_TCK)}")
        self.context.write(f"  SWDIO/TMS = {pin_desc(DebugProbe.ProtocolPin.SWDIO_TMS)}")
        self.context.write(f"  TDI =       {pin_desc(DebugProbe.ProtocolPin.TDI)}")
        self.context.write(f"  TDO =       {pin_desc(DebugProbe.ProtocolPin.TDO)}")
        self.context.write(f"  nRESET =    {pin_desc(DebugProbe.ProtocolPin.nRESET)}")
        self.context.write(f"  nTRST =     {pin_desc(DebugProbe.ProtocolPin.nTRST)}")

        # Test if there are any accessible GPIO pins.
        r_pins, w_pins = self.context.probe.get_accessible_pins(DebugProbe.PinGroup.GPIO_PINS)

        if (r_pins | w_pins) != 0:
            self.context.write(f"GPIO pins:")
            for b in range(msb(r_pins | w_pins) + 1):
                self.context.write(f"  GPIO {b:<6} {pin_desc(1 << b)}")

class PinsValue(ValueBase):
    INFO = {
            'names': ['pins'],
            'group': 'standard',
            'category': 'probe',
            'access': 'rw',
            'help': "Current debug probe protocol I/O pin states.",
            'extra_help':
                "The pins value is a mask containing the state of all accessible protocol pins. "
                "See the `accessible-pins` value for protocol pins that can be read and written by "
                "the connected debug probe.",
            }

    def display(self, args):
        if DebugProbe.Capability.PIN_ACCESS not in self.context.probe.capabilities:
            raise exceptions.CommandError("debug probe does not support pin access")
        self.print_current_pin_values()

    def print_current_pin_values(self):
        pins = self.context.probe.read_pins(DebugProbe.PinGroup.PROTOCOL_PINS,
                                            DebugProbe.ProtocolPin.ALL_PINS)

        def pin_desc(mask: int) -> str:
            v = int(pins & mask != 0)
            return f"{v} (mask {mask:#x})"

        self.context.write(f"Pins mask = {pins:#x}")
        self.context.write(f"SWCLK/TCK = {pin_desc(DebugProbe.ProtocolPin.SWCLK_TCK)}")
        self.context.write(f"SWDIO/TMS = {pin_desc(DebugProbe.ProtocolPin.SWDIO_TMS)}")
        self.context.write(f"TDI =       {pin_desc(DebugProbe.ProtocolPin.TDI)}")
        self.context.write(f"TDO =       {pin_desc(DebugProbe.ProtocolPin.TDO)}")
        self.context.write(f"nRESET =    {pin_desc(DebugProbe.ProtocolPin.nRESET)}")
        self.context.write(f"nTRST =     {pin_desc(DebugProbe.ProtocolPin.nTRST)}")

    def modify(self, args):
        if DebugProbe.Capability.PIN_ACCESS not in self.context.probe.capabilities:
            raise exceptions.CommandError("debug probe does not support pin access")
        if len(args) != 1:
            raise exceptions.CommandError("missing pins mask")
        state = int(args[0], base=0)
        self.context.probe.write_pins(DebugProbe.PinGroup.PROTOCOL_PINS,
                                        DebugProbe.ProtocolPin.ALL_PINS, state)
        self.print_current_pin_values()

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
        """Extract and apply option setting arguments.

        The syntax for each option is "name[=value]". The args are pre-split into individual tokens,
        where the '=' is a separate token. So a single "foo=bar" is split into "foo", "=", "bar" args.
        """
        if len(args) < 1:
            raise exceptions.CommandError("missing session option setting")
        while args:
            name = args.pop(0)
            if args and args[0] == "=":
                args.pop(0) # Remove "="
                if not args:
                    raise exceptions.CommandError("expected option value after '='")
                value = args.pop(0)
            else:
                value = None
            name, converted_value = convert_one_session_option(name, value)
            self.context.session.options[name] = converted_value

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
            'help': "The current HNONSEC attribute value used by the selected MEM-AP.",
            'extra_help':
                "This value controls whether memory transactions are secure or nonsecure. The value is an "
                "integer, either 0 or secure or 1 for nonsecure."
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
            'names': ['hprot', 'memap_attr'],
            'group': 'standard',
            'category': 'memory',
            'access': 'rw',
            'help': "The current memory transfer attributes value used by the selected MEM-AP.",
            'extra_help':
"""This integer value controls attributes of memory transfers. It is a direct mapping of the AHB
or AXI attribute settings, depending on the type of MEM-AP. For AHB-APs, the value is HPROT[4:0].
For AXI-APs, the value is {AxPROT[2:0}, AxCACHE[3:0]}, e.g. AxPROT in bits 6-4 and AxCACHE in
its 3-0. Not all MEM-AP implementations support all attributes. See the Arm Technical Reference
Manual for your device's MEM-AP for details."""
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
        def _node_desc(node: GraphNode) -> str:
            desc = node.__class__.__name__
            if node.node_name:
                desc = f'"{node.node_name}": ' + desc
            return desc

        def _dump(node: GraphNode, level: int) -> None:
            desc = ("  " * level) + "- " + _node_desc(node)
            self.context.write(desc)
            for child in node.children:
                _dump(child, level + 1)

        _dump(self.context.board, 0)

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
            self.context.write("Target is locked")
        else:
            self.context.write("Target is unlocked")

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
        except Exception:
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

class DebugSequencesValue(ValueBase):
    INFO = {
            'names': ['debug-sequences'],
            'group': 'pack-target',
            'category': 'cmsis-pack',
            'access': 'r',
            'help': "Show the available debug sequences from the target's DFP.",
            'extra_help': "Only available for CMSIS-Pack based targets.",
            }

    # Names of debug sequences that are both standard and supported by pyocd.
    STANDARD_SEQUENCE_NAMES = [
        "DebugPortSetup",
        "DebugPortStart",
        "DebugPortStop",
        "DebugDeviceUnlock",
        "DebugCoreStart",
        "DebugCoreStop",
        "ResetSystem",
        "ResetProcessor",
        "ResetHardware",
        "ResetCatchSet",
        "ResetCatchClear",
        "TraceStart",
        "TraceStop",
    ]

    def display(self, args):
        assert self.context.target

        if self.context.target.debug_sequence_delegate is None:
            self.context.write("Target does not use debug sequences")
            return

        pt = prettytable.PrettyTable(["Name", "Processor", "Standard", "Enabled"])
        pt.align = 'l'
        pt.border = False

        for seq in sorted(self.context.target.debug_sequence_delegate.all_sequences,
                key=lambda i: (i.name, i.pname)):
            is_standard = seq.name in self.STANDARD_SEQUENCE_NAMES
            pt.add_row([
                seq.name,
                seq.pname if seq.pname else "all",
                str(is_standard),
                seq.is_enabled,
            ])

        self.context.write(str(pt))

class ResetTypeValue(ValueBase):
    INFO = {
            'names': ['reset-type'],
            'group': 'standard',
            'category': 'target',
            'access': 'rw',
            'help': "Show reset configuration and all available reset types for each core. Set current reset type.",
            }

    def display(self, args):
        from ..coresight.cortex_m import CortexM

        assert self.context.target

        current_reset_type_option = self.context.session.options.get('reset_type')
        current_reset_type = convert_reset_type(current_reset_type_option)
        reset_type_desc = current_reset_type_option
        if current_reset_type is not None:
            reset_type_desc += f" ({current_reset_type.name})"
        self.context.write(f"Selected reset type ('reset_type' option): {reset_type_desc}")

        for core in self.context.target.cores.values():
            # Only handle Cortex-M cores for now.
            if not isinstance(core, CortexM):
                continue
            cm_core = cast(CortexM, core)

            actual_reset_type = cm_core._get_actual_reset_type(None)

            self.context.write(f"\nCore {cm_core.core_number} ({cm_core.node_name}):")
            self.context.write(f"  Effective:  {actual_reset_type.name}")
            self.context.write(f"  Default:    {cm_core.default_reset_type.name}")
            self.context.write(f"  Default SW: {cm_core.default_software_reset_type.name}")
            self.context.write("  Available:  " + ", ".join(r.name for r in cm_core.supported_reset_types))

    def modify(self, args):
        from ..utility.cmdline import RESET_TYPE_MAP
        if len(args) != 1:
            raise exceptions.CommandError("invalid arguments")

        new_reset_type = args[0]
        if new_reset_type.lower() not in RESET_TYPE_MAP:
            raise exceptions.CommandError("invalid reset type")

        self.context.session.options['reset_type'] = new_reset_type
