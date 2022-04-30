# pyOCD debugger
# Copyright (c) 2021 mikisama
# Copyright (C) 2021 Ciro Cattuto <ciro.cattuto@gmail.com>
# Copyright (C) 2021 Simon D. Levy <simon.d.levy@gmail.com>
# Copyright (C) 2022 Johan Carlsson <johan.carlsson@teenage.engineering>
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

import argparse
from typing import List
import logging
from pyocd.core.helpers import ConnectHelper
from pyocd.core.memory_map import MemoryMap, MemoryRegion, MemoryType
from pyocd.core.soc_target import SoCTarget
from pyocd.subcommands.base import SubcommandBase
from pyocd.utility.cmdline import convert_session_options, int_base_0
from pyocd.utility.kbhit import KBHit
from ctypes import Structure, c_char, c_int32, c_uint32, sizeof


LOG = logging.getLogger(__name__)


class SEGGER_RTT_BUFFER_UP(Structure):
    """@brief `SEGGER RTT Ring Buffer` target to host."""

    _fields_ = [
        ("sName", c_uint32),
        ("pBuffer", c_uint32),
        ("SizeOfBuffer", c_uint32),
        ("WrOff", c_uint32),
        ("RdOff", c_uint32),
        ("Flags", c_uint32),
    ]


class SEGGER_RTT_BUFFER_DOWN(Structure):
    """@brief `SEGGER RTT Ring Buffer` host to target."""

    _fields_ = [
        ("sName", c_uint32),
        ("pBuffer", c_uint32),
        ("SizeOfBuffer", c_uint32),
        ("WrOff", c_uint32),
        ("RdOff", c_uint32),
        ("Flags", c_uint32),
    ]


class SEGGER_RTT_CB(Structure):
    """@brief `SEGGER RTT control block` structure. """

    _fields_ = [
        ("acID", c_char * 16),
        ("MaxNumUpBuffers", c_int32),
        ("MaxNumDownBuffers", c_int32),
        ("aUp", SEGGER_RTT_BUFFER_UP * 3),
        ("aDown", SEGGER_RTT_BUFFER_DOWN * 3),
    ]


class RTTSubcommand(SubcommandBase):
    """@brief `pyocd rtt` subcommand."""

    NAMES = ["rtt"]
    HELP = "SEGGER RTT Viewer."

    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """@brief Add this subcommand to the subparsers object."""

        rtt_parser = argparse.ArgumentParser(cls.HELP, add_help=False)

        rtt_options = rtt_parser.add_argument_group("rtt options")
        rtt_options.add_argument("-a", "--address", type=int_base_0, default=None,
                                 help="Start address of RTT control block search range.")
        rtt_options.add_argument("-s", "--size", type=int_base_0, default=None,
                                 help="Size of RTT control block search range.")

        return [cls.CommonOptions.COMMON, cls.CommonOptions.CONNECT, rtt_parser]

    def invoke(self) -> int:

        session = None
        kb = None

        try:
            session = ConnectHelper.session_with_chosen_probe(
                project_dir=self._args.project_dir,
                config_file=self._args.config,
                user_script=self._args.script,
                no_config=self._args.no_config,
                pack=self._args.pack,
                unique_id=self._args.unique_id,
                target_override=self._args.target_override,
                frequency=self._args.frequency,
                blocking=(not self._args.no_wait),
                connect_mode=self._args.connect_mode,
                options=convert_session_options(self._args.options))

            if session is None:
                LOG.error("No target device available")
                return 1

            with session:

                target: SoCTarget = session.board.target

                memory_map: MemoryMap = target.get_memory_map()
                ram_region: MemoryRegion = memory_map.get_default_region_of_type(MemoryType.RAM)

                if self._args.address is None or self._args.size is None:
                    rtt_range_start = ram_region.start
                    rtt_range_size = ram_region.length
                elif ram_region.start <= self._args.address and self._args.size <= ram_region.length:
                    rtt_range_start = self._args.address
                    rtt_range_size = self._args.size

                LOG.info(f"RTT control block search range [{rtt_range_start:#08x}, {rtt_range_size:#08x}]")

                rtt_cb_addr = -1
                data = bytearray(b'0000000000')
                chunk_size = 1024
                while rtt_range_size > 0:
                    read_size = min(chunk_size, rtt_range_size)
                    data += bytearray(target.read_memory_block8(rtt_range_start, read_size))
                    pos = data[-(read_size + 10):].find(b"SEGGER RTT")
                    if pos != -1:
                        rtt_cb_addr = rtt_range_start + pos - 10
                        break
                    rtt_range_start += read_size
                    rtt_range_size -= read_size

                if rtt_cb_addr == -1:
                    LOG.error("No RTT control block available")
                    return 1

                data = target.read_memory_block8(rtt_cb_addr, sizeof(SEGGER_RTT_CB))
                rtt_cb = SEGGER_RTT_CB.from_buffer(bytearray(data))
                up_addr = rtt_cb_addr + SEGGER_RTT_CB.aUp.offset
                down_addr = up_addr + sizeof(SEGGER_RTT_BUFFER_UP) * rtt_cb.MaxNumUpBuffers

                LOG.info(f"_SEGGER_RTT @ {rtt_cb_addr:#08x} with {rtt_cb.MaxNumUpBuffers} aUp and {rtt_cb.MaxNumDownBuffers} aDown")

                # some targets might need this here
                #target.reset_and_halt()

                target.resume()

                # set up terminal input
                kb = KBHit()

                # byte array to send via RTT
                cmd = bytes()

                while True:
                    # read data from up buffers (target -> host)    
                    data = target.read_memory_block8(up_addr, sizeof(SEGGER_RTT_BUFFER_UP))
                    up = SEGGER_RTT_BUFFER_UP.from_buffer(bytearray(data))

                    if up.WrOff > up.RdOff:
                        """
                        |oooooo|xxxxxxxxxxxx|oooooo|
                        0    rdOff        WrOff    SizeOfBuffer
                        """
                        data = target.read_memory_block8(up.pBuffer + up.RdOff, up.WrOff - up.RdOff)
                        target.write_memory(up_addr + SEGGER_RTT_BUFFER_UP.RdOff.offset, up.WrOff)
                        print(bytes(data).decode(), end="", flush=True)

                    elif up.WrOff < up.RdOff:
                        """
                        |xxxxxx|oooooooooooo|xxxxxx|
                        0    WrOff        RdOff    SizeOfBuffer
                        """
                        data = target.read_memory_block8(up.pBuffer + up.RdOff, up.SizeOfBuffer - up.RdOff)
                        data += target.read_memory_block8(up.pBuffer, up.WrOff)
                        target.write_memory(up_addr + SEGGER_RTT_BUFFER_UP.RdOff.offset, up.WrOff)
                        print(bytes(data).decode(), end="", flush=True)

                    else: # up buffer is empty

                        # try and fetch character
                        if not kb.kbhit():
                            continue
                        c = kb.getch()

                        if ord(c) == 8 or ord(c) == 127: # process backspace
                            print("\b \b", end="", flush=True)
                            cmd = cmd[:-1]
                            continue
                        elif ord(c) == 27: # process ESC
                            break
                        else:
                            print(c, end="", flush=True)
                            cmd += c.encode()

                        # keep accumulating until we see CR or LF
                        if not c in "\r\n":
                            continue

                        # SEND TO TARGET

                        data = target.read_memory_block8(down_addr, sizeof(SEGGER_RTT_BUFFER_DOWN))
                        down = SEGGER_RTT_BUFFER_DOWN.from_buffer(bytearray(data))

                        # compute free space in down buffer
                        if down.WrOff >= down.RdOff:
                            num_avail = down.SizeOfBuffer - (down.WrOff - down.RdOff)
                        else:
                            num_avail = down.RdOff - down.WrOff - 1

                        # wait until there's space for the entire string in the RTT down buffer
                        if (num_avail < len(cmd)):
                            continue

                        # write data to down buffer (host -> target), char by char
                        for i in range(len(cmd)):
                            target.write_memory_block8(down.pBuffer + down.WrOff, cmd[i:i+1])
                            down.WrOff += 1
                            if down.WrOff == down.SizeOfBuffer:
                                down.WrOff = 0;
                        target.write_memory(down_addr + SEGGER_RTT_BUFFER_DOWN.WrOff.offset, down.WrOff)

                        # clear it and start anew
                        cmd = bytes()

        except KeyboardInterrupt:
            pass

        finally:
            if session:
                session.close()
            if kb:
                kb.set_normal_term()

        return 0
