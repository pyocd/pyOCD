"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2016 ARM Limited

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

from ..context import DebugContext
from ...utility import conversion
import logging
from intervaltree import (Interval, IntervalTree)

## @brief Reads flash memory regions from an ELF file instead of the target.
class FlashReaderContext(DebugContext):
    def __init__(self, parentContext, elf):
        super(FlashReaderContext, self).__init__(parentContext.core)
        self._parent = parentContext
        self._elf = elf
        self._log = logging.getLogger('flashreadercontext')

        self._build_regions()

    def _build_regions(self):
        self._tree = IntervalTree()
        for sect in [s for s in self._elf.sections if (s.region and s.region.is_flash)]:
            start = sect.start
            length = sect.length
            sect.data # Go ahead and read the data from the file.
            self._tree.addi(start, start + length, sect)
            self._log.debug("created flash section [%x:%x] for section %s", start, start + length, sect.name)

    def read_memory(self, addr, transfer_size=32, now=True):
        length = transfer_size // 8
        matches = self._tree.search(addr, addr + length)
        # Must match only one interval (ELF section).
        if len(matches) != 1:
            return self._parent.read_memory(addr, transfer_size, now)
        section = matches.pop().data
        addr -= section.start

        def read_memory_cb():
            self._log.debug("read flash data [%x:%x] from section %s", section.start + addr, section.start + addr  + length, section.name)
            data = section.data[addr:addr + length]
            if transfer_size == 8:
                return data[0]
            elif transfer_size == 16:
                return conversion.byte_list_to_u16le_list(data)[0]
            elif transfer_size == 32:
                return conversion.byte_list_to_u32le_list(data)[0]
            else:
                raise ValueError("invalid transfer_size (%d)" % transfer_size)

        if now:
            return read_memory_cb()
        else:
            return read_memory_cb

    def read_memory_block8(self, addr, size):
        matches = self._tree.search(addr, addr + size)
        # Must match only one interval (ELF section).
        if len(matches) != 1:
            return self._parent.read_memory_block8(addr, size)
        section = matches.pop().data
        addr -= section.start
        data = section.data[addr:addr + size]
        self._log.debug("read flash data [%x:%x]", section.start + addr, section.start + addr  + size)
        return list(data)

    def read_memory_block32(self, addr, size):
        return conversion.byte_list_to_u32le_list(self.read_memory_block8(addr, size))

    def write_memory(self, addr, value, transfer_size=32):
        return self._parent.write_memory(addr, value, transfer_size)

    def write_memory_block8(self, addr, value):
        return self._parent.write_memory_block8(addr, value)

    def write_memory_block32(self, addr, data):
        return self._parent.write_memory_block32(addr, data)

