# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
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

from typing import (Callable, Sequence, Union, cast, overload)
from typing_extensions import Literal

from ..utility import conversion

class MemoryInterface:
    """@brief Interface for memory access."""

    def write_memory(self, addr: int, data: int, transfer_size: int = 32) -> None:
        """@brief Write a single memory location.

        By default the transfer size is a word."""
        raise NotImplementedError()

    @overload
    def read_memory(self, addr: int, transfer_size: int = 32) -> int:
        ...

    @overload
    def read_memory(self, addr: int, transfer_size: int = 32, now: Literal[True] = True) -> int:
        ...

    @overload
    def read_memory(self, addr: int, transfer_size: int, now: Literal[False]) -> Callable[[], int]:
        ...

    @overload
    def read_memory(self, addr: int, transfer_size: int, now: bool) -> Union[int, Callable[[], int]]:
        ...

    def read_memory(self, addr: int, transfer_size: int = 32, now: bool = True) -> Union[int, Callable[[], int]]:
        """@brief Read a memory location.

        By default, a word will be read."""
        raise NotImplementedError()

    def write_memory_block32(self, addr: int, data: Sequence[int]) -> None:
        """@brief Write an aligned block of 32-bit words."""
        raise NotImplementedError()

    def read_memory_block32(self, addr: int, size: int) -> Sequence[int]:
        """@brief Read an aligned block of 32-bit words."""
        raise NotImplementedError()

    def write64(self, addr: int, value: int) -> None:
        """@brief Shorthand to write a 64-bit word."""
        self.write_memory(addr, value, 64)

    def write32(self, addr: int, value: int) -> None:
        """@brief Shorthand to write a 32-bit word."""
        self.write_memory(addr, value, 32)

    def write16(self, addr: int, value: int) -> None:
        """@brief Shorthand to write a 16-bit halfword."""
        self.write_memory(addr, value, 16)

    def write8(self, addr: int, value: int) -> None:
        """@brief Shorthand to write a byte."""
        self.write_memory(addr, value, 8)

    @overload
    def read64(self, addr: int) -> int:
        ...

    @overload
    def read64(self, addr: int, now: Literal[True] = True) -> int:
        ...

    @overload
    def read64(self, addr: int, now: Literal[False]) -> Callable[[], int]:
        ...

    @overload
    def read64(self, addr: int, now: bool = True) -> Union[int, Callable[[], int]]:
        ...

    def read64(self, addr: int, now: bool = True) -> Union[int, Callable[[], int]]:
        """@brief Shorthand to read a 64-bit word."""
        return self.read_memory(addr, 64, now)

    @overload
    def read32(self, addr: int) -> int:
        ...

    @overload
    def read32(self, addr: int, now: Literal[True] = True) -> int:
        ...

    @overload
    def read32(self, addr: int, now: Literal[False]) -> Callable[[], int]:
        ...

    @overload
    def read32(self, addr: int, now: bool = True) -> Union[int, Callable[[], int]]:
        ...

    def read32(self, addr: int, now: bool = True) -> Union[int, Callable[[], int]]:
        """@brief Shorthand to read a 32-bit word."""
        return self.read_memory(addr, 32, now)

    @overload
    def read16(self, addr: int) -> int:
        ...

    @overload
    def read16(self, addr: int, now: Literal[True] = True) -> int:
        ...

    @overload
    def read16(self, addr: int, now: Literal[False]) -> Callable[[], int]:
        ...

    @overload
    def read16(self, addr: int, now: bool = True) -> Union[int, Callable[[], int]]:
        ...

    def read16(self, addr: int, now: bool = True) -> Union[int, Callable[[], int]]:
        """@brief Shorthand to read a 16-bit halfword."""
        return self.read_memory(addr, 16, now)

    @overload
    def read8(self, addr: int) -> int:
        ...

    @overload
    def read8(self, addr: int, now: Literal[True] = True) -> int:
        ...

    @overload
    def read8(self, addr: int, now: Literal[False]) -> Callable[[], int]:
        ...

    @overload
    def read8(self, addr: int, now: bool = True) -> Union[int, Callable[[], int]]:
        ...

    def read8(self, addr: int, now: bool = True) -> Union[int, Callable[[], int]]:
        """@brief Shorthand to read a byte."""
        return self.read_memory(addr, 8, now)

    def read_memory_block8(self, addr: int, size: int) -> Sequence[int]:
        """@brief Read a block of unaligned bytes in memory.
        @return an array of byte values
        """
        res = []

        # try to read 8bits data
        if (size > 0) and (addr & 0x01):
            mem = self.read8(addr)
            res.append(mem)
            size -= 1
            addr += 1

        # try to read 16bits data
        if (size > 1) and (addr & 0x02):
            mem = cast(int, self.read16(addr))
            res.append(mem & 0xff)
            res.append((mem >> 8) & 0xff)
            size -= 2
            addr += 2

        # try to read aligned block of 32bits
        if (size >= 4):
            data32 = self.read_memory_block32(addr, size // 4)
            res += conversion.u32le_list_to_byte_list(data32)
            size -= 4*len(data32)
            addr += 4*len(data32)

        if (size > 1):
            mem = cast(int, self.read16(addr))
            res.append(mem & 0xff)
            res.append((mem >> 8) & 0xff)
            size -= 2
            addr += 2

        if (size > 0):
            mem = self.read8(addr)
            res.append(mem)

        return res

    def write_memory_block8(self, addr: int, data: Sequence[int]) -> None:
        """@brief Write a block of unaligned bytes in memory."""
        size = len(data)
        idx = 0

        #try to write 8 bits data
        if (size > 0) and (addr & 0x01):
            self.write8(addr, data[idx])
            size -= 1
            addr += 1
            idx += 1

        # try to write 16 bits data
        if (size > 1) and (addr & 0x02):
            self.write16(addr, data[idx] | (data[idx+1] << 8))
            size -= 2
            addr += 2
            idx += 2

        # write aligned block of 32 bits
        if (size >= 4):
            data32 = conversion.byte_list_to_u32le_list(data[idx:idx + (size & ~0x03)])
            self.write_memory_block32(addr, data32)
            addr += size & ~0x03
            idx += size & ~0x03
            size -= size & ~0x03

        # try to write 16 bits data
        if (size > 1):
            self.write16(addr, data[idx] | (data[idx+1] << 8))
            size -= 2
            addr += 2
            idx += 2

        #try to write 8 bits data
        if (size > 0):
            self.write8(addr, data[idx])

