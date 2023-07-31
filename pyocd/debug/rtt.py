# pyOCD debugger
# Copyright (c) 2021 mikisama
# Copyright (C) 2021 Ciro Cattuto <ciro.cattuto@gmail.com>
# Copyright (C) 2021 Simon D. Levy <simon.d.levy@gmail.com>
# Copyright (C) 2022 Johan Carlsson <johan.carlsson@teenage.engineering>
# Copyright (c) 2022 Samuel Dewan
# Copyright (C) 2023 Tejaswini Dasika <tejaswinidasika@gmail.com>
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

from abc import ABC, abstractmethod
from ctypes import Structure, c_char, c_int32, c_uint32, sizeof
import struct
from typing import Optional, Sequence

from ..core.memory_map import MemoryMap, MemoryRegion, MemoryType
from ..core.soc_target import SoCTarget
from ..core import exceptions


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
        ("MaxNumDownBuffers", c_int32)
    ]



class RTTUpChannel(ABC):
    """@brief Wrapper for an RTT up channel for target to host data transfer. """

    name: Optional[str]
    size: int

    @abstractmethod
    def read(self) -> bytes:
        """@brief Read all available data from RTT channel. """


class RTTDownChannel(ABC):
    """@brief Wrapper for an RTT down channel for host to target data transfer. """

    name: Optional[str]
    size: int

    @abstractmethod
    def write(self, data: bytes, blocking = False) -> int:
        """@brief Write data to RTT channel.

        Write as much of the provided data as possible to an the RTT down
        channel.

        @param data The data to be written.
        @param blocking If true will block until all data is sent.

        @return The number of bytes written to the target.
        """


class RTTControlBlock(ABC):
    """@brief Represents an RTT control block.

    This helper class can be used to search for and parse an RTT control block.
    Once the control block is found and parsed (using the start() method)
    RTTUpChannel and RTTDownChannel objects will be created to facilitate
    communication with the target.
    """

    up_channels: Sequence[RTTUpChannel]
    down_channels: Sequence[RTTDownChannel]

    @abstractmethod
    def start(self):
        """@brief Find the RTT control block on the target.

        Searches for the RTT control block. Once found, the up_channels and
        down_channels lists are populated with RTTUpChannel and RTTDownChannel
        objects that can be used to communicate with the target.
        """
        pass

    @classmethod
    def from_target(cls, target: SoCTarget, address: int = None,
                    size: int = None, control_block_id: bytes = b'SEGGER RTT'):
        """@brief Create an RTTControlBlock object using a given target.

        This function creates an instance of an appropriate RTTControlBlock
        subclass depending on the provided target.

        @param target The target with which RTT communication is desired.
        @param address Base address for control block search range.
        @param size Control block search range. If 0 the control block will be
                    expected to be located at the provided address.
        @param control_block_id The control block ID string to search for. Must
                                be at most 16 bytes long.  Will be padded with
                                zeroes if less than 16 bytes.

        @return An instance of an appropriate RTTControlBlock subclass.
        """
        # TODO: Handle targets connected with jlink differently
        return GenericRTTControlBlock(target, address = address, size = size,
                                      control_block_id = control_block_id)




class GenericRTTUpChannel(RTTUpChannel):
    """@brief Software implementation of RTT up channel. Does not require any
              support from interface.
    """

    _target: SoCTarget
    name: Optional[str]
    _buffer_address: int
    size: int
    _offsets_addr: int
    _desc_addr: int

    def __init__(self, target: SoCTarget, desc_addr: int):
        """
        @param target Target to communicate with.
        @param desc_addr Address of up buffer descriptor.
        """
        self._target = target
        self._desc_addr = desc_addr
        self._offsets_addr = self._desc_addr + SEGGER_RTT_BUFFER_UP.WrOff.offset

        self._read_descriptor()

    def _read_descriptor(self):
        # Get buffer descriptor
        up_buffer_words = sizeof(SEGGER_RTT_BUFFER_UP) // 4
        data = self._target.read_memory_block32(self._desc_addr, up_buffer_words)
        descriptor: SEGGER_RTT_BUFFER_UP = SEGGER_RTT_BUFFER_UP(*data)

        # Get name if there is one
        if descriptor.sName != 0:
            data = b''
            while True:
                data += bytes(self._target.read_memory_block8(descriptor.sName, 32))
                name_length = data.find(b'\0')
                if name_length != -1:
                    self.name = data[:name_length].decode("utf-8", "backslashreplace")
                    break
                elif len(data) >= 512:
                    # Give up, this probably isn't a valid string
                    self.name = data.decode("utf-8", "backslashreplace")
                    break
        else:
            self.name = None

        self._buffer_address = descriptor.pBuffer
        self.size = descriptor.SizeOfBuffer

    @property
    def bytes_available(self) -> int:
        """@brief Number of bytes available to be read from up channel. """
        if (self.size == 0) or (self._buffer_address == 0):
            # descriptor is not yet populated
            self._read_descriptor()
            if (self.size == 0) or (self._buffer_address == 0):
                # descriptor is still not populated
                return 0

        # Get offsets
        write_off, read_off = self.target.read_memory_block32(self._offsets_addr, 2)

        if (write_off >= self.size) or (read_off >= self.size):
            raise exceptions.RTTError("Invalid up buffer")
        elif write_off == self.read_off:
            return 0
        elif write_off > read_off:
            return write_off - read_off
        else:
            return (self.size - read_off) + write_off

    def read(self) -> bytes:
        """@brief Read all available data from RTT channel. """
        if (self.size == 0) or (self._buffer_address == 0):
            # descriptor is not yet populated
            self._read_descriptor()
            if (self.size == 0) or (self._buffer_address == 0):
                # descriptor is still not populated
                return b''

        # Get offsets
        write_off, read_off = self._target.read_memory_block32(self._offsets_addr, 2)

        if (write_off >= self.size) or (read_off >= self.size):
            raise exceptions.RTTError("Invalid up buffer")
        elif write_off == read_off:
            # empty
            return b''
        elif write_off > read_off:
            """
            |oooooo|xxxxxxxxxxxx|oooooo|
            0    rdOff        WrOff    SizeOfBuffer
            """
            data = self._target.read_memory_block8(self._buffer_address + read_off,
                                                   write_off - read_off)
        else:
            """
            |xxxxxx|oooooooooooo|xxxxxx|
            0    WrOff        RdOff    SizeOfBuffer
            """
            data = self._target.read_memory_block8(self._buffer_address + read_off,
                                                   self.size - read_off)
            data += self._target.read_memory_block8(self._buffer_address, write_off)

        # Update read offset
        self._target.write32(self._offsets_addr + 4, write_off)
        return bytes(data)


class GenericRTTDownChannel(RTTDownChannel):
    """@brief Software implementation of RTT down channel. Does not require any
              support from interface.
    """

    _target: SoCTarget
    name: Optional[str]
    _buffer_address: int
    size: int
    _offsets_addr: int
    _desc_addr: int

    def __init__(self, target: SoCTarget, desc_addr: int):
        """
        @param target Target to communicate with.
        @param desc_addr Address of down buffer descriptor.
        """
        self._target = target
        self._desc_addr = desc_addr
        self._offsets_addr = self._desc_addr + SEGGER_RTT_BUFFER_DOWN.WrOff.offset

        self._read_descriptor()

    def _read_descriptor(self):
        # Get buffer descriptor
        up_buffer_words = sizeof(SEGGER_RTT_BUFFER_DOWN) // 4
        data = self._target.read_memory_block32(self._desc_addr, up_buffer_words)
        descriptor: SEGGER_RTT_BUFFER_DOWN = SEGGER_RTT_BUFFER_DOWN(*data)

        # Get name if there is one
        if descriptor.sName != 0:
            data = b''
            while True:
                data += bytes(self._target.read_memory_block8(descriptor.sName, 64))
                name_length = data.find(b'\0')
                if name_length != -1:
                    self.name = data[:name_length].decode("utf-8", "backslashreplace")
                    break
                elif len(data) > 512:
                    # Give up, this probably isn't a valid string
                    self.name = data.decode("utf-8", "backslashreplace")
                    break
        else:
            self.name = None

        self._buffer_address = descriptor.pBuffer
        self.size = descriptor.SizeOfBuffer

    @property
    def bytes_free(self) -> int:
        """@brief Number of bytes free in RTT down channel ring buffer."""
        if (self.size == 0) or (self._buffer_address == 0):
            # descriptor is not yet populated
            self._read_descriptor()
            if (self.size == 0) or (self._buffer_address == 0):
                # descriptor is still not populated
                return 0

        # Get offsets
        write_off, read_off = self._target.read_memory_block32(self._offsets_addr, 2)

        if (write_off >= self.size) or (read_off >= self.size):
            raise exceptions.RTTError("Invalid down buffer")
        elif write_off == self.read_off:
            return self.size
        elif write_off > read_off:
            return (self.size - write_off) + (read_off - 1)
        else:
            return read_off - write_off - 1

    def write(self, data: bytes, blocking = False) -> int:
        """@brief Write data to RTT channel.

        Write as much of the provided data as possible to an the RTT down
        channel.

        @param data The data to be written.
        @param blocking If true will block until all data is sent.

        @return The number of bytes written to the target.
        """
        if (self.size == 0) or (self._buffer_address == 0):
            # descriptor is not yet populated
            self._read_descriptor()
            if (self.size == 0) or (self._buffer_address == 0):
                # descriptor is still not populated
                return 0

        if blocking:
            # Call non-blocking version until all data is written
            while data:
                bytes_sent: int = self.write(data, blocking = False)
                data = data[bytes_sent:]
            return

        # Get offsets
        write_off, read_off = self._target.read_memory_block32(self._offsets_addr, 2)

        if (write_off >= self.size) or (read_off >= self.size):
            raise exceptions.RTTError("Invalid down buffer")


        bytes_written: int = 0
        if write_off >= read_off:
            # There is some space to fill at the top of the buffer
            free_space: int = self.size - write_off
            if read_off == 0:
                # Can't use the last element in the buffer
                free_space -= 1
            data_to_write: bytes = data[:free_space]
            self._target.write_memory_block8(self._buffer_address + write_off,
                                             data_to_write)
            bytes_written = len(data_to_write)
            data = data[bytes_written:]
            write_off = (write_off + bytes_written) % self.size

        free_space: int = read_off - write_off - 1
        if free_space < 0:
            free_space = 0

        bytes_to_write: int = min(free_space, len(data))
        self._target.write_memory_block8(self._buffer_address + write_off,
                                         data[:bytes_to_write])
        bytes_written += bytes_to_write
        write_off += bytes_to_write

        # Store new write offset
        self._target.write32(self._offsets_addr, write_off)
        return bytes_written


class GenericRTTControlBlock(RTTControlBlock):
    """@brief Software implementation of RTT control block helper. Does not
              require any support from interface.
    """

    target: SoCTarget
    _cb_search_address: int
    _cb_search_size_bytes: int
    _control_block_id: Sequence[int]

    def __init__(self, target: SoCTarget, address: int = None,
                 size: int = None, control_block_id: bytes = b'SEGGER RTT'):
        """
        @param target The target with which RTT communication is desired.
        @param address Base address for control block search range.
        @param size Control block search range. If 0 the control block will be
                    expected to be located at the provided address.
        @param control_block_id The control block ID string to search for. Must
                                be at most 16 bytes long.  Will be padded with
                                zeroes if less than 16 bytes.
        """
        self.target = target
        self.up_channels = list()
        self.down_channels = list()

        if address is None:
            memory_map: MemoryMap = self.target.get_memory_map()
            ram_region: MemoryRegion = memory_map.get_default_region_of_type(MemoryType.RAM)

            self._cb_search_address = ram_region.start
            if size is None:
                size = ram_region.length
        else:
            self._cb_search_address = address

        if size is None:
            # Address was specified, but size was not. Assume that the control
            # block is located exactly at the provided address.
            self._cb_search_size_bytes = 0
        else:
            self._cb_search_size_bytes = size
        self._control_block_id = control_block_id

    def _find_control_block(self) -> Optional[int]:
        addr: int = self._cb_search_address & ~0x3
        search_size: int  = self._cb_search_size_bytes
        if search_size < len(self._control_block_id):
            search_size = len(self._control_block_id)

        id_len = len(self._control_block_id)
        offset: int = 0

        while search_size:
            read_size = min(search_size, 32)
            data = self.target.read_memory_block8(addr, read_size)

            if not data:
                break

            for byte in data:
                if byte == self._control_block_id[offset]:
                    offset += 1
                    if offset == id_len:
                        break
                else:
                    num_skip_words = (offset + 1)
                    addr += (num_skip_words * 1)
                    search_size -= num_skip_words
                    offset = 0

            if offset == id_len:
                break

        return addr if offset == id_len else None

    def start(self):
        """@brief Find the RTT control block on the target.

        Searches for the RTT control block. Once found, the up_channels and
        down_channels lists are populated with RTTUpChannel and RTTDownChannel
        objects that can be used to communicate with the target.
        """

        cb_addr = self._find_control_block()

        if cb_addr is None:
            raise exceptions.RTTError("Control block not found")

        # Get control block info
        num_up_buffs = self.target.read32(cb_addr + SEGGER_RTT_CB.MaxNumUpBuffers.offset)
        num_down_buffs = self.target.read32(cb_addr + SEGGER_RTT_CB.MaxNumDownBuffers.offset)

        # Setup up channels
        up_base = cb_addr + sizeof(SEGGER_RTT_CB)
        for i in range(num_up_buffs):
            addr = up_base + (i * sizeof(SEGGER_RTT_BUFFER_UP))
            self.up_channels.append(GenericRTTUpChannel(self.target, addr))

        # Setup down channels
        down_base = up_base + num_up_buffs * sizeof(SEGGER_RTT_BUFFER_UP)
        for i in range(num_down_buffs):
            addr = down_base + (i * sizeof(SEGGER_RTT_BUFFER_DOWN))
            self.down_channels.append(GenericRTTDownChannel(self.target, addr))
