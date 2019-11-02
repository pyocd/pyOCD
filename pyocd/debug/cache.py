# pyOCD debugger
# Copyright (c) 2016-2019 Arm Limited
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

from .context import DebugContext
from ..cache.memory import MemoryCache
from ..cache.register import RegisterCache

class CachingDebugContext(DebugContext):
    """! @brief Debug context combining register and memory caches."""

    def __init__(self, parent):
        super(CachingDebugContext, self).__init__(parent)
        self._regcache = RegisterCache(parent, self.core)
        self._memcache = MemoryCache(parent, self.core)

    def write_memory(self, addr, value, transfer_size=32):
        return self._memcache.write_memory(addr, value, transfer_size)

    def read_memory(self, addr, transfer_size=32, now=True):
        return self._memcache.read_memory(addr, transfer_size, now)

    def write_memory_block8(self, addr, value):
        return self._memcache.write_memory_block8(addr, value)

    def write_memory_block32(self, addr, data):
        return self._memcache.write_memory_block32(addr, data)

    def read_memory_block8(self, addr, size):
        return self._memcache.read_memory_block8(addr, size)

    def read_memory_block32(self, addr, size):
        return self._memcache.read_memory_block32(addr, size)

    def read_core_registers_raw(self, reg_list):
        return self._regcache.read_core_registers_raw(reg_list)

    def write_core_registers_raw(self, reg_list, data_list):
        return self._regcache.write_core_registers_raw(reg_list, data_list)

    def invalidate(self):
        self._regcache.invalidate()
        self._memcache.invalidate()



