# pyOCD debugger
# Copyright (c) 2017 Arm Limited
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

from ..symbols import SymbolProvider

class ELFSymbolProvider(SymbolProvider):
    """! @brief Get symbol information from an ELF file."""

    def __init__(self, elf):
        self._symbols = elf.symbol_decoder

    def get_symbol_value(self, name):
        sym = self._symbols.get_symbol_for_name(name)
        if sym is not None:
            return sym.address
        else:
            return None

