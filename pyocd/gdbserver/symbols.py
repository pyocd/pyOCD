# pyOCD debugger
# Copyright (c) 2016-2018 Arm Limited
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

from ..debug.symbols import SymbolProvider
from ..utility.compatibility import to_bytes_safe

class GDBSymbolProvider(SymbolProvider):
    """@brief Request symbol information from gdb."""

    def __init__(self, gdbserver):
        self._gdbserver = gdbserver

    def get_symbol_value(self, name):
        return self._gdbserver.get_symbol(to_bytes_safe(name))
