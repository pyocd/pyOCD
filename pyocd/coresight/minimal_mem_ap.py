# pyOCD debugger
# Copyright (c) 2023 David van Rijn
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

class MinimalMemAP:
    """
    Minimalistic Access Port implementation.
    This is used in some targets to access memory before the "real" AP's become available.
    """
    AP0_CSW_ADDR = 0x00
    AP0_CSW_ADDR_VAL = 0x03000012
    AP0_TAR_ADDR = 0x04
    AP0_IDR_ADDR = 0xFC
    AP0_DRW_ADDR = 0x0C

    def __init__(self, dp):
        self.dp = dp

    def init(self):
        # Init AP #0
        IDR = self.dp.read_ap(MinimalMemAP.AP0_IDR_ADDR)
        # Check expected MEM-AP
        assert IDR&0x0fffe00f == 0x04770001, f"Wrong IDR read from device: 0x{IDR:08x}"
        self.dp.write_ap(MinimalMemAP.AP0_CSW_ADDR, MinimalMemAP.AP0_CSW_ADDR_VAL)

    def read32(self, addr):
        self.dp.write_ap(MinimalMemAP.AP0_TAR_ADDR, addr)
        return self.dp.read_ap(MinimalMemAP.AP0_DRW_ADDR)

    def write32(self, addr, val):
        self.dp.write_ap(MinimalMemAP.AP0_TAR_ADDR, addr)
        self.dp.write_ap(MinimalMemAP.AP0_DRW_ADDR, val)
