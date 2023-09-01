# pyOCD debugger
# Copyright (c) 2021 Maxim Integrated (now owned by Analog Devices, Inc.)
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

from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...debug.svd.loader import SVDFile

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe00abe00,
    0x20604989, 0x6a4a6048, 0x44484888, 0x22006082, 0x688a624a, 0x68426042, 0x4270f022, 0x68426042,
    0x5200f042, 0x68406042, 0x47706088, 0x688a497e, 0x4448487e, 0x68426042, 0x4270f022, 0x68426042,
    0x6880608a, 0x47706248, 0x47702000, 0x47702000, 0xf7ffb500, 0x4b74ffd5, 0x48746899, 0x60414448,
    0xf4216841, 0x6041417f, 0xf4416841, 0x6041412a, 0x60996841, 0xf0416841, 0x60410102, 0x60986840,
    0x01c06898, 0xf7ffd4fc, 0x6a58ffd1, 0xf04f0780, 0xd5010000, 0x20016258, 0xb500bd00, 0x035b0b43,
    0xffaef7ff, 0x600b4960, 0x4860688a, 0x60424448, 0xf4226842, 0x6042427f, 0xf4426842, 0x604242aa,
    0x608a6842, 0xf0426842, 0x60420204, 0x60886840, 0x01c06888, 0x6a48d4fc, 0xd5050780, 0x62482000,
    0xffa4f7ff, 0xbd002001, 0xffa0f7ff, 0xbd002000, 0x4613b5f8, 0x4605460c, 0xff82f7ff, 0x6881484a,
    0x444a4a4a, 0x68516051, 0x6100f021, 0x68516051, 0x0110f041, 0x68516051, 0xe00e6081, 0x68196005,
    0x68516301, 0x0101f041, 0x68516051, 0x68816081, 0xd4fc01c9, 0x1f241d1b, 0x2c041d2d, 0x06e9d301,
    0x6811d1ec, 0xd1202980, 0xd31e2c10, 0x60516881, 0xf0216851, 0x60510110, 0x60816851, 0x68196005,
    0x68596301, 0x68996341, 0x68d96381, 0x685163c1, 0x0101f041, 0x68516051, 0x68816081, 0xd4fc01c9,
    0x3c103310, 0x2c103510, 0x2c04d2e8, 0x6881d31c, 0x68516051, 0x6100f021, 0x68516051, 0x0110f041,
    0x68516051, 0x60056081, 0x63016819, 0xf0416851, 0x60510101, 0x60816851, 0x01c96881, 0x1d1bd4fc,
    0x1d2d1f24, 0xd2ee2c04, 0xa119b314, 0x91006809, 0x21006886, 0x68566056, 0x6600f026, 0x68566056,
    0x0610f046, 0x68566056, 0x466e6086, 0x7b01f813, 0x1c495477, 0xd1f91e64, 0x99006005, 0x68516301,
    0x0101f041, 0x68516051, 0x68816081, 0xd4fc01c9, 0x07806a40, 0xf7ffd503, 0x2001ff09, 0xf7ffbdf8,
    0x2000ff05, 0x0000bdf8, 0x40029000, 0x00000004, 0xffffffff, 0x00000000, 0x00000020, 0x00000000,
    0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x2000004d,
    'pc_unInit': 0x20000051,
    'pc_program_page': 0x200000f5,
    'pc_erase_sector': 0x2000009f,
    'pc_eraseAll': 0x20000055,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000234,
    'begin_stack' : 0x20000448,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x400,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20002000],   # Enable double buffering
    'min_program_length' : 0x400,

    # Relative region addresses and sizes
    'ro_start': 0x0,
    'ro_size': 0x234,
    'rw_start': 0x234,
    'rw_size': 0x10,
    'zi_start': 0x244,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x40000,
    'sector_sizes': (
        (0x0, 0x2000),
    )
}

class MAX32660(CoreSightTarget):

    VENDOR = "Maxim"

    MEMORY_MAP = MemoryMap(
        FlashRegion(    start=0,           length=0x40000,  blocksize=0x2000, is_boot_memory=True, algo=FLASH_ALGO),
        RamRegion(      start=0x20000000,  length=0x18000),
        )

    def __init__(self, session):
        super().__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("max32660.svd")
