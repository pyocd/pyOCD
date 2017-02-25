"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2016 ARM Limited

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

from ..flash.flash import Flash
from ..core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from .target_LPC4088FBD144 import (Flash_lpc4088, LPC4088)

SPIFI_START = 0x28000000
SPIFI_SIZE = 16 * 1024 * 1024
SPIFI_SECTOR_SIZE = 4 * 1024

flash_algo = {
    'load_address' : 0x10000000,
    'instructions' : [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x28100b00, 0x210ebf24, 0x00d0eb01, 0xe92d4770, 0xf8df4df0, 0x4606831c, 0x460c44c8, 0x0000f8d8,
    0x1c402500, 0x0000f8c8, 0x0f01f010, 0x461749c1, 0x2080f44f, 0x63c8bf14, 0x05306388, 0xa2f8f8df,
    0xf04f0d00, 0x44ca0b00, 0xf8cad111, 0xf44fb010, 0xf8ca5080, 0xe9ca6000, 0xf8ca0b01, 0xf8d8b00c,
    0x4651000c, 0xf1a16882, 0x47900080, 0x2018b9c0, 0xb008f8ca, 0xb003e9ca, 0xf5b4b1cc, 0xbf8c7f80,
    0x7b80f44f, 0x197046a3, 0x0b00e9ca, 0x000cf8d8, 0x19794aa9, 0x6843444a, 0x0080f1a2, 0xb1104798,
    0xe8bd2001, 0x445d8df0, 0x040bebb4, 0x2000d1e5, 0x8df0e8bd, 0x41f0e92d, 0x8274f8df, 0x60e0f642,
    0x4d9e44c8, 0x0008f8c8, 0x70282000, 0x732820aa, 0x73282055, 0xf8052001, 0x22000c40, 0xf0002112,
    0x2200f91a, 0x4610210d, 0xf915f000, 0x210d2200, 0xf0002001, 0x2200f910, 0x20022113, 0xf90bf000,
    0x68204c8c, 0x5000f440, 0x6a206020, 0x2084f440, 0x6c206220, 0x2000f440, 0xf44f6420, 0x63e72780,
    0x61a6117e, 0xf4406c68, 0x64683080, 0xf8c52002, 0x22050134, 0xf0002107, 0x2205f8ee, 0x20002116,
    0xf8e9f000, 0x210f2205, 0xf0002000, 0x2205f8e4, 0x20002110, 0xf8dff000, 0x21112205, 0xf0002000,
    0x2205f8da, 0x20002112, 0xf8d5f000, 0xf44f4874, 0x6800727a, 0xf8c86940, 0xf8d8000c, 0xfbb11008,
    0xf8d5f1f2, 0xf8d02134, 0xf002c000, 0xfbb1021f, 0x496cf3f2, 0xfba1486c, 0x08892103, 0x444822c0,
    0x280047e0, 0x61e6bf04, 0x81f0e8bd, 0x61e663a7, 0xe8bd2001, 0x200081f0, 0xe92d4770, 0x4c6341f0,
    0x444c2032, 0x251d2700, 0xe9c460a5, 0x4e600700, 0x0114f104, 0x47b04620, 0xb9806960, 0x60a52034,
    0x0700e9c4, 0xf1044852, 0x44480114, 0x60e06880, 0x47b04620, 0x28006960, 0xe8bdbf08, 0x200181f0,
    0x81f0e8bd, 0x5f20f1b0, 0xf5b0bf32, 0x20002f00, 0xb5704770, 0x2c100b04, 0x200ebf24, 0x04d4eb00,
    0x4d4a2032, 0x444d4e4a, 0x0114f105, 0x0400e9c5, 0x60ac4628, 0x696847b0, 0x2034b978, 0x0400e9c5,
    0x60ac483b, 0xf1054448, 0x68800114, 0x462860e8, 0x696847b0, 0xbf082800, 0x2001bd70, 0xe92dbd70,
    0x4f3341f0, 0x444f4605, 0x68784614, 0x1c404a31, 0xf0106078, 0xf44f0f01, 0xbf145000, 0x619061d0,
    0x5f20f1b5, 0x4622d305, 0x5020f1a5, 0x41f0e8bd, 0xf5b5e6bd, 0xd3052f00, 0xf5a54622, 0xe8bd2000,
    0xe6b441f0, 0xe9d4b975, 0x44080100, 0x1202e9d4, 0x44084411, 0x44086921, 0x44086961, 0x440869a1,
    0x61e04240, 0x28100b28, 0x210ebf24, 0x00d0eb01, 0x4e1e2132, 0x8078f8df, 0xe9c6444e, 0x60b01000,
    0x0114f106, 0x47c04630, 0xb9886970, 0xe9c62033, 0xf44f0500, 0xe9c67000, 0x68b84002, 0xf1066130,
    0x46300114, 0x697047c0, 0xbf082800, 0x81f0e8bd, 0xe8bd2001, 0xeb0181f0, 0x490e1040, 0x0080eb01,
    0xf0216801, 0x60010107, 0x43116801, 0x47706001, 0x00000004, 0x20098000, 0x000000b4, 0x400fc080,
    0x1fff1ff8, 0xcccccccd, 0x00000034, 0x00000014, 0x1fff1ff1, 0x4002c000, 0x00000000, 0x00000001,
    0x00000000, 0x00000000, 0x00000000,
    ],

    'pc_init' : 0x100000D5,
    'pc_unInit': 0x100001D7,
    'pc_program_page': 0x1000027F,
    'pc_erase_sector': 0x10000225,
    'pc_eraseAll' : 0x100001DB,

    'static_base' : 0x10000000 + 0x00000020 + 0x00000400,
    'begin_stack' : 0x10000000 + 0x00000800,
    # Double buffering is not supported since there is not enough ram
    'begin_data' : 0x10000000 + 0x00000A00,  # Analyzer uses a max of 120 B data (30 pages * 4 bytes / page)
    'page_size' : 0x00000200,
    'analyzer_supported' : False,
    'min_program_length' : 512,
    'analyzer_supported' : True,
    'analyzer_address' : 0x10002000  # Analyzer 0x10002000..0x10002600
}


class Flash_lpc4088qsb_dm(Flash_lpc4088):
    def __init__(self, target):
        super(Flash_lpc4088qsb_dm, self).__init__(target, flash_algo)

    def programPage(self, flashPtr, bytes):
        if SPIFI_START <= flashPtr < SPIFI_START + SPIFI_SIZE:
            assert len(bytes) <= SPIFI_SECTOR_SIZE
            Flash.programPage(self, flashPtr, bytes)
        else:
            super(Flash_lpc4088qsb_dm, self).programPage(flashPtr, bytes)

class LPC4088dm(LPC4088):

    memoryMap = MemoryMap(
        FlashRegion(    start=0,           length=0x10000,      blocksize=0x1000, isBootMemory=True),
        FlashRegion(    start=0x10000,     length=0x70000,      blocksize=0x8000),
        FlashRegion(    start=0x28000000,  length=0x1000000,    blocksize=0x400),
        RamRegion(      start=0x10000000,  length=0x10000),
        )

    def __init__(self, link):
        super(LPC4088dm, self).__init__(link, self.memoryMap)
