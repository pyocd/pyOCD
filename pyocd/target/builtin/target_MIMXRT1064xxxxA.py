# pyOCD debugger
# Copyright (c) 2017 NXP
# Copyright (c) 2020 Arm Ltd
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

from ...core.memory_map import (FlashRegion, RomRegion, RamRegion, MemoryMap)
from ...debug.svd.loader import SVDFile
from ..family.target_imxrt import IMXRT

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x4770ba40, 0x4770ba40, 0x4770bac0, 0x4770bac0, 0x4855b51c, 0x48559000, 0x08498901, 0x81010049,
    0x890a4953, 0x00520852, 0x8802810a, 0x07522304, 0xda022a00, 0x439a8802, 0x88088002, 0xd5020740,
    0x43988808, 0x484c8008, 0x6041494a, 0x6081494b, 0x22806801, 0x22204391, 0x60014311, 0xf8a8f000,
    0x68014847, 0xd54503c9, 0x60014946, 0x29006801, 0x6b01dafc, 0x03122201, 0x63014391, 0x29006b01,
    0x4a42dafc, 0x60114940, 0x03092103, 0x69016101, 0xdafc2900, 0x22016901, 0x43910412, 0x4b3b6101,
    0x3b40493b, 0x493b6319, 0x610b2301, 0x4c3a694b, 0x00544023, 0x2405191b, 0x43230264, 0x698b614b,
    0x40234c36, 0x04a42403, 0x4c35191b, 0x618b4323, 0x4c3469cb, 0x24034023, 0x191b0764, 0x43234c32,
    0x680161cb, 0x60014391, 0x43916b01, 0x69016301, 0x61014391, 0x466a492d, 0x20014449, 0xf9d3f000,
    0xd1062800, 0x20014929, 0xf0004449, 0x2800f9b7, 0x2001d000, 0x2000bd1c, 0x49244770, 0x4449b510,
    0xf0002001, 0x2800f9ba, 0x2001d000, 0x2109bd10, 0x18420709, 0xb510491d, 0x041b2301, 0x20014449,
    0xf9b7f000, 0xd0002800, 0xbd102001, 0x46132109, 0x18420709, 0xb5104915, 0x20014449, 0xf994f000,
    0xd0002800, 0xbd102001, 0xc0000007, 0x400b8000, 0x400d0000, 0xd928c520, 0x400bc000, 0x0000ffff,
    0x400d8000, 0x00012018, 0x18131818, 0x400d8100, 0x0f1a2323, 0x400fc000, 0xfff8e0ff, 0x1ff3fcff,
    0xe0000100, 0x9c7fff80, 0x03800001, 0x00000008, 0x49d42001, 0x69c00540, 0x60084449, 0x4ad14770,
    0x6812444a, 0x68526992, 0x49ce4710, 0x68094449, 0x68896989, 0x4acb4708, 0x6812444a, 0x68d26992,
    0x49c84710, 0x68094449, 0x69096989, 0x4ac54708, 0x6812444a, 0x69526992, 0x49c24710, 0x68094449,
    0x69896989, 0x49bf4708, 0x68094449, 0x69c96989, 0x49bc4708, 0x68094449, 0x6a096989, 0x4bb94708,
    0x681b444b, 0x6a5b699b, 0x48b64718, 0x68004448, 0x6ac06980, 0x48b34700, 0x68004448, 0x6bc06980,
    0x49b04700, 0x68094449, 0x6c096989, 0x49ad4708, 0x68094449, 0x6c496989, 0x49aa4708, 0x68094449,
    0x6b096989, 0x48a74708, 0x68004448, 0x6b406980, 0x49a44700, 0x68094449, 0x6b896989, 0x48a14708,
    0x68004448, 0x6c806980, 0x489e4700, 0x68004448, 0x6cc06980, 0x499b4700, 0x68094449, 0x6a896989,
    0x4a984708, 0x6812444a, 0x32806992, 0x47106a52, 0x444a4a94, 0x69926812, 0x6b123280, 0x4a914710,
    0x6812444a, 0x32806992, 0x47106a92, 0x4448488d, 0x69806800, 0x6ac03080, 0x498a4700, 0x68094449,
    0x6d096989, 0x48874708, 0x68004448, 0x6d406980, 0x49844700, 0x68094449, 0x6d896989, 0x48814708,
    0x68004448, 0x6dc06980, 0x497e4700, 0x68094449, 0x6e096989, 0x487b4708, 0x68004448, 0x6e406980,
    0x49784700, 0x68094449, 0x6e896989, 0x48754708, 0x68004448, 0x6ec06980, 0x49724700, 0x68094449,
    0x6f096989, 0x486f4708, 0x68004448, 0x6f406980, 0x496c4700, 0x68094449, 0x6f896989, 0x48694708,
    0x68004448, 0x6fc06980, 0x49664700, 0x68094449, 0x31806989, 0x47086809, 0x44484862, 0x69806800,
    0x68403080, 0x495f4700, 0x68094449, 0x31806989, 0x47086889, 0x444a4a5b, 0x69926812, 0x68d23280,
    0x49584710, 0x68094449, 0x31806989, 0x47086909, 0x444a4a54, 0x69926812, 0x69523280, 0x49514710,
    0x68094449, 0x31806989, 0x47086989, 0x4449494d, 0x69896809, 0x69c93180, 0x494a4708, 0x68094449,
    0x31806989, 0x47086a09, 0x444a4a46, 0x69926812, 0x6b523280, 0x48434710, 0x68004448, 0x30806980,
    0x47006b80, 0x444a4a3f, 0x69d26812, 0x47106a12, 0x4449493c, 0x69c96809, 0x47086809, 0x444a4a39,
    0x69d26812, 0x47106852, 0x44494936, 0x69c96809, 0x47086889, 0x44494933, 0x6a096809, 0x47086809,
    0x444a4a30, 0x6a126812, 0x47106852, 0x4449492d, 0x6a096809, 0x47086889, 0x4449492a, 0x6a096809,
    0x47086989, 0x444a4a27, 0x6a126812, 0x471069d2, 0x44494924, 0x6a096809, 0x47086ac9, 0x444a4a21,
    0x69126812, 0x47106852, 0x4c1eb430, 0x6824444c, 0x68a46924, 0xbc3046a4, 0x4a1a4760, 0x6812444a,
    0x68d26912, 0x4b174710, 0x681b444b, 0x6a5b691b, 0xb4304718, 0x444c4c13, 0x69246824, 0x46a46924,
    0x4760bc30, 0x9c04b538, 0x4c0e9400, 0x6824444c, 0x69646924, 0xbd3847a0, 0x4c0ab430, 0x6824444c,
    0x6a246924, 0xbc3046a4, 0x4a064760, 0x6812444a, 0x69d26912, 0x49034710, 0x68094449, 0x69896909,
    0x00004708, 0x00000004, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000031,
    'pc_unInit': 0x20000137,
    'pc_program_page': 0x2000016d,
    'pc_erase_sector': 0x2000014f,
    'pc_eraseAll': 0x2000013b,

    'static_base' : 0x00000000 + 0x00000020 + 0x00000508,
    'begin_stack' : 0x20000800,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20001100],   # Enable double buffering
    'min_program_length' : 0x100
}


class MIMXRT1064xxxxA(IMXRT):

    VENDOR = "NXP"

    # Note: itcm, dtcm, and ocram share a single 512 KB block of RAM that can be configurably
    # divided between those regions (this is called FlexRAM). Thus, the memory map regions for
    # each of these RAMs allocate the maximum possible of 512 KB, but that is the maximum and
    # will not actually be available in all regions simultaneously.
    memoryMap = MemoryMap(
        RamRegion(name="itcm",      start=0x00000000, length=0x80000), # 512 KB
        RomRegion(name="romcp",     start=0x00200000, length=0x20000),
        RamRegion(name="dtcm",      start=0x20000000, length=0x80000), # 512 KB
        RamRegion(name="ocram",     start=0x20200000, length=0x80000), # 512 KB
        FlashRegion(name="flexspi", start=0x70000000, length=0x400000, blocksize=0x10000, is_boot_memory=True,
            algo=FLASH_ALGO, page_size=0x100),
        RamRegion(name="semc",      start=0x80000000, length=0x1e00000, is_external=True), # external sdram
    )

    def __init__(self, link):
        super(MIMXRT1064xxxxA, self).__init__(link, self.memoryMap)
        self._svd_location = SVDFile.from_builtin("MIMXRT1064.xml")