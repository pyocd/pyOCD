# Copyright (c) 2010 - 2023, Nordic Semiconductor ASA All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of Nordic Semiconductor ASA nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY, AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from ...core.memory_map import FlashRegion, RamRegion, MemoryMap
from ...debug.svd.loader import SVDFile
from ..family.target_nRF91 import NRF91, FLASH_ALGO_UICR

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0xf240b5b0, 0xf2c00504, 0x20000500, 0x0105eb09, 0x0005f849, 0x0001e9c1, 0xb2d060c8, 0xf0004614,
    0xb120fa3d, 0x0105eb09, 0x0402e9c1, 0xeb09bdb0, 0x21010005, 0xf0006041, 0x2000fa2b, 0xbf00bdb0,
    0x4604b510, 0xf0002000, 0xb138fa29, 0x0104f240, 0x0100f2c0, 0xe9c14449, 0xbd100402, 0x0004f240,
    0x0000f2c0, 0x0100eb09, 0x29006889, 0x2000bf04, 0xf244bd10, 0xf2c20100, 0x22010100, 0xf859600a,
    0x44482000, 0x6842604a, 0x6882608a, 0x68c060ca, 0x20006108, 0xbf00bd10, 0x0004f240, 0x0000f2c0,
    0xf8492101, 0x44481000, 0xe9c02100, 0x60c11101, 0xba28f000, 0xf240b5b0, 0x46040504, 0x0500f2c0,
    0xf8492002, 0xeb090005, 0x21000005, 0x1101e9c0, 0xf00060c1, 0xfbb4f9a5, 0xfb01f1f0, 0xb1304010,
    0x0005eb09, 0xe9c02103, 0x20651402, 0xeb09bdb0, 0x21010005, 0xf0006041, 0x42a0f9ad, 0xf000d813,
    0x42a0f9ab, 0xeb09d90f, 0x21020005, 0x46206041, 0xf9c2f000, 0xbf1c2803, 0xbdb02067, 0xf0004620,
    0x2000f9e7, 0xeb09bdb0, 0x21040005, 0x1402e9c0, 0xbdb02066, 0x41f0e92d, 0x0704f240, 0xf2c04604,
    0x46150700, 0x2003460e, 0x0107eb09, 0x07a32200, 0x0007f849, 0x2201e9c1, 0xd00660ca, 0x0107eb09,
    0x0402e9c1, 0xe8bd2065, 0xeb0981f0, 0x21010007, 0xf0006041, 0x42a0f96f, 0xf000d815, 0x42a0f96d,
    0xeb09d911, 0x21030007, 0xeb066041, 0xf0000804, 0x4580f963, 0xeb09d90f, 0x21040007, 0x1802e9c0,
    0xe8bd2066, 0xeb0981f0, 0x21040007, 0x1402e9c0, 0xe8bd2066, 0xeb0981f0, 0x21040007, 0xf0006041,
    0xb130f969, 0x0007eb09, 0x60812102, 0xe8bd2067, 0xeb0981f0, 0x21050007, 0x46206041, 0xf95cf000,
    0xd2072802, 0x0007eb09, 0xe9c02102, 0x20671402, 0x81f0e8bd, 0x22ffd10f, 0x46314620, 0xf836f000,
    0x2003b148, 0x0007f849, 0x0007eb09, 0x60412105, 0xe8bd2067, 0x200381f0, 0x0007f849, 0xebb02000,
    0xeb090f96, 0xf04f0107, 0x604a0206, 0xe8bdbf08, 0xea4f81f0, 0x26000896, 0x0026f854, 0xd10c3001,
    0x0026f855, 0x0026f844, 0xf942f000, 0x45463601, 0x0000f04f, 0xe8bdd3f0, 0xeb0981f0, 0x21050007,
    0xe9c019a2, 0x20681202, 0x81f0e8bd, 0x41f0e92d, 0x0704f240, 0x4604460d, 0x0700f2c0, 0x46162005,
    0x0007f849, 0x0007eb09, 0x07aa2100, 0x1101e9c0, 0xd00760c1, 0x0007eb09, 0xe9c02103, 0x20651502,
    0x81f0e8bd, 0x0007eb09, 0x60412102, 0xf8d2f000, 0xd81542a0, 0xf8d0f000, 0xd91142a0, 0x0007eb09,
    0x60412103, 0x0804eb05, 0xf8c6f000, 0xd90f4580, 0x0007eb09, 0xe9c02104, 0x20661802, 0x81f0e8bd,
    0x0007eb09, 0xe9c02104, 0x20661402, 0x81f0e8bd, 0x0007eb09, 0x2d002104, 0xbf046041, 0xe8bd2000,
    0x210081f0, 0xbf00e007, 0x42a93101, 0x0000f04f, 0xe8bdbf28, 0x5c6081f0, 0xd0f542b0, 0xeb091860,
    0x22050107, 0x2002e9c1, 0xe8bd2001, 0xbf0081f0, 0x41f0e92d, 0x0504f240, 0xf2c04604, 0x20040500,
    0x460f4690, 0x0005f849, 0x0005eb09, 0x07a22100, 0x1101e9c0, 0xd00860c1, 0x0005eb09, 0x26652103,
    0x1402e9c0, 0xe8bd4630, 0xeb0981f0, 0x21010005, 0xf0006041, 0x42a0f86f, 0xf000d812, 0x42a0f86d,
    0xeb09d90e, 0x21030005, 0x193e6041, 0xf864f000, 0xd90e4286, 0x0005eb09, 0xe9c02104, 0xe0041602,
    0x0005eb09, 0xe9c02104, 0x26661402, 0xe8bd4630, 0x210081f0, 0x0f97ebb1, 0x0005eb09, 0x0104f04f,
    0xd00b6041, 0x210008b8, 0xf8586822, 0x429a3021, 0x3101d10b, 0xf1044281, 0xd3f50404, 0x0005eb09,
    0x60412105, 0xe8bd4630, 0xeb0981f0, 0x21060005, 0x1402e9c0, 0xe8bd4620, 0x000081f0, 0x1030f240,
    0x00fff2c0, 0x31016801, 0x6800bf1c, 0xf6404770, 0xf2cf71e0, 0x78080100, 0xf3616849, 0x4770200b,
    0x2020f240, 0x00fff2c0, 0x31016801, 0x6800bf14, 0x5080f44f, 0xbf004770, 0x2024f240, 0x00fff2c0,
    0x31016801, 0x6800bf14, 0x7000f44f, 0xbf004770, 0x47702000, 0x47702000, 0xf7ffb510, 0x4604ffe1,
    0xffeaf7ff, 0xf004fb00, 0xbf00bd10, 0x42814401, 0x2001bf9c, 0xe0034770, 0xbf244288, 0x47702001,
    0x2b04f850, 0xbf1c3201, 0x47702000, 0xbf00e7f4, 0xbf004770, 0x47702000, 0x47702003, 0xbf842803,
    0x47702069, 0xb240b580, 0xf851a105, 0xf2490020, 0xf2c55104, 0x60080103, 0xf80af000, 0xbd802000,
    0x00000000, 0x00000002, 0x00000001, 0x00000000, 0x4000f249, 0x0003f2c5, 0x29006801, 0x4770d0fc,
    0x500cf249, 0x0003f2c5, 0x60012101, 0xbf00e7f0, 0x9000b081, 0xf04f9800, 0x600131ff, 0xe7e7b001,
    0x47702069, 0xf7ffb5b0, 0x4604ffa7, 0x2500b140, 0xf7ff4628, 0xf7ffffed, 0x4405ff83, 0xd3f742a5,
    0xbdb02000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000005,
    'pc_unInit': 0x20000045,
    'pc_program_page': 0x20000139,
    'pc_erase_sector': 0x200000b9,
    'pc_eraseAll': 0x2000009d,

    'static_base' : 0x20000000 + 0x00000004 + 0x00000524,
    'begin_stack' : 0x20003540,
    'end_stack' : 0x20002540,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x1000,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x20000540,
        0x20001540
    ],
    'min_program_length' : 0x1000,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x524,
    'rw_start': 0x528,
    'rw_size': 0x4,
    'zi_start': 0x52c,
    'zi_size': 0x10,

    # Flash information
    'flash_start': 0x0,
    'flash_size': 0x200000,
    'sector_sizes': (
        (0x0, 0x1000),
    )
}

class NRF91XX(NRF91):
    MEMORY_MAP = MemoryMap(
        FlashRegion(
            start=0x0,
            length=0x100000,
            blocksize=0x1000,
            is_boot_memory=True,
            algo=FLASH_ALGO,
        ),
        # User Information Configation Registers (UICR) as a flash region
        FlashRegion(
            start=0x00ff8000,
            length=0x1000,
            blocksize=0x1000,
            is_testable=False,
            is_erasable=False,
            algo=FLASH_ALGO_UICR,
        ),
        RamRegion(start=0x20000000, length=0x40000),
    )

    def __init__(self, session):
        super(NRF91XX, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("nrf9160.svd")
