# pyOCD debugger
# Copyright (c) 2026 NXP
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

import logging

from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RomRegion, RamRegion, MemoryMap)
from ...debug.svd.loader import SVDFile
from ...coresight.ap import AccessPort, APv1Address
from ...coresight.cortex_m import CortexM
from ...core.target import Target
from pyocd.flash.flash import Flash
from pyocd.core.options import add_option_set, OptionInfo
import time

LOG = logging.getLogger(__name__)

# Register custom option 'vtor' properly
add_option_set({
    OptionInfo("vtor", str, None, "Manual VTOR address override")
})

AP_SEL = 3

SRC_M7MIX_SLICE_SW_CTRL = 0x54464820
SRC_M7MIX_SLICE_SW_CTRL_RSTR_0_MASK = 0x100000

SRC_M7MIX_SLICE_RSTR_STAT = 0x544648B8
SRC_M7MIX_SLICE_RSTR_STAT_RSTR_0_MASK = 0x1

FLASH_ALGO_CM7 = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0xf644b081, 0xf2c40120, 0x68084146, 0x98009000, 0x1080f440, 0x98009000, 0xb0016008, 0xbf004770,
    0xf644b081, 0xf2c40120, 0x68084146, 0x98009000, 0x1080f420, 0x98009000, 0xb0016008, 0xbf004770,
    0xb090b580, 0x910c900d, 0x2000920b, 0xf3ef900a, 0xb6728010, 0x980b900f, 0xd1092803, 0x2100e7ff,
    0x215ef2c4, 0x1012f243, 0x70fff6cf, 0xe0086008, 0xf2c42100, 0xf243215e, 0xf6cf0032, 0x600870ff,
    0x2104e7ff, 0x215ef2c4, 0x30fff04f, 0x21086008, 0x215ef2c4, 0x10f7f244, 0x0000f2c2, 0x210c6008,
    0x215ef2c4, 0x60082038, 0xf2c42120, 0x2000215e, 0x000ff2c8, 0x21246008, 0x215ef2c4, 0x21286008,
    0x215ef2c4, 0x212c6008, 0x215ef2c4, 0x21306008, 0x215ef2c4, 0x21346008, 0x215ef2c4, 0x21386008,
    0x215ef2c4, 0x213c6008, 0x215ef2c4, 0xf2c82080, 0x60080000, 0xf2c42160, 0xf44f215e, 0x60083000,
    0xf2c42164, 0x2000215e, 0x21686008, 0x215ef2c4, 0x216c6008, 0x215ef2c4, 0x22706008, 0x225ef2c4,
    0xf2c02163, 0x60110102, 0xf2c42274, 0x2163225e, 0x22786011, 0x225ef2c4, 0x227c6011, 0x225ef2c4,
    0x22806011, 0x225ef2c4, 0x6110f44f, 0x21846011, 0x215ef2c4, 0x21886008, 0x215ef2c4, 0x218c6008,
    0x215ef2c4, 0x21946008, 0x215ef2c4, 0x600820c3, 0x2803980b, 0xe7ffd103, 0xfa0ef000, 0x21c0e009,
    0x215ef2c4, 0x60082079, 0xf2c421c4, 0x6008215e, 0x2100e7ff, 0x215ef2c4, 0x68089101, 0x0002f020,
    0xf0006008, 0x9901f81d, 0xf0406808, 0x60080001, 0x2000e7ff, 0x205ef2c4, 0x07c06800, 0xe7ffb108,
    0xf000e7f7, 0x900af845, 0xb118980a, 0x980ae7ff, 0xe002900e, 0x900e980a, 0x980ee7ff, 0xbd80b010,
    0x2118b081, 0x215ef2c4, 0x20f0f645, 0x20f0f6c5, 0x211c6008, 0x215ef2c4, 0x60082002, 0x90002000,
    0x9800e7ff, 0xd813283b, 0x9a00e7ff, 0x40e0f240, 0x0000f2c0, 0xf8504478, 0xf2400022, 0xf2c42100,
    0xf841215e, 0xe7ff0022, 0x30019800, 0xe7e89000, 0xf2c42118, 0xf645215e, 0xf6c520f0, 0x600820f0,
    0xf2c4211c, 0x2001215e, 0xb0016008, 0xbf004770, 0xb084b580, 0x93012300, 0x90002002, 0x461a4619,
    0xf84ef000, 0x98029002, 0xe7ffb118, 0x90039802, 0x2008e019, 0x466a2100, 0xf0002301, 0x9002f841,
    0xb1189802, 0x9802e7ff, 0xe00c9003, 0xf0002001, 0x9002f8f7, 0xb1189802, 0x9802e7ff, 0xe0029003,
    0x90039802, 0x9803e7ff, 0xbd80b004, 0xbf00bf00, 0x9000b081, 0xb0012000, 0xbf004770, 0xbf00bf00,
    0xb082b580, 0x93002300, 0x46192004, 0xf000461a, 0x9000f817, 0xb1189800, 0x9800e7ff, 0xe0099001,
    0x2300200b, 0x461a4619, 0xf80af000, 0x98009000, 0xe7ff9001, 0xb0029801, 0xbf00bd80, 0xbf00bf00,
    0x9007b088, 0x92059106, 0x3012f8ad, 0x90032000, 0xf2c42180, 0x6808215e, 0x4000f040, 0x21146008,
    0x215ef2c4, 0x703ff640, 0x98066008, 0xf2c421a0, 0x6008215e, 0xf8bd9907, 0xea400012, 0x21a44001,
    0x215ef2c4, 0x21bc6008, 0x215ef2c4, 0x60082001, 0xf2c421b0, 0x6008215e, 0xf8bde7ff, 0xb3d00012,
    0xf8bde7ff, 0x28070012, 0xe7ffd804, 0x0012f8bd, 0xe0029000, 0x90002008, 0x9800e7ff, 0xf2409001,
    0xf2c41080, 0x9002205e, 0x2014e7ff, 0x205ef2c4, 0x06406800, 0xd4012800, 0xe7f6e7ff, 0xf1019905,
    0x90050008, 0x68496808, 0xe9c29a02, 0x20140100, 0x205ef2c4, 0x60012140, 0xf8bd9a01, 0x1a891012,
    0x1012f8ad, 0xf0106800, 0xd0030f0a, 0x2001e7ff, 0xe0009003, 0xe7ffe7c1, 0xf2c420e0, 0x6800205e,
    0x28000780, 0xe7ffd401, 0x2014e7f6, 0x205ef2c4, 0xf0106800, 0xd0030f0a, 0x2001e7ff, 0xe7ff9003,
    0xb0089803, 0xbf004770, 0xb084b580, 0x98029002, 0x4058f100, 0x23009001, 0x20049300, 0x461a4619,
    0xff6ef7ff, 0x98009000, 0xe7ffb118, 0x90039800, 0x9901e023, 0x23002005, 0xf7ff461a, 0x9000ff61,
    0xb1189800, 0x9800e7ff, 0xe0169003, 0xf0002001, 0x9000f817, 0xf2c42100, 0x6808215e, 0x0001f040,
    0xe7ff6008, 0xf2c42000, 0x6800205e, 0xb10807c0, 0xe7f7e7ff, 0x90039800, 0x9803e7ff, 0xbd80b004,
    0xb086b580, 0x0013f88d, 0x0013f89d, 0x200107c1, 0xbf182900, 0x9000200a, 0x9800e7ff, 0xaa022100,
    0xf0002301, 0x9001f8a5, 0xb1189801, 0x9801e7ff, 0xe0169005, 0x0008f89d, 0xb12007c0, 0x2001e7ff,
    0x0012f88d, 0x2000e003, 0x0012f88d, 0xe7ffe7ff, 0x0012f89d, 0x280007c0, 0xe7ffd1df, 0x90059801,
    0x9805e7ff, 0xbd80b006, 0xb088b580, 0x91059006, 0x98069204, 0x4058f100, 0x23009003, 0xf44f9302,
    0x90017080, 0x46192004, 0xf7ff461a, 0x9002fef9, 0xb1189802, 0x9802e7ff, 0xe03a9007, 0x90002000,
    0x9800e7ff, 0x42889905, 0xe7ffd230, 0x9a049903, 0x3004f8bd, 0xf7ff2007, 0x9002fee3, 0xb1189802,
    0x9802e7ff, 0xe0249007, 0xf7ff2001, 0x9002ff99, 0xf2c42100, 0x6808215e, 0x0001f040, 0xe7ff6008,
    0xf2c42000, 0x6800205e, 0xb10807c0, 0xe7f7e7ff, 0x9901e7ff, 0x44089800, 0x99019000, 0x44089804,
    0x99019004, 0x44089803, 0xe7ca9003, 0x90079802, 0x9807e7ff, 0xbd80b008, 0x23c0b081, 0x235ef2c4,
    0x60182002, 0xf2c422c4, 0x6010225e, 0x60182000, 0x21796010, 0x60116019, 0xe7ff9000, 0xf2489800,
    0xf2c0619f, 0x42880101, 0xe7ffdc10, 0xf2c420e8, 0x6800205e, 0x1003f000, 0x1f03f1b0, 0xe7ffd101,
    0xe7ffe004, 0x30019800, 0xe7e79000, 0x4770b001, 0x9007b088, 0x92059106, 0x3012f8ad, 0x90032000,
    0xf2c42180, 0xf640215e, 0xf2c81000, 0x60080000, 0xf2c42114, 0xf640215e, 0x6008703f, 0x21a09806,
    0x215ef2c4, 0x99076008, 0x0012f8bd, 0x4001ea40, 0xf2c421a4, 0x6008215e, 0xf2c421b8, 0x2001215e,
    0x21b06008, 0x215ef2c4, 0xe7ff6008, 0x0012f8bd, 0xe7ffb3d0, 0x0012f8bd, 0xd8042807, 0xf8bde7ff,
    0x90000012, 0x2008e002, 0xe7ff9000, 0x90019800, 0x1000f240, 0x205ef2c4, 0xe7ff9002, 0xf2c42014,
    0x6800205e, 0x28000680, 0xe7ffd401, 0x9802e7f6, 0x0200e9d0, 0xf1019905, 0x93050308, 0x6008604a,
    0xf2c42014, 0x2120205e, 0x9a016001, 0x1012f8bd, 0xf8ad1a89, 0x68001012, 0x0f0af010, 0xe7ffd003,
    0x90032001, 0xe7c1e000, 0x20e0e7ff, 0x205ef2c4, 0x07806800, 0xd4012800, 0xe7f6e7ff, 0xf2c42014,
    0x6800205e, 0x0f0af010, 0xe7ffd003, 0x90032001, 0x9803e7ff, 0x4770b008, 0x871187ee, 0xb3288b20,
    0x0000a704, 0x00000000, 0x24040405, 0x00000000, 0x00000000, 0x00000000, 0x00000406, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x87f98706, 0x00000000,
    0x00000000, 0x00000000, 0x87de8721, 0x00008b20, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x87ed8712, 0xa3048b20, 0x00000000, 0x00000000, 0x04000472, 0x04000400,
    0x20010400, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x87fa8705, 0xb3048b20,
    0x0000a704, 0x00000000, 0x8b2007c4, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x000007b7, 0x00000000, 0x00000000, 0x00000000, 0xa7010770, 0x00000000,
    0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000045,
    'pc_unInit': 0x200002b5,
    'pc_program_page': 0x200004ed,
    'pc_erase_sector': 0x2000040d,
    'pc_eraseAll': 0x200002c5,

    'static_base' : 0x20000000 + 0x00000004 + 0x000007e8,
    'begin_stack' : 0x200019f0,
    'end_stack' : 0x200009f0,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x200007f0,
        0x200008f0
    ],
    'min_program_length' : 0x100,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x7e8,
    'rw_start': 0x7ec,
    'rw_size': 0x4,
    'zi_start': 0x7f0,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x28000000,
    'flash_size': 0x4000000,
    'sector_sizes': (
        (0x0, 0x1000),
    )
}


FLASH_ALGO_CM33 = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0xf644b081, 0xf2c40120, 0x68084146, 0x98009000, 0x1080f440, 0x98009000, 0xb0016008, 0xbf004770,
    0xf644b081, 0xf2c40120, 0x68084146, 0x98009000, 0x1080f420, 0x98009000, 0xb0016008, 0xbf004770,
    0xb092b580, 0x910e900f, 0x2000920d, 0x900c9001, 0x8110f3ef, 0x9111b672, 0xf2c52200, 0xf242422e,
    0x60115122, 0x5194f64e, 0x0100f2ce, 0xf7ff6008, 0x9801ffc7, 0x1194f240, 0x413cf2c4, 0xf2406008,
    0xf2c441f4, 0x2201413c, 0x600a9202, 0x3398f240, 0x433cf2c4, 0x6019217e, 0x1398f240, 0x433cf2c4,
    0xf2406018, 0xf2c43c9c, 0xf2404c3c, 0xf8cc33fe, 0xf2403000, 0xf2c41c9c, 0xf8cc4c3c, 0xf2400000,
    0xf2c43ca0, 0xf8cc4c3c, 0xf2403000, 0xf2c41390, 0x6018433c, 0x43d0f240, 0x433cf2c4, 0xf240601a,
    0xf2c43394, 0x6019433c, 0x1170f240, 0x413cf2c4, 0xf2406008, 0xf2c441d4, 0x600a413c, 0x3374f240,
    0x433cf2c4, 0x91032102, 0xf2406019, 0xf2c41374, 0x6018433c, 0x43d8f240, 0x433cf2c4, 0xf240601a,
    0xf2c43378, 0x6019433c, 0x1378f240, 0x433cf2c4, 0xf2406018, 0xf2c443dc, 0x601a433c, 0x337cf240,
    0x433cf2c4, 0xf2406019, 0xf2c4137c, 0x6018433c, 0x43e0f240, 0x433cf2c4, 0xf240601a, 0xf2c43380,
    0x6019433c, 0x1380f240, 0x433cf2c4, 0xf2406018, 0xf2c443e4, 0x601a433c, 0x3384f240, 0x433cf2c4,
    0xf2406019, 0xf2c41384, 0x6018433c, 0x43e8f240, 0x433cf2c4, 0xf240601a, 0xf2c43388, 0x6019433c,
    0x1388f240, 0x433cf2c4, 0xf2406018, 0xf2c443ec, 0x601a433c, 0x338cf240, 0x433cf2c4, 0xf2406019,
    0xf2c4138c, 0x6018433c, 0x43f0f240, 0x433cf2c4, 0xf240601a, 0xf2c43290, 0x6011423c, 0xf2c42100,
    0x60084140, 0x0100f640, 0x4140f2c4, 0xf6426008, 0xf2c42180, 0xf2404145, 0x60082003, 0xf6c221e4,
    0xf04f0103, 0x60084010, 0x2803980d, 0xe7ffd109, 0xf2c42100, 0xf243215e, 0xf6cf1012, 0x600870ff,
    0x2100e008, 0x215ef2c4, 0x0032f243, 0x70fff6cf, 0xe7ff6008, 0xf2c42104, 0xf04f215e, 0x600830ff,
    0xf2c42108, 0xf244215e, 0xf2c210f7, 0x60080000, 0xf2c4210c, 0x2038215e, 0x21206008, 0x215ef2c4,
    0xf2c82000, 0x6008000f, 0xf2c42124, 0x6008215e, 0xf2c42128, 0x6008215e, 0xf2c4212c, 0x6008215e,
    0xf2c42130, 0x6008215e, 0xf2c42134, 0x6008215e, 0xf2c42138, 0x6008215e, 0xf2c4213c, 0x2080215e,
    0x0000f2c8, 0x21606008, 0x215ef2c4, 0x3000f44f, 0x21646008, 0x215ef2c4, 0x60082000, 0xf2c42168,
    0x6008215e, 0xf2c4216c, 0x6008215e, 0xf2c42270, 0x2163225e, 0x0102f2c0, 0x22746011, 0x225ef2c4,
    0x60112163, 0xf2c42278, 0x6011225e, 0xf2c4227c, 0x6011225e, 0xf2c42280, 0xf44f225e, 0x60116110,
    0xf2c42184, 0x6008215e, 0xf2c42188, 0x6008215e, 0xf2c4218c, 0x6008215e, 0xf2c42194, 0x20c3215e,
    0x980d6008, 0xd1032803, 0xf000e7ff, 0xe009fa11, 0xf2c421c0, 0x2079215e, 0x21c46008, 0x215ef2c4,
    0xe7ff6008, 0xf2c42100, 0x9100215e, 0xf0206808, 0x60080002, 0xf820f000, 0x68089900, 0x0001f040,
    0xe7ff6008, 0xf2c42000, 0x6800205e, 0xb10807c0, 0xe7f7e7ff, 0xf848f000, 0x980c900c, 0xe7ffb118,
    0x9010980c, 0x980ce002, 0xe7ff9010, 0xb0129810, 0xbf00bd80, 0xbf00bf00, 0x2118b081, 0x215ef2c4,
    0x20f0f645, 0x20f0f6c5, 0x211c6008, 0x215ef2c4, 0x60082002, 0x90002000, 0x9800e7ff, 0xd813283b,
    0x9a00e7ff, 0x40e0f240, 0x0000f2c0, 0xf8504478, 0xf2400022, 0xf2c42100, 0xf841215e, 0xe7ff0022,
    0x30019800, 0xe7e89000, 0xf2c42118, 0xf645215e, 0xf6c520f0, 0x600820f0, 0xf2c4211c, 0x2001215e,
    0xb0016008, 0xbf004770, 0xb084b580, 0x93012300, 0x90002002, 0x461a4619, 0xf84ef000, 0x98029002,
    0xe7ffb118, 0x90039802, 0x2008e019, 0x466a2100, 0xf0002301, 0x9002f841, 0xb1189802, 0x9802e7ff,
    0xe00c9003, 0xf0002001, 0x9002f8f7, 0xb1189802, 0x9802e7ff, 0xe0029003, 0x90039802, 0x9803e7ff,
    0xbd80b004, 0xbf00bf00, 0x9000b081, 0xb0012000, 0xbf004770, 0xbf00bf00, 0xb082b580, 0x93002300,
    0x46192004, 0xf000461a, 0x9000f817, 0xb1189800, 0x9800e7ff, 0xe0099001, 0x2300200b, 0x461a4619,
    0xf80af000, 0x98009000, 0xe7ff9001, 0xb0029801, 0xbf00bd80, 0xbf00bf00, 0x9007b088, 0x92059106,
    0x3012f8ad, 0x90032000, 0xf2c42180, 0x6808215e, 0x4000f040, 0x21146008, 0x215ef2c4, 0x703ff640,
    0x98066008, 0xf2c421a0, 0x6008215e, 0xf8bd9907, 0xea400012, 0x21a44001, 0x215ef2c4, 0x21bc6008,
    0x215ef2c4, 0x60082001, 0xf2c421b0, 0x6008215e, 0xf8bde7ff, 0xb3d00012, 0xf8bde7ff, 0x28070012,
    0xe7ffd804, 0x0012f8bd, 0xe0029000, 0x90002008, 0x9800e7ff, 0xf2409001, 0xf2c41080, 0x9002205e,
    0x2014e7ff, 0x205ef2c4, 0x06406800, 0xd4012800, 0xe7f6e7ff, 0xf1019905, 0x90050008, 0x68496808,
    0xe9c29a02, 0x20140100, 0x205ef2c4, 0x60012140, 0xf8bd9a01, 0x1a891012, 0x1012f8ad, 0xf0106800,
    0xd0030f0a, 0x2001e7ff, 0xe0009003, 0xe7ffe7c1, 0xf2c420e0, 0x6800205e, 0x28000780, 0xe7ffd401,
    0x2014e7f6, 0x205ef2c4, 0xf0106800, 0xd0030f0a, 0x2001e7ff, 0xe7ff9003, 0xb0089803, 0xbf004770,
    0xb084b580, 0x98029002, 0x4058f100, 0x23009001, 0x20049300, 0x461a4619, 0xff6ef7ff, 0x98009000,
    0xe7ffb118, 0x90039800, 0x9901e023, 0x23002005, 0xf7ff461a, 0x9000ff61, 0xb1189800, 0x9800e7ff,
    0xe0169003, 0xf0002001, 0x9000f817, 0xf2c42100, 0x6808215e, 0x0001f040, 0xe7ff6008, 0xf2c42000,
    0x6800205e, 0xb10807c0, 0xe7f7e7ff, 0x90039800, 0x9803e7ff, 0xbd80b004, 0xb086b580, 0x0013f88d,
    0x0013f89d, 0x200107c1, 0xbf182900, 0x9000200a, 0x9800e7ff, 0xaa022100, 0xf0002301, 0x9001f8a5,
    0xb1189801, 0x9801e7ff, 0xe0169005, 0x0008f89d, 0xb12007c0, 0x2001e7ff, 0x0012f88d, 0x2000e003,
    0x0012f88d, 0xe7ffe7ff, 0x0012f89d, 0x280007c0, 0xe7ffd1df, 0x90059801, 0x9805e7ff, 0xbd80b006,
    0xb088b580, 0x91059006, 0x98069204, 0x4058f100, 0x23009003, 0xf44f9302, 0x90017080, 0x46192004,
    0xf7ff461a, 0x9002fef9, 0xb1189802, 0x9802e7ff, 0xe03a9007, 0x90002000, 0x9800e7ff, 0x42889905,
    0xe7ffd230, 0x9a049903, 0x3004f8bd, 0xf7ff2007, 0x9002fee3, 0xb1189802, 0x9802e7ff, 0xe0249007,
    0xf7ff2001, 0x9002ff99, 0xf2c42100, 0x6808215e, 0x0001f040, 0xe7ff6008, 0xf2c42000, 0x6800205e,
    0xb10807c0, 0xe7f7e7ff, 0x9901e7ff, 0x44089800, 0x99019000, 0x44089804, 0x99019004, 0x44089803,
    0xe7ca9003, 0x90079802, 0x9807e7ff, 0xbd80b008, 0x23c0b081, 0x235ef2c4, 0x60182002, 0xf2c422c4,
    0x6010225e, 0x60182000, 0x21796010, 0x60116019, 0xe7ff9000, 0xf2489800, 0xf2c0619f, 0x42880101,
    0xe7ffdc10, 0xf2c420e8, 0x6800205e, 0x1003f000, 0x1f03f1b0, 0xe7ffd101, 0xe7ffe004, 0x30019800,
    0xe7e79000, 0x4770b001, 0x9007b088, 0x92059106, 0x3012f8ad, 0x90032000, 0xf2c42180, 0xf640215e,
    0xf2c81000, 0x60080000, 0xf2c42114, 0xf640215e, 0x6008703f, 0x21a09806, 0x215ef2c4, 0x99076008,
    0x0012f8bd, 0x4001ea40, 0xf2c421a4, 0x6008215e, 0xf2c421b8, 0x2001215e, 0x21b06008, 0x215ef2c4,
    0xe7ff6008, 0x0012f8bd, 0xe7ffb3d0, 0x0012f8bd, 0xd8042807, 0xf8bde7ff, 0x90000012, 0x2008e002,
    0xe7ff9000, 0x90019800, 0x1000f240, 0x205ef2c4, 0xe7ff9002, 0xf2c42014, 0x6800205e, 0x28000680,
    0xe7ffd401, 0x9802e7f6, 0x0200e9d0, 0xf1019905, 0x93050308, 0x6008604a, 0xf2c42014, 0x2120205e,
    0x9a016001, 0x1012f8bd, 0xf8ad1a89, 0x68001012, 0x0f0af010, 0xe7ffd003, 0x90032001, 0xe7c1e000,
    0x20e0e7ff, 0x205ef2c4, 0x07806800, 0xd4012800, 0xe7f6e7ff, 0xf2c42014, 0x6800205e, 0x0f0af010,
    0xe7ffd003, 0x90032001, 0x9803e7ff, 0x4770b008, 0x871187ee, 0xb3288b20, 0x0000a704, 0x00000000,
    0x24040405, 0x00000000, 0x00000000, 0x00000000, 0x00000406, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x87f98706, 0x00000000, 0x00000000, 0x00000000,
    0x87de8721, 0x00008b20, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x87ed8712, 0xa3048b20, 0x00000000, 0x00000000, 0x04000472, 0x04000400, 0x20010400, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x87fa8705, 0xb3048b20, 0x0000a704, 0x00000000,
    0x8b2007c4, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x000007b7, 0x00000000, 0x00000000, 0x00000000, 0xa7010770, 0x00000000, 0x00000000, 0x00000000,
    0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000045,
    'pc_unInit': 0x2000046d,
    'pc_program_page': 0x200006a5,
    'pc_erase_sector': 0x200005c5,
    'pc_eraseAll': 0x2000047d,

    'static_base' : 0x20000000 + 0x00000004 + 0x000009a0,
    'begin_stack' : 0x20001bb0,
    'end_stack' : 0x20000bb0,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x100,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x200009b0,
        0x20000ab0
    ],
    'min_program_length' : 0x100,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x9a0,
    'rw_start': 0x9a4,
    'rw_size': 0x4,
    'zi_start': 0x9a8,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x28000000,
    'flash_size': 0x4000000,
    'sector_sizes': (
        (0x0, 0x1000),
    )
}

class FlexSpiFlash(Flash):

    def init(self, operation, address=None, clock=0, reset=True):
        LOG.debug(f"FlexSPI Init {self.target.ap3}")
        super().init(operation, address, clock, reset)

        # IOMUXC_PAD_XSPI1_SCLK__FLEXSPI1_A_SCLK
        self.target.ap3.write32(0x443C0194, 0x0)
        self.target.ap3.write32(0x443C04F4, 0x1)
        self.target.ap3.write32(0x443C0398, 0x7E)

        # IOMUXC_PAD_XSPI1_SS0_B__FLEXSPI1_A_SS0_B
        self.target.ap3.write32(0x443C0198, 0x0)
        self.target.ap3.write32(0x443C039C, 0x3fe)

        # IOMUXC_PAD_XSPI1_SS1_B__FLEXSPI1_A_SS1_B
        self.target.ap3.write32(0x443C019C, 0x0)
        self.target.ap3.write32(0x443C03A0, 0x3fe)

        # IOMUXC_PAD_XSPI1_DQS__FLEXSPI1_A_DQS
        self.target.ap3.write32(0x443C0190, 0x0)
        self.target.ap3.write32(0x443C04D0, 0x1)
        self.target.ap3.write32(0x443C0394, 0x7E)

        # IOMUXC_PAD_XSPI1_DATA0__FLEXSPI1_A_DATA_BIT0
        self.target.ap3.write32(0x443C0170, 0x0)
        self.target.ap3.write32(0x443C04D4, 0x1)
        self.target.ap3.write32(0x443C0374, 0x002)

        # IOMUXC_PAD_XSPI1_DATA1__FLEXSPI1_A_DATA_BIT1
        self.target.ap3.write32(0x443C0174, 0x0)
        self.target.ap3.write32(0x443C04D8, 0x1)
        self.target.ap3.write32(0x443C0378, 0x002)

        # IOMUXC_PAD_XSPI1_DATA2__FLEXSPI1_A_DATA_BIT2
        self.target.ap3.write32(0x443C0178, 0x0)
        self.target.ap3.write32(0x443C04DC, 0x1)
        self.target.ap3.write32(0x443C037C, 0x002)

        # IOMUXC_PAD_XSPI1_DATA3__FLEXSPI1_A_DATA_BIT3
        self.target.ap3.write32(0x443C017C, 0x0)
        self.target.ap3.write32(0x443C04E0, 0x1)
        self.target.ap3.write32(0x443C0380, 0x002)

        # IOMUXC_PAD_XSPI1_DATA4__FLEXSPI1_A_DATA_BIT4
        self.target.ap3.write32(0x443C0180, 0x0)
        self.target.ap3.write32(0x443C04E4, 0x1)
        self.target.ap3.write32(0x443C0384, 0x002)

        # IOMUXC_PAD_XSPI1_DATA5__FLEXSPI1_A_DATA_BIT5
        self.target.ap3.write32(0x443C0184, 0x0)
        self.target.ap3.write32(0x443C04E8, 0x1)
        self.target.ap3.write32(0x443C0388, 0x002)

        # IOMUXC_PAD_XSPI1_DATA6__FLEXSPI1_A_DATA_BIT6
        self.target.ap3.write32(0x443C0188, 0x0)
        self.target.ap3.write32(0x443C04EC, 0x1)
        self.target.ap3.write32(0x443C038C, 0x002)

        # IOMUXC_PAD_XSPI1_DATA7__FLEXSPI1_A_DATA_BIT7
        self.target.ap3.write32(0x443C018C, 0x0)
        self.target.ap3.write32(0x443C04F0, 0x1)
        self.target.ap3.write32(0x443C0390, 0x002)

        # Disable cache
        self.target.ap3.write32(0x44400000, 0x0)
        self.target.ap3.write32(0x44400800, 0x0)

        # Set FlexSPI0 clock to 200MHz
        self.target.ap3.write32(0x44452A80, 0x203)

        # Reset FlexSPI0 
        self.target.ap3.write32(0x280300E4, 0x90000000)

class MyCortexM(CortexM):
    def reset(self, reset_type=None):
        self.target.reset(reset_type)

    def reset_and_halt(self, reset_type=None):
        self.target.reset_and_halt(reset_type)

    def set_target(self, target):
        self.target = target


class MIMX95_CM7(CoreSightTarget):
    VENDOR = "NXP"

    # Note: itcm, dtcm share a single 512 KB block of RAM that can be configurably
    # divided between those regions (this is called FlexRAM). Thus, the memory map regions for
    # each of these RAMs allocate the maximum possible of 512 KB, but that is the maximum and
    # will not actually be available in all regions simultaneously.
    memoryMap = MemoryMap(
        RamRegion(name="itcm",              start=0x00000000, length=0x80000, is_boot_memory=True), # 512 KB
        RomRegion(name="romcp",             start=0x00100000, length=0x40000), # 256 KB
        RamRegion(name="dtcm",              start=0x20000000, length=0x80000), # 512 KB
        RamRegion(name="ocram",             start=0x20480000, length=0x58000), # 352 KB
        RamRegion(name="aips",              start=0x40000000, length=0x10000000),
        RamRegion(name="ddr",              start=0x80000000, end=0xdfffffff, is_external=True)
        )

    def __init__(self, session):
        self.AP_NUM = 0
        super(MIMX95_CM7, self).__init__(session, self.memoryMap)

    def power_up_m7mix(self):
        self._discoverer._create_1_ap(3)
        self.ap3 = self.dp.aps[3]  # CM33 MEM‑AP
        self.ap3.write32(SRC_M7MIX_SLICE_SW_CTRL, 0x00000000)
        self._discoverer._create_1_ap(2)
        self.ap2 = self.dp.aps[2]  # CM7 MEM‑AP

        cpu_sleep_hold = self.ap2.read32(0x4447080c)
        self.ap2.write32(0x4447080c, cpu_sleep_hold & ~(1 << 1))

    def create_init_sequence(self):
        seq = super(MIMX95_CM7, self).create_init_sequence()
        seq.insert_before('discovery', ('power_up_m7mix', self.power_up_m7mix))
        seq.wrap_task('discovery',
            lambda seq: seq.replace_task('find_aps', self.find_aps),
            )
        seq.wrap_task('discovery',
            lambda seq: seq.replace_task('create_cores', self.create_cores)
            )
        return seq

    def reset_and_halt(self, reset_type=None, map_to_user=True):
        self.reset(reset_type)
        self.halt()
        
        self._discoverer._create_1_ap(2)
        self.ap2 = self.dp.aps[2]  # CM7 MEM‑AP
        self.create_cores()

    def reset(self, reset_type=None):
        self.vtor_entry  = int(self.session.options.get("vtor"), 0) if self.session.options.get("vtor") else self.ap2.read32(0xE000ED08)

        LOG.debug(f"TYPE = {reset_type}")
        self.ap3.write32(0x544F0108, self.vtor_entry)
        val = self.ap3.read32(0x544F0108)
        LOG.debug(f"ENTRY = 0x{val:08X}")
        
        rb = self.ap3.read32(SRC_M7MIX_SLICE_SW_CTRL)
        val = self.ap3.read32(SRC_M7MIX_SLICE_RSTR_STAT)
        LOG.debug(f"SRC_M7MIX_SLICE_RSTR_STAT = 0x{val:08X} RB = 0x{rb:08X}")

        rb = self.ap3.read32(SRC_M7MIX_SLICE_SW_CTRL)
        self.ap3.write32(SRC_M7MIX_SLICE_SW_CTRL, rb | SRC_M7MIX_SLICE_SW_CTRL_RSTR_0_MASK)
        time.sleep(4 / 1000.0)
        val = self.ap3.read32(SRC_M7MIX_SLICE_RSTR_STAT)
        LOG.debug(f"SRC_M7MIX_SLICE_RSTR_STAT = 0x{val:08X} RB = 0x{rb:08X}")

        rb = self.ap3.read32(SRC_M7MIX_SLICE_SW_CTRL)
        self.ap3.write32(SRC_M7MIX_SLICE_SW_CTRL, rb & ~SRC_M7MIX_SLICE_SW_CTRL_RSTR_0_MASK)

        val = self.ap3.read32(SRC_M7MIX_SLICE_RSTR_STAT)
        LOG.debug(f"SRC_M7MIX_SLICE_RSTR_STAT = 0x{val:08X} RB = 0x{rb:08X}")

    def find_aps(self):
        if self.dp.valid_aps is not None:
            return
        self.dp.read_ap(0xFC)
        self.dp.valid_aps = [2]
        ap = AccessPort.create(self.dp, APv1Address(0))

    def create_cores(self):
        core0 = MyCortexM(self.session, self.aps[2], self.memory_map, 0)
        core0.default_reset_type = self.ResetType.DEFAULT
        core0.set_target(self)

        self.aps[2].core = core0

        core0.init()

        self.add_core(core0)

class MIMX95_CM7_MX25UM(MIMX95_CM7):
    VENDOR = "NXP"

    # Note: itcm, dtcm share a single 512 KB block of RAM that can be configurably
    # divided between those regions (this is called FlexRAM). Thus, the memory map regions for
    # each of these RAMs allocate the maximum possible of 512 KB, but that is the maximum and
    # will not actually be available in all regions simultaneously.
    memoryMap = MemoryMap(
        RamRegion(name="itcm",              start=0x00000000, length=0x80000), # 512 KB
        RomRegion(name="romcp",             start=0x00100000, length=0x40000), # 256 KB
        RamRegion(name="dtcm",              start=0x20000000, length=0x80000), # 512 KB
        RamRegion(name="ocram",             start=0x20480000, length=0x58000), # 352 KB
        RamRegion(name="aips",              start=0x40000000, length=0x10000000),
        FlashRegion(name="flexspi",         start=0x28000000, length=0x7FFFFFF, blocksize=0x1000,
            is_boot_memory=True, algo=FLASH_ALGO_CM7, page_size=0x100, flash_class=FlexSpiFlash),
        RamRegion(name="ddr",              start=0x80000000, end=0xdfffffff, is_external=True)
        )

    def __init__(self, session):
        self.AP_NUM = 0
        super(MIMX95_CM7, self).__init__(session, self.memoryMap)

class MIMX95_CM33(CoreSightTarget):

    VENDOR = "NXP"

    # Note: itcm, dtcm share a single 512 KB block of RAM that can be configurably
    # divided between those regions (this is called FlexRAM). Thus, the memory map regions for
    # each of these RAMs allocate the maximum possible of 512 KB, but that is the maximum and
    # will not actually be available in all regions simultaneously.
    memoryMap = MemoryMap(
        RamRegion(name="codetcm",           start=0x0ff80000, length=0x80000, is_boot_memory=True), # 512 KB
        RomRegion(name="romcp",             start=0x00000000, length=0x40000), # 256 KB
        RamRegion(name="systemtcm",         start=0x20000000, length=0x80000), # 512 KB
        RamRegion(name="ocram",             start=0x20480000, length=0x58000), # 352 KB
        RamRegion(name="aips",              start=0x40000000, length=0x10000000),
        RamRegion(name="ddr",              start=0x80000000, end=0xdfffffff, is_external=True)
        )

    def __init__(self, link):
        self.AP_NUM = 1
        super(MIMX95_CM33, self).__init__(link, self.memoryMap)

    def create_init_sequence(self):
        seq = super(MIMX95_CM33, self).create_init_sequence()
        seq.wrap_task('discovery',
            lambda seq: seq.replace_task('find_aps', self.find_aps)
            )
        seq.wrap_task('discovery',
            lambda seq: seq.replace_task('create_cores', self.create_cores)
            )
        return seq

    def disconnect(self, resume: bool):
        # Force no-resume during teardown
        super().disconnect(False)

    def reset_and_halt(self, reset_type=None, map_to_user=True):
        super(MIMX95_CM33, self).reset_and_halt(self.ResetType.EMULATED)

    def find_aps(self):
        if self.dp.valid_aps is not None:
            return
        self.dp.read_ap(0xFC)
        self.dp.valid_aps = [3]
        ap = AccessPort.create(self.dp, APv1Address(0))

    def create_cores(self):
        core0 = CortexM(self.session, self.aps[3], self.memory_map, 0)
        core0.default_reset_type = self.ResetType.DEFAULT

        self.aps[3].core = core0

        core0.init()

        self.add_core(core0)

        self.ap3 = self.aps[3]
        
        # Disable watchdog
        self.ap3.write32(0x542E0000, 0x2522)

class MIMX95_CM33_MX25UM(MIMX95_CM33):

    VENDOR = "NXP"

    # Note: itcm, dtcm share a single 512 KB block of RAM that can be configurably
    # divided between those regions (this is called FlexRAM). Thus, the memory map regions for
    # each of these RAMs allocate the maximum possible of 512 KB, but that is the maximum and
    # will not actually be available in all regions simultaneously.
    memoryMap = MemoryMap(
        RamRegion(name="codetcm",           start=0x0ff80000, length=0x80000), # 512 KB
        RomRegion(name="romcp",             start=0x00000000, length=0x40000), # 256 KB
        RamRegion(name="systemtcm",         start=0x20000000, length=0x80000), # 512 KB
        RamRegion(name="ocram",             start=0x20480000, length=0x58000), # 352 KB
        RamRegion(name="aips",              start=0x40000000, length=0x10000000),
        FlashRegion(name="flexspi",         start=0x28000000, length=0x7FFFFFF, blocksize=0x1000,
            is_boot_memory=True, algo=FLASH_ALGO_CM33, page_size=0x100, flash_class=FlexSpiFlash),
        RamRegion(name="ddr",              start=0x80000000, end=0xdfffffff, is_external=True)
        )
