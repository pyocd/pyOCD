#!/usr/bin/env python3
# pyOCD debugger
# Copyright (c) 2011-2021 Arm Limited
# Copyright (c) 2021-2022 Chris Reed
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

import os
import argparse
import colorama
from datetime import datetime
import struct
import binascii
import jinja2
from pyocd.target.pack.flash_algo import PackFlashAlgo
from pyocd.utility.mask import align_up

# This header consists of two instructions:
#
# ```
# bkpt  #0
# b     .-2     # branch to the bkpt
# ```
#
# Before running a flash algo operation, LR is set to the address of the `bkpt` instruction,
# so when the operation function returns it will halt the CPU.
BLOB_HEADER = '0xe7fdbe00,'
HEADER_SIZE = 4

STACK_SIZE = 0x1000

PYOCD_TEMPLATE = \
"""# pyOCD debugger
# Copyright (c) {{year}} {{copyright_owner}}
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

FLASH_ALGO = {
    'load_address' : {{'0x%08x' % entry}},

    # Flash algorithm as a hex string
    'instructions': [
    {{prog_header}}
    {{algo.format_algo_data(4, 8, "c")}}
    ],

    # Relative function addresses
    'pc_init': {{'0x%08x' % (algo.symbols['Init'] + header_size + entry)}},
    'pc_unInit': {{'0x%08x' % (algo.symbols['UnInit'] + header_size + entry)}},
    'pc_program_page': {{'0x%08x' % (algo.symbols['ProgramPage'] + header_size + entry)}},
    'pc_erase_sector': {{'0x%08x' % (algo.symbols['EraseSector'] + header_size + entry)}},
    'pc_eraseAll': {{'0x%08x' % (algo.symbols['EraseChip'] + header_size + entry)}},

    'static_base' : {{'0x%08x' % entry}} + {{'0x%08x' % header_size}} + {{'0x%08x' % algo.rw_start}},
    'begin_stack' : {{'0x%08x' % stack_pointer}},
    'end_stack' : {{'0x%08x' % stack_base}},
    'begin_data' : {{'0x%08x' % entry}} + 0x1000,
    'page_size' : {{'0x%x' % algo.page_size}},
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        {{'0x%08x' % (page_buffers[0])}},
        {{'0x%08x' % (page_buffers[1])}}
    ],
    'min_program_length' : {{'0x%x' % algo.page_size}},

    # Relative region addresses and sizes
    'ro_start': {{'0x%x' % (header_size + algo.ro_start)}},
    'ro_size': {{'0x%x' % algo.ro_size}},
    'rw_start': {{'0x%x' % (header_size + algo.rw_start)}},
    'rw_size': {{'0x%x' % algo.rw_size}},
    'zi_start': {{'0x%x' % (header_size + algo.zi_start)}},
    'zi_size': {{'0x%x' % algo.zi_size}},

    # Flash information
    'flash_start': {{'0x%x' % algo.flash_start}},
    'flash_size': {{'0x%x' % algo.flash_size}},
    'sector_sizes': (
    {%- for start, size  in algo.sector_sizes %}
        {{ "(0x%x, 0x%x)" % (start, size) }},
    {%- endfor %}
    )
}

"""

colorama.init()

def str_to_num(val):
    return int(val, 0)  #convert string to number and automatically handle hex conversion

class PackFlashAlgoGenerator(PackFlashAlgo):
    """
    Class to wrap a flash algo

    This class is intended to provide easy access to the information
    provided by a flash algorithm, such as symbols and the flash
    algorithm itself.
    """

    def format_algo_data(self, spaces, group_size, fmt):
        """"
        Return a string representing algo_data suitable for use in a template

        The string is intended for use in a template.

        :param spaces: The number of leading spaces for each line
        :param group_size: number of elements per line (element type
            depends of format)
        :param fmt: - format to create - can be either "hex" or "c"
        """
        padding = " " * spaces
        if fmt == "hex":
            blob = binascii.b2a_hex(self.algo_data).decode()
            line_list = []
            for i in range(0, len(blob), group_size):
                line_list.append('"' + blob[i:i + group_size] + '"')
            return ("\n" + padding).join(line_list)
        elif fmt == "c":
            blob = self.algo_data[:]
            pad_size = 0 if len(blob) % 4 == 0 else 4 - len(blob) % 4
            blob = blob + b"\x00" * pad_size
            integer_list = struct.unpack("<" + "L" * (len(blob) // 4), blob)
            line_list = []
            for pos in range(0, len(integer_list), group_size):
                group = ["0x%08x" % value for value in
                         integer_list[pos:pos + group_size]]
                line_list.append(", ".join(group))
            return (",\n" + padding).join(line_list)
        else:
            raise ValueError("Unsupported format %s" % fmt)

    def process_template(self, template_text, data_dict=None):
        """
        Generate output from the supplied template

        All the public methods and fields of this class can be accessed from
        the template via "algo".

        :param template_path: Relative or absolute file path to the template
        :param data_dict: Additional data to use when generating
        """
        if data_dict is None:
            data_dict = {}
        else:
            assert isinstance(data_dict, dict)
            data_dict = dict(data_dict)
        assert "algo" not in data_dict, "algo already set by user data"
        data_dict["algo"] = self

        template = jinja2.Template(template_text)
        return template.render(data_dict)

def main():
    parser = argparse.ArgumentParser(description="Blob generator")
    parser.add_argument("elf_path", help="Elf, axf, or flm to extract flash algo from")
    parser.add_argument("--blob-start", default=0x20000000, type=str_to_num, help="Starting "
                        "address of the flash blob in target RAM. (default 0x20000000)")
    parser.add_argument("--stack-size", default=STACK_SIZE, type=str_to_num, help="Stack size for the algo. "
                        f"(default {STACK_SIZE})")
    parser.add_argument("-i", "--info-only", action="store_true", help="Only print information about the flash "
                        "algo, do not generate a blob.")
    parser.add_argument("-o", "--output", default="pyocd_blob.py", help="Path of output file "
                        "(default 'pyocd_blob.py').")
    parser.add_argument("-t", "--template", help="Path to Jinja template file (default is an internal "
                        "template for pyocd).")
    parser.add_argument('-c', '--copyright', help="Set copyright owner.")
    args = parser.parse_args()

    if not args.copyright and not args.info_only:
        print(f"{colorama.Fore.YELLOW}Warning! No copyright owner was specified. Defaulting to \"PyOCD Authors\". "
            f"Please set via --copyright, or edit output.{colorama.Style.RESET_ALL}")

    if args.template:
        with open(args.template, "r") as tmpl_file:
            tmpl = tmpl_file.read()
    else:
        tmpl = PYOCD_TEMPLATE

    with open(args.elf_path, "rb") as file_handle:
        algo = PackFlashAlgoGenerator(file_handle)

        print(algo.flash_info)

        # Page buffer base begins after algo and its rw/zi data, rounded up to 16 bytes.
        buffer_base = align_up(args.blob_start + HEADER_SIZE
                        + algo.ro_size + algo.rw_size + algo.zi_size, 0x10)

        page_buffers = [
            buffer_base,
            buffer_base + algo.page_size,
        ]

        # Allocate stack after buffers, with top and bottom rounded to 8 bytes.
        stack_base = align_up(buffer_base + algo.page_size * 2, 8)
        sp = align_up(stack_base + args.stack_size, 8)

        header_end = args.blob_start + HEADER_SIZE
        print(f"load addr:   {args.blob_start:#010x}")
        print(f"data:        {HEADER_SIZE + len(algo.algo_data):#x} bytes")
        print(f"  header:    {args.blob_start:#010x} + {HEADER_SIZE:#x} bytes")
        print(f"  ro:        {header_end + algo.ro_start:#010x} + {algo.ro_size:#x} bytes")
        print(f"  rw:        {header_end + algo.rw_start:#010x} + {algo.rw_size:#x} bytes")
        print(f"  zi:        {header_end + algo.zi_start:#010x} + {algo.zi_size:#x} bytes")
        print(f"buffer[0]:   {page_buffers[0]:#010x}")
        print(f"buffer[1]:   {page_buffers[1]:#010x}")
        print(f"stack:       {stack_base:#010x} .. {sp:#010x} ({sp - stack_base:#x} bytes)")

        print("\nSymbol offsets:")
        for n, v in algo.symbols.items():
            print(f"{n}:{' ' * (11 - len(n))} {v:#010x}")

        if args.info_only:
            return

        if len(algo.sector_sizes) > 1:
            print(f"{colorama.Fore.YELLOW}Warning! Flash has more than one sector size. Remember to create one flash memory region for each sector size range.{colorama.Style.RESET_ALL}")

        data_dict = {
            'name': os.path.splitext(os.path.split(args.elf_path)[-1])[0],
            'prog_header': BLOB_HEADER,
            'header_size': HEADER_SIZE,
            'entry': args.blob_start,
            'stack_base': stack_base,
            'stack_pointer': sp,
            'page_buffers': page_buffers,
            'year': datetime.now().year,
            'copyright_owner': args.copyright or "PyOCD Authors",
        }

        text = algo.process_template(tmpl, data_dict)

        with open(args.output, "w") as file_handle:
            file_handle.write(text)

        print(f"Wrote flash algo dict to {args.output}")

if __name__ == '__main__':
    main()
