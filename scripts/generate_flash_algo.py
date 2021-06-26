#!/usr/bin/env python3
# pyOCD debugger
# Copyright (c) 2011-2021 Arm Limited
# Copyright (c) 2021 Chris Reed
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

from __future__ import print_function
import os
import argparse
import struct
import binascii
import jinja2
from pyocd.target.pack.flash_algo import PackFlashAlgo

# TODO
# FIXED LENGTH - remove and these (shrink offset to 4 for bkpt only)
BLOB_HEADER = '0xe00abe00,' #, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,'
HEADER_SIZE = 4 #0x20

STACK_SIZE = 0x200

PYOCD_TEMPLATE = \
"""# pyOCD debugger
# Copyright (c) 2017-2021 Arm Limited
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
    'begin_data' : {{'0x%08x' % entry}} + 0x1000,
    'page_size' : {{'0x%x' % algo.page_size}},
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [{{'0x%08x' % (entry + 4096)}}, {{'0x%08x' % (entry + 4096 + algo.page_size)}}],   # Enable double buffering
    'min_program_length' : {{'0x%x' % algo.page_size}},

    # Relative region addresses and sizes
    'ro_start': {{'0x%x' % algo.ro_start}},
    'ro_size': {{'0x%x' % algo.ro_size}},
    'rw_start': {{'0x%x' % algo.rw_start}},
    'rw_size': {{'0x%x' % algo.rw_size}},
    'zi_start': {{'0x%x' % algo.zi_start}},
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
            blob = binascii.b2a_hex(self.algo_data)
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
            raise Exception("Unsupported format %s" % fmt)

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
                        "address of the flash blob in target RAM.")
    parser.add_argument("--stack-size", default=STACK_SIZE, type=str_to_num, help="Stack size for the algo "
                        f"(default {STACK_SIZE}).")
    parser.add_argument("-i", "--info-only", action="store_true", help="Only print information about the flash "
                        "algo, do not generate a blob.")
    parser.add_argument("-o", "--output", default="pyocd_blob.py", help="Path of output file "
                        "(default 'pyocd_blob.py').")
    parser.add_argument("-t", "--template", help="Path to Jinja template file (default is an internal "
                        "template for pyocd).")
    args = parser.parse_args()
    
    if args.template:
        with open(args.template, "r") as tmpl_file:
            tmpl = tmpl_file.read()
    else:
        tmpl = PYOCD_TEMPLATE

    with open(args.elf_path, "rb") as file_handle:
        algo = PackFlashAlgoGenerator(file_handle)

        print(algo.flash_info)

        if args.info_only:
            return

        # Allocate stack after algo and its rw data, with top and bottom rounded to 8 bytes.
        stack_base = args.blob_start + HEADER_SIZE + algo.rw_start + algo.rw_size
        stack_base = (stack_base + 7) // 8 * 8
        sp = stack_base + args.stack_size
        sp = (sp + 7) // 8 * 8

        data_dict = {
            'name': os.path.splitext(os.path.split(args.elf_path)[-1])[0],
            'prog_header': BLOB_HEADER,
            'header_size': HEADER_SIZE,
            'entry': args.blob_start,
            'stack_pointer': sp,
        }

        text = algo.process_template(tmpl, data_dict)
        
        with open(args.output, "w") as file_handle:
            file_handle.write(text)


if __name__ == '__main__':
    main()
