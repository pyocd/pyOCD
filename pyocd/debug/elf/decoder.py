# pyOCD debugger
# Copyright (c) 2017 Arm Limited
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

import os
from elftools.elf.elffile import ELFFile
from elftools.dwarf.constants import DW_LNE_set_address
from intervaltree import IntervalTree
from collections import namedtuple
from itertools import islice
import logging

LOG = logging.getLogger(__name__)

FunctionInfo = namedtuple('FunctionInfo', 'name subprogram low_pc high_pc')
LineInfo = namedtuple('LineInfo', 'cu filename dirname line')
SymbolInfo = namedtuple('SymbolInfo', 'name address size type')

class ElfSymbolDecoder(object):
    def __init__(self, elf):
        assert isinstance(elf, ELFFile)
        self.elffile = elf

        self.symtab = self.elffile.get_section_by_name('.symtab')
        self.symcount = self.symtab.num_symbols()
        self.symbol_dict = {}
        self.symbol_tree = None

        # Build indices.
        self._build_symbol_search_tree()
        self._process_arm_type_symbols()

    def get_elf(self):
        return self.elffile

    def get_symbol_for_address(self, addr):
        try:
            return sorted(self.symbol_tree[addr])[0].data
        except IndexError:
            return None
    
    def get_symbol_for_name(self, name):
        try:
            return self.symbol_dict[name]
        except KeyError:
            return None

    def _build_symbol_search_tree(self):
        self.symbol_tree = IntervalTree()
        symbols = self.symtab.iter_symbols()
        for symbol in symbols:
            # Only look for functions and objects.
            sym_type = symbol.entry['st_info']['type']
            if sym_type not in ['STT_FUNC', 'STT_OBJECT']:
                continue

            sym_value = symbol.entry['st_value']
            sym_size = symbol.entry['st_size']

            # Cannot put an empty interval into the tree, so ensure symbols have
            # at least a size of 1.
            real_sym_size = sym_size
            if sym_size == 0:
                sym_size = 1

            syminfo = SymbolInfo(name=symbol.name, address=sym_value, size=real_sym_size, type=sym_type)

            # Add to symbol dict.
            self.symbol_dict[symbol.name] = syminfo
            
            # Add to symbol tree.
            self.symbol_tree.addi(sym_value, sym_value+sym_size, syminfo)

    def _process_arm_type_symbols(self):
        pass
#         type_symbols = self._get_arm_type_symbol_iter()
#         map(print, imap(lambda x:"%s : 0x%x" % (x.name, x['st_value']), type_symbols))

    def _get_arm_type_symbol_iter(self):
        # Scan until we find $m symbol.
        i = 1
        while i < self.symcount:
            symbol = self.symtab.get_symbol(i)
            if symbol.name == '$m':
                break
            i += 1
        if i >= self.symcount:
            return
        n = symbol['st_value']
        return islice(self.symtab.iter_symbols(), i, n)


class DwarfAddressDecoder(object):
    def __init__(self, elf):
        assert isinstance(elf, ELFFile)
        self.elffile = elf
        self.dwarfinfo = None

        self.subprograms = []
        self.function_tree = IntervalTree()
        self.line_tree = IntervalTree()

        if self.elffile.has_dwarf_info():
            self.dwarfinfo = self.elffile.get_dwarf_info()

            # Build indices.
            self._get_subprograms()
            self._build_function_search_tree()
            self._build_line_search_tree()

    def get_function_for_address(self, addr):
        try:
            return sorted(self.function_tree[addr])[0].data
        except IndexError:
            return None

    def get_line_for_address(self, addr):
        try:
            return sorted(self.line_tree[addr])[0].data
        except IndexError:
            return None

    def _get_subprograms(self):
        for CU in self.dwarfinfo.iter_CUs():
            self.subprograms.extend([d for d in CU.iter_DIEs() if d.tag == 'DW_TAG_subprogram'])

    def _build_function_search_tree(self):
        for prog in self.subprograms:
            try:
                name = prog.attributes['DW_AT_name'].value
                low_pc = prog.attributes['DW_AT_low_pc'].value
                high_pc = prog.attributes['DW_AT_high_pc'].value

                # Skip subprograms excluded from the link.
                if low_pc == 0:
                    continue
                # Skip empty subprograms (no null intervals are allowed).
                if low_pc == high_pc:
                    continue

                # If high_pc is not explicitly an address, then it's an offset from the
                # low_pc value.
                if prog.attributes['DW_AT_high_pc'].form != 'DW_FORM_addr':
                    high_pc = low_pc + high_pc

                fninfo = FunctionInfo(name=name, subprogram=prog, low_pc=low_pc, high_pc=high_pc)

                self.function_tree.addi(low_pc, high_pc, fninfo)
            except KeyError:
                pass

    def _build_line_search_tree(self):
        for cu in self.dwarfinfo.iter_CUs():
            lineprog = self.dwarfinfo.line_program_for_CU(cu)
            prevstate = None
            skipThisSequence = False
            for entry in lineprog.get_entries():
                # Look for a DW_LNE_set_address command with a 0 address. This indicates
                # code that is not actually included in the link.
                #
                # TODO: find a better way to determine the code is really not present and
                #       doesn't have a real address of 0
                if entry.is_extended and entry.command == DW_LNE_set_address \
                        and len(entry.args) == 1 and entry.args[0] == 0:
                    skipThisSequence = True

                # We're interested in those entries where a new state is assigned
                if entry.state is None:
                    continue

                # Looking for a range of addresses in two consecutive states.
                if prevstate and not skipThisSequence:
                    try:
                        fileinfo = lineprog['file_entry'][prevstate.file - 1]
                        filename = fileinfo.name
                        try:
                            dirname = lineprog['include_directory'][fileinfo.dir_index - 1]
                        except IndexError:
                            dirname = ""
                    except IndexError:
                        filename = ""
                        dirname = ""
                    info = LineInfo(cu=cu, filename=filename, dirname=dirname, line=prevstate.line)
                    fromAddr = prevstate.address
                    toAddr = entry.state.address
                    try:
                        if fromAddr != 0 and toAddr != 0:
                            # Ensure we don't insert null intervals.
                            if fromAddr == toAddr:
                                toAddr += 1
                            self.line_tree.addi(fromAddr, toAddr, info)
                    except:
                        LOG.debug("Problematic lineprog:")
                        self._dump_lineprog(lineprog)
                        raise

                if entry.state.end_sequence:
                    prevstate = None
                    skipThisSequence = False
                else:
                    prevstate = entry.state

    def _dump_lineprog(self, lineprog):
        for i, e in enumerate(lineprog.get_entries()):
            s = e.state
            if s is None:
                LOG.debug("%d: cmd=%d ext=%d args=%s", i, e.command, int(e.is_extended), repr(e.args))
            else:
                LOG.debug("%d: %06x %4d stmt=%1d block=%1d end=%d file=[%d]%s", i, s.address, s.line, s.is_stmt, int(s.basic_block), int(s.end_sequence), s.file, lineprog['file_entry'][s.file-1].name)

    def dump_subprograms(self):
        for prog in self.subprograms:
            name = prog.attributes['DW_AT_name'].value
            try:
                low_pc = prog.attributes['DW_AT_low_pc'].value
            except KeyError:
                low_pc = 0
            try:
                high_pc = prog.attributes['DW_AT_high_pc'].value
            except KeyError:
                high_pc = 0xffffffff
            filename = os.path.basename(prog._parent.attributes['DW_AT_name'].value.replace('\\', '/'))
            LOG.debug("%s%s%08x %08x %s", name, (' ' * (50-len(name))), low_pc, high_pc, filename)


