# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
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

import logging
from copy import copy
from typing import (Any, Callable, Dict, Iterator, List, Optional, Sequence, Set, Union)

from ..utility import conversion

LOG = logging.getLogger(__name__)

# Core register related types.
CoreRegisterNameOrNumberType = Union[str, int]
CoreRegisterValueType = Union[int, float]

class CoreRegisterInfo:
    """@brief Useful information about a core register.

    Provides properties for classification of the register, and utilities to convert to and from
    the raw integer representation of the register value.

    Each core register has both a name (string), which is always lowercase, and an integer index.
    The index is a unique identifier with an architecture-specified meaning.
    """

    ## Map of register name to info.
    #
    # This is just the type declaration. The architecture-specific subclass must define the attribute, so
    # that architectures
    _NAME_MAP: Dict[str, "CoreRegisterInfo"]

    ## Map of register index to info.
    #
    # This is just a placeholder. The architecture-specific subclass should override the definition. Its
    # value is set to None to cause an exception if used.
    _INDEX_MAP: Dict[int, "CoreRegisterInfo"]

    @classmethod
    def add_to_map(cls, all_regs: Sequence["CoreRegisterInfo"]) -> None:
        """@brief Build info map from list of CoreRegisterInfo instance."""
        for reg in all_regs:
            cls._NAME_MAP[reg.name] = reg
            cls._INDEX_MAP[reg.index] = reg

    @classmethod
    def get(cls, reg: "CoreRegisterNameOrNumberType") -> "CoreRegisterInfo":
        """@brief Return the CoreRegisterInfo instance for a register.
        @param reg Either a register name or internal register number.
        @return CoreRegisterInfo
        @exception KeyError
        """
        try:
            if isinstance(reg, str):
                reg = reg.lower()
                return cls._NAME_MAP[reg]
            else:
                return cls._INDEX_MAP[reg]
        except KeyError as err:
            raise KeyError('unknown core register %s' % reg) from err

    def __init__(
                self,
                name: str,
                index: int,
                bitsize: int,
                reg_type: str,
                reg_group: str,
                reg_num: Optional[int] = None,
                feature: Optional[str] = None
                ) -> None:
        """@brief Constructor."""
        self._name = name
        self._index = index
        self._bitsize = bitsize
        self._group = reg_group
        self._gdb_type = reg_type
        self._gdb_regnum = reg_num
        self._gdb_feature = feature

    @property
    def name(self) -> str:
        """@brief Name of the register. Always lowercase."""
        return self._name

    @property
    def index(self) -> int:
        """@brief Integer index of the register."""
        return self._index

    @property
    def bitsize(self) -> int:
        """@brief Bit width of the register.."""
        return self._bitsize

    @property
    def group(self) -> str:
        """@brief Named group the register is contained within."""
        return self._group

    @property
    def gdb_type(self) -> str:
        """@brief Value type specific to gdb."""
        return self._gdb_type

    @property
    def gdb_regnum(self) -> Optional[int]:
        """@brief Register number specific to gdb."""
        return self._gdb_regnum

    @property
    def gdb_feature(self) -> Optional[str]:
        """@brief GDB architecture feature to which the register belongs."""
        return self._gdb_feature

    @property
    def is_float_register(self) -> bool:
        """@brief Returns true for registers single or double precision float registers (but not, say, FPSCR)."""
        return self.is_single_float_register or self.is_double_float_register

    @property
    def is_single_float_register(self) -> bool:
        """@brief Returns true for registers holding single-precision float values"""
        return self.gdb_type == 'ieee_single'

    @property
    def is_double_float_register(self) -> bool:
        """@brief Returns true for registers holding double-precision float values"""
        return self.gdb_type == 'ieee_double'

    def from_raw(self, value: int) -> "CoreRegisterValueType":
        """@brief Convert register value from raw (integer) to canonical type."""
        # Convert int to float.
        if self.is_single_float_register:
            return conversion.u32_to_float32(value)
        elif self.is_double_float_register:
            return conversion.u64_to_float64(value)
        else:
            return value

    def to_raw(self, value: "CoreRegisterValueType") -> int:
        """@brief Convert register value from canonical type to raw (integer)."""
        # Convert float to int.
        if isinstance(value, float):
            if self.is_single_float_register:
                value = conversion.float32_to_u32(value)
            elif self.is_double_float_register:
                value = conversion.float64_to_u64(value)
            else:
                raise TypeError("non-float register value has float type")
        return value

    def clone(self) -> "CoreRegisterInfo":
        """@brief Return a copy of the register info."""
        return copy(self)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, CoreRegisterInfo) and (self.index == other.index)

    def __hash__(self) -> int:
        return hash(self.index)

    def __repr__(self) -> str:
        return "<{}@{:#x} {}={} {}-bit>".format(self.__class__.__name__, id(self), self.name, self.index, self.bitsize)

class CoreRegistersIndex:
    """@brief Class to hold indexes of available core registers.

    This class is meant to be used by a core to hold the set of core registers that are actually present on
    a particular device, as determined by runtime inspection of the core. A number of properties are made
    available to access the core registers by various keys.
    """

    def __init__(self):
        self._groups: Set[str] = set()
        self._all: Set[CoreRegisterInfo] = set()
        self._by_name: Dict[str, CoreRegisterInfo] = {}
        self._by_index: Dict[int, CoreRegisterInfo] = {}
        self._by_feature: Dict[str, List[CoreRegisterInfo]] = {}

    @property
    def groups(self) -> Set[str]:
        """@brief Set of unique register group names."""
        return self._groups

    @property
    def as_set(self) -> Set[CoreRegisterInfo]:
        """@brief Set of available registers as CoreRegisterInfo objects."""
        return self._all

    @property
    def by_name(self) -> Dict[str, CoreRegisterInfo]:
        """@brief Dict of (register name) -> CoreRegisterInfo."""
        return self._by_name

    @property
    def by_index(self) -> Dict[int, CoreRegisterInfo]:
        """@brief Dict of (register index) -> CoreRegisterInfo."""
        return self._by_index

    @property
    def by_feature(self) -> Dict[str, List[CoreRegisterInfo]]:
        """@brief Dict of (register gdb feature) -> List[CoreRegisterInfo]."""
        return self._by_feature

    def iter_matching(self, predicate: Callable[[CoreRegisterInfo], bool]) -> Iterator[CoreRegisterInfo]:
        """@brief Iterate over registers matching a given predicate callable.
        @param self The object.
        @param predicate Callable accepting a single argument, a CoreRegisterInfo, and returning a boolean.
            If the predicate returns True then the iterator will include the register.
        """
        for reg in self._all:
            if predicate(reg):
                yield reg

    def add_group(self, regs: Sequence[CoreRegisterInfo]) -> None:
        """@brief Add a list of registers.
        @param self The object.
        @param regs Iterable of CoreRegisterInfo objects. The objects are copied as they are added.
        """
        for reg in regs:
            reg_copy = reg.clone()
            self._groups.add(reg_copy.group)
            self._all.add(reg_copy)
            self._by_name[reg_copy.name] = reg_copy
            self._by_index[reg_copy.index] = reg_copy
            if reg_copy.gdb_feature is not None:
                try:
                    self._by_feature[reg_copy.gdb_feature].append(reg_copy)
                except KeyError:
                    self._by_feature[reg_copy.gdb_feature] = [reg_copy]

