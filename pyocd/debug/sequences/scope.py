# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

from __future__ import annotations

import logging
from typing import (Dict, Iterable, Optional, Set)

LOG = logging.getLogger(__name__)
TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

class Scope:
    """@brief Debug sequence execution scope.

    Scopes have both a link to a parent scope. The former is used to read regular variables defined in
    super-scopes. Writing a variable always sets it in the scope to in which it was defined, unless the
    variable hasn't been set before in which case it is set in the scope that was called.
    """

    def __init__(
                self,
                parent: Optional["Scope"] = None,
                name: str = ""
            ) -> None:
        """@brief Constructor.
        @param self The Scope object.
        @param parent Optional parent scope reference. If not provided or set to None, the new scope
            becomes a root.
        @param specials Optional specials scope reference. If not provided or set to None, and a
            parent was provided, then the specials scope from the parent is used.
        @param name Optional name for the scope.
        """
        self._name = name
        self._parent = parent
        self._variables: Dict[str, int] = {} # Map from name: value.
        # A variable is read-only if its name is in this set. Start off with
        self._ro_variables: Set[str] = set()

    @property
    def name(self) -> str:
        """@brief The scope's name."""
        return self._name

    @property
    def parent(self) -> Optional[Scope]:
        """@brief Parent scope.

        The parent of the root scope is None.
        """
        return self._parent

    @property
    def variables(self) -> Set[str]:
        """@brief Set of the names of all variables defined in this scope.

        Does not include any variables from parent scopes.
        """
        return set(self._variables.keys())

    def get(self, name: str) -> int:
        """@brief Read a variable."""
        try:
            value = self._variables[name]
        except KeyError:
            if self._parent is not None:
                value = self._parent.get(name)
            else:
                raise
        TRACE.debug("get '%s' -> 0x%016x", name, value)
        return value

    def set(self, name: str, value: int, readonly: bool = False) -> None:
        """@brief Write a variable.

        The variable is set in the scope in which it is defined (following the parent links). The first
        time a variable is set, it can be marked as read-only via the `readonly` parameter.

        @param self
        @param name Name of the variable.
        @param value Integer value of the variable. Limited to 64-bit.
        @param readonly If the variable has not been previously defined, this parameter determines if it
            is writable. Primarily used for debugvars and other predefined variables.
        """
        TRACE.debug("set '%s' <- 0x%016x", name, value)

        # Catch attempt to rewrite a read-only variable.
        if self.is_read_only(name):
            raise RuntimeError("attempt to modify read-only variable '%s'" % name)

        scope = self
        while scope is not None:
            if name in scope._variables:
                # Found a scope with the variable definition.
                scope._variables[name] = value
                return
            scope = scope.parent

        # An existing definition of the variable wasn't found, so add it to the this scope.
        self._variables[name] = value
        if readonly:
            self._ro_variables.add(name)

    def copy_variables(self, from_scope: Scope, variables: Iterable[str]) -> None:
        """@brief Copy a set of variables from another scope into this one.

        @param self
        @param from_scope Scope to copy from. This scope must not be connected via parent links to the
            called scope, or the behaviour is undefined.
        @param variables Iterable of variable names which will be copied. If a variable is not defined
            in the `from_scope`, it will not be copied.
        """
        for name in variables:
            if from_scope.is_defined(name):
                self.set(name, from_scope.get(name))

    def is_defined(self, name: str, recurse_parents: bool = True) -> bool:
        """@brief Returns whether a variable has been set in this or any linked scope.

        @param self
        @param name Name of the variable to query.
        @param recurse_parents Whether parent scopes should also be queried if this scope doesn't contain the specified
            variable.
        @return Boolean of whether the named variable has been defined.
        """
        if name in self._variables:
            return True
        elif recurse_parents and (self._parent is not None):
            return self._parent.is_defined(name, recurse_parents)
        else:
            return False

    def freeze(self) -> None:
        """@brief Make all variables defined in the scope read-only."""
        self._ro_variables = set(self._variables.keys())

    def is_read_only(self, name: str) -> bool:
        """@brief Returns a boolean for whether the named variable is read-only.

        First checks the called scope. If the variable isn't found to be read-only, it asks the
        parent. Thus, once a variable is marked as read-only, it remains read-only in all child
        scopes.
        """
        if name in self._ro_variables:
            return True
        elif self.parent is not None:
            return self.parent.is_read_only(name)
        else:
            return False

    def _build_dump(self, indent: str) -> str:
        """@brief Construct a scope dump with a given ident level."""
        s = f"<{type(self).__name__}@{id(self):x} {self.name}\n"
        if self.parent:
            parent_str = self.parent._build_dump(indent + '  ')
        else:
            parent_str = "None"
        s += f"{indent}parent={parent_str}\n"
        s += f"{indent}variables=[\n"
        for n, v in self._variables.items():
            s += f"{indent}  '{n}'={v:#x} {'(RO)' if n in self._ro_variables else '(RW)'}\n"
        s += f"{indent}]>"
        return s

    def dump(self) -> str:
        """@brief Return a string detailing the scope, its parents, and all variable values."""
        return self._build_dump(indent="  ")

    def __len__(self) -> int:
        """@brief Return the number of variables in this scope (not including parents)."""
        return len(self._variables)

    def __repr__(self) -> str:
        """@brief Shortened representation of the scope without variable values."""
        return f"<{type(self).__name__}@{id(self):x} {self.name} "\
               f"parent={self._parent!r} [{', '.join(self._variables.keys())}]>"
