# pyOCD debugger
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

import re
from typing import (Iterable, Sequence, Optional, Tuple)

class UniquePrefixMatcher:
    """@brief Manages detection of shortest unique prefix match of a set of strings."""

    def __init__(self, items: Optional[Iterable[str]] = None):
        """@brief Constructor.
        @param self This object.
        @param items Optional sequence of strings.
        """
        self._items = set(items) if (items is not None) else set()

    def add_items(self, items: Iterable[str]) -> None:
        """@brief Add some items to be matched.
        @param self This object.
        @param items Sequence of strings.
        """
        self._items.update(items)

    def find_all(self, prefix: str) -> Tuple[str, ...]:
        """@brief Return all items matching the given prefix.
        @param self This object.
        @param prefix String that is compared as a prefix against the items passed to the constructor.
            Must not be the empty string.
        @return List of all items where `prefix` is a valid prefix.
        @exception ValueError Raised for an empty `prefix`.
        """
        if len(prefix) == 0:
            raise ValueError("empty prefix")
        # First look for an exact match.
        if prefix in self._items:
            return (prefix,)
        return tuple(i for i in self._items if i.startswith(prefix))

    def find_one(self, prefix: str) -> Optional[str]:
        """@brief Return the item matching the given prefix, or None.
        @param self This object.
        @param prefix String that is compared as a prefix against the items passed to the constructor.
        @return The full value of the matching item where `prefix` is a valid prefix.
        @exception ValueError Raised for an empty `prefix`.
        """
        all_matches = self.find_all(prefix)
        if len(all_matches) == 1:
            return all_matches[0]
        return None


_INT_SUFFIX_RE = re.compile(r'[0-9]+$')

def uniquify_name(name: str, others: Sequence[str]) -> str:
    """@brief Ensure the given name is unique amongst the other provided names.

    If the `name` parameter is not unique, an integer will be appended to it. If the name already ends in an
    integer, that value will be incremented by 1.

    @param name The name to uniqify.
    @param others Sequence of other names to compare against.
    @return A string guaranteed to not be the same as any string contained in `others`.
    """
    while name in others:
        # Look for an integer at the end.
        matches = list(_INT_SUFFIX_RE.finditer(name))
        if len(matches):
            match = matches[0]
            u_value = int(match.group())
            name = name[:match.start()]
        else:
            name += "_"
            u_value = 0

        # Update the name with the trailing int incremented.
        name += str(u_value + 1)

    return name
