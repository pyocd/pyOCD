# pyOCD debugger
# Copyright (c) 2013-2019 Arm Limited
# Copyright (c) 2022 Chris Reed
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

import string

from .builtin import BUILTIN_TARGETS

## @brief Dictionary of all targets.
#
# This table starts off with only the builtin targets. At runtime it may be extended with
# additional targets from CMSIS DFPs or other sources.
TARGET = BUILTIN_TARGETS.copy()

## @brief Legal characters in target type names.
#
# Basically, C language identifier characters.
_TARGET_TYPE_NAME_CHARS = string.ascii_letters + string.digits + '_'

def normalise_target_type_name(target_type: str) -> str:
    """@brief Normalise a target type name.

    The output string has all non-ASCII alphanumeric characters replaced with underscores and is
    converted to all lowercase. Only one underscore in a row will be inserted in the output. For example,
    "foo--bar" will be normalised to "foo_bar".
    """
    result = ""
    in_replace = False
    for c in target_type:
        if c in _TARGET_TYPE_NAME_CHARS:
            result += c.lower()
            in_replace = False
        elif not in_replace:
            result += '_'
            in_replace = True
    return result
