# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
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

from typing import Union

# to_bytes_safe() converts a unicode string to a bytes object by encoding as
# latin-1. It will also accept a value that is already a bytes object and
# return it unmodified.
def to_bytes_safe(v: Union[str, bytes]) -> bytes:
    if isinstance(v, str):
        return v.encode('utf-8')
    else:
        return v

# to_str_safe() converts a bytes object to a unicode string by decoding from
# latin-1. It will also accept a value that is already a str object and
# return it unmodified.
def to_str_safe(v: Union[str, bytes]) -> str:
    if isinstance(v, str):
        return v
    else:
        return v.decode('utf-8')

