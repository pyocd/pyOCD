#!/usr/bin/env python3

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

from pyocd.core.soc_target import SoCTarget
from pyocd.target.builtin import BUILTIN_TARGETS


def gen_one_target(name: str, target: type[SoCTarget]) -> None:
    print(f"""    <tr><td><code>{name.lower()}</code></td>
    <td>{target.VENDOR}</td>
    <td>{target.__name__}</td>
    </tr>
""")

def gen_targets() -> None:
    for target_name in sorted(BUILTIN_TARGETS.keys()):
        target = BUILTIN_TARGETS[target_name]
        gen_one_target(target_name, target)
        

def main() -> None:
    print("""---
title: Built-in targets
---

<table>

<tr><th>Target Type Name</th><th>Vendor</th><th>Name</th></tr>
""")
    gen_targets()
    print("""
</table>
""")


if __name__ == '__main__':
    main()


