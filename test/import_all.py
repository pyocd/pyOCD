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

from pathlib import Path
from importlib import import_module

# Import pyocd to get its filesystem path.
import pyocd

# Total count of modules imported.
import_count = 0

def process_dir(dotted_path: str, dir_path: Path) -> None:
    global import_count
    for entry in sorted(dir_path.iterdir(), key=lambda v: v.name):
        is_subpackage = (entry.is_dir() and (entry / "__init__.py").exists())
        is_module = entry.suffix == ".py"
        
        if not (is_subpackage or is_module):
            continue
        
        module_path = dotted_path + '.' + entry.stem
        print(f"Importing: {module_path}")
        import_module(module_path)
        import_count += 1
        
        # Recursive into valid sub-packages.
        if is_subpackage:
            process_dir(module_path, entry)

def main() -> None:
    pyocd_path = Path(pyocd.__file__).parent.resolve()
    print(f"pyocd package path: {pyocd_path}")
    process_dir("pyocd", pyocd_path)
    print(f"Imported {import_count} modules successfully")

if __name__ == "__main__":
    main()
