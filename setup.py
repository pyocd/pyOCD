# pyOCD debugger
# Copyright (c) 2012-2020 Arm Limited
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
from setuptools import setup
import zipfile
from pathlib import Path

# Get the directory containing this setup.py. Even though full paths are used below, we must
# chdir in order for setuptools-scm to successfully pick up the version.
SCRIPT_DIR = Path(__file__).parent.resolve()
os.chdir(SCRIPT_DIR)

# Build zip of SVD files.
#
# The SVD files are stored individually in the data/ directory only in the repo. For both sdist and
# wheel, the svd_data.zip file is used rather than including the data directory. Thus, this setup
# script needs to skip building svd_data.zip if the data/ directory is not present.
svd_dir_path = SCRIPT_DIR / "pyocd" / "debug" / "svd"
svd_data_dir_path = svd_dir_path / "data"
svd_zip_path = svd_dir_path / "svd_data.zip"
if svd_data_dir_path.exists():
    with zipfile.ZipFile(svd_zip_path, 'w', zipfile.ZIP_DEFLATED) as svd_zip:
        for svd_file in sorted(svd_data_dir_path.iterdir()):
            svd_zip.write(svd_file, svd_file.name)
elif not svd_zip_path.exists():
    raise RuntimeError("neither the source SVD data directory nor built svd_data.zip exist")

setup()
