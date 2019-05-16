# pyOCD debugger
# Copyright (c) 2012-2019 Arm Limited
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

import sys
import os
from setuptools import setup, find_packages

open_args = { 'mode': 'r' }
if sys.version_info[0] > 2:
    # Python 3.x version requires explicitly setting the encoding.
    # Python 2.x version of open() doesn't support the encoding parameter.
    open_args['encoding'] = 'utf-8'

with open('README.md', **open_args) as f:
    readme = f.read()

setup(
    name="pyocd",
    use_scm_version={
        'local_scheme': 'dirty-tag',
        'write_to': 'pyocd/_version.py'
    },
    setup_requires=[
        'setuptools>=40.0',
        'setuptools_scm!=1.5.3,!=1.5.4',
        'setuptools_scm_git_archive',
        ],
    description="Cortex-M debugger for Python",
    long_description=readme,
    long_description_content_type='text/markdown',
    author="Chris Reed, Martin Kojtal, Russ Butler",
    author_email="chris.reed@arm.com, martin.kojtal@arm.com, russ.butler@arm.com",
    url='https://github.com/mbedmicro/pyOCD',
    license="Apache 2.0",
    # Allow installation on 2.7.9+, and 3.4+ even though we officially only support 3.6+.
    python_requires=">=2.7.9, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*",
    install_requires = [
        'cmsis-pack-manager>=0.2.7',
        'colorama',
        'enum34>=1.0,<2.0;python_version<"3.4"',
        'hidapi;platform_system=="Darwin"',
        'intelhex>=2.0,<3.0',
        'intervaltree>=3.0.2,<4.0',
        'prettytable',
        'pyelftools',
        'pyusb>=1.0.0b2,<2.0',
        'pywinusb>=0.4.0;platform_system=="Windows"',
        'pyyaml>=5.1,<6.0',
        'six>=1.0,<2.0',
        ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Software Development :: Debuggers",
        "Topic :: Software Development :: Embedded Systems",
    ],
    extras_require={
        'dissassembler': ['capstone'],
    },
    entry_points={
        'console_scripts': [
            'pyocd = pyocd.__main__:main',

            # Keep deprecated tools for compatibility.
            'pyocd-gdbserver = pyocd.tools.gdb_server:main',
            'pyocd-flashtool = pyocd.tools.flash_tool:main',
            'pyocd-tool = pyocd.tools.pyocd:main',
        ],
    },
    packages=find_packages(),
    include_package_data=True,  # include files from MANIFEST.in
    package_data={
        'pyocd': ['debug/svd/svd_data.zip'],
    },
    zip_safe=True,
    options={
        'bdist_wheel': {
            'universal': True,
        },
    },
)
