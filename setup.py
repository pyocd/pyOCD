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
from setuptools import setup, find_packages
import zipfile

# Get the directory containing this setup.py. Even though full paths are used below, we must
# chdir in order for setuptools-scm to successfully pick up the version.
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
os.chdir(SCRIPT_DIR)

# Get the readme content.
readme_path = os.path.join(SCRIPT_DIR, "README.md")
with open(readme_path, mode='r', encoding='utf-8') as f:
    readme = f.read()

# Build zip of SVD files.
#
# The SVD files are stored individually in the data/ directory only in the repo. For both sdist and
# wheel, the svd_data.zip file is used rather than including the data directory. Thus, this setup
# script needs to skip building svd_data.zip if the data/ directory is not present.
svd_dir_path = os.path.join(SCRIPT_DIR, "pyocd", "debug", "svd")
svd_data_dir_path = os.path.join(svd_dir_path, "data")
svd_zip_path = os.path.join(svd_dir_path, "svd_data.zip")
if os.path.exists(svd_data_dir_path):
    with zipfile.ZipFile(svd_zip_path, 'w', zipfile.ZIP_DEFLATED) as svd_zip:
        for name in sorted(os.listdir(svd_data_dir_path)):
            svd_zip.write(os.path.join(svd_data_dir_path, name), name)
elif not os.path.exists(svd_zip_path):
    raise RuntimeError("neither the source SVD data directory nor built svd_data.zip exist")

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
    author="Chris Reed, Martin Kojtal",
    author_email="chris.reed@arm.com, martin.kojtal@arm.com",
    url='https://github.com/pyocd/pyOCD',
    license="Apache 2.0",
    python_requires=">=3.6.0",
    install_requires = [
        'capstone>=4.0,<5.0',
        'cmsis-pack-manager>=0.2.10',
        'colorama<1.0',
        'hidapi;platform_system!="Linux"', # Use hidapi on macOS and Windows
        'intelhex>=2.0,<3.0',
        'intervaltree>=3.0.2,<4.0',
        'naturalsort>=1.5,<2.0',
        'prettytable>=2.0,<3.0',
        'pyelftools<1.0',
        'pylink-square>=0.8.2,<1.0',
        'pyocd_pemicro>=1.0.0.post2', # Only supports python 3.6+
        'pyusb>=1.2.1,<2.0',
        'pyyaml>=5.1,<6.0',
        'six>=1.15.0,<2.0',
        ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Software Development :: Debuggers",
        "Topic :: Software Development :: Embedded Systems",
    ],
    entry_points={
        'console_scripts': [
            'pyocd = pyocd.__main__:main',

            # Keep deprecated tools for compatibility.
            'pyocd-gdbserver = pyocd.tools.gdb_server:main',
        ],
        'pyocd.probe': [
            'cmsisdap = pyocd.probe.cmsis_dap_probe:CMSISDAPProbePlugin',
            'jlink = pyocd.probe.jlink_probe:JLinkProbePlugin',
            'picoprobe = pyocd.probe.picoprobe:PicoprobePlugin',
            'remote = pyocd.probe.tcp_client_probe:TCPClientProbePlugin',
            'stlink = pyocd.probe.stlink_probe:StlinkProbePlugin',
        ],
        'pyocd.rtos': [
            'argon = pyocd.rtos.argon:ArgonPlugin',
            'freertos = pyocd.rtos.freertos:FreeRTOSPlugin',
            'rtx5 = pyocd.rtos.rtx5:RTX5Plugin',
            'threadx = pyocd.rtos.threadx:ThreadXPlugin',
            'zephyr = pyocd.rtos.zephyr:ZephyrPlugin',
        ],
    },
    packages=find_packages(),
    include_package_data=True,  # include files from MANIFEST.in
    package_data={
        'pyocd': ['debug/svd/svd_data.zip'],
    },
    zip_safe=True,
)
