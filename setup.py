"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2012-2015 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

from setuptools import setup, find_packages
import sys

install_requires = dict(
    win32=['pyWinUSB'],
    linux2=['pyUSB'],
    darwin=['hidapi']
)

setup(
    name="pyOCD",
    use_scm_version={
        'local_scheme': 'dirty-tag',
        'write_to': 'pyOCD/_version.py'
    },
    setup_requires=['setuptools-scm!=1.5.3,!=1.5.4'],
    description="CMSIS-DAP debugger for Python",
    long_description=open('README.rst', 'Ur').read(),
    author="samux, emilmont",
    author_email="Samuel.Mokrani@arm.com, Emilio.Monti@arm.com",
    url='https://github.com/mbedmicro/pyOCD',
    license="Apache 2.0",
    install_requires=install_requires[sys.platform] + ['intelhex'],
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python",
    ],
    extras_require={
        'dissassembler': ['capstone']
    },
    entry_points={
        'console_scripts': [
            'pyocd-gdbserver = pyOCD.tools.gdb_server:main',
            'pyocd-flashtool = pyOCD.tools.flash_tool:main',
            'pyocd-tool = pyOCD.tools.pyocd:main',
        ],
    },
    use_2to3=True,
    packages=find_packages(),
    include_package_data=True,  # include files from MANIFEST.in
)
