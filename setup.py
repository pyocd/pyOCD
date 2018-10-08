"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2012-2018 ARM Limited

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

setup(
    name="pyOCD",
    use_scm_version={
        'local_scheme': 'dirty-tag',
        'write_to': 'pyOCD/_version.py'
    },
    setup_requires=[
        'setuptools_scm!=1.5.3,!=1.5.4',
        'setuptools_scm_git_archive'
    ],
    description="CMSIS-DAP debugger for Python",
    long_description=open('README.rst', 'r').read(),
    author="Chris Reed, Martin Kojtal, Russ Butler",
    author_email="chris.reed@arm.com, martin.kojtal@arm.com, russ.butler@arm.com",
    url='https://github.com/mbedmicro/pyOCD',
    license="Apache 2.0",
    install_requires = [
        'intelhex',
        'six',
        'enum34;python_version<"3.4"',
        'future',
        'websocket-client',
        'intervaltree',
        'colorama',
        'pyelftools',
        'pyusb>=1.0.0b2',
        'pywinusb>=0.4.0;platform_system=="Windows"',
        'hidapi;platform_system=="Darwin"'
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
    packages=find_packages(),
    include_package_data=True,  # include files from MANIFEST.in
)
