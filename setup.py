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
import sys
from setuptools import setup, find_packages

install_requires = []
if sys.platform.startswith('linux'):
    install_requires.extend([
        'pyusb',
    ])
elif sys.platform.startswith('win'):
    install_requires.extend([
        'pywinusb',
    ])
elif sys.platform.startswith('darwin'):
    install_requires.extend([
        'hidapi',
    ])


setup(
    name="pyOCD",
    version="0.4.2",
    description="CMSIS-DAP debugger for Python",
    author="samux, emilmont",
    author_email="Samuel.Mokrani@arm.com, Emilio.Monti@arm.com",
    license="Apache 2.0",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python",
    ],
    entry_points={
        'console_scripts': [
            'pyocd-gdbserver = pyOCD.tools.gdb_server:main',
            'pyocd-flashtool = pyOCD.tools.flash_tool:main',
            'pyocd-tool = pyOCD.tools.pyocd:main',
        ],
    },
    install_requires=install_requires,
    use_2to3=True,
    packages=find_packages(),
    include_package_data=True,  # include files from MANIFEST.in
)
