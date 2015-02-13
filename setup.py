"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2012-2013 ARM Limited

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

from distutils.core import setup

setup(
    name="pyOCD",
    version="0.3",
    description="CMSIS-DAP debugger for Python",
    author="samux, emilmont",
    author_email="Samuel.Mokrani@arm.com, Emilio.Monti@arm.com",
    license="Apache 2.0",
    classifiers = [
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python",
    ],
    use_2to3=True,
    packages=["pyOCD", "pyOCD.flash", "pyOCD.gdbserver", "pyOCD.interface", "pyOCD.target", "pyOCD.transport", "pyOCD.board"]
)
