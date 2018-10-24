"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013 ARM Limited

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

from ...flash.flash import Flash

class Flash_cortex_m(Flash):

    def __init__(self, target):
        super(Flash_cortex_m, self).__init__(target, None)

    def init(self):
        raise Exception("Unsupported flash operation on generic cortex_m")

    def compute_crcs(self, sectors):
        raise Exception("Unsupported flash operation on generic cortex_m")

    def erase_all(self):
        raise Exception("Unsupported flash operation on generic cortex_m")

    def erase_page(self, flashPtr):
        raise Exception("Unsupported flash operation on generic cortex_m")

    def program_page(self, flashPtr, bytes):
        raise Exception("Unsupported flash operation on generic cortex_m")

    def get_page_info(self, addr):
        raise Exception("Unsupported flash operation on generic cortex_m")

    def get_flash_info(self):
        raise Exception("Unsupported flash operation on generic cortex_m")
