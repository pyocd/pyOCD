# pyOCD debugger
# Copyright (c) 2006-2013,2018 Arm Limited
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


class Interface(object):

    def __init__(self):
        self.vid = 0
        self.pid = 0
        self.vendor_name = ""
        self.product_name = ""
        self.serial_number = ""
        self.packet_count = 1
        self.packet_size = 64
    
    @property
    def has_swo_ep(self):
        return False

    def open(self):
        return

    def close(self):
        return

    def write(self, data):
        return

    def read(self, size=-1, timeout=-1):
        return

    def get_info(self):
        return self.vendor_name + " " + \
               self.product_name + " (" + \
               str(hex(self.vid)) + ", " + \
               str(hex(self.pid)) + ")"

    def get_packet_count(self):
        return self.packet_count

    def set_packet_count(self, count):
        # No interface level restrictions on count
        self.packet_count = count

    def set_packet_size(self, size):
        self.packet_size = size

    def get_packet_size(self):
        return self.packet_size

    def get_serial_number(self):
        return self.serial_number
