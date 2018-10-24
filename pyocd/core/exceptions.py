# pyOCD debugger
# Copyright (c) 2018 Arm Limited
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

class Error(RuntimeError):
    """Parent of all errors pyOCD can raise"""
    pass

class ProbeError(Error):
    """Error communicating with device"""
    pass

class TransferError(ProbeError):
    """Error ocurred with a transfer over SWD or JTAG"""
    pass

class TransferTimeoutError(TransferError):
    """A SWD or JTAG timeout occurred"""
    pass

class TransferFaultError(TransferError):
    """A SWD Fault occurred"""
    def __init__(self, faultAddress=None, length=None):
        super(TransferFaultError, self).__init__(faultAddress)
        self._address = faultAddress
        self._length = length

    @property
    def fault_address(self):
        return self._address

    @fault_address.setter
    def fault_address(self, addr):
        self._address = addr
    
    @property
    def fault_end_address(self):
        return (self._address + self._length - 1) if (self._length is not None) else self._address
    
    @property
    def fault_length(self):
        return self._length
    
    @fault_length.setter
    def fault_length(self, length):
        self._length = length

    def __str__(self):
        desc = "SWD/JTAG Transfer Fault"
        if self._address is not None:
            desc += " @ 0x%08x" % self._address
            if self._length is not None:
                desc += "-0x%08x" % self.fault_end_address
        return desc
  
  

