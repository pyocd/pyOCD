# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
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
    """! @brief Parent of all errors pyOCD can raise"""
    pass

class InternalError(Error):
    """! @brief Internal consistency or logic error.
    
    This error indicates that something has happened that shouldn't be possible.
    """
    pass

class TimeoutError(Error):
    """! @brief Any sort of timeout"""
    pass

class TargetSupportError(Error):
    """! @brief Error related to target support"""
    pass

class ProbeError(Error):
    """! @brief Error communicating with the debug probe"""
    pass

class ProbeDisconnected(ProbeError):
    """! @brief The connection to the debug probe was lost"""
    pass

class TargetError(Error):
    """! @brief An error that happens on the target"""
    pass

class DebugError(TargetError):
    """! @brief Error controlling target debug resources"""
    pass

class CoreRegisterAccessError(DebugError):
    """! @brief Failure to read or write a core register."""
    pass

class TransferError(DebugError):
    """! @brief Error ocurred with a transfer over SWD or JTAG"""
    pass

class TransferTimeoutError(TransferError):
    """! @brief An SWD or JTAG timeout occurred"""
    pass

class TransferFaultError(TransferError):
    """! @brief A memory fault occurred.
    
    This exception class is extended to optionally record the start address and an optional length of the
    attempted memory access that caused the fault. The address and length, if available, will be included
    in the description of the exception when it is converted to a string.
    
    Positional arguments passed to the constructor are passed through to the superclass'
    constructor, and thus operate like any other standard exception class. Keyword arguments of
    'fault_address' and 'length' can optionally be passed to the constructor to initialize the fault
    start address and length. Alternatively, the corresponding property setters can be used after
    the exception is created.
    """
    def __init__(self, *args, **kwargs):
        super(TransferFaultError, self).__init__(*args)
        self._address = kwargs.get('fault_address', None)
        self._length = kwargs.get('length', None)

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
        desc = "Memory transfer fault"
        if self.args:
            if len(self.args) == 1:
                desc += " (" + str(self.args[0]) + ")"
            else:
                desc += " " + str(self.args) + ""
        if self._address is not None:
            desc += " @ 0x%08x" % self._address
            if self._length is not None:
                desc += "-0x%08x" % self.fault_end_address
        return desc
  
class FlashFailure(TargetError):
    """! @brief Exception raised when flashing fails for some reason.
    
    Positional arguments passed to the constructor are passed through to the superclass'
    constructor, and thus operate like any other standard exception class. The flash address that
    failed and/or result code from the algorithm can optionally be recorded in the exception, if
    passed to the constructor as 'address' and 'result_code' keyword arguments.
    """
    def __init__(self, *args, **kwargs):
        super(FlashFailure, self).__init__(*args)
        self._address = kwargs.get('address', None)
        self._result_code = kwargs.get('result_code', None)
    
    @property
    def address(self):
        return self._address
    
    @property
    def result_code(self):
        return self._result_code

    def __str__(self):
        desc = super(FlashFailure, self).__str__()
        parts = []
        if self.address is not None:
            parts.append("address 0x%08x" % self.address)
        if self.result_code is not None:
            parts.append("result code 0x%x" % self.result_code)
        if parts:
            if desc:
                desc += " "
            desc += "(%s)" % ("; ".join(parts))
        return desc

class FlashEraseFailure(FlashFailure):
    """! @brief An attempt to erase flash failed. """
    pass

class FlashProgramFailure(FlashFailure):
    """! @brief An attempt to program flash failed. """
    pass

class CommandError(Error):
    """! @brief Raised when a command encounters an error."""
    pass

