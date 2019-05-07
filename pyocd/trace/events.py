# pyOCD debugger
# Copyright (c) 2017-2019 Arm Limited
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

class TraceEvent(object):
    """! @brief Base trace event class."""
    def __init__(self, desc="", ts=0):
        self._desc = desc
        self._timestamp = ts
    
    @property
    def timestamp(self):
        return self._timestamp
    
    @timestamp.setter
    def timestamp(self, ts):
        self._timestamp = ts
        
    def __str__(self):
        return "[{}] {}".format(self._timestamp, self._desc)

    def __repr__(self):
        return "<{}: {}>".format(self.__class__.__name__, str(self))

class TraceOverflow(TraceEvent):
    """! @brief Trace overflow event."""
    def __init__(self, ts=0):
        super(TraceOverflow, self).__init__("overflow", ts)

class TraceTimestamp(TraceEvent):
    """! @brief Trace local timestamp."""
    def __init__(self, tc, ts=0):
        super(TraceTimestamp, self).__init__("timestamp", ts)
        self._tc = 0
    
    @property
    def tc(self):
        return self._tc
        
    def __str__(self):
        return "[{}] local timestamp TC={:#x} {}".format(self._timestamp, self.tc, self.timestamp)

class TraceITMEvent(TraceEvent):
    """! @brief Trace ITM stimulus port event."""
    def __init__(self, port, data, width, ts=0):
        super(TraceITMEvent, self).__init__("itm", ts)
        self._port = port
        self._data = data
        self._width = width
    
    @property
    def port(self):
        return self._port
    
    @property
    def data(self):
        return self._data
    
    @property
    def width(self):
        return self._width
    
    def __str__(self):
        width = self.width
        if width == 1:
            d = "{:#04x}".format(self.data)
        elif width == 2:
            d = "{:#06x}".format(self.data)
        else:
            d = "{:#010x}".format(self.data)
        return "[{}] ITM: port={:d} data={}".format(self.timestamp, self.port, d)

class TraceEventCounter(TraceEvent):
    """! @brief Trace DWT counter overflow event."""
    CPI_MASK = 0x01
    EXC_MASK = 0x02
    SLEEP_MASK = 0x04
    LSU_MASK = 0x08
    FOLD_MASK = 0x10
    CYC_MASK = 0x20

    def __init__(self, counterMask, ts=0):
        super(TraceEventCounter, self).__init__("exception", ts)
        self._mask = counterMask
    
    @property
    def counter_mask(self):
        return self._mask
    
    def _get_event_desc(self, evt):
        msg = ""
        if evt & TraceEventCounter.CYC_MASK:
            msg += " Cyc"
        if evt & TraceEventCounter.FOLD_MASK:
            msg += " Fold"
        if evt & TraceEventCounter.LSU_MASK:
            msg += " LSU"
        if evt & TraceEventCounter.SLEEP_MASK:
            msg += " Sleep"
        if evt & TraceEventCounter.EXC_MASK:
            msg += " Exc"
        if evt & TraceEventCounter.CPI_MASK:
            msg += " CPI"
        return msg
    
    def __str__(self):
        return "[{}] DWT: Event:{}".format(self.timestamp, self._get_event_desc(self.counter_mask))

class TraceExceptionEvent(TraceEvent):
    """! @brief Exception trace event."""
    ENTERED = 1
    EXITED = 2
    RETURNED = 3

    ACTION_DESC = {
        ENTERED : "Entered",
        EXITED : "Exited",
        RETURNED : "Returned"
        }
    
    def __init__(self, exceptionNumber, exceptionName, action, ts=0):
        super(TraceExceptionEvent, self).__init__("exception", ts)
        self._number = exceptionNumber
        self._name = exceptionName
        self._action = action
    
    @property
    def exception_number(self):
        return self._number
    
    @property
    def exception_name(self):
        return self._name
    
    @property
    def action(self):
        return self._action
    
    def __str__(self):
        action = TraceExceptionEvent.ACTION_DESC.get(self.action, "<invalid action>")
        return "[{}] DWT: Exception #{:d} {} {}".format(self.timestamp, self.exception_number, action, self.exception_name)

class TracePeriodicPC(TraceEvent):
    """! @brief Periodic PC trace event."""
    def __init__(self, pc, ts=0):
        super(TracePeriodicPC, self).__init__("pc", ts)
        self._pc = pc

    @property
    def pc(self):
        return self._pc
    
    def __str__(self):
        return "[{}] DWT: PC={:#010x}".format(self.timestamp, self.pc)

class TraceDataTraceEvent(TraceEvent):
    """! @brief DWT data trace event.
    
    Valid combinations:
    - PC value.
    - Bits[15:0] of a data address.
    - Data value, whether it was read or written, and the transfer size.
    - PC value, data value, whether it was read or written, and the transfer size.
    - Bits[15:0] of a data address, data value, whether it was read or written, and the transfer size.
    """
    def __init__(self, cmpn=None, pc=None, addr=None, value=None, rnw=None, sz=None, ts=0):
        super(TraceDataTraceEvent, self).__init__("data-trace", ts)
        self._cmpn = cmpn
        self._pc = pc
        self._addr = addr
        self._value = value
        self._rnw = rnw
        self._sz = sz

    @property
    def comparator(self):
        return self._cmpn

    @property
    def pc(self):
        return self._pc
    
    @property
    def address(self):
        return self._addr
    
    @property
    def value(self):
        return self._value
    
    @property
    def is_read(self):
        return self._rnw
    
    @property
    def transfer_size(self):
        return self._sz
    
    def __str__(self):
        hasPC = self.pc is not None
        hasAddress = self.address is not None
        hasValue = self.value is not None
        if hasPC:
            msg = "PC={:#010x}".format(self.pc)
        elif hasAddress:
            msg = "Addr[15:0]={:#06x}".format(self.address)
        else:
            msg = ""
        if hasValue:
            width = self.transfer_size
            rnw = "R" if self.is_read else "W"
            if width == 1:
                msg +=  " Value={}:{:#04x}".format(rnw, self.value)
            elif width == 2:
                msg +=  " Value={}:{:#06x}".format(rnw, self.value)
            else:
                msg += " Value={}:{:#010x}".format(rnw, self.value)
        return "[{}] DWT: Data Trace {}".format(self.timestamp, msg.strip())

