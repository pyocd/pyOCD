# pyOCD debugger
# Copyright (c) 2017-2019 Arm Limited
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

from . import events

class SWOParser(object):
    """! @brief SWO data stream parser.
    
    Processes a stream of SWO data and generates TraceEvent objects. SWO data is passed to the
    parse() method. It processes the data and creates TraceEvent objects which are passed to an
    event sink object that is a subclass of TraceEventSink. The event sink must either be provided
    when the SWOParser is constructed, or can be set using the connect() method.
    
    A SWOParser instance can be reused for multiple SWO sessions. If a break in SWO data streaming
    occurs, the reset() method should be called before passing further data to parse().
    """
    def __init__(self, core, sink=None):
        self.reset()
        self._core = core
        self._sink = sink
    
    def reset(self):
        self._bytes_parsed = 0
        self._itm_page = 0
        self._timestamp = 0
        self._pending_events = []
        self._pending_data_trace = None
        
        # Get generator instance and prime it.
        self._parser = self._parse()
        next(self._parser)
    
    def connect(self, sink):
        """! @brief Connect the downstream trace sink or filter."""
        self._sink = sink

    @property
    def bytes_parsed(self):
        """! @brief The number of bytes of SWO data parsed thus far."""
        return self._bytes_parsed

    def parse(self, data):
        """! @brief Process SWO data.
        
        This method will return once the provided data is consumed, and can be called again when
        more data is available. There is no minimum or maximum limit on the size of the provided
        data. As trace events are identified during parsing, they will be passed to the event
        sink object passed into the constructor or connect().
        
        @param self
        @param data A sequence of integer byte values, usually a bytearray.
        """
        for value in data:
            self._parser.send(value)
            self._bytes_parsed += 1
    
    def _flush_events(self):
        """! @brief Send all pending events to event sink."""
        if self._sink is not None:
            for event in self._pending_events:
                self._sink.receive(event)
        self._pending_events = []
    
    def _merge_data_trace_events(self, event):
        """! @brief Look for pairs of data trace events and merge."""
        if isinstance(event, events.TraceDataTraceEvent):
            # Record the first data trace event.
            if self._pending_data_trace is None:
                self._pending_data_trace = event
            else:
                # We've got the second in a pair. If the comparator numbers are the same, then
                # we can merge the two events. Otherwise we just add them to the pending event
                # queue separately.
                if event.comparator == self._pending_data_trace.comparator:
                    # Merge the two data trace events.
                    ev = events.TraceDataTraceEvent(cmpn=event.comparator,
                        pc=(event.pc or self._pending_data_trace.pc),
                        addr=(event.address or self._pending_data_trace.address),
                        value=(event.value or self._pending_data_trace.value),
                        rnw=(event.is_read or self._pending_data_trace.is_read),
                        sz=(event.transfer_size or self._pending_data_trace.transfer_size),
                        ts=self._pending_data_trace.timestamp)
                else:
                    ev = self._pending_data_trace
                self._pending_events.append(ev)
                self._pending_data_trace = None
            return True
        # If we get a non-data-trace event while waiting for a second data trace event, then
        # just place the pending data trace event in the pending event queue.
        elif self._pending_data_trace is not None:
            self._pending_events.append(self._pending_data_trace)
            self._pending_data_trace = None
        return False
    
    def _send_event(self, event):
        """! @brief Process event objects and decide when to send to event sink.
        
        This method handles the logic to associate a timestamp event with the prior other
        event. A list of pending events is built up until either a timestamp or overflow event
        is generated, at which point all pending events are flushed to the event sink. If a
        timestamp is seen, the timestamp of all pending events is set prior to flushing.
        """
        flush = False
        
        # Handle merging data trace events.
        if self._merge_data_trace_events(event):
            return
        
        if isinstance(event, events.TraceTimestamp):
            for ev in self._pending_events:
                ev.timestamp = event.timestamp
            flush = True
        else:
            self._pending_events.append(event)
            if isinstance(event, events.TraceOverflow):
                flush = True
        
        if flush:
            self._flush_events()
    
    def _parse(self):
        """! @brief SWO parser as generator function coroutine.
        
        The generator yields every time it needs a byte of SWO data. The caller must use the
        generator's send() method to provide the next byte.
        """
        timestamp = 0
        invalid = False
        while True:
            byte = yield
            hdr = byte
            
            # Sync packet.
            if hdr == 0:
                packets = 0
                while True:
                    # Check for final 1 bit after at least 5 all-zero sync packets
                    if (packets >= 5) and (byte == 0x80):
                        break
                    elif byte == 0:
                        packets += 1
                    else:
                        # Get early non-zero packet, reset sync packet counter.
                        #packets = 0
                        invalid = True
                        break
                    byte = yield
                self._itm_page = 0
            # Overflow packet.
            elif hdr == 0x70:
                self._send_event(events.TraceOverflow(timestamp))
            # Protocol packet.
            elif (hdr & 0x3) == 0:
                c = (hdr >> 7) & 0x1
                d = (hdr >> 4) & 0b111
                # Local timestamp.
                if (hdr & 0xf) == 0 and d not in (0x0, 0x3):
                    ts = 0
                    tc = 0
                    # Local timestamp packet format 1.
                    if c == 1:
                        tc = (hdr >> 4) & 0x3
                        while c == 1:
                            byte = yield
                            ts = (ts << 7) | (byte & 0x7f)
                            c = (byte >> 7) & 0x1
                    # Local timestamp packet format 2.
                    else:
                        ts = (hdr >> 4) & 0x7
                    timestamp += ts
                    self._send_event(events.TraceTimestamp(tc, timestamp))
                # Global timestamp.
                elif hdr in (0b10010100, 0b10110100):
                    # TODO handle global timestamp
                    # t = (hdr >> 5) & 0x1
                    pass
                # Extension.
                elif (hdr & 0x8) == 0x8:
                    sh = (hdr >> 2) & 0x1
                    if c == 0:
                        ex = (hdr >> 4) & 0x7
                    else:
                        ex = 0
                        while c == 1:
                            byte = yield
                            ex = (ex << 7) | (byte & 0x7f)
                            c = (byte >> 7) & 0x1
                    if sh == 0:
                        # Extension packet with sh==0 sets ITM stimulus page.
                        self._itm_page = ex
                    else:
                        #self._send_event(events.TraceEvent("Extension: SH={:d} EX={:#x}\n".format(sh, ex), timestamp))
                        invalid = True
                # Reserved packet.
                else:
                    invalid = True
            # Source packet.
            else:
                ss = hdr & 0x3
                l = 1 << (ss - 1)
                a = (hdr >> 3) & 0x1f
                if l == 1:
                    payload = yield
                elif l == 2:
                    byte1 = yield
                    byte2 = yield
                    payload = (byte1 | 
                                (byte2 << 8))
                else:
                    byte1 = yield
                    byte2 = yield
                    byte3 = yield
                    byte4 = yield
                    payload = (byte1 | 
                                (byte2 << 8) |
                                (byte3 << 16) |
                                (byte4 << 24))
                
                # Instrumentation packet.
                if (hdr & 0x4) == 0:
                    port = (self._itm_page * 32) + a
                    self._send_event(events.TraceITMEvent(port, payload, l, timestamp))
                # Hardware source packets...
                # Event counter
                elif a == 0:
                    self._send_event(events.TraceEventCounter(payload, timestamp))
                # Exception trace
                elif a == 1:
                    exceptionNumber = payload & 0x1ff
                    exceptionName = self._core.exception_number_to_name(exceptionNumber, True)
                    fn = (payload >> 12) & 0x3
                    if 1 <= fn <= 3:
                        self._send_event(events.TraceExceptionEvent(exceptionNumber, exceptionName, fn, timestamp))
                    else:
                        invalid = True
                # Periodic PC
                elif a == 2:                        
                    # A payload of 0 indicates a period PC sleep event.
                    self._send_event(events.TracePeriodicPC(payload, timestamp))
                # Data trace
                elif 8 <= a <= 23:
                    type = (hdr >> 6) & 0x3
                    cmpn = (hdr >> 4) & 0x3
                    bit3 = (hdr >> 3) & 0x1
                    # PC value
                    if type == 0b01 and bit3 == 0:
                        self._send_event(events.TraceDataTraceEvent(cmpn=cmpn, pc=payload, ts=timestamp))
                    # Address
                    elif type == 0b01 and bit3 == 1:
                        self._send_event(events.TraceDataTraceEvent(cmpn=cmpn, addr=payload, ts=timestamp))
                    # Data value
                    elif type == 0b10:
                        self._send_event(events.TraceDataTraceEvent(cmpn=cmpn, value=payload, rnw=(bit3 == 0), sz=l, ts=timestamp))
                    else:
                        invalid = True
                # Invalid DWT 'a' value.
                else:
                    invalid = True
        


