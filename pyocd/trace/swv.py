# pyOCD debugger
# Copyright (c) 2019-2020 Arm Limited
# Copyright (c) 2020 Patrick Huesmann
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

import logging
import threading
from time import sleep

from .sink import TraceEventSink
from .events import TraceITMEvent
from .swo import SWOParser
from ..coresight.itm import ITM
from ..coresight.tpiu import TPIU
from ..core.target import Target
from ..core import exceptions
from ..probe.debug_probe import DebugProbe
from ..utility.server import StreamServer

LOG = logging.getLogger(__name__)

class SWVEventSink(TraceEventSink):
    """! @brief Trace event sink that converts ITM packets to a text stream."""
    
    def __init__(self, console):
        """! @brief Constructor.
        @param self
        @param console File-like object to which SWV data will be written.
        """
        self._console = console
    
    def receive(self, event):
        """! @brief Handle an SWV trace event.
        @param self
        @param event An instance of TraceITMEvent. If the event is not this class, or isn't
            for ITM port 0, then it will be ignored. The individual bytes of 16- or 32-bit events
            will be extracted and written to the console.
        """
        if not isinstance(event, TraceITMEvent):
            return

        # Extract bytes.
        if event.width == 1:
            data = chr(event.data)
        elif event.width == 2:
            data = chr(event.data & 0xff) + chr((event.data >> 8) & 0xff)
        elif event.width == 4:
            data = (chr(event.data & 0xff)
                    + chr((event.data >> 8) & 0xff)
                    + chr((event.data >> 16) & 0xff)
                    + chr((event.data >> 24) & 0xff))

        self._console.write(data)

class SWVReader(threading.Thread):
    """! @brief Sets up SWV and processes data in a background thread."""

    def __init__(self, session, core_number=0, lock=None):
        """! @brief Constructor.
        @param self
        @param session The Session instance.
        @param core_number The number of the core being traced. Default is core 0.
        """
        super(SWVReader, self).__init__()
        self.name = "SWVReader"
        self.daemon = True
        self._session = session
        self._core_number = core_number
        self._shutdown_event = threading.Event()
        self._swo_clock = 0
        self._lock = lock
        
        self._session.subscribe(self._reset_handler, Target.Event.POST_RESET, self._session.target.cores[core_number])
        
    def init(self, sys_clock, swo_clock, console):
        """! @brief Configures trace graph and starts thread.
        
        This method performs all steps required to start up SWV. It first calls the target's
        trace_start() method, which allows for target-specific trace initialization. Then it
        configures the TPIU and ITM modules. A simple trace data processing graph is created that
        connects an SWVEventSink with a SWOParser. Finally, the reader thread is started.
        
        If the debug probe does not support SWO, a warning is printed but nothing else is done.
        
        @param self
        @param sys_clock
        @param swo_clock
        @param console
        """
        self._swo_clock = swo_clock
        
        if DebugProbe.Capability.SWO not in self._session.probe.capabilities:
            LOG.warning("Probe %s does not support SWO", self._session.probe.unique_id)
            return
        
        self._session.target.trace_start()
        
        itm = self._session.target.get_first_child_of_type(ITM)
        tpiu = self._session.target.get_first_child_of_type(TPIU)

        itm.init()
        itm.enable()
        tpiu.init()

        if tpiu.set_swo_clock(swo_clock, sys_clock):
            LOG.info("Set SWO clock to %d", swo_clock)
        else:
            LOG.warning("Failed to set SWO clock rate")
            return

        self._parser = SWOParser(self._session.target.cores[self._core_number])
        self._sink = SWVEventSink(console)
        self._parser.connect(self._sink)
        
        self.start()
    
    def stop(self):
        """! @brief Stops processing SWV data.
        
        The reader thread is terminated first, then the ITM is disabled. The last step is to call
        the target's trace_stop() method.
        
        Does nothing if the init() method did not complete successfully.
        """
        if not self.is_alive():
            return

        self._shutdown_event.set()
        self.join()

        itm = self._session.target.get_first_child_of_type(ITM)
        itm.disable()
        
        self._session.target.trace_stop()
    
    def run(self):
        """! @brief SWV reader thread routine.
        
        Starts the probe receiving SWO data by calling DebugProbe.swo_start(). For as long as the
        thread runs, it reads SWO data from the probe and passes it to the SWO parser created in
        init(). When the thread is signaled to stop, it calls DebugProbe.swo_stop() before exiting.
        """

        if self._lock:
            self._lock.acquire()

        swv_raw_server = StreamServer(
                            self._session.options.get('swv_raw_port'),
                            serve_local_only=self._session.options.get('serve_local_only'),
                            name="SWV raw",
                            is_read_only=True) \
                         if self._session.options.get('swv_raw_enable') else None

        # Stop SWO first in case the probe already had it started. Ignore if this fails.
        try:
            self._session.probe.swo_stop()
        except exceptions.ProbeError:
            pass
        self._session.probe.swo_start(self._swo_clock)
        
        while not self._shutdown_event.is_set():
            data = self._session.probe.swo_read()
            if data:
                if swv_raw_server:
                    swv_raw_server.write(data)
                self._parser.parse(data)
        
            if self._lock:
                self._lock.release()

            sleep(0.001)

            if self._lock:
                self._lock.acquire()
            
        self._session.probe.swo_stop()

        if swv_raw_server:
            swv_raw_server.stop()
    
        if self._lock:
            self._lock.release()
    
    def _reset_handler(self, notification):
        """! @brief Reset notification handler.
        
        If the target is reset while the SWV reader is running, then the Target::trace_start()
        method is called to reinit trace output.
        """
        if self.is_alive():
            self._session.target.trace_start()

