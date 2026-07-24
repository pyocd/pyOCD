# pyOCD debugger
# Copyright (c) 2019-2020,2026 Arm Limited
# Copyright (c) 2020 Patrick Huesmann
# Copyright (c) 2021-2022 Chris Reed
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
from pathlib import Path
import threading
from time import sleep
from typing import (Optional, BinaryIO, TextIO, TYPE_CHECKING)

from .sink import TraceEventSink
from .events import (TraceEvent, TraceITMEvent)
from .swo import SWOParser
from ..coresight.itm import ITM
from ..coresight.tpiu import TPIU
from ..core import exceptions
from ..probe.debug_probe import DebugProbe
from ..utility.server import StreamServer
from ..debug.sequences.delegates import TraceSetup

if TYPE_CHECKING:
    from ..core.session import Session
    from ..utility.notification import Notification

LOG = logging.getLogger(__name__)

class SWVEventSink(TraceEventSink):
    """@brief Trace event sink that converts ITM packets to a text stream."""

    def __init__(self, console: Optional[TextIO]) -> None:
        """@brief Constructor.
        @param self
        @param console File-like object to which SWV data will be written. If None, decoded
            text output is suppressed (raw data still flows to swv_raw_file/swv_raw_port).
        """
        self._console = console

    def receive(self, event: TraceEvent) -> None:
        """@brief Handle an SWV trace event.
        @param self
        @param event An instance of TraceITMEvent. If the event is not this class, or isn't
            for ITM port 0, then it will be ignored. The individual bytes of 16- or 32-bit events
            will be extracted and written to the console.
        """
        if self._console is None:
            return

        if not isinstance(event, TraceITMEvent):
            return

        if event.port != 0:
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
        else:
            return

        self._console.write(data)

class SWVReader(threading.Thread):
    """@brief Sets up SWV and processes data in a background thread."""

    def __init__(self, session: "Session", core_number: int = 0) -> None:
        """@brief Constructor.
        @param self
        @param session The Session instance.
        @param core_number The number of the core being traced. Default is core 0.
        """
        super().__init__(name="SWVReader", daemon=True)
        self._session = session
        self._core_number = core_number
        self._shutdown_event = threading.Event()
        self._sys_clock = 0
        self._swo_clock = 0
        self._is_subscribed = False
        self._trace_data_lock = threading.Lock()
        self._swv_raw_file: Optional[BinaryIO] = None

        target = self._session.target
        assert target
        self._target = target
        self._core = target.cores[core_number]
        if target.debug_sequence_delegate is not None:
            self._trace_setup = target.debug_sequence_delegate.trace_setup
        else:
            self._trace_setup = TraceSetup.LEGACY

    def _init_components(self, sys_clock: int, swo_clock: int) -> bool:
        """@brief Configure the target's standard SWV trace components."""
        if self._trace_setup == TraceSetup.FULL:
            # The target's debug sequence delegate is responsible for configuring the trace components
            return True

        itm = self._target.get_first_child_of_type(ITM)
        if not itm:
            LOG.warning("SWV not initalized: Target does not have ITM component")
            return False
        tpiu = self._target.get_first_child_of_type(TPIU, 'has_swo_uart')
        if not tpiu:
            LOG.warning("SWV not initalized: Target does not have TPIU component with SWO UART mode")
            return False

        itm.init()
        itm.enable()
        tpiu.init()

        if tpiu.set_swo_clock(swo_clock, sys_clock):
            LOG.info("Set SWO clock to %d", swo_clock)
            return True
        else:
            LOG.warning("SWV not initalized: Failed to set SWO clock rate")
            return False

    def init(self, sys_clock: int, swo_clock: int, console: Optional[TextIO]) -> bool:
        """@brief Configures trace graph and starts thread.

        This method performs all steps required to start up SWV. It first configures the TPIU and
        ITM modules. A simple trace data processing graph is created that connects an SWVEventSink
        with a SWOParser. Finally, the reader thread is started.

        If the debug probe or target do not support SWO, a warning is printed and False returns,
        but nothing else is done (no exception raised).

        @param self
        @param sys_clock System clock frequency in Hertz, from which the SWO clock is derived.
        @param swo_clock Desired SWO output frequency in Hertz.
        @param console File-like object to which SWV data will be written. If None, decoded
            text output is suppressed.

        @return Boolean indicating whether the SWV reader was successfully started.
        """
        self._sys_clock = sys_clock
        self._swo_clock = swo_clock

        assert self._session.probe
        if DebugProbe.Capability.SWO not in self._session.probe.capabilities:
            LOG.warning(f"SWV not initalized: Probe {self._session.probe.unique_id} does not support SWO")
            return False

        if not self._init_components(sys_clock, swo_clock):
            return False

        self._parser = SWOParser(self._core)
        self._sink = SWVEventSink(console)
        self._parser.connect(self._sink)

        self._session.subscribe(self._reset_handler, self._session.Event.TRACE_RESTART, self._session)
        if self._session.ctrace_run is not None:
            self._session.subscribe(self._trace_data_handler,
                                    (self._session.Event.TRACE_DATA_FLUSH, self._session.Event.TRACE_DATA_CAPTURE),
                                    self._session)
        self._is_subscribed = True

        self.start()

        return True

    def stop(self) -> None:
        """@brief Stops processing SWV data.

        The reader thread is terminated first, then the ITM is disabled.

        Does nothing if the init() method did not complete successfully.
        """
        if self._is_subscribed:
            self._session.unsubscribe(self._reset_handler, self._session.Event.TRACE_RESTART)
            if self._session.ctrace_run is not None:
                self._session.unsubscribe(self._trace_data_handler,
                                          (self._session.Event.TRACE_DATA_FLUSH,
                                           self._session.Event.TRACE_DATA_CAPTURE))
            self._is_subscribed = False

        if not self.is_alive():
            return

        self._shutdown_event.set()
        self.join()

        if self._trace_setup == TraceSetup.LEGACY:
            # init() should never have started the SWV thread unless the target has ITM and TPIU.
            itm = self._target.get_first_child_of_type(ITM)
            assert itm
            itm.disable()

    def run(self) -> None:
        """@brief SWV reader thread routine.

        Starts the probe receiving SWO data by calling DebugProbe.swo_start(). For as long as the
        thread runs, it reads SWO data from the probe and passes it to the SWO parser created in
        init(). When the thread is signaled to stop, it calls DebugProbe.swo_stop() before exiting.
        """
        assert self._session.probe

        swv_raw_server = None
        if self._session.options.get('swv_raw_enable'):
            raw_file_name = self._session.options.get('swv_raw_file')
            if raw_file_name:
                if self._session.ctrace_run is None:
                    # swv_raw_file takes precedence over swv_raw_port.
                    raw_file_path = Path(raw_file_name).expanduser()
                    try:
                        self._swv_raw_file = raw_file_path.open('wb')
                    except OSError as err:
                        LOG.warning("Failed to open SWV raw output file '%s': %s", raw_file_path, err)
            else:
                swv_raw_server = StreamServer(
                                    self._session.options.get('swv_raw_port'),
                                    serve_local_only=self._session.options.get('serve_local_only'),
                                    name="SWV raw",
                                    is_read_only=True)

        # Stop SWO first in case the probe already had it started. Ignore if this fails.
        try:
            self._session.probe.swo_stop()
        except exceptions.ProbeError:
            pass
        self._session.probe.swo_start(self._swo_clock)

        while not self._shutdown_event.is_set():
            with self._trace_data_lock:
                data = self._session.probe.swo_read()
                if data:
                    if self._swv_raw_file:
                        self._swv_raw_file.write(data)
                    elif swv_raw_server:
                        swv_raw_server.write(data)
                    self._parser.parse(data)

            sleep(0.001)

        self._session.probe.swo_stop()

        with self._trace_data_lock:
            if self._swv_raw_file:
                self._swv_raw_file.flush()
                self._swv_raw_file.close()
                self._swv_raw_file = None

        if swv_raw_server:
            swv_raw_server.stop()

    def _reset_handler(self, notification: "Notification") -> None:
        """@brief Reconfigure SWV components after target trace support has restarted."""
        if not self.is_alive():
            return

        try:
            self._init_components(self._sys_clock, self._swo_clock)
        except exceptions.Error:
            LOG.warning("Failed to reinitialize SWV after reset", exc_info=self._session.log_tracebacks)

    def _trace_data_handler(self, notification: "Notification") -> None:
        """Open or flush the raw trace output file."""
        with self._trace_data_lock:
            if notification.event == self._session.Event.TRACE_DATA_CAPTURE:
                raw_file_name = self._session.options.get('swv_raw_file')
                if not raw_file_name:
                    return
                try:
                    if self._swv_raw_file is not None:
                        self._swv_raw_file.close()
                    mode = 'wb' if notification.data else 'ab'
                    self._swv_raw_file = Path(raw_file_name).expanduser().open(mode)
                except OSError as err:
                    self._swv_raw_file = None
                    LOG.warning("Failed to open SWV raw output file '%s': %s", raw_file_name, err)
                return

            if self._swv_raw_file is None:
                return

            raw_file = self._swv_raw_file
            self._swv_raw_file = None
            try:
                with raw_file:
                    while data := self._session.probe.swo_read():
                        raw_file.write(data)
                        self._parser.parse(data)
            except (OSError, exceptions.ProbeError) as err:
                LOG.warning("Failed to update SWV raw output file: %s", err)
