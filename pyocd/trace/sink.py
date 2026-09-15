# pyOCD debugger
# Copyright (c) 2017-2019,2026 Arm Limited
# COpyright (c) 2021-2022 Chris Reed
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

import collections.abc
import logging
from pathlib import Path
from typing import (Any, BinaryIO, Dict, Mapping, TYPE_CHECKING, Iterable, List, Optional, Sequence, Union)

from ..utility.server import StreamServer

if TYPE_CHECKING:
    from .events import TraceEvent

LOG = logging.getLogger(__name__)


class TraceDataSink:
    """Base interface for a raw trace output destination."""

    @staticmethod
    def file(path: Path) -> "TraceDataSink":
        """Create a raw trace file destination."""
        return _TraceFileSink(path)

    @staticmethod
    def server(port: int, serve_local_only: bool, name: str) -> "TraceDataSink":
        """Create a raw trace TCP server destination."""
        return _TraceServerSink(port, serve_local_only, name)

    def start(self, changed: bool) -> None:
        """Start a trace capture, resetting output if the configuration changed."""
        raise NotImplementedError()

    def write(self, data: bytes) -> int:
        """Write raw trace data."""
        raise NotImplementedError()

    def flush(self) -> None:
        """Flush data at the end of a capture."""
        raise NotImplementedError()

    def shutdown(self) -> None:
        """Release the output destination."""
        raise NotImplementedError()


class _TraceFileSink(TraceDataSink):
    """Raw trace data written to a file from capture through flush."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._file: Optional[BinaryIO] = None
        self._started = False

    def start(self, changed: bool) -> None:
        self.flush()
        if self._path.parent.name == '.trace':
            self._path.parent.mkdir(exist_ok=True)
        self._file = self._path.open('wb' if changed or not self._started else 'ab')
        self._started = True

    def write(self, data: bytes) -> int:
        if self._file is None:
            return 0
        self._file.write(data)
        return len(data)

    def flush(self) -> None:
        if self._file is not None:
            self._file.flush()
            self._file.close()
            self._file = None

    def shutdown(self) -> None:
        self.flush()


class _TraceServerSink(TraceDataSink):
    """Raw trace data delivered to a TCP client by a StreamServer."""

    def __init__(self, port: int, serve_local_only: bool, name: str) -> None:
        self._server = StreamServer(
            port,
            serve_local_only=serve_local_only,
            name=name,
            is_read_only=True,
        )

    def start(self, changed: bool) -> None:
        pass

    def write(self, data: bytes) -> int:
        return self._server.write(data)

    def flush(self) -> None:
        pass

    def shutdown(self) -> None:
        self._server.stop()


class TraceBufferSinks:
    """Routes named raw trace streams to configured sinks."""

    def __init__(self, session: Any, trace_buffers: Mapping[str, Any]) -> None:
        self._session = session
        self._trace_buffers = trace_buffers
        self._outputs: Dict[str, TraceDataSink] = {}
        self._capture_changed = True
        for name, sink in trace_buffers.items():
            if not sink.enabled:
                continue
            try:
                self._outputs[name] = self._create_output(sink)
            except OSError as err:
                LOG.warning("Failed to initialize TB '%s' output: %s", name, err)
        session.subscribe(self._trace_data_handler, session.Event.TRACE_DATA_CAPTURE, session)
        session.subscribe(self._trace_data_handler, session.Event.TRACE_DATA_FLUSH, session)

    def shutdown(self) -> None:
        self._session.unsubscribe(self._trace_data_handler, self._session.Event.TRACE_DATA_CAPTURE)
        self._session.unsubscribe(self._trace_data_handler, self._session.Event.TRACE_DATA_FLUSH)
        for output in self._outputs.values():
            output.shutdown()
        self._outputs.clear()

    def _trace_data_handler(self, notification: Any) -> None:
        if notification.event == self._session.Event.TRACE_DATA_CAPTURE:
            self._capture_changed = bool(notification.data)
            for name, output in tuple(self._outputs.items()):
                try:
                    output.start(self._capture_changed)
                except OSError as err:
                    LOG.warning("Failed to start TB '%s' output: %s", name, err)
                    del self._outputs[name]
        else:
            for output in self._outputs.values():
                output.flush()

    def write(self, name: str, data: bytes) -> int:
        sink = self._trace_buffers.get(name)
        if sink is None or not sink.enabled:
            raise ValueError(f"TB '{name}' is not selected")

        output = self._outputs.get(name)
        try:
            if output is None:
                output = self._create_output(sink)
                output.start(self._capture_changed)
                self._outputs[name] = output
            return output.write(data)
        except OSError as err:
            raise ValueError(f"failed to write TB '{name}': {err}") from err

    def _create_output(self, trace_buffer: Any) -> TraceDataSink:
        if trace_buffer.mode == 'file' and trace_buffer.file is not None:
            return TraceDataSink.file(Path(trace_buffer.file))
        if trace_buffer.mode == 'server' and trace_buffer.server_port is not None:
            return TraceDataSink.server(trace_buffer.server_port, self._session.options.get('serve_local_only'),
                                        f"TB {trace_buffer.name or 'default'} raw")
        raise ValueError(f"TB '{trace_buffer.name}' has no output destination")


class TraceEventSink:
    """@brief Abstract interface for a trace event sink."""
    def receive(self, event: "TraceEvent") -> None:
        """@brief Handle a single trace event.
        @param self
        @param event An instance of TraceEvent or one of its subclasses.
        """
        raise NotImplementedError()

class TraceEventFilter(TraceEventSink):
    """@brief Abstract interface for a trace event filter."""

    def __init__(self, sink: Optional[TraceEventSink] = None) -> None:
        self._sink = sink

    def connect(self, sink: TraceEventSink) -> None:
        """@brief Connect the downstream trace sink or filter."""
        self._sink = sink

    def receive(self, event: "TraceEvent") -> None:
        """@brief Handle a single trace event.

        Passes the event through the filter() method. If one or more objects are returned, they
        are then passed to the trace sink connected to this filter (which may be another filter).

        @param self
        @param event An instance of TraceEvent or one of its subclasses.
        """
        filtered_event = self.filter(event)
        if (filtered_event is not None) and (self._sink is not None):
            if isinstance(event, collections.abc.Iterable):
                for event_item in event:
                    self._sink.receive(event_item)
            else:
                self._sink.receive(event)

    def filter(self, event: "TraceEvent") -> Union[None, "TraceEvent", Sequence["TraceEvent"]]:
        """@brief Filter a single trace event.

        @param self
        @param event An instance of TraceEvent or one of its subclasses.
        @return Either None, a single TraceEvent, or a sequence of TraceEvents.
        """
        raise NotImplementedError()

class TraceEventTee(TraceEventSink):
    """@brief Trace event sink that replicates events to multiple sinks."""

    def __init__(self) -> None:
        self._sinks: List[TraceEventSink] = []

    def connect(self, sinks: Iterable[TraceEventSink]) -> None:
        """@brief Connect one or more downstream trace sinks.

        @param self
        @param sinks If this parameter is a single object, it will be added to the list of
          downstream trace event sinks. If it is an iterable (list, tuple, etc.), then it will
          completely replace the current list of trace event sinks.
        """
        if isinstance(sinks, collections.abc.Iterable):
            self._sinks = list(sinks)
        elif sinks not in self._sinks:
            self._sinks.append(sinks)

    def receive(self, event: "TraceEvent") -> None:
        """@brief Replicate a single trace event to all connected downstream trace event sinks.

        @param self
        @param event An instance of TraceEvent or one of its subclasses.
        """
        for sink in self._sinks:
            sink.receive(event)
