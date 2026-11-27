# pyOCD debugger
# Copyright (c) 2026 Solarboaters
# SPDX-License-Identifier: Apache-2.0

import io
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pyocd.trace.swo import SWOParser
from pyocd.trace.swv import SWVReader, SWVEventSink
from pyocd.trace import swv


def parser_with_events():
    events = []
    return SWOParser(None, SimpleNamespace(receive=events.append)), events


def test_timestamp_still_dates_preceding_events():
    parser, events = parser_with_events()
    parser.parse(b'\x01A\x01B')
    assert events == []
    parser.parse(b'\x30')
    assert [e.data for e in events] == [65, 66]
    assert [e.timestamp for e in events] == [3, 3]


def test_high_volume_without_timestamps_is_bounded():
    parser, events = parser_with_events()
    parser.parse(b'\x01A' * 4096)
    assert len(events) == 4096
    assert all(e.timestamp == 0 for e in events)


def test_flush_preserves_partial_packet_and_last_timestamp():
    parser, events = parser_with_events()
    parser.parse(b'\x30\x01A\x02B')  # Complete A, half of a two-byte ITM payload.
    parser.flush()
    assert [(e.data, e.timestamp) for e in events] == [(65, 3)]
    parser.parse(b'C\x20')
    assert [(e.data, e.timestamp) for e in events] == [(65, 3), (0x4342, 5)]
    parser.flush()
    assert len(events) == 2


def test_flush_emits_unpaired_data_trace():
    parser, events = parser_with_events()
    parser.parse(b'\x47\x00\x10\x00\x00')  # Comparator 0 PC sample.
    parser.flush()
    assert len(events) == 1
    assert events[0].pc == 0x1000
    parser.flush()
    assert len(events) == 1


def test_paired_data_trace_retains_timestamp():
    parser, events = parser_with_events()
    parser.parse(b'\x47\x00\x10\x00\x00\x85\x42\x20')
    assert len(events) == 1
    assert events[0].pc == 0x1000
    assert events[0].value == 0x42
    assert events[0].timestamp == 2


@pytest.mark.parametrize('stop_time', [0.5, 1.5])
def test_reader_outputs_short_message_without_timestamps(monkeypatch, stop_time):
    clock = [0.0]
    console = io.StringIO()
    probe = Mock()
    target = SimpleNamespace(cores={0: None}, debug_sequence_delegate=None)
    reader = SWVReader(SimpleNamespace(target=target, probe=probe))
    reader._parser = SWOParser(None, SWVEventSink(console))
    probe.swo_read.side_effect = lambda: b'\x01A' if clock[0] == 0 else b''
    monkeypatch.setattr(swv, 'monotonic', lambda: clock[0])

    def sleep(_):
        clock[0] += 0.25
        if clock[0] >= stop_time:
            # For the longer run, prove delivery before shutdown, despite an idle probe.
            if stop_time > 1:
                assert console.getvalue() == 'A'
            reader._shutdown_event.set()

    monkeypatch.setattr(swv, 'sleep', sleep)
    reader.run()
    assert console.getvalue() == 'A'
    assert probe.swo_stop.call_count == 2
