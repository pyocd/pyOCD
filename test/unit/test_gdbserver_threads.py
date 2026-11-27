# pyOCD debugger
# Copyright (c) 2026 Solarboaters
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

"""Exercise monitor commands and resume with a simulated ThreadX target."""

import io
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pyocd.core import exceptions
from pyocd.core.session import Session
from pyocd.core.target import Target
from pyocd.gdbserver.gdbserver import GDBServer
from pyocd.rtos.threadx import ThreadXThreadProvider


@pytest.fixture
def server(monkeypatch):
    # Construct the real server, but do not open a probe, socket, or service thread.
    monkeypatch.setattr('pyocd.gdbserver.gdbserver.ListenerSocket', Mock())
    session = Session(None, no_config=True, options={
        'stdio_mode': 'off', 'gdbserver_port': 0,
        'debug.status_fault_retry_timeout': 0.01,
    })
    context = Mock()
    context.read32.return_value = 0  # No ThreadX threads created yet.
    context.read_core_register.return_value = 0
    target = Mock(core_number=0, run_token=0)
    target.get_target_context.return_value = context
    target.get_state.return_value = Target.State.HALTED
    target.selected_core = target
    target.session = session
    session._board = SimpleNamespace(target=target)
    session._inited = True  # Simulate an already-open target; no probe is connected.
    session._closed = False
    instance = GDBServer(session, rtt_config=SimpleNamespace(channels=None))
    session.gdbservers[0] = instance
    instance._command_context.output_stream = io.StringIO()
    provider = ThreadXThreadProvider(target)
    provider.init(SimpleNamespace(get_symbol_value=lambda name: {
        '_tx_thread_created_ptr': 0x20000000,
        '_tx_thread_created_count': 0x20000004,
        '_tx_thread_current_ptr': 0x20000008,
        '_tx_thread_system_state': 0x2000000c,
    }[name]))
    instance.thread_provider = provider
    yield instance
    instance.stdio_handler.shutdown()
    instance.listen_socket.close()
    session._closed = True


def make_client():
    client = Mock()
    client.non_stop = False
    client.shutdown_event = threading.Event()
    client.is_connection_closed = False
    client.is_interrupted.return_value = False
    client.target_facade.get_t_response.return_value = b'T05'
    return client


def resume(server):
    client = make_client()
    with server.lock:
        return server.resume(client, b'c')


def test_disable_survives_first_resume(server):
    server._command_context.process_command_line('threads disable')
    resume(server)
    assert not server.thread_provider.read_from_target


def test_disable_survives_reset_and_resume(server):
    server._command_context.process_command_line('threads disable')
    server.event_handler(SimpleNamespace(event=Target.Event.POST_RESET))
    resume(server)
    assert not server.thread_provider.read_from_target


def test_disabled_threadx_does_not_read_uninitialized_target(server):
    def read_register(name):
        if name == 'ipsr':
            raise exceptions.TransferFaultError('ThreadX context unavailable in bootloader')
        return 0x1000

    server.target_context.read_core_register.side_effect = read_register
    server._command_context.process_command_line('threads disable')
    reply = resume(server)
    assert reply.startswith(b'$T05')
    assert b'thread:1;' in reply
    assert all(call.args != ('ipsr',) for call in server.target_context.read_core_register.call_args_list)


def test_automatic_reporting_still_enabled_after_first_resume(server):
    assert not server.thread_provider.read_from_target
    assert b'thread:1;' in server.get_t_response(make_client())
    server.target_context.read32.assert_not_called()
    resume(server)
    assert server.thread_provider.read_from_target
    server.target_context.read32.assert_called()


def test_manual_enable_after_disable(server):
    server._command_context.process_command_line('threads disable')
    resume(server)
    server._command_context.process_command_line('threads enable')
    assert server.thread_provider.read_from_target
    resume(server)
    assert server.thread_provider.read_from_target


def test_manual_enable_restores_rtos_stop_reply(server):
    # A discovered, running RTOS exposes its current thread to GDB again.
    thread_context = Mock()
    server.thread_provider = SimpleNamespace(
        read_from_target=True, is_enabled=True,
        current_thread=SimpleNamespace(unique_id=7, context=thread_context),
    )
    client = make_client()
    server._command_context.process_command_line('threads disable')
    assert b'thread:1;' in server.get_t_response(client)
    client.target_facade.set_context.assert_called_with(server.target_context)
    server._command_context.process_command_line('threads enable')
    assert b'thread:7;' in server.get_t_response(client)
    client.target_facade.set_context.assert_called_with(thread_context)


def test_enabled_threadx_fault_is_not_silently_hidden(server):
    server.thread_provider.read_from_target = True
    server.target_context.read_core_register.side_effect = exceptions.TransferFaultError('unavailable')
    with pytest.raises(exceptions.TransferFaultError):
        server.get_t_response(make_client())
