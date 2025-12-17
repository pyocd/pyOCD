# pyOCD debugger
# Copyright (c) 2025 Arm Limited
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

from __future__ import annotations

import logging
import sys
import threading
from typing import Dict, Optional, Tuple, Type

from ..utility.compatibility import to_bytes_safe, to_str_safe
from ..core.session import Session
from .server import StreamServer
import os

LOG = logging.getLogger(__name__)

class StdioBase:
    """Abstract STDIO interface."""

    def __init__(self, session: Session = None, core=0) -> None:
        pass

    def write(self, data: bytes) -> int:
        return len(data)

    def read(self, max_bytes: int) -> bytes:
        return b""

    def shutdown(self) -> None:
        pass

    @property
    def info(self) -> str:
        return ""

class StdioOff(StdioBase):
    """STDIO backend that discards all input/output."""
    @property
    def info(self) -> str:
        return "off"

class StdioTelnet(StdioBase):
    """STDIO backend that uses a telnet server for reading from and writing to stdin/stdout."""

    def __init__(self, session: Session, core: int = 0) -> None:
        if session.options.is_set('cbuild_run.telnet_ports'):
            # Per-core telnet ports configured.
            telnet_port = session.options.get('cbuild_run.telnet_ports')[core]
            if telnet_port is None:
                LOG.info("Telnet port for core %d is not specified and will be auto-assigned", core)
                telnet_port = 0
        else:
            telnet_port = session.options.get('telnet_port')
            if telnet_port != 0:
                telnet_port += core
        serve_local_only = session.options.get('serve_local_only')

        self._server = StreamServer(
            port=telnet_port,
            serve_local_only=serve_local_only,
            name="STDIO",
            is_read_only=False,
            extra_info=f"core {core}"
        )

        if telnet_port == 0:
            telnet_port = self._server.port

        self._telnet_port = telnet_port

        # ToDo: consider waiting for client to connect
        # while self._server._connected_socket is None:
        #     time.sleep(0.1)

    def write(self, data: bytes) -> int:
        try:
            return self._server.write(data)
        except Exception as e:
            LOG.debug("Error writing to STDIO telnet server (port %d): %s", self._telnet_port, e)
            return 0

    def read(self, max_bytes: int) -> bytes:
        data = None
        try:
            data = self._server.read(max_bytes)
        except Exception as e:
            LOG.debug("Error reading from STDIO telnet server (port %d): %s", self._telnet_port, e)
        if data is None:
            return b""
        return bytes(data)

    def shutdown(self) -> None:
        try:
            self._server.stop()
        except Exception as e:
            LOG.debug("Error stopping STDIO telnet server (port %d): %s", self._telnet_port, e)

    @property
    def info(self) -> str:
        return f"telnet (port: {self._server.port})"

class StdioFile(StdioBase):
    """STDIO backend that reads from and writes to files."""

    def __init__(self, session: Session, core: int = 0) -> None:
        # Get file paths from session options
        if session.options.is_set('cbuild_run.telnet_files_out'):
            telnet_file_out = session.options.get('cbuild_run.telnet_files_out')[core]
            if telnet_file_out is None:
                raise ValueError(f"STDIO file for core {core} requires a valid output file path")
        else:
            raise ValueError(f"STDIO file for core {core} requires a valid output file path")

        if session.options.is_set('cbuild_run.telnet_files_in'):
            telnet_file_in = session.options.get('cbuild_run.telnet_files_in')[core]
        else:
            telnet_file_in = None

        # Check if the folder exists for input/output files
        dir_out = os.path.dirname(telnet_file_out)
        self._fname_out =  os.path.basename(telnet_file_out)
        if dir_out and not os.path.exists(dir_out):
            raise FileNotFoundError(f"Directory {dir_out} for STDIO file {self._fname_out} does not exist")

        # Open files
        if telnet_file_in is not None and os.path.exists(telnet_file_in):
            self._input_file = open(telnet_file_in, 'rb')
            self._fname_in = os.path.basename(telnet_file_in)
        else:
            LOG.debug("Input file '%s' does not exist; STDIN will be disabled", telnet_file_in)
            self._input_file = None
            self._fname_in = None

        try:
            self._output_file = open(telnet_file_out, 'wb')
        except OSError as e:
            if self._input_file:
                self._input_file.close()
            raise IOError(f"Failed to open STDIO file {telnet_file_out}: {e}")

    def write(self, data: bytes) -> int:
        # Output file is valid - else exception raised in constructor
        bytes_written = self._output_file.write(data)
        return bytes_written

    def read(self, max_bytes: int) -> bytes:
        if self._input_file is None:
            return b""
        try:
            data = self._input_file.read(max_bytes)
            return data if data else b""
        except Exception:
            return b""

    def shutdown(self) -> None:
        if self._output_file:
            self._output_file.flush()
            self._output_file.close()
        if self._input_file:
            self._input_file.close()

    @property
    def info(self) -> str:
        if self._input_file is None:
            return f"file (file-out: {self._fname_out})"
        else:
            return f"file (file-out: {self._fname_out}, file-in: {self._fname_in})"

class StdioConsole(StdioBase):
    """STDIO backend that reads from and writes to the console (stdin/stdout)."""

    def __init__(self, session: Session, core: int = 0) -> None:
        # Prefer binary buffered streams (available in most cases).
        self._out_bin = getattr(sys.stdout, "buffer", None)
        self._in_bin = getattr(sys.stdin, "buffer", None)

        # Keep text streams, for fallback.
        self._out_text = sys.stdout
        self._in_text = sys.stdin

    def write(self, data: bytes) -> int:
        if self._out_bin is not None:
            try:
                written = self._out_bin.write(data)
                self._out_bin.flush()
                return written
            except Exception:
                # Fallback
                pass

        # Fallback: stdout has no .buffer, treat as text.
        try:
            text = to_str_safe(data)
            self._out_text.write(text)
            self._out_text.flush()
            # We still report how many *bytes* we consumed.
            return len(data)
        except Exception:
            return 0

    def read(self, max_bytes: int) -> bytes:
        try:
            if self._in_bin is not None:
                return self._in_bin.read(max_bytes) or b""
        except Exception:
            pass

        # Fallback: stdin has no .buffer, read text and encode.
        try:
            text = self._in_text.read(max_bytes) or ""
            return to_bytes_safe(text)
        except Exception:
            return b""

    @property
    def info(self) -> str:
        return "console"

# Backend mapping
_BACKEND_CLASSES: Dict[str, Type[StdioBase]] = {
    "off":     StdioOff,
    "telnet":  StdioTelnet,
    "file":    StdioFile,
    "console": StdioConsole
}

class StdioHandler(StdioBase):
    """
        Per-core STDIO handler that builds its backend(s) from session options.
    """

    def __init__(self, session: Session, core: int = 0, eot_enabled: bool = False) -> None:

        if session.options.is_set('cbuild_run.telnet_modes'):
            # Per-core telnet modes configured.
            stdio_mode = session.options.get('cbuild_run.telnet_modes')[core]
        else:
            stdio_mode = session.options.get('semihost_console_type')

        if stdio_mode not in _BACKEND_CLASSES:
            LOG.warning("Invalid STDIO mode '%s'; Defaulting to 'off'", stdio_mode)
            stdio_mode = "off"
        else:
            LOG.debug("STDIO mode '%s'", stdio_mode)

        self._mode = stdio_mode
        self._core = core

        # Get the backend class
        backend_class = _BACKEND_CLASSES.get(self._mode)

        # Instantiate the backend
        self._backend = backend_class(session, self._core)

        # EOT signalling
        if self._mode == "off":
            # EOT handling makes no sense with no output
            self._eot_enabled = False
        else:
            self._eot_enabled = eot_enabled
        self._eot_event = threading.Event()
        self._eot_seen = False

    # StdioBackend API: forward to the chosen backend
    def write(self, data) -> int:
        """Write data to stdout.

        If EOT (0x04) is detected, data is trimmed at EOT position.
        Data at and after EOT is discarded. EOT event is set only after
        all data before EOT has been successfully written.

        Args:
            data: String or bytes to write.

        Returns:
            Number of bytes written.
        """
        if not data:
            return 0

        # Convert to bytes if needed
        data_bytes = to_bytes_safe(data)

        if self._eot_enabled:
            # Check for EOT and trim data if found
            data_to_write, eot_found = self._eot_handler(data_bytes)
        else:
            data_to_write = data_bytes
            eot_found = False

        # Write the data (before EOT, if any)
        if data_to_write:
            bytes_written = self._backend.write(data_to_write)
        else:
            bytes_written = 0

        # Only set EOT after successful write
        if self._eot_enabled and eot_found:
            self._set_eot()

        return bytes_written

    def read(self, max_bytes: int) -> bytes:
        if max_bytes <= 0:
            return b""
        return self._backend.read(max_bytes)

    def shutdown(self) -> None:
        self._backend.shutdown()

    @property
    def info(self) -> str:
        return self._backend.info

    # EOT Handling
    @property
    def eot_event(self) -> threading.Event:
        """Event that becomes set when 0x04 is first seen."""
        return self._eot_event

    @property
    def eot_seen(self) -> bool:
        """Whether 0x04 has been seen on stdout/stderr."""
        return self._eot_seen

    def wait_for_eot(self, timeout: Optional[float] = None) -> bool:
        """Block until EOT (0x04) seen or timeout.

        Returns True if EOT occurred, False on timeout.
        """
        if not self._eot_enabled:
            return False
        return self._eot_event.wait(timeout)

    def _eot_handler(self, data: bytes) -> Tuple[bytes, bool]:
        """ Check for EOT (0x04) in data and trim if found.
            Tuple of (data_to_write, eot_found):
                - data_to_write: Data before EOT (or full data if no EOT)
                - eot_found: True if EOT was detected
        """
        if self._eot_seen:
            # EOT already seen - should we even be here?
            LOG.debug("Data received after EOT on core %d; discarding", self._core)
            return b"", False

        # Look for EOT character
        eot_index = data.find(b"\x04")

        if eot_index == -1:
            # No EOT found - return all data
            return data, False

        # EOT found - trim data at EOT position
        data_before_eot = data[:eot_index]
        LOG.debug("EOT (0x04) detected (core %d)", self._core)

        return data_before_eot, True


    def _set_eot(self) -> None:
        """Mark EOT as seen and set the event.

        Called only after data before EOT has been successfully written.
        """
        if not self._eot_seen:
            self._eot_seen = True
            self._eot_event.set()
