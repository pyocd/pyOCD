# pyOCD debugger
# Copyright (c) 2026 Arm Limited
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

from typing import Optional, Tuple, List
import os
import logging
from pathlib import Path
from dataclasses import dataclass

from ..core import exceptions
from ..core.session import Session
from ..debug.elf.elf import ELFBinaryFile
from .stdio import StdioHandler
from .rtt_server import RTTServer, RTTChanStdioWorker, RTTChanTCPWorker, RTTChanSysViewFileWorker, RTTChanSysViewTCPWorker
from .systemview import SystemViewConfig

LOG = logging.getLogger(__name__)

@dataclass
class RTTConfig:
    """@brief Data class representing RTT configuration for a specific core."""

    # type aliases scoped to the class
    RTTControlBlock = Optional[Tuple[Optional[int], Optional[int], bool]]  # (address, size, auto-detect)
    RTTChannel      = Optional[Tuple[int, str, Optional[int]]]             # (number, mode, port)
    RTTChannelList  = Optional[Tuple[RTTChannel, ...]]

    _session: Session
    _target: str
    _core: int
    control_block: RTTControlBlock = None
    channels: RTTChannelList = None

    def __post_init__(self):
        self._rtt_configuration()

    # Helper methods
    def _add_channel(self, ch_list: List["RTTConfig.RTTChannel"], number: int, mode: str, port: Optional[int] = None) -> None:
        SUPPORTED_MODES = {'stdio', 'server', 'systemview', 'systemview-server'}

        if number is None:
            # Warn about missing channel number
            LOG.warning("RTT channel configuration for core %d: missing channel number; channel disabled", self._core)
            return
        if ch_list and any(number == ch[0] for ch in ch_list):
            LOG.warning("RTT channel %d for core %d: already configured; skipping duplicate", number, self._core)
            return
        if mode is None:
            # Warn about missing channel mode
            LOG.warning("RTT channel %d configuration for core %d: missing mode; channel disabled", number, self._core)
            return
        if mode not in SUPPORTED_MODES:
            # Warn about unsupported channel mode
            LOG.warning("RTT channel %d configuration for core %d: unsupported mode '%s'; channel disabled",
                        number, self._core, mode)
            return
        # Server mode or SystemView server mode requires a port number
        if mode in {'server', 'systemview-server'}:
            if port is None:
                LOG.warning("RTT channel %d configuration for core %d: missing port for %s mode; channel disabled", number, self._core, mode)
                return
            conflict = next((ch for ch in ch_list if ch[1] in {'server', 'systemview-server'} and ch[2] == port), None)
            if conflict is not None:
                LOG.warning("RTT channel %d configuration for core %d: port %d is already in use for %s mode on channel %d; channel disabled",
                             number, self._core, port, conflict[1], conflict[0])
                return
        else:
            port = None

        port_str = f", port={port}" if port is not None else ""
        ch_list.append((number, mode, port))

    def _rtt_configuration(self) -> None:
        rtt_config_list = self._session.options.get('rtt') or []
        if not rtt_config_list:
            return

        rtt_config_by_pname = {cfg.get('pname'): cfg for cfg in rtt_config_list}
        proc_name = self._target.node_name if self._target.node_name else None

        # Core-specific configuration
        pname_config = rtt_config_by_pname.get(proc_name)

        # Global configuration (applies to all cores, but core-specific config takes precedence)
        global_config = rtt_config_by_pname.get(None)

        cb_g = global_config.get('control-block') if global_config else None
        cb_l = pname_config.get('control-block') if pname_config else None

        # Merge local and global configurations: local values take precedence unless explicitly None
        if cb_g is None and cb_l is None:
            rtt_cb = None
        else:
            address = cb_l.get('address') if (cb_l and cb_l.get('address') is not None) else (cb_g.get('address') if cb_g else None)
            size = cb_l.get('size') if (cb_l and cb_l.get('size') is not None) else (cb_g.get('size') if cb_g else None)
            auto_detect = cb_l.get('auto-detect') if (cb_l and cb_l.get('auto-detect') is not None) else (cb_g.get('auto-detect', False) if cb_g else False)
            if address is not None or auto_detect:
                rtt_cb = (address, size, auto_detect)
            else:
                rtt_cb = None

        self.control_block = rtt_cb

        ch_g = global_config.get('channel') if global_config else None
        ch_l = pname_config.get('channel') if pname_config else None

        rtt_ch: List["RTTConfig.RTTChannel"] = []
        if ch_l is not None:
            for ch in ch_l:
                self._add_channel(rtt_ch, ch.get('number'), ch.get('mode'), ch.get('port'))
        if ch_g is not None:
            for ch in ch_g:
                if ch_l is not None and any(ch.get('number') == local_ch.get('number') for local_ch in ch_l):
                    # Skip global channel configuration if a local channel with the same number exists
                    LOG.debug("RTT channel %d configuration for core %d: pname specific configuration used; skipping global channel configuration",
                              ch.get('number'), self._core)
                else:
                    self._add_channel(rtt_ch, ch.get('number'), ch.get('mode'), ch.get('port'))

        # Sort channels by channel number if any were added
        if rtt_ch:
            rtt_ch.sort(key=lambda x: x[0])
            self.channels = tuple(rtt_ch)
        else:
            self.channels = None

class RTTManager:
    """@brief Helper class to configure and start RTT server."""

    def __init__(self, session: Session, core: Optional[int] = None, rtt_config: RTTConfig = None, systemview_config: SystemViewConfig = None):
        self._session = session
        self._board = session.board
        if core is None:
            self._core = 0
            self._target = self._board.target
        else:
            self._core = core
            self._target = self._board.target.cores[core]

        # RTT configuration
        self._rtt_config = rtt_config

        # SystemView configuration
        self._systemview = systemview_config

        self._rtt_server: Optional[RTTServer] = None

    def _start_rtt_server(self, address: Optional[int], size: Optional[int]) -> Optional[RTTServer]:
        """@brief Create and start RTT server with the given address and size.
            If address is None, auto-detect will be attempted."""

        try:
            server = RTTServer(self._target, address, size, b'SEGGER RTT')
            server.start()
            LOG.debug("RTT started for core %d", self._core)
            return server
        except exceptions.RTTError:
            return None

    def _find_segger_rtt_symbol(self) -> Optional[int]:
        """@brief Attempt to find the address of the _SEGGER_RTT symbol in the ELF file for the current core."""

        try:
            get_output = getattr(self._board.target, 'get_output', None)
            if not callable(get_output):
                return None
            symbol_files = get_output(load='symbol')
            if not symbol_files:
                return None

            # Iterate through all outputs
            for f, (_, _, pname) in symbol_files.items():
                # Skip if pname is specified and does not match the current core's name
                if pname is not None and pname != self._target.node_name:
                    continue
                elf = ELFBinaryFile(f)
                symbol_info = elf.symbol_decoder.get_symbol_for_name('_SEGGER_RTT')
                if symbol_info:
                    return symbol_info.address
            return None
        except Exception as e:
            LOG.warning("RTT for core %d: failed to get _SEGGER_RTT symbol address from ELF: %s", self._core, e)
            return None

    def start_server(self) -> Optional[RTTServer]:
        """@brief Create and start RTT server."""

        if self._rtt_config.channels is None:
            LOG.warning("RTT for core %d: no channels configured; RTT disabled", self._core)
            return None

        if self._rtt_server is not None:
            LOG.warning("RTT for core %d: already running; start_server() call ignored", self._core)
            return self._rtt_server

        # Get RTT control block configuration for this core
        rtt_cb = self._rtt_config.control_block

        if rtt_cb is not None:
            address, size, auto_detect = rtt_cb
            if address is not None:
                self._rtt_server = self._start_rtt_server(address, size)
                if self._rtt_server is not None:
                    if size:
                        LOG.debug("RTT for core %d: RTT control block found via scan of memory specified with address 0x%X and size 0x%X", self._core, address, size)
                    else:
                        LOG.debug("RTT for core %d: RTT control block found via specified address 0x%X", self._core, address)
                    return self._rtt_server
                else:
                    if size:
                        LOG.warning("RTT for core %d: failed to find RTT control block with specified address 0x%X and size 0x%X", self._core, address, size)
                    else:
                        LOG.warning("RTT for core %d: failed to find RTT control block with specified address 0x%X", self._core, address)
            if auto_detect:
                # Fallback: auto-detect via memory scan in default memory region if no address specified
                self._rtt_server = self._start_rtt_server(None, None)
                if self._rtt_server is not None:
                    LOG.debug("RTT for core %d: RTT control block found via auto-detect memory scan in default memory region", self._core)
                    return self._rtt_server
                else:
                    LOG.warning("RTT for core %d: failed to find RTT control block with auto-detected address", self._core)
            return None
        else:
            # Auto-detect via symbol "_SEGGER_RTT" lookup in the ELF file
            address = self._find_segger_rtt_symbol()
            if address is None:
                LOG.warning("RTT for core %d: failed to find _SEGGER_RTT symbol in ELF; cannot auto-detect RTT control block", self._core)
                return None
            self._rtt_server = self._start_rtt_server(address, None)
            if self._rtt_server is not None:
                LOG.debug("RTT for core %d: RTT control block found via _SEGGER_RTT symbol lookup at address 0x%X", self._core, address)
                return self._rtt_server

            LOG.warning("RTT for core %d: failed to find RTT control block with _SEGGER_RTT symbol address 0x%X", self._core, address)
            return None

    def configure_channels(self, stdio_handler: Optional[StdioHandler] = None):
        """@brief Configure RTT channels."""

        if self._rtt_server is None:
            LOG.warning("RTT for core %d: RTT not started; cannot configure RTT channels", self._core)
            return

        stdio_enabled = False

        for number, mode, server_port in self._rtt_config.channels:
            if self._rtt_server.is_channel_idx_valid(number) is False:
                LOG.warning("RTT for core %d: channel index %d is out of range; skipping configuration for channel %d", self._core, number, number)
                continue
            if self._rtt_server.is_channel_configured(number):
                LOG.warning("RTT for core %d: channel %d is already configured; skipping configuration for channel %d", self._core, number, number)
                continue
            # STDIO mode
            if mode == 'stdio':
                if stdio_handler is None:
                    LOG.warning("RTT for core %d: StdioHandler is not provided; skipping configuration for channel %d", self._core, number)
                    continue
                if stdio_enabled:
                    LOG.warning("RTT for core %d: stdio mode is already enabled; skipping configuration for channel %d", self._core, number)
                    continue
                try:
                    self._rtt_server.add_channel_worker(number, lambda: RTTChanStdioWorker(channel=number, stdio=stdio_handler))
                    LOG.info("RTT channel %d configuration for core %d: mode=%s", number, self._core, mode)
                    stdio_enabled = True
                except exceptions.RTTError as e:
                    LOG.error("RTT for core %d: failed to enable stdio mode for RTT channel %d: %s", self._core, number, e)
            # Server mode
            elif mode == 'server':
                try:
                    self._rtt_server.add_channel_worker(number, lambda: RTTChanTCPWorker(server_port, listen=True))
                    LOG.info("RTT channel %d configuration for core %d: mode=%s, port=%d", number, self._core, mode, server_port)
                except exceptions.RTTError as e:
                    LOG.error("RTT for core %d: failed to enable server mode for RTT channel %d: %s", self._core, number, e)
            # SystemView mode
            elif mode == 'systemview':
                try:
                    fname_root = self._systemview.file.rsplit('.', 1)[0]
                    fname = f'{fname_root}.core{self._core}.ch{number}.bin'
                    self._rtt_server.add_channel_worker(number, lambda: RTTChanSysViewFileWorker(rtt_server=self._rtt_server, rtt_channel=number, file_out=fname, auto_start=self._systemview.auto_start, auto_stop=self._systemview.auto_stop))
                    LOG.info("RTT channel %d configuration for core %d: mode=%s", number, self._core, mode)
                except (IOError, exceptions.RTTError) as e:
                    LOG.error("RTT for core %d: failed to enable systemview mode for RTT channel %d: %s", self._core, number, e)
            # SystemView server mode
            elif mode == 'systemview-server':
                try:
                    self._rtt_server.add_channel_worker(number, lambda: RTTChanSysViewTCPWorker(server_port, listen=True))
                    LOG.info("RTT channel %d configuration for core %d: mode=%s, port=%d", number, self._core, mode, server_port)
                except exceptions.RTTError as e:
                    LOG.error("RTT for core %d: failed to enable systemview server mode for RTT channel %d: %s", self._core, number, e)
            else:
                LOG.warning("RTT for core %d: unsupported channel mode '%s' for channel %d; skipping configuration for channel %d", self._core, mode, number, number)
