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

from typing import Optional, Tuple
import os
from pathlib import Path
import logging

from ..core import exceptions
from ..core.session import Session
from ..debug.elf.elf import ELFBinaryFile
from .stdio import StdioHandler
from .rtt_server import RTTServer, RTTChanStdioWorker, RTTChanTCPWorker, RTTChanSystemViewWorker

LOG = logging.getLogger(__name__)

class RTTManager:
    """@brief Helper class to configure and start RTT server based on cbuild-run configuration in the session."""

    def __init__(self, session: Session, core: Optional[int] = None):
        self._session = session
        self._board = session.board
        if core is None:
            self._core = 0
            self._target = self._board.target
        else:
            self._core = core
            self._target = self._board.target.cores[core]

        self._rtt_server: Optional[RTTServer] = None

    def _resolve_rtt_control_block(self) -> Tuple[Optional[int], Optional[int], bool]:
        """
        @brief Resolve RTT control block configuration for the current core.
        @returns Tuple of (address, size, auto_detect) where:
                 - address: the address of the RTT control block if specified, otherwise None
                 - size: the size of the RTT control block if specified, otherwise None
                 - auto_detect: True if auto-detect is enabled in the configuration, False otherwise
        """

        address = None
        size = None
        auto_detect = False
        control_block_list = self._session.options.get('cbuild_run.rtt_control_block')
        control_block_cfg = (control_block_list[self._core] if control_block_list else None)
        if control_block_cfg is not None:
            address = control_block_cfg.get('address', None)
            size = control_block_cfg.get('size', None)
            auto_detect = control_block_cfg.get('auto-detect', False)
        return address, size, auto_detect

    def _start_rtt_server(self, address: Optional[int], size: Optional[int]) -> Optional[RTTServer]:
        """@brief Create and start RTT server with the given address and size.
            If address is None, auto-detect will be attempted."""

        try:
            server = RTTServer(self._target, address, size, b'SEGGER RTT')
            server.start()
            LOG.info("RTT server started for core %d", self._core)
            return server
        except exceptions.RTTError as e:
            return None

    def _find_segger_rtt_symbol(self) -> Optional[int]:
        """@brief Attempt to find the address of the _SEGGER_RTT symbol in the ELF file for the current core."""

        try:
            # Get the outputs list from cbuild-run
            outputs = self._session.cbuild_run._data.get('output', [])
            # Iterate through all outputs
            for output in outputs or []:
                load_type = output.get('load')
                pname = output.get('pname')

                # Skip if not symbol output
                if not load_type or 'symbols' not in load_type:
                    continue
                # Skip if pname is specified and does not match the current core's name
                if pname is not None and pname != self._target.node_name:
                    continue

                elf_file = output.get('file')
                if elf_file:
                    elf = ELFBinaryFile(elf_file)
                    symbol_info = elf.symbol_decoder.get_symbol_for_name('_SEGGER_RTT')
                    if symbol_info:
                        return symbol_info.address
            return None
        except Exception as e:
            LOG.warning("Failed to get RTT symbol address from ELF for core %d: %s", self._core, e)
            return None


    def start_server(self) -> Optional[RTTServer]:
        """@brief Create and start RTT server based on cbuild-run configuration in the session."""

        # Check if RTT configuration exists
        if not self._session.cbuild_run:
            raise RuntimeError("No cbuild-run configuration found; cannot configure RTT server")


        # Check if RTT channel configuration exists for this core; if not, skip starting RTT server
        channel_cfg_list = self._session.options.get('cbuild_run.rtt_channel')
        channel_cfg = channel_cfg_list[self._core] if (channel_cfg_list and self._core < len(channel_cfg_list)) else None
        if not channel_cfg:
            LOG.debug("No RTT channel configuration found for core %d; RTT server will not be started", self._core)
            return None

        # Get RTT control block configuration for this core
        address, size, auto_detect = self._resolve_rtt_control_block()

        if address is not None or auto_detect:
            if address is not None:
                self._rtt_server = self._start_rtt_server(address, size)
                if self._rtt_server is not None:
                    return self._rtt_server
            if auto_detect:
                # Fallback: auto-detect via memory scan in default memory region if no address specified
                self._rtt_server = self._start_rtt_server(None, None)
                if self._rtt_server is not None:
                    return self._rtt_server

            LOG.warning("Failed to create and start RTT server for core %d", self._core)
            return None
        else:
            # Auto-detect via symbol "_SEGGER_RTT" lookup in the ELF file
            address = self._find_segger_rtt_symbol()
            if address is not None:
                self._rtt_server = self._start_rtt_server(address, None)
                if self._rtt_server is not None:
                    return self._rtt_server

            LOG.warning("Failed to create and start RTT server for core %d", self._core)
            return None

    def configure_channels(self, stdio_handler: Optional[StdioHandler] = None):
        """@brief Configure RTT channels based on cbuild-run configuration in the session."""

        if self._rtt_server is None:
           LOG.warning("RTT server not started; cannot configure RTT channels for core %d", self._core)
           return

        if self._session.options.is_set('cbuild_run'):
            cbuild_run = self._session.options.get('cbuild_run')
        else:
            raise RuntimeError("No cbuild-run configuration found; cannot configure RTT channels")

        if 'cbuild-run' in cbuild_run:
            path = Path(cbuild_run).resolve()
            fname_root = path.stem.split('.cbuild-run')[0]
        else:
            fname_root = os.getcwd()

        channel_cfg_list = self._session.options.get('cbuild_run.rtt_channel')
        channel_cfg = channel_cfg_list[self._core] if (channel_cfg_list and self._core < len(channel_cfg_list)) else []

        # Get SystemView configuration for auto-start and auto-stop settings
        sv_cfg = self._session.options.get('cbuild_run.systemview')
        sv_auto_start = sv_cfg.get('auto-start', True) if sv_cfg else True
        sv_auto_stop = sv_cfg.get('auto-stop', True) if sv_cfg else True

        stdio_enabled = False

        for ch_cfg in channel_cfg or []:
            ch_num = ch_cfg.get('number')
            ch_mode = ch_cfg.get('mode')
            telnet_port = ch_cfg.get('port')

            if self._rtt_server.is_channel_idx_valid(ch_num) is False:
                LOG.warning("RTT channel index %d for core %d is out of range; skipping configuration for channel %d", ch_num, self._core, ch_num)
                continue
            if self._rtt_server.is_channel_configured(ch_num):
                LOG.warning("RTT channel %d for core %d is already configured; skipping configuration for channel %d", ch_num, self._core, ch_num)
                continue
            # STDIO mode
            if ch_mode == 'stdio':
                if stdio_handler is None:
                    LOG.warning("StdioHandler for core %d is not provided; skipping configuration for channel %d", self._core, ch_num)
                    continue
                if stdio_enabled:
                    LOG.warning("STDIO RTT channel already enabled for core %d; skipping configuration for channel %d", self._core, ch_num)
                    continue
                try:
                    self._rtt_server.add_channel_worker(ch_num, lambda: RTTChanStdioWorker(channel=ch_num, stdio=stdio_handler))
                    LOG.info("STDIO enabled on RTT channel %d for core %d", ch_num, self._core)
                    stdio_enabled = True
                except exceptions.RTTError as e:
                    LOG.error("Failed to enable STDIO for RTT channel %d for core %d: %s", ch_num, self._core, e)
            # Telnet mode
            elif ch_mode == 'telnet':
                try:
                    self._rtt_server.add_channel_worker(ch_num, lambda: RTTChanTCPWorker(telnet_port, listen=True))
                    LOG.info("Telnet enabled on RTT channel %d for core %d", ch_num, self._core)
                except exceptions.RTTError as e:
                    LOG.error("Failed to enable Telnet server for RTT channel %d for core %d: %s", ch_num, self._core, e)
            #SystemView mode
            elif ch_mode == 'systemview':
                try:
                    fname = f'{fname_root}.core{self._core}.ch{ch_num}.bin'
                    self._rtt_server.add_channel_worker(ch_num, lambda: RTTChanSystemViewWorker(rtt_server=self._rtt_server, rtt_channel=ch_num, file_out=fname, auto_start=sv_auto_start, auto_stop=sv_auto_stop))
                    LOG.info("SystemView enabled on RTT channel %d for core %d", ch_num, self._core)
                except (IOError, exceptions.RTTError) as e:
                    LOG.error("Failed to enable SystemView for RTT channel %d for core %d: %s", ch_num, self._core, e)
            else:
                LOG.warning("Unsupported RTT channel mode '%s' for channel %d for core %d; skipping configuration for channel %d", ch_mode, ch_num, self._core, ch_num)

