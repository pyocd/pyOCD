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

from typing import Optional, Dict, List
import os
from pathlib import Path
from datetime import datetime
import logging

from ..core.session import Session

LOG = logging.getLogger(__name__)

class SystemViewSVDat():
    def __init__(self, session: Session):
        self._session = session
        self._files_per_core: Dict[int, List[str]] = {}
        self._out_file: Optional[str] = None

        if not session.cbuild_run:
            raise RuntimeError("No cbuild-run configuration found; cannot enable SystemView")

        systemview = session.options.get('cbuild_run.systemview') or {}

        # Check if the folder exists for output file
        out_file = systemview.get('file')
        if not out_file:
            raise RuntimeError("SystemView output file is not configured; cannot enable SystemView")

        dir_out = os.path.dirname(out_file)
        if dir_out and not os.path.exists(dir_out):
            f_name_out = os.path.basename(out_file)
            raise FileNotFoundError(
                f"Output directory '{dir_out}' for SystemView output file '{f_name_out}' does not exist; cannot enable SystemView"
            )
        self._out_file = out_file

        # Determine output file names for each core and channel based on cbuild-run configuration
        cbuild_run = self._session.options.get('cbuild_run')
        if 'cbuild-run' in cbuild_run:
            path = Path(cbuild_run).resolve()
            fname_root = path.stem.split('.cbuild-run')[0]
        else:
            fname_root = os.getcwd()

        channel_cfg_list = self._session.options.get('cbuild_run.rtt_channel')

        # Create a list of output files for each core
        # and delete any existing files with the same name to ensure clean output for SystemView
        for core in range(len(self._session.target.cores)):
            channel_cfg = channel_cfg_list[core] if (channel_cfg_list and core < len(channel_cfg_list)) else []
            file_list = []
            for ch_cfg in channel_cfg:
                ch_num = ch_cfg.get('number')
                ch_mode = ch_cfg.get('mode')
                if ch_mode == 'systemview':
                    fname = f'{fname_root}.core{core}.ch{ch_num}.bin'
                    if os.path.exists(fname):
                        os.remove(fname)
                    file_list.append(fname)
            self._files_per_core[core] = file_list

    def assemble_file(self) -> bool:
        """@brief Assemble SystemView .SVDat file from individual channel binary files collected for each core."""
        # collect non-empty files (remove empty ones)
        collected_files: List[str] = []
        for _, files in sorted(self._files_per_core.items()):
            for f in files or []:
                if not f:
                    continue
                if os.path.exists(f):
                    if os.path.getsize(f) > 0:
                        collected_files.append(f)
                    else:
                        try:
                            os.remove(f)
                        except OSError:
                            LOG.warning("Failed to remove empty SystemView file '%s'", f)

        if not collected_files:
            LOG.debug("No temporary SystemView files; skipping SVDat generation.")
            return False

        try:
            with open(self._out_file, 'wb') as f_out:
                # Write header
                header = [
                    ";",
                    f"; RecordTime   {datetime.now().strftime('%d %b %Y %H:%M:%S')}",
                    f"; Author       pyOCD",
                ]

                # Core index in the SVDat file is determined by the order how files collected from each core are appended
                # and it is not necessarily the same as the core index in the target
                svdat_core_idx = 0
                offset = 0
                for f in collected_files:
                    size = os.path.getsize(f)
                    header.append(f"; Offset Core{svdat_core_idx} {offset}")
                    svdat_core_idx += 1
                    offset += size
                header.append(";")
                f_out.write("\n".join(header).encode('utf-8') + b"\n")

                # Append each binary file and remove it
                for f in collected_files:
                    with open(f, 'rb') as f_in:
                        while True:
                            chunk = f_in.read(8192)
                            if not chunk:
                                break
                            f_out.write(chunk)
                    try:
                        os.remove(f)
                    except OSError:
                        LOG.warning("Failed to remove SystemView file '%s' after appending", f)
        except OSError as e:
            raise OSError(f"Failed to open/write SystemView output file {self._out_file}: {e}")

        return True