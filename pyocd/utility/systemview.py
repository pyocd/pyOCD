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

from typing import Optional, Dict, List, TYPE_CHECKING
import os
import logging
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass

from ..core.session import Session

if TYPE_CHECKING:
    from .rtt_manager import RTTConfig

LOG = logging.getLogger(__name__)

@dataclass
class SystemViewConfig:
    """@brief Data class representing SystemView configuration."""

    _session: Session
    file: Optional[str] = None
    auto_start: bool = True
    auto_stop: bool = True

    def __post_init__(self):
        systemview = self._session.options.get('systemview') or {}

        # Set default values
        file = f"{self._session.board.target_type}.SVDat"
        auto_start = True
        auto_stop = True

        if systemview:
            file = systemview.get('file', file)
            auto_start = systemview.get('auto-start', auto_start)
            auto_stop = systemview.get('auto-stop', auto_stop)
            if file is not None:
                file = str(Path(os.path.expandvars(str(file))).expanduser().resolve())

        # Check if the folder exists for output file
        outdir = os.path.dirname(file)
        if outdir and not os.path.exists(outdir):
            fname = os.path.basename(file)
            raise FileNotFoundError(
                f"Output directory '{outdir}' for SystemView output file '{fname}' does not exist"
            )

        self.file = file
        self.auto_start = auto_start
        self.auto_stop = auto_stop

class SystemViewSVDat():
    def __init__(self, session: Session, rtt_configs: Dict[int, "RTTConfig"], systemview_config: SystemViewConfig):
        self._session = session
        self._systemview = systemview_config
        self._files_per_core: Dict[int, List[str]] = {}

        if not self._systemview.file:
            LOG.debug("SystemView: No output file configured; cannot configure SystemView SVDat generation")
            return

        # Create a list of output files for each core
        # and delete any existing files with the same name to ensure clean output for SystemView
        fname_root = self._systemview.file.rsplit('.', 1)[0]
        for core_number, rtt in rtt_configs.items():
            if not rtt.channels:
                # No RTT channel configuration for this core; skip to next core
                self._files_per_core[core_number] = []
                continue

            file_list: List[str] = []
            for ch in rtt.channels:
                number, mode, _ = ch
                if mode == 'systemview':
                    fname = f'{fname_root}.core{core_number}.ch{number}.bin'
                    if os.path.exists(fname):
                        os.remove(fname)
                    file_list.append(fname)
            self._files_per_core[core_number] = file_list

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
                            LOG.error("SystemView: failed to remove temporary empty SystemView file '%s'", f)

        if not collected_files:
            LOG.debug("SystemView: no temporary SystemView files; skipping SVDat generation")
            return False

        try:
            with open(self._systemview.file, 'wb') as f_out:
                # Write header
                header = [
                    ";",
                    f"; RecordTime   {datetime.now().strftime('%d %b %Y %H:%M:%S')}",
                    "; Author       pyOCD",
                ]

                # Core index in the SVDat file is determined by the order in which files from each core are appended
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
                        LOG.error("SystemView: failed to remove SystemView file '%s' after appending", f)
        except OSError as e:
            LOG.error("SystemView: failed to open/write SystemView output file '%s': %s", self._systemview.file, e)
            return False

        LOG.info("SystemView: SVDat file '%s' generated", self._systemview.file)
        return True
