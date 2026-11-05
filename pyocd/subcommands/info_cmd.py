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

import argparse
import logging
from typing import List, cast

from .base import SubcommandBase
from ..core.session import Session
from ..core.helpers import ConnectHelper
from ..core.core_target import CoreTarget
from ..coresight.dap import ProbeConnector
from ..probe.debug_probe import DebugProbe
from ..probe.shared_probe_proxy import SharedDebugProbeProxy
from ..utility.cmdline import convert_session_options

class _InfoProbeProxy(SharedDebugProbeProxy):
    """@brief Report probe information before the session creates its board and target."""

    @staticmethod
    def _format_frequency(frequency: float) -> str:
        """@brief Format a frequency in Hz with an appropriate unit."""
        if frequency >= 1000000:
            return f"{frequency / 1000000:g}MHz"
        elif frequency >= 1000:
            return f"{frequency / 1000:g}kHz"
        return f"{frequency:g}Hz"

    def _probe_info(self) -> None:
        """@brief Display probe and port information before target selection."""

        print(f"Debug Probe: {self.description} [{self.unique_id}]")
        capabilities = [protocol.name for protocol in (DebugProbe.Protocol.SWD, DebugProbe.Protocol.JTAG)
                        if protocol in self.supported_wire_protocols]
        if DebugProbe.Capability.SWO in self.capabilities:
            capabilities.append("SWO (UART)")
        if capabilities:
            print(f"  Capabilities: {', '.join(capabilities)}")

        assert self.session
        frequency = self.session.options.get('frequency')

        self.set_clock(frequency)
        ProbeConnector(cast(DebugProbe, self)).connect()

        protocol = self.wire_protocol
        if protocol is not None:
            print(f"Debug Port: {protocol.name} [{self._format_frequency(frequency)}]")

        if self.session.options.get('enable_swv'):
            swo_frequency = self.session.options.get('swv_clock')
            print(f"Trace Port: SWO (UART) [{self._format_frequency(swo_frequency)}]")
        else:
            print("Trace Port: disabled")

    def create_associated_board(self):
        # Session options and the user script are loaded before this constructor hook is called.
        self.open()
        self._probe_info()
        return self.probe.create_associated_board()

    def release(self) -> None:
        """@brief Disconnect and close the probe after session cleanup."""
        try:
            if self.probe.is_open and self.probe.wire_protocol is not None:
                self.probe.disconnect()
        finally:
            if self.probe.is_open:
                self.probe.close()

class InfoSubcommand(SubcommandBase):
    """@brief `pyocd info` subcommand."""

    NAMES = ['info']
    HELP = "Display information about the connected target."
    DEFAULT_LOG_LEVEL = logging.WARNING

    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """@brief Add this subcommand to the subparsers object."""
        info_parser = argparse.ArgumentParser(description='info', add_help=False)
        return [cls.CommonOptions.COMMON, cls.CommonOptions.CONNECT, info_parser]

    @staticmethod
    def _print_core_info(core: CoreTarget, show_core_number: bool) -> None:
        """@brief Display the information and detected features of a core."""
        core_label = "CPU core"
        if show_core_number:
            core_label += f" #{core.core_number}"
        core_info = f"{core_label}: {core.name}"
        revision = getattr(core, 'cpu_revision', None)
        patch = getattr(core, 'cpu_patch', None)
        if revision is not None and patch is not None:
            core_info += f" r{revision}p{patch}"
        architecture_version = getattr(core, 'architecture_version', None)
        if architecture_version is not None:
            major, minor = architecture_version
            core_info += f", v{major}.{minor}-M architecture"
        print(core_info)

        extensions = getattr(core, 'extensions', [])
        if extensions:
            print(f"  Extensions: {', '.join(sorted(x.name for x in extensions))}")

        fpb = getattr(core, 'fpb', None)
        if fpb is not None:
            print(f"  {fpb.nb_code} hardware breakpoints, {fpb.nb_lit} literal comparators")

        dwt = getattr(core, 'dwt', None)
        if dwt is not None:
            print(f"  {dwt.watchpoint_count} hardware watchpoints")

    def invoke(self) -> int:
        """@brief Handle the 'info' subcommand."""
        # Unset the logging level for debug sequence messages
        logging.getLogger('pyocd.debug.sequences.functions.message').setLevel(logging.NOTSET)

        probe = ConnectHelper.choose_probe(blocking=False, unique_id=self._args.unique_id)
        if probe is None:
            return 1

        probe_proxy = _InfoProbeProxy(probe)

        session = None
        try:
            session = Session(cast(DebugProbe, probe_proxy),
                            project_dir=self._args.project_dir,
                            config_file=self._args.config,
                            user_script=self._args.script,
                            no_config=self._args.no_config,
                            pack=self._args.pack,
                            cbuild_run=self._args.cbuild_run,
                            target_override=self._args.target_override,
                            frequency=self._args.frequency,
                            connect_mode=self._args.connect_mode,
                            command=self._args.cmd,
                            options=convert_session_options(self._args.options),
                            option_defaults=self._modified_option_defaults(),
                            )

            # Initialising the board performs DP/AP and ROM table discovery,
            # which provides the target and core information reported below.
            session.open()
            assert session.target

            cores = session.target.cores
            if not cores:
                print("CPU Core: None discovered")
            else:
                for core in cores.values():
                    self._print_core_info(core, show_core_number=(len(cores) > 1))
        finally:
            try:
                if session is not None:
                    session.close()
            finally:
                probe_proxy.release()

        return 0
