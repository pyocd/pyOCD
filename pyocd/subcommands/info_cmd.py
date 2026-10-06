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
from typing import List

from .base import SubcommandBase
from ..core.helpers import ConnectHelper
from ..core.core_target import CoreTarget
from ..utility.cmdline import convert_session_options

LOG = logging.getLogger(__name__)


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
    def _print_core(core: CoreTarget, show_core_number: bool) -> None:
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
        session = ConnectHelper.session_with_chosen_probe(
                            project_dir=self._args.project_dir,
                            config_file=self._args.config,
                            user_script=self._args.script,
                            no_config=self._args.no_config,
                            pack=self._args.pack,
                            cbuild_run=self._args.cbuild_run,
                            unique_id=self._args.unique_id,
                            target_override=self._args.target_override,
                            frequency=self._args.frequency,
                            blocking=False,
                            connect_mode=self._args.connect_mode,
                            command=self._args.cmd,
                            options=convert_session_options(self._args.options),
                            option_defaults=self._modified_option_defaults(),
                            )
        if session is None:
            LOG.error("No target device available")
            return 1

        try:
            # Initialising the board performs DP/AP and ROM table discovery,
            # which provides the target and core information reported below.
            session.open()
            assert session.probe
            assert session.target

            print(f"Debug Probe: {session.probe.description} [{session.probe.unique_id}]")

            protocol = session.probe.wire_protocol
            frequency = session.options.get('frequency')
            if frequency >= 1000000:
                frequency_text = f"{frequency / 1000000:g}MHz"
            elif frequency >= 1000:
                frequency_text = f"{frequency / 1000:g}kHz"
            else:
                frequency_text = f"{frequency:g}Hz"
            print(f"Debug Port: {protocol.name} [{frequency_text}]")

            cores = session.target.cores
            if not cores:
                print("CPU Core: None discovered")
            else:
                for core in cores.values():
                    self._print_core(core, show_core_number=(len(cores) > 1))
        finally:
            session.close()

        return 0
