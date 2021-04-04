# pyOCD debugger
# Copyright (c) 2021 Chris Reed
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
from typing import List
import logging
import sys

from .base import SubcommandBase
from ..core.helpers import ConnectHelper
from ..core.target import Target
from ..utility.cmdline import (
    convert_session_options,
    convert_reset_type,
    )

LOG = logging.getLogger(__name__)

class ResetSubcommand(SubcommandBase):
    """! @brief Base class for pyocd command line subcommand."""
    
    NAMES = ['reset']
    HELP = "Reset a device."
    DEFAULT_LOG_LEVEL = logging.WARNING
    
    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """! @brief Add this subcommand to the subparsers object."""
        reset_parser = argparse.ArgumentParser(description='reset', add_help=False)

        reset_options = reset_parser.add_argument_group("reset options")
        reset_options.add_argument("-m", "--method", default='hw', dest='reset_type', metavar="METHOD",
            help="Reset method to use ('hw', 'sw', and others). Default is 'hw'.")
        
        return [cls.CommonOptions.COMMON, cls.CommonOptions.CONNECT, reset_parser]
    
    def invoke(self) -> None:
        """! @brief Handle 'reset' subcommand."""
        # Verify selected reset type.
        try:
            the_reset_type = convert_reset_type(self._args.reset_type)
        except ValueError:
            LOG.error("Invalid reset method: %s", self._args.reset_type)
            return
        
        session = ConnectHelper.session_with_chosen_probe(
                            project_dir=self._args.project_dir,
                            config_file=self._args.config,
                            user_script=self._args.script,
                            no_config=self._args.no_config,
                            pack=self._args.pack,
                            unique_id=self._args.unique_id,
                            target_override=self._args.target_override,
                            frequency=self._args.frequency,
                            blocking=(not self._args.no_wait),
                            connect_mode=self._args.connect_mode,
                            options=convert_session_options(self._args.options))
        if session is None:
            LOG.error("No device available to reset")
            sys.exit(1)
        try:
            # Handle hw reset specially using the probe, so we don't need a valid connection
            # and can skip discovery.
            is_hw_reset = the_reset_type == Target.ResetType.HW
            
            # Only init the board if performing a sw reset.
            session.open(init_board=(not is_hw_reset))
            
            LOG.info("Performing '%s' reset...", self._args.reset_type)
            if is_hw_reset:
                session.probe.reset()
            else:
                session.target.reset(reset_type=the_reset_type)
            LOG.info("Done.")
        finally:
            session.close()

