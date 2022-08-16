# pyOCD debugger
# Copyright (c) 2021 mikisama
# Copyright (C) 2021 Ciro Cattuto <ciro.cattuto@gmail.com>
# Copyright (C) 2021 Simon D. Levy <simon.d.levy@gmail.com>
# Copyright (C) 2022 Johan Carlsson <johan.carlsson@teenage.engineering>
# Copyright (C) 2022 Samuel Dewan
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
import sys
from time import sleep
from typing import List

from pyocd.core.helpers import ConnectHelper
from pyocd.core.soc_target import SoCTarget
from pyocd.debug.rtt import RTTControlBlock, RTTUpChannel, RTTDownChannel
from pyocd.subcommands.base import SubcommandBase
from pyocd.utility.cmdline import convert_session_options, int_base_0
from pyocd.utility.kbhit import KBHit


LOG = logging.getLogger(__name__)


class RTTSubcommand(SubcommandBase):
    """@brief `pyocd rtt` subcommand."""

    NAMES = ["rtt"]
    HELP = "SEGGER RTT Viewer."

    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """@brief Add this subcommand to the subparsers object."""

        rtt_parser = argparse.ArgumentParser(cls.HELP, add_help=False)

        rtt_options = rtt_parser.add_argument_group("rtt options")
        rtt_options.add_argument("-a", "--address", type=int_base_0, default=None,
                                 help="Start address of RTT control block search range.")
        rtt_options.add_argument("-s", "--size", type=int_base_0, default=None,
                                 help="Size of RTT control block search range.")

        return [cls.CommonOptions.COMMON, cls.CommonOptions.CONNECT, rtt_parser]

    def invoke(self) -> int:

        session = None
        kb = None

        try:
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
                LOG.error("No target device available")
                return 1

            with session:

                target: SoCTarget = session.board.target

                control_block = RTTControlBlock.from_target(target,
                            address = self._args.address,
                            size = self._args.size)
                control_block.start()

                if len(control_block.up_channels) < 1:
                    LOG.error("No up channels.")
                    return 1

                if len(control_block.down_channels) < 1:
                    LOG.error("No down channels.")
                    return 1

                LOG.info(f"{len(control_block.up_channels)} up channels and "
                         f"{len(control_block.down_channels)} down channels found")

                up_chan: RTTUpChannel = control_block.up_channels[0]
                down_chan: RTTDownChannel = control_block.down_channels[0]

                up_name = up_chan.name if up_chan.name is not None else ""
                down_name = down_chan.name if down_chan.name is not None else ""
                LOG.info(f"Reading from up channel 0 (\"{up_name}\"), writing to "
                         f"down channel 0 (\"{down_name}\")")

                # some targets might need this here
                #target.reset_and_halt()

                target.resume()

                # set up terminal input
                kb = KBHit()

                # byte array to send via RTT
                cmd = bytes()

                while True:
                    # poll at most 1000 times per second to limit CPU use
                    sleep(0.001)

                    # read data from up buffer 0 (target -> host) and write to
                    # stdout
                    up_data: bytes = up_chan.read()
                    sys.stdout.buffer.write(up_data)
                    sys.stdout.buffer.flush()

                    # try to fetch character
                    if kb.kbhit():
                        c: str = kb.getch()

                        if ord(c) == 27: # process ESC
                            break
                        elif c.isprintable() or c == '\n':
                            print(c, end="", flush=True)

                        # add char to buffer
                        cmd += c.encode("utf-8")

                    # write buffer to target
                    if not cmd:
                        continue

                    # write cmd buffer to down buffer 0 (host -> target)
                    bytes_out = down_chan.write(cmd)
                    cmd = cmd[bytes_out:]

        except KeyboardInterrupt:
            pass

        finally:
            if session:
                session.close()
            if kb:
                kb.set_normal_term()

        return 0
