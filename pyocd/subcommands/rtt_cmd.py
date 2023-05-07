# pyOCD debugger
# Copyright (c) 2021 mikisama
# Copyright (C) 2021 Ciro Cattuto <ciro.cattuto@gmail.com>
# Copyright (C) 2021 Simon D. Levy <simon.d.levy@gmail.com>
# Copyright (C) 2022 Johan Carlsson <johan.carlsson@teenage.engineering>
# Copyright (C) 2022 Samuel Dewan
# Copyright (C) 2022 Zhengji Li
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
import time
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
    HELP = "SEGGER RTT Viewer/Logger."

    @classmethod
    def get_args(cls) -> List[argparse.ArgumentParser]:
        """@brief Add this subcommand to the subparsers object."""

        rtt_parser = argparse.ArgumentParser(cls.HELP, add_help=False)

        rtt_options = rtt_parser.add_argument_group("rtt options")
        rtt_options.add_argument("-a", "--address", type=int_base_0, default=None,
                                 help="Start address of RTT control block search range.")
        rtt_options.add_argument("-s", "--size", type=int_base_0, default=None,
                                 help="Size of RTT control block search range.")
        rtt_options.add_argument("--up-channel-id", type=int, default=0,
                                 help="Up channel ID.")
        rtt_options.add_argument("--down-channel-id", type=int, default=0,
                                 help="Down channel ID.")
        rtt_options.add_argument("-d", "--log-file", type=str, default=None,
                                 help="Log file name. When specified, logging mode is enabled.")

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
                options=convert_session_options(self._args.options),
                option_defaults=self._modified_option_defaults(),
                )

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

                LOG.info(f"{len(control_block.up_channels)} up channels and "
                         f"{len(control_block.down_channels)} down channels found")

                up_chan: RTTUpChannel = control_block.up_channels[self._args.up_channel_id]
                up_name = up_chan.name if up_chan.name is not None else ""
                LOG.info(f"Reading from up channel {self._args.up_channel_id} (\"{up_name}\")")

                # some targets might need this here
                #target.reset_and_halt()

                target.resume()

                # set up terminal input
                kb = KBHit()

                if self._args.log_file is None:
                    if len(control_block.down_channels) < 1:
                        LOG.error("No down channels.")
                        return 1
                    down_chan: RTTDownChannel = control_block.down_channels[self._args.down_channel_id]
                    down_name = down_chan.name if down_chan.name is not None else ""
                    LOG.info(f"Writing to down channel {self._args.down_channel_id} (\"{down_name}\")")

                    self.viewer_loop(up_chan, down_chan, kb)
                else:
                    self.logger_loop(up_chan, kb)

        except KeyboardInterrupt:
            pass

        finally:
            if session:
                session.close()
            if kb:
                kb.set_normal_term()

        return 0

    def logger_loop(self, up_chan, kb):

        LOG.info("start logging ... Press any key to stop")
        total_size = 0
        block_size = 0
        last_time = time.time()

        with open(self._args.log_file, 'wb') as log_file:

            while True:
                # poll at most 1000 times per second to limit CPU use
                sleep(0.001)

                # read data from up buffer
                data = up_chan.read()
                log_file.write(data)

                s = len(data)
                block_size += s
                total_size += s
                diff = time.time() - last_time
                if diff > 1.0:
                    print(f"Transfer rate: {block_size / 1000:.1f} KByte/s; Bytes written: {total_size / 1000:.0f} KByte", end="\r")
                    block_size = 0
                    last_time = time.time()

                # try to fetch character
                if kb.kbhit():
                    break

    def viewer_loop(self, up_chan, down_chan, kb):
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
