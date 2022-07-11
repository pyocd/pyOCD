# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
# Copyright (c) 2021-2022 Chris Reed
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

import colorama
from colorama import (Fore, Style)
import logging
from shutil import get_terminal_size
import sys
from typing import (IO, Optional)

class ColorFormatter(logging.Formatter):
    """@brief Log formatter that applies colours based on the record's log level."""

    FORMAT = "{timecolor}{relativeCreated:07.0f}{_reset} {lvlcolor:s}{levelname:<{levelnamewidth}.{levelnamewidth}s}{_reset} {msgcolor}{message} {_dim}[{module:s}]{_reset}"

    ## Colors for the log level name.
    LEVEL_COLORS = {
            'CRITICAL': Style.BRIGHT + Fore.LIGHTRED_EX,
            'ERROR': Fore.LIGHTRED_EX,
            'WARNING': Fore.LIGHTYELLOW_EX,
            'INFO': Fore.CYAN,
            'DEBUG': Style.DIM,
        }

    ## Colors for the rest of the log message.
    MESSAGE_COLORS = {
            'CRITICAL': Fore.LIGHTRED_EX,
            'ERROR': Fore.RED,
            'WARNING': Fore.YELLOW,
            'DEBUG': Style.DIM + Fore.LIGHTWHITE_EX,
        }

    ## Fixed maximum length of the log level name in log messages.
    MAX_LEVELNAME_WIDTH = 1

    def __init__(self, msg, use_color: bool, is_tty: bool) -> None:
        super().__init__(msg, style='{')
        self._use_color = use_color
        self._is_tty = is_tty

        # TODO: Handle resizing of terminal?
        self._term_width = get_terminal_size()[0]

    # Note: we can't set the type of `record` param to LogRecord because that causes type errors for
    # each time below when an attribute is set on the record.
    def format(self, record) -> str:
        # Capture and remove exc_info and stack_info so the superclass format() doesn't
        # print it and we can control the formatting.
        exc_info = record.exc_info
        record.exc_info = None
        stack_info = record.stack_info
        record.stack_info = None

        # Add colors to the record.
        if self._use_color:
            record.lvlcolor = self.LEVEL_COLORS.get(record.levelname, '')

            # Colorise the line.
            record.msgcolor = self.MESSAGE_COLORS.get(record.levelname, '')

            # Fixed colors.
            record.timecolor = Fore.BLUE
            record._reset = Style.RESET_ALL
            record._dim = Style.DIM
        else:
            record.lvlcolor = ""
            record.msgcolor = ""
            record.timecolor = ""
            record._reset = ""
            record._dim = ""

        record.message = record.getMessage()

        # Add levelname alignment to record.
        record.levelname_align = " " * max(self.MAX_LEVELNAME_WIDTH - len(record.levelname), 0)
        record.levelnamewidth = self.MAX_LEVELNAME_WIDTH

        # Let superclass handle formatting.
        log_msg = super().format(record)

        # Append uncolored exception/stack info.
        if exc_info:
            log_msg += "\n" + Style.DIM + self.formatException(exc_info) + Style.RESET_ALL
        if stack_info:
            log_msg += "\n" + Style.DIM + self.formatStack(stack_info) + Style.RESET_ALL

        return log_msg


def build_color_logger(
            level: int = logging.INFO,
            color_setting: str = 'auto',
            stream: Optional[IO[str]] = None,
            is_tty: Optional[bool] = None,
        ) -> logging.Logger:
    """@brief Sets up color logging for the root logger.

    @param level Log level of the root logger.
    @param color_setting One of 'auto', 'always', or 'never'. The default 'auto' enables color if `is_tty` is True.
    @param stream The stream to which the log will be output. The default is stderr.
    @param is_tty Whether the output stream is a tty. Affects the 'auto' color_setting. If not provided, the
        `isatty()` method of both `sys.stdout` and `sys.stderr` is called if they exists. Both must return
        True for the 'auto' color setting to enable color output.
    """
    if stream is None:
        stream = sys.stderr
    if is_tty is None:
        stdout_is_tty = sys.stdout.isatty() if hasattr(sys.stdout, 'isatty') else False
        stderr_is_tty = sys.stderr.isatty() if hasattr(sys.stderr, 'isatty') else False
        is_tty = stdout_is_tty and stderr_is_tty
    use_color = (color_setting == "always") or (color_setting == "auto" and is_tty)

    # Init colorama with appropriate color setting.
    colorama.init(strip=(not use_color))

    # Create handler to output logging to stderr.
    console = logging.StreamHandler(stream)

    # Create the color formatter and attach to our stream handler.
    color_formatter = ColorFormatter(ColorFormatter.FORMAT, use_color, is_tty)
    console.setFormatter(color_formatter)

    # Set stream handler and log level on root logger.
    root_logger = logging.getLogger()
    root_logger.addHandler(console)
    root_logger.setLevel(level)

    return root_logger

