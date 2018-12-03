# pyOCD debugger
# Copyright (c) 2018 Arm Limited
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

from collections import namedtuple

OptionInfo = namedtuple('OptionInfo', 'name type help')

OPTIONS_INFO = {
    # Common options
    'auto_unlock': OptionInfo('auto_unlock', bool, "Whether to unlock secured target by erasing."),
    'config_file': OptionInfo('config_file', str, "Path to custom config file."),
    'frequency': OptionInfo('frequency', int, "SWD/JTAG frequency in Hertz."),
    'halt_on_connect': OptionInfo('halt_on_connect', bool, "Whether to halt CPU when connecting."),
    'no_config': OptionInfo('no_config', bool, "Do not use default config file."),
    'resume_on_disconnect': OptionInfo('resume_on_disconnect', bool, "Whether to run target on disconnect."),
    'target_override': OptionInfo('target_override', str, "Name of target to use instead of default."),
    'test_binary': OptionInfo('test_binary', str, "Name of test firmware binary."),

    # GDBServer options
    'chip_erase': OptionInfo('chip_erase', str, "Whether to perform a chip erase or sector erases when programming flash."),
    'enable_semihosting': OptionInfo('enable_semihosting', str, "Set to True to handle semihosting requests."),
    'fast_program': OptionInfo('fast_program', str, "Setting this option to True will use CRC checks of existing flash sector contents to determine whether pages need to be programmed."),
    'gdbserver_port': OptionInfo('gdbserver_port', str, "Base TCP port for the gdbserver."),
    'hide_programming_progress': OptionInfo('hide_programming_progress', str, "Disables flash programming progress bar."),
    'persist': OptionInfo('persist', str, "If True, the GDB server will not exit after GDB disconnects."),
    'report_core_number': OptionInfo('report_core_number', str, "Whether gdb server should report core number as part of the per-thread information."),
    'semihost_console_type': OptionInfo('semihost_console_type', str, "If set to \"telnet\" then the semihosting telnet server will be started, otherwise semihosting will print to the console."),
    'semihost_use_syscalls': OptionInfo('semihost_use_syscalls', str, "Whether to use GDB syscalls for semihosting file access operations."),
    'serve_local_only': OptionInfo('serve_local_only', str, "When this option is True, the GDB server and semihosting telnet ports are only served on localhost."),
    'soft_bkpt_as_hard': OptionInfo('soft_bkpt_as_hard', str, "Whether to force all breakpoints to be hardware breakpoints."),
    'step_into_interrupt': OptionInfo('step_into_interrupt', str, "Enable interrupts when performing step operations."),
    'telnet_port': OptionInfo('telnet_port', str, "Base TCP port number for the semihosting telnet server."),
    'vector_catch': OptionInfo('vector_catch', str, "Enable vector catch sources."),
    }
