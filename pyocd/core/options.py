# pyOCD debugger
# Copyright (c) 2018-2019 Arm Limited
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

OptionInfo = namedtuple('OptionInfo', 'name type default help')

OPTIONS_INFO = {
    # Common options
    'allow_no_cores': OptionInfo('allow_no_cores', bool, False,
        "Prevents raising an error if no core were found after CoreSight discovery."),
    'auto_unlock': OptionInfo('auto_unlock', bool, True,
        "Whether to unlock secured target by erasing."),
    'chip_erase': OptionInfo('chip_erase', str, "sector",
        "Whether to perform a chip erase or sector erases when programming flash. The value must be"
        " one of \"auto\", \"sector\", or \"chip\"."),
    'config_file': OptionInfo('config_file', str, None,
        "Path to custom config file."),
    'connect_mode': OptionInfo('connect_mode', str, "halt",
        "One of 'halt', 'pre-reset', 'under-reset', 'attach'. Default is 'halt'."),
    'dap_protocol': OptionInfo('dap_protocol', str, 'default',
        "Wire protocol, either 'swd', 'jtag', or 'default'."),
    'dap_enable_swj': OptionInfo('dap_swj_enable', bool, True,
        "Send SWJ transition sequence to switch between SWD and JTAG."),
    'dap_use_deprecated_swj': OptionInfo('dap_swj_use_deprecated', bool, True,
        "Use the SWJ sequence deprecated in ADIv5.2 to transition between SWD and JTAG."),
    'debug.log_flm_info': OptionInfo('debug.log_flm_info', bool, False,
        "Log details of loaded .FLM flash algos."),
    'debug.traceback': OptionInfo('debug.traceback', bool, True,
        "Print tracebacks for exceptions."),
    'enable_multicore_debug': OptionInfo('enable_multicore', bool, False,
        "Whether to put pyOCD into multicore debug mode."),
    'fast_program': OptionInfo('fast_program', bool, False,
        "Setting this option to True will use CRC checks of existing flash sector contents to "
        "determine whether pages need to be programmed."),
    'frequency': OptionInfo('frequency', int, 1000000,
        "SWD/JTAG frequency in Hertz."),
    'hide_programming_progress': OptionInfo('hide_programming_progress', bool, False,
        "Disables flash programming progress bar."),
    'keep_unwritten': OptionInfo('keep_unwritten', bool, True,
        "Whether to load existing flash content for ranges of sectors that will be erased but not "
        "written with new data. Default is True."),
    'logging': OptionInfo('logging', (str, dict), None,
        "Logging configuration dictionary, or path to YAML file containing logging configuration."),
    'no_config': OptionInfo('no_config', bool, False,
        "Do not use default config file."),
    'pack': OptionInfo('pack', (str, list), None,
        "Path or list of paths to CMSIS Device Family Packs. Devices defined in the pack(s) are "
        "added to the list of available targets."),
    'probe_all_aps': OptionInfo('scan_all_aps', bool, False,
        "Controls whether all 256 ADIv5 AP addresses will be probed. Default is False."),
    'project_dir': OptionInfo('project_dir', str, None,
        "Path to the session's project directory. Defaults to the working directory when the pyocd "
        "tool was executed."),
    'reset_type': OptionInfo('reset_type', str, 'default',
        "Which type of reset to use by default ('default', 'hw', 'sw', 'sw_sysresetreq', "
        "'sw_vectreset', 'sw_emulated'). The default is 'sw'."),
    'resume_on_disconnect': OptionInfo('resume_on_disconnect', bool, True,
        "Whether to run target on disconnect."),
    'smart_flash': OptionInfo('smart_flash', bool, True,
        "If set to True, the flash loader will attempt to not program pages whose contents are not "
        "going to change by scanning target flash memory. A value of False will force all pages to "
        "be erased and programmed. Default is True."),
    'target_override': OptionInfo('target_override', str, None,
        "Name of target to use instead of default."),
    'test_binary': OptionInfo('test_binary', str, None,
        "Name of test firmware binary."),
    'user_script': OptionInfo('user_script', str, None,
        "Path of the user script file."),

    # GDBServer options
    'enable_semihosting': OptionInfo('enable_semihosting', bool, False,
        "Set to True to handle semihosting requests."),
    'enable_swv': OptionInfo('enable_swv', bool, False,
        "Whether to enable SWV printf output over the semihosting console. Requires the "
        "swv_system_clock option to be set. The SWO baud rate can be controlled with the "
        "swv_clock option."),
    'gdbserver_port': OptionInfo('gdbserver_port', int, 3333,
        "Base TCP port for the gdbserver."),
    'persist': OptionInfo('persist', bool, False,
        "If True, the GDB server will not exit after GDB disconnects."),
    'report_core_number': OptionInfo('report_core_number', bool, False,
        "Whether gdb server should report core number as part of the per-thread information."),
    'semihost_console_type': OptionInfo('semihost_console_type', str, 'telnet',
        "If set to \"telnet\" then the semihosting telnet server will be started, otherwise "
        "semihosting will print to the console."),
    'semihost_use_syscalls': OptionInfo('semihost_use_syscalls', bool, False,
        "Whether to use GDB syscalls for semihosting file access operations."),
    'serve_local_only': OptionInfo('serve_local_only', bool, True,
        "When this option is True, the GDB server and semihosting telnet ports are only served on "
        "localhost."),
    'step_into_interrupt': OptionInfo('step_into_interrupt', bool, False,
        "Enable interrupts when performing step operations."),
    'swv_clock': OptionInfo('swv_clock', int, 1000000,
        "Frequency in Hertz of the SWO baud rate. Default is 1 MHz."),
    'swv_system_clock': OptionInfo('swv_system_clock', int, None,
        "Frequency in Hertz of the target's system clock. Used to compute the SWO baud rate "
        "divider. No default."),
    'telnet_port': OptionInfo('telnet_port', int, 4444,
        "Base TCP port number for the semihosting telnet server."),
    'vector_catch': OptionInfo('vector_catch', str, 'h',
        "Enable vector catch sources."),
    'xpsr_control_fields': OptionInfo('xpsr_control_fields', bool, False,
        "When set to True, XPSR and CONTROL registers will have their respective bitfields defined "
        "for presentation in gdb."),
    }
