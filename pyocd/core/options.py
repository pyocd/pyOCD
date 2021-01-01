# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
# Copyright (c) 2020 Patrick Huesmann
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

## @brief Definitions of the builtin options.
BUILTIN_OPTIONS = [
    # Common options
    OptionInfo('adi.v5.max_invalid_ap_count', int, 3,
        "If this number of invalid APs is found in a row, then AP scanning will stop. The 'scan_all_aps' option "
        "takes precedence over this option if set."),
    OptionInfo('allow_no_cores', bool, False,
        "Prevents raising an error if no core were found after CoreSight discovery."),
    OptionInfo('auto_unlock', bool, True,
        "Whether to unlock secured target by erasing."),
    OptionInfo('cache.read_code_from_elf', bool, True,
        "Controls whether reads of code sections will be taken from an attached ELF file instead of the "
        "target memory."),
    OptionInfo('chip_erase', str, "sector",
        "Whether to perform a chip erase or sector erases when programming flash. The value must be"
        " one of \"auto\", \"sector\", or \"chip\"."),
    OptionInfo('cmsis_dap.deferred_transfers', bool, True,
        "Whether the CMSIS-DAP probe backend will use deferred transfers for improved performance."),
    OptionInfo('cmsis_dap.limit_packets', bool, False,
        "Restrict CMSIS-DAP backend to using a single in-flight command at a time."),
    OptionInfo('commander.history_length', int, 1000,
        "Number of entries in the pyOCD Commander command history. Set to -1 for unlimited. Default is 1000."),
    OptionInfo('config_file', str, None,
        "Path to custom config file."),
    OptionInfo('connect_mode', str, "halt",
        "One of 'halt', 'pre-reset', 'under-reset', 'attach'. Default is 'halt'."),
    OptionInfo('cpu.step.instruction.timeout', float, 0.0,
        "Timeout in seconds for instruction step operations. Defaults to 0, or no timeout."),
    OptionInfo('dap_protocol', str, 'default',
        "Wire protocol, either 'swd', 'jtag', or 'default'."),
    OptionInfo('dap_swj_enable', bool, True,
        "Send SWJ transition sequence to switch between SWD and JTAG."),
    OptionInfo('dap_swj_use_dormant', bool, False,
        "When switching between SWD and JTAG, use the SWJ sequence from ADIv5.2 that utilizes a new dormant state."),
    OptionInfo('debug.log_flm_info', bool, False,
        "Log details of loaded .FLM flash algos."),
    OptionInfo('debug.traceback', bool, True,
        "Print tracebacks for exceptions."),
    OptionInfo('enable_multicore', bool, False,
        "Whether to put pyOCD into multicore debug mode."),
    OptionInfo('fast_program', bool, False,
        "Setting this option to True will use CRC checks of existing flash sector contents to "
        "determine whether pages need to be programmed."),
    OptionInfo('frequency', int, 1000000,
        "SWD/JTAG frequency in Hertz."),
    OptionInfo('hide_programming_progress', bool, False,
        "Disables flash programming progress bar."),
    OptionInfo('keep_unwritten', bool, True,
        "Whether to load existing flash content for ranges of sectors that will be erased but not "
        "written with new data. Default is True."),
    OptionInfo('logging', (str, dict), None,
        "Logging configuration dictionary, or path to YAML file containing logging configuration."),
    OptionInfo('no_config', bool, False,
        "Do not use default config file."),
    OptionInfo('pack', (str, list), None,
        "Path or list of paths to CMSIS Device Family Packs. Devices defined in the pack(s) are "
        "added to the list of available targets."),
    OptionInfo('probeserver.port', int, 5555,
        "TCP port for the debug probe server."),
    OptionInfo('project_dir', str, None,
        "Path to the session's project directory. Defaults to the working directory when the pyocd "
        "tool was executed."),
    OptionInfo('reset_type', str, 'default',
        "Which type of reset to use by default ('default', 'hw', 'sw', 'sw_sysresetreq', "
        "'sw_vectreset', 'sw_emulated'). The default is 'sw'."),
    OptionInfo('reset.hold_time', float, 0.1,
        "Number of seconds to hold hardware reset asserted. Default is 0.1 s (100 ms)."),
    OptionInfo('reset.post_delay', float, 0.1,
        "Number of seconds to delay after a reset is issued. Default is 0.1 s (100 ms)."),
    OptionInfo('reset.halt_timeout', float, 2.0,
        "Timeout for waiting for the core to halt after a reset and halt. Default is 2.0 s."),
    OptionInfo('resume_on_disconnect', bool, True,
        "Whether to run target on disconnect."),
    OptionInfo('scan_all_aps', bool, False,
        "Controls whether all 256 ADIv5 AP addresses will be probed. Default is False."),
    OptionInfo('serve_local_only', bool, True,
        "When this option is True, the GDB server, probe server, and semihosting telnet, and raw SWV "
        "server are only served on localhost. Set to False to enable remote connections."),
    OptionInfo('smart_flash', bool, True,
        "If set to True, the flash loader will attempt to not program pages whose contents are not "
        "going to change by scanning target flash memory. A value of False will force all pages to "
        "be erased and programmed. Default is True."),
    OptionInfo('target_override', str, None,
        "Name of target to use instead of default."),
    OptionInfo('test_binary', str, None,
        "Name of test firmware binary."),
    OptionInfo('user_script', str, None,
        "Path of the user script file."),
    OptionInfo('warning.cortex_m_default', bool, True,
        "Whether to show the warning about use of the cortex_m target type. Default is True."),

    # GDBServer options
    OptionInfo('enable_semihosting', bool, False,
        "Set to True to handle semihosting requests."),
    OptionInfo('enable_swv', bool, False,
        "Whether to enable SWV printf output over the semihosting console. Requires the "
        "swv_system_clock option to be set. The SWO baud rate can be controlled with the "
        "swv_clock option."),
    OptionInfo('gdbserver_port', int, 3333,
        "Base TCP port for the gdbserver."),
    OptionInfo('persist', bool, False,
        "If True, the GDB server will not exit after GDB disconnects."),
    OptionInfo('report_core_number', bool, False,
        "Whether gdb server should report core number as part of the per-thread information."),
    OptionInfo('rtos.enable', bool, True,
        "Overall enable flag for RTOS aware debugging. By default it's enabled but can be switched off "
        "if necessary."),
    OptionInfo('rtos.name', str, None,
        "Name of the RTOS plugin to use. If not set, all RTOS plugins are given a chance to load."),
    OptionInfo('semihost_console_type', str, 'telnet',
        "If set to \"telnet\" then the semihosting telnet server will be started, otherwise "
        "semihosting will print to the console."),
    OptionInfo('semihost_use_syscalls', bool, False,
        "Whether to use GDB syscalls for semihosting file access operations."),
    OptionInfo('step_into_interrupt', bool, False,
        "Enable interrupts when performing step operations."),
    OptionInfo('swv_clock', int, 1000000,
        "Frequency in Hertz of the SWO baud rate. Default is 1 MHz."),
    OptionInfo('swv_system_clock', int, None,
        "Frequency in Hertz of the target's system clock. Used to compute the SWO baud rate "
        "divider. No default."),
    OptionInfo('swv_raw_enable', bool, True,
        "Enable flag for the raw SWV stream server."),
    OptionInfo('swv_raw_port', int, 3443,
        "TCP port number for the raw SWV stream server."),
    OptionInfo('telnet_port', int, 4444,
        "Base TCP port number for the semihosting telnet server."),
    OptionInfo('vector_catch', str, 'h',
        "Enable vector catch sources."),
    OptionInfo('xpsr_control_fields', bool, False,
        "When set to True, XPSR and CONTROL registers will have their respective bitfields defined "
        "for presentation in gdb."),
    ]

## @brief The runtime dictionary of options.
OPTIONS_INFO = {}

def add_option_set(options):
    """! @brief Merge a list of OptionInfo objects into OPTIONS_INFO."""
    OPTIONS_INFO.update({oi.name: oi for oi in options})

# Start with only builtin options.
add_option_set(BUILTIN_OPTIONS)
