Session options list
=================

_**Note:** The names of these options are expected to change before the 1.0 release of pyOCD, so
they will be better normalized and grouped._

## General options

Note that the `project_dir`, `no_config`, and `config` options must come from either a keyword
argument or the _options_ parameter passed to the `Session` constructor due to how early they are
processed. The consequence of this is that these options cannot be set in a YAML config file.

<table>

<tr><th>Option Name</th><th>Type</th><th>Default</th><th>Description</th></tr>

<tr><td>allow_no_cores</td>
<td>bool</td>
<td>False</td>
<td>
Prevents raising an error if no core were found after CoreSight discovery.
</td></tr>

<tr><td>auto_unlock</td>
<td>bool</td>
<td>True</td>
<td>
If the target is locked, it will by default be automatically mass erased in order to gain debug
access. Set this option to False to disable auto unlock.
</td></tr>

<tr><td>cache.read_code_from_elf</td>
<td>bool</td>
<td>True</td>
<td>
Controls whether reads of code sections will be taken from an attached ELF file instead of the target memory.
This can improve performance, especially over slow target connections. Requires an ELF file to be set.
</td></tr>

<tr><td>chip_erase</td>
<td>str</td>
<td>'sector'</td>
<td>
Whether to perform a chip erase or sector erases when programming flash. The value must be one of
'auto', 'sector', or 'chip'.
</td></tr>

<tr><td>cmsis_dap.deferred_transfers</td>
<td>bool</td>
<td>True</td>
<td>
Whether to use deferred transfers in the CMSIS-DAP probe backend. By disabling deferred transfers,
all writes take effect immediately. However, performance is negatively affected.
</td></tr>

<tr><td>commander.history_length</td>
<td>int</td>
<td>1000</td>
<td>
Number of entries in the pyOCD Commander command history. Set to -1 for unlimited.
</td></tr>

<tr><td>config_file</td>
<td>str</td>
<td><i>See description</i></td>
<td>
Relative path to a YAML config file that lets you specify session options either globally or per probe.
The format of the file is documented above. The default is a <tt>pyocd.yaml</tt> or <tt>pyocd.yml</tt> file in the
working directory.
</td></tr>

<tr><td>connect_mode</td>
<td>str</td>
<td>'halt'</td>
<td>
Controls how pyOCD connects to the target. One of 'halt', 'pre-reset', 'under-reset', 'attach'.
</td></tr>

<tr><td>cpu.step.instruction.timeout</td>
<td>float</td>
<td>0.0</td>
<td>
<p>Timeout in seconds for instruction step operations. The default of 0 means no timeout.<p>
<p>Note that stepping may take a very long time for to return in cases such as stepping over a branch
into the Secure world where the debugger doesn't have secure debug access, or similar for Privileged
code in the case of UDE.</p>
</td></tr>

<tr><td>dap_protocol</td>
<td>str</td>
<td>'default'</td>
<td>
Wire protocol, either 'swd', 'jtag', or 'default'.
</td></tr>

<tr><td>dap_swj_enable</td>
<td>bool</td>
<td>True</td>
<td>
Send SWJ transition sequence to switch between SWD and JTAG.
</td></tr>

<tr><td>dap_swj_use_dormant</td>
<td>bool</td>
<td>False</td>
<td>
When switching between SWD and JTAG, use the SWJ sequence added in ADIv5.2 that transitions through
a new dormant state. Requires a SWJ-DPv2. Note that if the connection attempt fails using the
deprecated sequence (when this option is disabled), then pyOCD will automatically attempt to use the
new sequence. This option simply skips the deprecated sequence in case it causes problems or it is
known that dormant state is required for the target.
</td></tr>

<tr><td>debug.log_flm_info</td>
<td>bool</td>
<td>False</td>
<td>
Log details of loaded .FLM flash algos.
</td></tr>

<tr><td>debug.traceback</td>
<td>bool</td>
<td>True</td>
<td>
Print tracebacks for exceptions.
</td></tr>

<tr><td>enable_multicore_debug</td>
<td>bool</td>
<td>False</td>
<td>
Whether to put pyOCD into multicore debug mode. The primary effect is to modify the default software
reset type for secondary cores to use VECTRESET, which will fall back to emulated reset if the
secondary core is not v7-M.
</td></tr>

<tr><td>fast_program</td>
<td>bool</td>
<td>False</td>
<td>
Setting this option to True will use CRC checks of existing flash sector
contents to determine whether pages need to be programmed.
</td></tr>

<tr><td>frequency</td>
<td>int</td>
<td>1000000 (1 MHz)</td>
<td>
SWD/JTAG frequency in Hertz.
</td></tr>

<tr><td>hide_programming_progress</td>
<td>bool</td>
<td>False</td>
<td>
Disables flash programming progress bar when True.
</td></tr>

<tr><td>keep_unwritten</td>
<td>bool</td>
<td>True</td>
<td>
Whether to load existing flash content for ranges of sectors that will be erased but not written
with new data.
</td></tr>

<tr><td>logging</td>
<td>str, dict</td>
<td><i>No default</i></td>
<td>
Either a dictionary with logging configuration, or a path to a separate yaml logging configuration
file. See the <a href="configuring_logging.md">logging configuration documentation</a> for details of how to
use this option.
</td></tr>

<tr><td>no_config</td>
<td>bool</td>
<td>False</td>
<td>
Do not use default config file.
</td></tr>

<tr><td>pack</td>
<td>str, list of str</td>
<td><i>No default</i></td>
<td>
Path or list of paths to CMSIS Device Family Packs. Devices defined in the pack(s) are added to the
list of available targets.
</td></tr>

<tr><td>probeserver.port</td>
<td>int</td>
<td>5555</td>
<td>
TCP port for the debug probe server.
</td></tr>

<tr><td>project_dir</td>
<td>str</td>
<td><i>See description</i></td>
<td>
Path to the session's project directory. Defaults to the working directory when the pyocd tool was
executed.
</td></tr>

<tr><td>reset_type</td>
<td>str</td>
<td>'sw'</td>
<td>
Which type of reset to use by default (one of 'default', 'hw', 'sw', 'sw_sysresetreq',
'sw_vectreset', 'sw_emulated').
</td></tr>

<tr><td>reset.hold_time</td>
<td>float</td>
<td>0.1</td>
<td>
Number of seconds to hold hardware reset asserted.
</td></tr>

<tr><td>reset.post_delay</td>
<td>float</td>
<td>0.1</td>
<td>
Number of seconds to delay after a reset is issued.
</td></tr>

<tr><td>reset.halt_timeout</td>
<td>float</td>
<td>2.0</td>
<td>
Timeout for waiting for the core to halt after a reset and halt.
</td></tr>

<tr><td>resume_on_disconnect</td>
<td>bool</td>
<td>True</td>
<td>
Whether to resume a halted target when disconnecting.
</td></tr>

<tr><td>scan_all_aps</td>
<td>bool</td>
<td>False</td>
<td>
Controls whether all 256 ADIv5 AP addresses will be probed.
</td></tr>

<tr><td>smart_flash</td>
<td>bool</td>
<td>True</td>
<td>
If set to True, the flash loader will attempt to not program pages whose contents are not going to
change by scanning target flash memory. A value of False will force all pages to be erased and
programmed.
</td></tr>

<tr><td>target_override</td>
<td>str</td>
<td><i>No default</i></td>
<td>
Target type name to use instead of default board target or default <tt>cortex_m</tt>.
</td></tr>

<tr><td>test_binary</td>
<td>str</td>
<td><i>No default</i></td>
<td>
Specify the test binary file name used by the functional test suite (in the <tt>test/</tt> directory). The
binary must be in the <tt>binaries/</tt> directory. This option is most useful when set in a board config
file for running the functional tests on boards that cannot be automatically detected.
</td></tr>

<tr><td>user_script</td>
<td>str</td>
<td><i>No default</i></td>
<td>
Path of the user script file.
</td></tr>

<tr><td>warning.cortex_m_default</td>
<td>bool</td>
<td><i>True</i></td>
<td>Whether to show the warning when no target type is selected and the default cortex_m target
type is used. The warning is never shown if the cortex_m target type is explicitly specified.
</td></tr>

</table>


## GDB server options

These session options are currently only applied when running the GDB server.

<table>

<tr><th>Option Name</th><th>Type</th><th>Default</th><th>Description</th></tr>

<tr><td>enable_semihosting</td>
<td>bool</td>
<td>False</td>
<td>
Set to True to handle semihosting requests. Also see the <tt>semihost_console_type</tt> option.
</td></tr>

<tr><td>enable_swv</td>
<td>bool</td>
<td>False</td>
<td>
Whether to enable SWV printf output over the semihosting console. Requires the <tt>swv_system_clock</tt>
option to be set. The SWO baud rate can be controlled with the <tt>swv_clock</tt> option.
</td></tr>

<tr><td>gdbserver_port</td>
<td>int</td>
<td>3333</td>
<td>
Base TCP port for the gdbserver. The core number, which is 0 for the primary core, will be added to
this value.
</td></tr>

<tr><td>persist</td>
<td>bool</td>
<td>False</td>
<td>
If True, the GDB server will not exit after GDB disconnects.
</td></tr>

<tr><td>report_core_number</td>
<td>bool</td>
<td>False</td>
<td>
Whether gdb server should report core number as part of the per-thread information.
</td></tr>

<tr><td>rtos.enable</td>
<td>bool</td>
<td>True</td>
<td>
Overall enable flag for RTOS aware debugging. By default it's enabled but can be switched off
if necessary.
</td></tr>

<tr><td>rtos.name</td>
<td>str</td>
<td><i>No default</i></td>
<td>
Name of the RTOS plugin to use. If not set, all RTOS plugins are given a chance to load.
</td></tr>

<tr><td>semihost_console_type</td>
<td>str</td>
<td>'telnet'</td>
<td>
If set to 'telnet' then the semihosting telnet server will be started. If set to 'console' then
semihosting will print to the console.
<td></tr>

<tr><td>semihost_use_syscalls</td>
<td>bool</td>
<td>False</td>
<td>
Whether to use GDB syscalls for semihosting file access operations, or to have pyOCD perform the
operations. This is most useful if GDB is running on a remote system.
</td></tr>

<tr><td>serve_local_only</td>
<td>bool</td>
<td>True</td>
<td>
When this option is True, the GDB server and semihosting telnet ports are only served on localhost,
making them inaccessible across the network. If False, you can connect to these ports from any
machine that is on the same network.
</td></tr>

<tr><td>step_into_interrupt</td>
<td>bool</td>
<td>False</td>
<td>
Set this option to True to enable interrupts when performing step operations. Otherwise
interrupts will be disabled and step operations cannot be interrupted.
</td></tr>

<tr><td>swv_clock</td>
<td>int</td>
<td>1000000 (1 MHz)</td>
<td>
Frequency in Hertz of the SWO baud rate.
</td></tr>

<tr><td>swv_system_clock</td>
<td>int</td>
<td><i>No default</i></td>
<td>
Frequency in Hertz of the target's system clock. Used to compute the SWO baud rate
divider.
</td></tr>

<tr><td>telnet_port</td>
<td>int</td>
<td>4444</td>
<td>
Base TCP port number for the semihosting telnet server. The core number, which will be 0 for the
primary core, is added to this value.
</td></tr>

<tr><td>vector_catch</td>
<td>str</td>
<td>'h'</td>
<td>
Enable vector catch sources, one letter per enabled source in any order, or
<tt>all</tt> or <tt>none</tt>.

The source letters are:
- <tt>h</tt>=hard fault
- <tt>b</tt>=bus fault
- <tt>m</tt>=mem fault
- <tt>e</tt>=secure fault
- <tt>i</tt>=irq err
- <tt>s</tt>=state err
- <tt>c</tt>=check err
- <tt>p</tt>=nocp
- <tt>r</tt>=reset
- <tt>a</tt>=all
- <tt>n</tt>=none
</td></tr>

<tr><td>xpsr_control_fields</td>
<td>bool</td>
<td>False</td>
<td>
When set to True, XPSR and CONTROL registers will have their respective bitfields defined for
presentation in gdb.
</td></tr>

</table>

## J-Link probe options

These session options are available when the SEGGER J-Link debug probe plugin is active.

<table>

<tr><th>Option Name</th><th>Type</th><th>Default</th><th>Description</th></tr>

<tr><td>jlink.power</td>
<td>bool</td>
<td>True</td>
<td>
Enable target power when connecting via a JLink probe, and disable power when disconnecting.
Default is True.
</td></tr>

<tr><td>jlink.device</td>
<td>str</td>
<td><i>No default</i></td>
<td>
Set the device name passed to the J-Link. Normally, it doesn't matter because pyOCD does has its own
device support, and so when this option is unset, "Cortex-M4" is used just to supply something
valid. (For non-M4-based devices, you might see a warning about unexpected core type if you look at
the J-Link logs, but this is harmless. J-Link does not support a "none" or "unknown" device type.)
</td></tr>

</table>
