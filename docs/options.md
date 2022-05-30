---
title: Session options list
---

_**Note:** The names of these options are expected to change before the 1.0 release of pyOCD, so
they will be better normalized and grouped._

## General options

Note that the `project_dir`, `no_config`, and `config` options must come from either a keyword
argument or the _options_ parameter passed to the `Session` constructor due to how early they are
processed. The consequence of this is that these options cannot be set in a YAML config file.

<table class="docs-table">

<tr><th>Option Name</th><th>Type</th><th>Default</th><th>Description</th></tr>

<tr><td>adi.v5.max_invalid_ap_count</td>
<td>int</td>
<td>3</td>
<td>
If this number of invalid APs is found in a row, then AP scanning will stop. The 'scan_all_aps' option
takes precedence over this option if set.
</td></tr>

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

<tr><td>cmsis_dap.prefer_v1</td>
<td>bool</td>
<td>False</td>
<td>
If a device provides both CMSIS-DAP v1 and v2 interfaces, use the v1 interface in preference of v2.
Normal behaviour is to prefer the v2 interface. This option is primarily intended for testing.
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
<ul>
<li>'halt': immediately halt all accessible cores upon connect.</li>
<li>'pre-reset': perform a hardware reset prior to connect and halt.</li>
<li>'under-reset': assert hardware reset during the connect sequence, then deassert after the cores are halted.
    This connect mode is often necessary to gain control of a target that is in a deep low power mode.</li>
<li>'attach': connect to a running target without halting cores.</li>
</ul>
</td></tr>

<tr><td>cpu.step.instruction.timeout</td>
<td>float</td>
<td>0.0</td>
<td>
<p>Timeout in seconds for instruction step operations. The default of 0 means no timeout.</p>
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

<tr><td>flash.timeout.init</td>
<td>float</td>
<td>5.0</td>
<td>
Flash algorithm init and uninit timeout in seconds.
</td></tr>

<tr><td>flash.timeout.analyzer</td>
<td>float</td>
<td>30.0</td>
<td>
Flash CRC analyzer timeout in seconds.
</td></tr>

<tr><td>flash.timeout.erase_all</td>
<td>float</td>
<td>240.0</td>
<td>
Flash algorithm erase all timeout in seconds.
</td></tr>

<tr><td>flash.timeout.erase_sector</td>
<td>float</td>
<td>10.0</td>
<td>
Flash algorithm sector erase timeout in seconds.
</td></tr>

<tr><td>flash.timeout.program</td>
<td>float</td>
<td>10.0</td>
<td>
Flash algorithm programming timeout in seconds.
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
<td>False</td>
<td>
Whether to preserve existing flash content for ranges of sectors that will be erased but not written
with new data.
</td></tr>

<tr><td>logging</td>
<td>str, dict</td>
<td><i>No default</i></td>
<td>
Either a dictionary with logging configuration, or a path to a separate yaml logging configuration
file. See the <a href="{% link _docs/configuring_logging.md %}">logging configuration documentation</a> for details of how to
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

<tr><td>reset.dap_recover.timeout</td>
<td>float</td>
<td>5.0</td>
<td>
Timeout for waiting for the DAP to be accessible after reset, in seconds. If the timeout lapses, an attempt
will be made to reconnect the DP and retry.
</td></tr>

<tr><td>reset.core_recover.timeout</td>
<td>float</td>
<td>2.0</td>
<td>
Timeout in seconds for waiting for a core to be accessible after reset. A warning is printed if the timeout
lapses. Set to 0 to disable the core accessibility test. For halting reset, this is also the timeout for waiting
for the core to halt.
</td></tr>

<tr><td>reset.halt_timeout</td>
<td>float</td>
<td>2.0</td>
<td>
Timeout in seconds for waiting for the core to halt after a reset and halt.
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

<tr><td>serve_local_only</td>
<td>bool</td>
<td>True</td>
<td>
When this option is True, the GDB server, probe server, semihosting telnet, and raw SWV server are only served
on localhost, making them inaccessible across the network. Set to False to enable connecting to these ports
from any machine on the network.
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

<tr><td>debug.status_fault_retry_timeout</td>
<td>float</td>
<td>1</td>
<td>
Duration in seconds that a failed target status check will be retried before an error is raised. Only
applies while the target is running after a resume operation in the debugger and pyOCD is waiting for
it to halt again.
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
</td></tr>

<tr><td>semihost_use_syscalls</td>
<td>bool</td>
<td>False</td>
<td>
Whether to use GDB syscalls for semihosting file access operations, or to have pyOCD perform the
operations. This is most useful if GDB is running on a remote system.
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

<tr><td>swv_raw_enable</td>
<td>bool</td>
<td>True</td>
<td>
Enable flag for the raw SWV stream server.
</td></tr>

<tr><td>swv_raw_port</td>
<td>int</td>
<td>3443</td>
<td>
TCP port number for the raw SWV stream server.
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

## CMSIS-DAP probe options

These session options are available when the CMSIS-DAP debug probe plugin is active.

<table>

<tr><th>Option Name</th><th>Type</th><th>Default</th><th>Description</th></tr>

<tr><td>cmsis_dap.deferred_transfers</td>
<td>bool</td>
<td>True</td>
<td>
Whether to use deferred transfers in the CMSIS-DAP probe backend. By disabling deferred transfers,
all writes take effect immediately. However, performance is negatively affected.
</td></tr>

<tr><td>cmsis_dap.limit_packets</td>
<td>bool</td>
<td>False</td>
<td>
Restrict CMSIS-DAP backend to using a single in-flight command at a time. This is useful on some systems
where USB is problematic, in particular virtual machines.
</td></tr>

</table>

## J-Link probe options

These session options are available when the SEGGER J-Link debug probe plugin is active.

<table>

<tr><th>Option Name</th><th>Type</th><th>Default</th><th>Description</th></tr>

<tr><td>jlink.device</td>
<td>str</td>
<td><i>No default</i></td>
<td>
If this option is set to a supported J-Link device name, then the J-Link will be asked connect
using this name. Otherwise, when unset, the J-Link is configured for only the low-level CoreSight operations
required by pyOCD. Ordinarily, it does not need to be set.
</td></tr>

<tr><td>jlink.non_interactive</td>
<td>bool</td>
<td>True</td>
<td>
Controls whether the J-Link DLL is allowed to present UI dialog boxes and its control
panel. Note that dialog boxes will actually still be visible, but the default option
will be chosen automatically after 5 seconds.

Note: This has the effect of also silencing dialog boxes that appear when
updating firmware / to confirm updating firmware.
</td></tr>

<tr><td>jlink.power</td>
<td>bool</td>
<td>True</td>
<td>
Enable target power when connecting via a JLink probe, and disable power when disconnecting.
Default is True.
</td></tr>

</table>

## Picoprobe options

These session options are available when the Picoprobe debug probe plugin is active.

<table>

<tr><th>Option Name</th><th>Type</th><th>Default</th><th>Description</th></tr>

<tr><td>picoprobe.safeswd</td>
<td>bool</td>
<td>False</td>
<td>
Use safer but slower SWD transfer function with Picoprobe.
Default is False, so possible WAIT or FAULT SWD acknowldeges and protocol errors will not be caught immediately.
</td></tr>

</table>

## STLink options

These session options are available when the STLink debug probe plugin is active.

<table>

<tr><th>Option Name</th><th>Type</th><th>Default</th><th>Description</th></tr>

<tr><td>stlink.v3_prescaler</td>
<td>int</td>
<td>1</td>
<td>
Sets the HCLK prescaler of an STLinkV3, changing performance versus power tradeoff.
The value must be one of 1=high performance (default), 2=normal, or 4=low power.
</td></tr>

</table>
