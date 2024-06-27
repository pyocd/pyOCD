---
title: gdb remote server
---

The `pyocd gdbserver` subcommand runs a gdb remote serial protocol (RSP) server that allows gdb to debug embedded targets.

To run a debug session, the pyOCD gdbserver needs to first be started. Then gdb connects to pyOCD and debugging can begin.


## Running the gdbserver

The usual way to start the gdbserver is by running `pyocd gdbserver` (or `pyocd gdb`) on the command line. The gdbserver will remain available as long as the `pyocd` process is running.

If using an IDE like Microsoft Visual Studio Code or Eclipse Embedded with plugins that support pyOCD, the gdbserver will automatically be started when you launch a debug session. Alternatively, the plugin can be configured to connect to an already-running gdbserver.

From the commander, a gdbserver can be run with the [`gdbserver` command]({% link _docs/command_reference.md %}#gdbserver-1).

The default gdbserver TCP/IP port number is 3333. This can be changed using the `-p` / `--port` or the `gdbserver_port` session option.

### Multicore targets

pyOCD always runs separate gdbservers for each core on multicore devices. This requires separate gdb instances and debug sessions for the cores being debugged, but is the most reliable method since gdb doesn't support heterogenous multicore.

By default, a gdbserver is started for all cores on the target. This can be changed using the `--core` argument, which takes a comma-separated list of core numbers.

The TCP/IP port numbers for each core's gdbserver are determined by adding the core number to the base port number (see above). For a dual core device, core 0 uses the default base port of 3333, and core 1 uses port 3334.

See the [multicore debug documentation]({% link _docs/multicore_debug.md %}) for more information about multicore targets.


## Connecting from gdb

To connect gdb to pyOCD's gdbserver, use the `target remote <host>:<port>` command. These take the server's host name and port number separated by a colon as an argument. For a server running on the same host as gdb, using the default pyOCD port (see above for how to change it), this will be `target remote localhost:3333`.

PyOCD also support extended remote mode. In this case, the connect command is `target extended-remote <host>:<port>`. Extended remote mode allows using the gdb `disconnect` command to disconnect from pyOCD while keeping the gdbserver running.

After connecting gdb, perform the following steps to program updated firmware and run the new code.

1. Program firmware using the `load` command.

2. Reset the target and halt with `monitor reset halt`. This halts the core at the first instruction.

3. Set breakpoints and resume, or use a command line `until main` to run to the first line of `main()`.


## Gdbserver exit

The pyOCD gdbserver process will normally exit automatically when gdb detaches using any of the `detach`, `kill`, or `disconnect` commands. This can be changed with the `--persist` argument or `persist` session option, so that the gdbserver always remains running until terminated directly (by Control-C or equivalent signal).

When gdb connects in extended remote mode, the gdb `disconnect` command will detach gdb but keep the gdbserver running even if persist isn't enabled.


## Useful commands

Gdb by default restricts memory accesses to regions defined in the target memory map provided by pyOCD. This has the unhappy side effect of preventing access to peripheral registers or other Device memory, since the memory maps do not include those regions.

To work around this, disable gbd's `mem inaccessible-by-default` setting.

This line can be added into your `.gdbinit` file:

    (gdb) set mem inaccessible-by-default off

It can also be useful to add an alias to make monitor commands (below) easier to access:

    (gdb) alias m = monitor

To catch crashes and unexpected exceptions, use [`set vector-catch`]({% link _docs/command_reference.md %}#vector-catch) to enable the M-profile vector catch feature:

    (gdb) monitor set vector-catch all

If the core halts in an exception handler, use [`show fault`]({% link _docs/command_reference.md %}#fault) to print out the M-profile fault syndrome registers.

    (gdb) monitor show fault

For most targets, peripheral registers can be accessed using pyOCD's [`reg`]({% link _docs/command_reference.md %}#reg) and [`wreg`]({% link _docs/command_reference.md %}#wreg) commands.

    (gdb) monitor reg TIM21.PSC

Enabling access to all memory as described above is required for this to work.


## Monitor commands

Commands can be sent directly to pyOCD using the gdb `monitor` command. Any output from pyOCD is returned through gdb and printed on the console. This is effectively the same as running the `pyocd commander` subcommand. All [pyOCD commands]({% link _docs/command_reference.md %}) are available.

pyOCD initial selects the core controlled by the gdbserver as the target for monitor commands. Similarly, the selected AP is initially set to the gdbserver's core's MEM-AP. PyOCD's [`core` command]({% link _docs/command_reference.md %}#core-1) can be used to select a different core. This might be useful in order to release a secondary core from reset before starting to debug it, although a [user script]({% link _docs/user_scripts.md %}) could be a better choice.


## Semihosting and RTT

The gdbserver supports [semihosting]({% link _docs/semihosting.md %}), SEGGER RTT, and [Arm SWV]({% link _docs/swo_swv.md %}).


## Caching

Several forms of caching are supported to improve performance when communicating with gdb.

Note that these caches are currently only used with gdb, not for pyOCD's commander interface or the `Target` Python API. (But they will be used for the `DebugContext` objects return from `SoCTarget.get_target_context()`, if that is used through the Python API.)

### Reading memory from the ELF

If provided the firmware's ELF executable file with the `--elf` argument, pyOCD will read target memory contents present in the ELF from that file instead of reading from the target via SWD/JTAG. This can be faster, especially with slower debug probe connections or wire protocol speeds.

The `cache.read_code_from_elf` session option (bool) controls whether this feature is enabled. It's turned on by default, but of course requires the ELF to be passed to pyOCD. (Unfortunately, there is no way to access the executable through gdb.)

### Memory and register cache

Caches for target memory and core register values are present and enabled by default. Both caches are invalidated every time the core is resumed or stepped.

The memory cache will cache any memory region marked as cacheable (all are by default). To disable caching for a memory region, a user script can be used to set its `is_cacheable` property to False.

For example, to disable caching of the "iram" region:

```py
def will_connect():
    target.memory_map.get_first_matching_region(name="iram").is_cacheable = False
```

(Use the `show map` command to see the list of memory regions.)

These session options allow control over the memory and register caches. Both are enabled by default.

- `cache.enable_memory` (bool)
- `cache.enable_register` (bool)


## RTOS thread awareness

The gdbserver supports thread awareness for several RTOSes. Additional RTOS support can be added with plugins.

When gdb connects, pyOCD will attempt to enable thread awareness. By default, all available RTOS plugins are queried. When the first one is successfully enabled, the process stops. If the `rtos.name` session option is set to the name of an RTOS plugin, only that one will be queried. To completely disable thread awareness, set the `rtos.enable` session option to false.

Builtin RTOS plugins are shown in the following table.

  RTOS Plugin Name   |   Description
---------------------|----------------
  argon              |   Argon RTOS
  freertos           |   FreeRTOS
  rtx5               |   RTX5
  threadx            |   ThreadX
  zephyr             |   Zephyr


### Viewing and selecting threads

Within gdb, the set of current threads can be printed with `info threads`. gdb assigns each thread a unique integer identifier used to reference the thread in other commands.

This example shows a gdb thread listing for a Zephyr RTOS program.

<div class="highlight"><pre class="highlight"><code>  Id   Target Id                                            Frame
* 3    Thread 536871784 "idle" (Running; Priority 15)       <span style="color: yellow">arch_cpu_idle</span> ()
    at <span style="color: green">/Users/creed/projects/zephyrproject/zephyr/arch/arm/core/aarch32/cpu_idle.S</span>:126
  4    Thread 536871584 "uart_out_id" (Pending; Priority 7) <span style="color: yellow">arch_swap</span> (<span style="color: cyan">key</span>=0)
    at <span style="color: green">/Users/creed/projects/zephyrproject/zephyr/arch/arm/core/aarch32/swap.c</span>:53
  5    Thread 536871416 "blink1_id" (Suspended; Priority 7) <span style="color: yellow">arch_swap</span> (<span style="color: cyan">key=key@entry</span>=0)
    at <span style="color: green">/Users/creed/projects/zephyrproject/zephyr/arch/arm/core/aarch32/swap.c</span>:53
  6    Thread 536871248 "blink0_id" (Suspended; Priority 7) <span style="color: yellow">arch_swap</span> (<span style="color: cyan">key=key@entry</span>=0)
    at <span style="color: green">/Users/creed/projects/zephyrproject/zephyr/arch/arm/core/aarch32/swap.c</span>:53
  7    Thread 536872152 "sysworkq" (Pending; Priority -1)   <span style="color: yellow">arch_swap</span> (<span style="color: cyan">key</span>=0)
    at <span style="color: green">/Users/creed/projects/zephyrproject/zephyr/arch/arm/core/aarch32/swap.c</span>:53
</code></pre></div>

Note how the thread name is shown in quotes, and thread state and priority are shown in parentheses. The actual description of threads is specific to each RTOS plugin.

The `thread` command takes a gdb thread ID to switches between threads; after switching, `backtrace` will show the selected thread's state.

### Thread reporting

There can be issues caused by a mismatch between the target's current memory contents and the expected location of RTOS related symbols. For instance, if a new version of firmware is being debugged but the target's flash has not been reprogrammed yet, or if there is stale data in RAM. If this happens, an out of date or corrupt view of the RTOS state could be reported.

To prevent this from happening, pyOCD will disable reporting threads to gdb (and reading the RTOS data from target memory) until the first time the target is resumed after any of these events:
- gdb connects to pyOCD
- Target reset
- Flash is reprogrammed using gdb commands

Note that a single instruction step will not enable thread reporting. A full resume is required. Gdb will see the list of threads when the target halts after the first resume, eg which a breakpoint is hit or the target is manually halted.

The actual behaviour depends on the plugin, so there is some slight variation between RTOSes. But the general sequence applies.

This logic not perfect, so there is a [`threads` command]({% link _docs/command_reference.md %}#threads-1) that provides manual control. It takes an argument with one of these actions:
- `status`: Show whether thread reporting is enabled.
- `enable`: Enable thread reporting.
- `disable`: Disallow thread reporting.
- `flush`: Forcibly invalidate the threads list.

If `threads` is executed and an RTOS plugin has not successfully loaded, it will print "Threads are unavailable".

After thread reporting is enabled or disabled manually, you must step or resume in gdb to force gdb to refresh its view of threads. (There is no flush or invalidate for threads in gdb.)

When thread reporting is disabled, gdb will see a single thread just like when no RTOS plugin is loaded.


### RTOS notes

These sections document specific features or requirements for using thread awareness with different RTOSes.

#### Zephyr RTOS

To enable thread awareness, the `CONFIG_DEBUG_THREAD_INFO` Kconfig setting must be enabled.


### Handler mode thread

The RTOS plugins will report an artificial thread when an M-profile core is in Handler mode, eg in an exception or interrupt handler. This lets you view the state of the exception handler separately from RTOS threads.


