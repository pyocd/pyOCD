Multicore Debug
===============

pyOCD supports debugging multicore devices. It does this by serving one gdb server per core, to which
you connect independant gdb instances. This is the most reliable method of debugging multicore
embedded devices using gdb.

`pyocd gdbserver` automatically creates one `GDBServer` instance per core. The first core is given the
user-specified port number. Additional cores have port numbers incremented from there.

To prevent reset requests from multiple connected gdb instances causing havoc, secondary cores have
their default reset type set to core-only reset (VECTRESET), which will fall back to an emulated
reset for non-v7-M architectures. This feature can be disabled by setting the
`enable_multicore_debug` user option to false.

To debug a multicore device, run `pyocd gdbserver` as usual. This will connect to the device, detect
the cores, and create the gdb server instances on separate ports. Next, start up two gdb instances
and connect to the two gdb server ports. For instance, on a dual core device if you pass 3333 for
the port, connect to port 3333 for the first core and port 3334 for the second core.

On many devices, secondary cores are by default held in reset until released by the primary core.
Because gdb does not have a concept of a core held in reset, pyOCD will report a core held in reset
by telling gdb that there is a single thread with the name "Reset". This is visible if you run the
show threads gdb command, and will appear in the Eclipe Debug view's list of threads. All register
values will be reported as 0 until the core is released from reset.

Usually you want to have the primary core load code for the secondary core, so configure the second
core's gdb to not load any code to the target. This is highly device-specific, though, and may
depend on whether the secondary core's code is running out of flash or RAM.

