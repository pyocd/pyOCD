---
title: Multicore debug
---

pyOCD supports debugging multicore devices. It does this by serving one gdb server per core, to which
independent gdb instances are connected. This is the most reliable method of debugging asymmetric multicore
devices using gdb.

`pyocd gdbserver` automatically creates one gdb server instance per core by default. The primary core is given the user-specified port number. Additional cores have port numbers incremented from there. If a gdb server for only one or a subset of cores is desired, the `--core` command line argument can be used with a list of core numbers.

By default, the primary core is core number 0. For Arm CoreSight based devices, this will be the core with the lowest associated access port address. Use the `primary_core` session option to change the primary core.

When performing multicore debug where multiple gdb instances are connected simultaneously, it is important to set the `enable_multicore_debug` session option to true. This changes secondary cores to have their default reset type set to core-only reset (`sw_core`). This prevents competing reset requests from the multiple gdb instances causing havoc. On v7-M architecture cores, VECTRESET is used. However, VECTRESET is not supported on other core architecture, so non-v7-M architectures will fall back to an emulated core reset.

To debug a multicore device, run `pyocd gdbserver` as usual. This will connect to the device, detect
the cores, and create the gdb server instances on separate ports. Next, start up two gdb instances
and connect to the two gdb server ports. For instance, on a dual core device if you pass 3333 for
the port (or leave it set to default), connect to port 3333 for the first core and port 3334 for the second core.

On many devices, secondary cores are by default held in reset until released by the primary core.
Because gdb does not have a concept of a core held in reset, pyOCD will report a core held in reset
by telling gdb that there is a single thread with the name “Reset”. This is visible if you run the
show threads gdb command, and will appear in the VSCode or Eclipse Debug view's list of threads. All register
values will be reported as 0 until the core is released from reset.

Usually you want to have the primary core load code and/or configure the reset vector for secondary cores prior to releasing those cores from reset. For this situation, configure the second
core's gdb to not load any code to the target. This usage is highly device-specific, though, and may
depend on whether the secondary core's code is running out of flash or RAM.

