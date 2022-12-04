---
title: SWO/SWV
---

The Arm Cortex-M and CoreSight architectures support a single-wire trace output called Serial Wire Output (SWO).
This SWO trace feature can be used for everything from printf debugging to PC-sampling based profiling and various
performance measurements.

SWO supports two wire protocols, asynchronous UART and Manchester encoding, although in practise UART is used almost
exclusively. (SWO is also available as a standalone CoreSight component, but this is relatively rare.)

The Arm Cortex-M DWT and ITM core peripherals generate packets that can be output over SWO when a configurable set of
events occur. The combination of DWT/ITM packets transmitted via SWO is called the Serial Wire Viewer (SWV). A common
use case for SWV is printf-style log output, so much so that "SWV" has more or less come to mean exactly that.

The major features are:

- The gdbserver supports SWV printf-style log output to console or telnet, muxed with semihosting stdout.
- Raw SWO data can be served through a TCP port while the gdbserver is running, allowing other tools such as
    [Orbuculum](https://github.com/orbcode/orbuculum) to process it.
- The Python API has a set of classes for building a trace event data flow graph.


### SWO support

PyOCD supports SWO and SWV for those debug probes that support it. This includes CMSIS-DAP, J-Link, and STLink.

Be aware that even if a probe type supports SWO, the MCU (and its CPU) must also support SWO, and the board must route
the SWO signal from the MCU to the debug header. In a surprising number of cases, even for silicon vendor evaluation
kits, the probe and MCU support it but the signal simply wasn't routed.

Not all versions of the Arm M-profile architecture support SWO. The Arm v7-M and Arm v8-M Mainline architectures do
support SWO, while the Arm v6-M and Arm v8-M Baseline, architectures do not.


 Core           | Architecture      | Supports SWO
----------------|-------------------|--------------
 Cortex-M0      | v6-M              | -
 Cortex-M0+     | v6-M              | -
 Cortex-M1      | v6-M              | -
 Cortex-M3      | v7-M              | ✓
 Cortex-M4      | v7-M              | ✓
 Cortex-M7      | v7-M              | ✓
 Cortex-M23     | v8.0-M Baseline   | -
 Cortex-M33     | v8.0-M Mainline   | ✓
 Cortex-M55     | v8.1-M Mainline   | ✓
 Cortex-M85     | v8.1-M Mainline   | ✓



### Configuration

If `enable_swv` is true, pyOCD will set up ITM and TPIU to output ITM stimulus ports over SWO at the specified baud
rate.  Currently, [semihosting]({% link _docs/semihosting.md %}) must also be enabled for SWV to work, so the
`enable_semihosting` option must be on. A thread reads the data from the probe in the background and parses it.

The SWV stream from ITM port 0 will be output to the semihosting console (see the [Routing]({% link _docs/semihosting.md
%}#routing) section of the [semihosting documentation]({% link _docs/semihosting.md %})), which is either the telnet
server or stdout depending on the `semihost_console_type` option.




An example of running the gdbserver with SWV output is:

```
pyocd gdb -S -Oenable_swv=1 -Oswv_system_clock=80000000 -Osemihost_console_type=console
```

This will turn on semihosting and SWV with the default 1 MHz baud rate, an 80 MHz system clock, and output to stdout.


### Session options

Several session options are used to control and configure SWV:

- `enable_swv` - Flag to enable SWV output.
- `swv_clock` - Optional baud rate for SWO, which defaults to 1 MHz if not set.
- `swv_system_clock` - Required system clock frequency. Used to compute TPIU baud rate divider.
- `swv_raw_enable` - Enable flag for the raw SWV stream server.
- `swv_raw_port` - TCP port number for the raw SWV stream server. The default port is 3443, which is the default port for the Orbuculum client.

