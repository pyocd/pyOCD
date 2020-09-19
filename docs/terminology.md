---
title: Terminology
---

These are the key terms used by pyOCD and its documentation.

- **ADI**: Arm Debug Interface, an Arm architecture specification for how JTAG and SWD interface with CoreSight.
    It defines the DAP structure and registers.
- **AP**: Access Port, part of the DAP, connected to the DP, that allows the debugger to perform operations
    on the chip and cores. There are multiple types of AP that serve different purposes (see MEM-AP). Some MCU
    vendors implement proprietary APs in their chips.
- **Commander**: Refers to the `pyocd commander` subcommand that presents an interactive interface for exploring
    the connected target.
- **CoreSight**: An Arm architecture specification for debug subsystems. It defines a standardised way
    to discover the debug resources provided by a device.
- **DAP**: Debug Access Port, the debugging module that is accessed via the JTAG or SWD port. Composed of a
    DP and one or more APs.
- **DP**: Debug Port, part of the DAP that handles SWD or JTAG. Most chips only have a single DP.
- **debug link**: The connection between the debugger and target. This is usually a physical connection over
    which the SWD or JTAG wire protocol runs, but different arrangements are possible.
- **debug probe**: The device that drives SWD or JTAG. Usually connected to the host via USB.
- **delegation**: A code pattern used to extend or modify functionality of a class by implementing
    methods in a companion object rather than through subclassing.
- **core**: Refers to a CPU and the closely coupled components surrounding it such as debug and trace
    support.
- **flash algorithm**: A small piece of code downloaded to and executed from target RAM that
    performs flash erase and program operations.
- **gdbserver**: A server that implements gdb's Remote Serial Protocol (RSP) to allow gdb to debug a remote
    target. PyOCD acts as a bridge between gdb and the target.
- **host**: The computer running pyOCD.
- **JTAG**: Debug link wire protocol standard defined by IEEE Std 1149.1-2001 and subsequent specifications.
- **MEM-AP**: Generic standard for a special type of AP used by the debugger to perform memory reads and
    writes within the chip. Concrete MEM-APs have names that represent the kind of bus fabric with which they
    interface, such as AHB-AP or AXI-AP.
- **probe server**: Server that shares a debug probe over TCP/IP.
- **REPL**: Read-Eval-Print-Loop. An interactive type of command interface used by pyOCD Commander, as well as
    Python and other similar tools.
- **session**: Represents a connection to a debug probe and the runtime object graph.
- **session option**: A named setting that controls some feature of pyOCD. Options are associated with
    a session, and each session can have different values for a given option.. They can be set from the
    command line or configuration files.
- **SoC**: System on Chip, a complete computer on a single chip, like a microcontroller.
- **SWD**: Serial Wire Debug, an Arm standard for a 2-signal serial wire protocol that is an alternative to
    JTAG. It provides nearly the same functionality, except for lack of boundary scan.
- **SWO**: Serial Wire Output, SWV frames usually come out this one pin output. Because it shares the JTAG
    signal TDO, SWO is only accessible when using SWD.
- **SWV**: Serial Wire Viewer, A trace capability providing display of reads, writes, exceptions, PC Samples
    and printf.
- **target**: The device that is being controlled by pyOCD through the debug probe.
- **target type**: The part number for the target. Represented by an identifier that is either
    the full part number or a shortened form of it.
- **unique ID**: The unique identifier for a debug probe. Nominally a URI, but usually just the probe's
    serial number.
- **user script**: A Python script written by the user and loaded at runtime that can extend or
    modify pyOCD's behaviour.
- **wire protocol**: The protocol used on the debug link, either SWD or JTAG for Arm-based devices.

