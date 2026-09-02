---
title: Terminology
---

These are the key terms used by pyOCD and its documentation.

- **ADI**: Arm Debug Interface, an Arm architecture specification for how JTAG and SWD interface with CoreSight.
    It defines the DAP structure and registers.
- **AP**: Access Port, part of the DAP, connected to the DP, that allows the debugger to perform operations
    on the chip and cores. There are multiple types of AP that serve different purposes (see MEM-AP). Some MCU
    vendors implement proprietary APs in their chips.
- **command**: Refers to one of pyOCD's [commands]({% link _docs/command_reference.md %}) that can be executed in the commander REPL or as a gdb monitor command.
- **commander**: Refers to the `pyocd commander` subcommand that presents an interactive interface for exploring
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
- **gdbserver**: A server that implements gdb's [Remote Serial Protocol](https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html#Remote-Protocol) (RSP) to allow gdb to debug a remote
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
    a session, and each session can have different values for a given option. They can be set from the
    command line or configuration files.
- **SoC**: System on Chip, a complete computer on a single chip, like a microcontroller.
- **SWD**: Serial Wire Debug, an Arm standard for a 2-signal serial wire protocol that is an alternative to
    JTAG. It provides nearly the same functionality, except for lack of boundary scan.
- **SWO**: Serial Wire Output, SWV frames usually come out this one pin output. Because it shares the JTAG
    signal TDO, SWO is only accessible when using SWD.
- **SWV**: Serial Wire Viewer, A trace capability providing display of reads, writes, exceptions, PC Samples
    and printf.
- **subcommand**: One of the subcommands selected as the first argument(s) to the `pyocd` command line tool.
- **target**: The device that is being controlled by pyOCD through the debug probe.
- **target type**: The part number for the target. Represented by an identifier that is either
    the full part number or a shortened form of it.
- **unique ID**: The unique identifier for a debug probe. Nominally a URI, but usually just the probe's
    serial number.
- **user script**: A Python script written by the user and loaded at runtime that can extend or
    modify pyOCD's behaviour. Different from a Python script that uses pyOCD as a package, because the
    `pyocd` command line tool is the driving process.
- **wire protocol**: The protocol used on the debug link, either SWD or JTAG for Arm-based devices.
- **Abstract Command**: A RISC-V debug mechanism for accessing core registers without halting the hart,
    defined in the RISC-V Debug Specification.
- **DMI**: Debug Module Interface, the RISC-V register bus connecting the DTM to the Debug Module.
    Accessed via JTAG using a 41-bit data register scan.
- **DM**: Debug Module, the RISC-V equivalent of Arm's debug components. Controls hart debug state,
    provides abstract commands, program buffer execution, and System Bus Access.
- **DTM**: Debug Transport Module, the RISC-V equivalent of Arm's DP. Provides transport-layer
    access (JTAG) to the DMI register space.
- **hart**: HARdware Thread, the RISC-V term for a hardware execution context (equivalent to a CPU core
    in Arm terminology). A multi-hart RISC-V core has multiple execution contexts.
- **Program Buffer**: A region in the Debug Module that holds executable instructions, allowing the
    debugger to run small code sequences on the hart for operations not supported by abstract commands.
- **SBA**: System Bus Access, a RISC-V debug feature allowing the debugger to perform memory reads
    and writes directly on the system bus without involving the hart.
- **CSR**: Control and Status Register, the RISC-V equivalent of Arm's system control registers.
    CSRs are accessed via dedicated instructions (CSRR/CSRW) and are grouped into standard,
    custom, and vendor-specific address ranges.
- **ebreak**: A RISC-V instruction that causes a breakpoint exception. Used for software breakpoints
    (replacing instructions in RAM with EBREAK or C.EBREAK) and semihosting (3-instruction ebreak sequence).
- **FENCE.I**: A RISC-V instruction that synchronizes the instruction and data caches. Required after
    writing code or data to memory to ensure the CPU fetches the updated contents.
- **mcontrol**: A RISC-V trigger register (tdata1 when type=2) used for hardware breakpoints and
    watchpoints. Provides execute, load, and store address matching with configurable actions.
- **trigger**: The RISC-V equivalent of Arm's FPB (breakpoints) and DWT (watchpoints). Each trigger
    can be configured as a hardware breakpoint (execute match) or watchpoint (load/store address match).
    The number of triggers is hardware-dependent (typically 2-8).
- **WARL**: Write-Any-Read-Legal, a RISC-V register property where writing any value is accepted but
    only legal values are retained when read back. Used for capability discovery in trigger registers.

