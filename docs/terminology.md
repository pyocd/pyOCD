Terminology
===========

These are the key terms used by pyOCD and its documentation.

- **CoreSight** — A standard Arm architecture for debug subsystems. It defines a standardised way
    to discover the debug resources provided by a device.
- **debug link** — The interface provided by a chip to allow for its debugging. Mostly SWD or JTAG.
- **debug probe** — The device that drives SWD or JTAG. Usually connected to the host via USB.
- **delegation** — A code pattern used to extend or modify functionality of a class by implementing
    methods in a companion object rather than through subclassing.
- **flash algorithm** — A small piece of code downloaded to and executed from target RAM that
    performs flash erase and program operations.
- **gdbserver** — A server that implements gdb's Remote Serial Protocol (RSP) to allow gdb to debug a remote
    target. PyOCD acts as a bridge between gdb and the target.
- **host** — The computer running pyOCD.
- **JTAG** — Debug link standard defined by IEEE Std 1149.1-2001 and subsequent specifications.
- **session** — Represents a connection to a debug probe and the runtime object graph.
- **session option** — A named setting that controls some feature of pyOCD. Options are associated with
    a session, and each session can have different values for a given option.. They can be set from the
    command line or configuration files.
- **SWD** — Serial Wire Debug, an Arm standard for a 2-signal debug link.
- **target** — The device that is being controlled by pyOCD through the debug probe.
- **target type** — The part number for the target. Represented by an identifier that is either
    the full part number or a shortened form of it.
- **unique ID** — The unique identifier for a debug probe. Nominally a URI, but usually just the probe's
    serial number.
- **user script** — A Python script written by the user and loaded at runtime that can extend or
    modify pyOCD's behaviour.

