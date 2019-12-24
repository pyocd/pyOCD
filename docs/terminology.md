Terminology
===========

These are the key terms used by pyOCD and its documentation.

- **CoreSight** — A standard Arm architecture for debug subsystems. It defines a standardised way
    to discover the debug resources provided by a device.
- **debug probe** — The device that drives SWD or JTAG. Usually connected to the host via USB.
- **delegation** — A code pattern used to extend or modify functionality of a class by implementing
    methods in a companion object rather than through subclassing.
- **flash algorithm** — A small piece of code downloaded to and executed from target RAM that
    performs flash erase and program operations.
- **host** — The PC running pyOCD.
- **target** — The device that is being controlled by pyOCD through the debug probe.
- **target type** — The part number for the target. Represented by an identifier that is either
    the full part number or a shortened form of it.
- **unique ID** — The unique serial number of a debug probe.
- **user option** — A named value that controls some feature of pyOCD. Options can be set from the
    command line or configuration files.
- **user script** — A Python script written by the user and loaded at runtime that can extend or
    modify pyOCD's behaviour.

