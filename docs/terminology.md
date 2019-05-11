Terminology
===========

These are the key terms used by pyOCD and its documentation.

- **CoreSight** — A standard Arm architecture for debug subsystems. It delivers a standardised way
    to discover the debug resources provided by a device.
- **debug probe** — The USB device that drives SWD or JTAG.
- **flash algorithm** — A small piece of code downloaded to and executed from target RAM that
    performs flash erase and program operations.
- **target** — The device that is being controlled by pyOCD.
- **target type** — The part number for the target. Represented by an identifier that is either
    the full part number or a shortened form of it.
- **unique ID** — The unique serial number of a debug probe.
- **user option** — A named value that controls some feature of pyOCD. Options can be set from the
    command line or configuration files.
- **user script** — A Python script written by the user and loaded at runtime that can extend or
    modify pyOCD's behaviour.

