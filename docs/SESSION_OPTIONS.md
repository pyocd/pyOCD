Session Options
===============

This guide documents the session options that are supported by pyOCD.

Many of these options have dedicated command line arguments for the pyOCD tools. Any option can
be set with the `-Ooption=value` argument.

- `auto_unlock`: (bool) If the target is locked, it will by default be automatically mass erased in
    order to gain debug access. Set this option to False to disable auto unlock.
- `board_config_file`: (str) Path to a JSON file that lets you set options per probe, based on the
    probe's unique ID. No default.

    Example board config file:
    ````json
    {
        "066EFF555051897267233656" : {
            "target_override" : "stm32l475xg",
            "test_binary" :     "stm32l475vg_iot01a.bin"
        },
    }
    ````
- `frequency`: (int) SWD/JTAG frequency in Hertz. Default is 1 MHz.
- `halt_on_connect`: (bool) Whether to halt the target immediately upon connecting. Default is True.
- `report_core_number`: (bool) Whether gdb server should report core number as part of the
    per-thread information. Default is False.
- `resume_on_disconnect`: (bool) Whether to resume a halted target when disconnecting. Default is True.
- `target_override`: (str) Target type name to use instead of default board target or default `cortex_m`.
- `test_binary`: (str) Specify the test binary file name. The binary must be in the `binaries/`
    directory. This option is most useful when set in a board config file for running the functional
    tests on boards that cannot be automatically detected.

