Session Options
===============

This guide documents the session options that are supported by pyOCD.

Many of these options have dedicated command line arguments for the pyOCD tools. Any option can
be set with the `-Ooption=value` argument.

- `auto_unlock`: (bool) If the target is locked, it will by default be automatically mass erased in
    order to gain debug access. Set this option to False to disable auto unlock.

- `config_file`: (str) Path to a YAML file that lets you specify session options either globally
    or per probe, based on the probe's unique ID. No default.

    Any keys in the top-level dictionary are set as session options. If there is a top-level
    `probes` key, its value must be a dictionary with keys uniquely matching a substring of
    debug probe unique IDs. The values of the unique ID keys are dictionaries containing session
    options.

    Example board config file:
    ````yaml
    probes:
      066EFF555051897267233656:
        board_id:         0764
        target_override:  stm32l475xg
        test_binary:      stm32l475vg_iot01a.bin
    auto_unlock: false
    frequency: 8000000 # 8 MHz default for all probes
    ````

- `frequency`: (int) SWD/JTAG frequency in Hertz. Default is 1 MHz.

- `halt_on_connect`: (bool) Whether to halt the target immediately upon connecting. Default is True.

- `resume_on_disconnect`: (bool) Whether to resume a halted target when disconnecting. Default is True.

- `target_override`: (str) Target type name to use instead of default board target or default `cortex_m`.

- `test_binary`: (str) Specify the test binary file name. The binary must be in the `binaries/`
    directory. This option is most useful when set in a board config file for running the functional
    tests on boards that cannot be automatically detected.

