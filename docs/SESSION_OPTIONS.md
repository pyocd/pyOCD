Session Options
===============

This guide documents the session options that are supported by pyOCD and how to use them.

Many of these options have dedicated command line arguments. Arbitrary options can be set
individually with the `-Ooption=value` command line argument. You may also use a YAML config file to
set multiple options. And if you are using the Python API, you may pass any session options directly
to the `ConnectHelper` methods or `Session` constructor as keyword arguments.

## Config file

pyOCD supports a YAML configuration file that lets you provide session options that either apply to
all probes or to a single probe, based on the probe's unique ID.

The easiest way to use a config file is to use the `--config` command line option, for instance
`--config=myconfig.yaml`. Alternatively, you can set the `config_file` session option.

The top level of the YAML file is a dictionary. The keys in the top-level dictionary must be names
of session options, or the key `probes`. Session options are set to the value corresponding to the
dictionary entry. Unrecognized option names are ignored.

If there is a top-level `probes` key, its value must be a dictionary with keys that match a
substring of debug probe unique IDs. Usually you would just use the complete unique ID shown by
listing connected boards (i.e., `pyocd-gdbserver --list`). The values for the unique ID entries are
dictionaries containing session options, just like the top level of the YAML file. Of course, these
session options are only applied when connecting with the given probe. If the probe unique ID
substring listed in the config file matches more than one probe, the corresponding session options
will be applied to all matching probes.

Example board config file:
````yaml
probes:
  066EFF555051897267233656: # Probe's unique ID.
    target_override:  stm32l475xg
    test_binary:      stm32l475vg_iot01a.bin

# Global options
auto_unlock: false
frequency: 8000000 # Set 8 MHz SWD default for all probes
````

## Options list

- `auto_unlock`: (bool) If the target is locked, it will by default be automatically mass erased in
    order to gain debug access. Set this option to False to disable auto unlock.

- `config_file`: (str) Relative path to a YAML config file that lets you specify session options
    either globally or per probe. No default. The format of the file is documented above.

- `frequency`: (int) SWD/JTAG frequency in Hertz. Default is 1 MHz.

- `halt_on_connect`: (bool) Whether to halt the target immediately upon connecting. Default is True.

- `report_core_number`: (bool) Whether gdb server should report core number as part of the
    per-thread information. Default is False.

- `resume_on_disconnect`: (bool) Whether to resume a halted target when disconnecting. Default is True.

- `target_override`: (str) Target type name to use instead of default board target or default `cortex_m`.

- `test_binary`: (str) Specify the test binary file name used by the functional test suite (in the
    `test/` directory). The binary must be in the `binaries/` directory. This option is most useful
    when set in a board config file for running the functional tests on boards that cannot be
    automatically detected.

