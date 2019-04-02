Configuration
=============

This guide documents how to configure pyOCD and the supported set of options.

## Introduction

pyOCD allows you to control many aspects of its behaviour by setting session options. There are
multiple ways to set these options.

- Many of the most commonly used user options have dedicated command line arguments.
- Options can be placed in a YAML config file.
- Arbitrary options can be set individually with the `-Ooption=value` command line argument.
- If you are using the Python API, you may pass any option values directly
    to the `ConnectHelper` methods or `Session` constructor as keyword arguments. You can also
    pass a dictionary for the `options` parameter of these methods.

## Project directory

To help pyOCD automatically find configuration files and other resources, it has the concept of
the project directory. By default this is simply the working directory where you ran the `pyocd`
tool. You can set the project directory explicitly with the `-j` or `--dir` command line
arguments. This can be helpful if you are running pyOCD from another tool or application.

When pyOCD looks for files such as the config file or a user script, it first expands '~'
references to the home directory. Then it checks whether the filename is absolute, and if so, it
uses the filename as-is. Otherwise, it looks for the file in the project directory.

## Config file

pyOCD supports a YAML configuration file that lets you set session options that either apply to
all probes or to a single probe, based on the probe's unique ID.

The easiest way to use a config file is to place a `pyocd.yaml` file in the project directory.
An alternate `.yml` extension and
optional dot prefix on the config file name are allowed. Alternatively, you can use the
`--config` command line option, for instance `--config=myconfig.yaml`. Finally, you can set the
`config_file` session option.

The top level of the YAML file is a dictionary. The keys in the top-level dictionary must be names
of session options, or the key `probes`. Session options are set to the value corresponding to the
dictionary entry. Unrecognized option names are ignored.

If there is a top-level `probes` key, its value must be a dictionary with keys that match a
substring of debug probe unique IDs. Usually you would just use the complete unique ID shown by
listing connected boards (i.e., `pyocd list`). The values for the unique ID entries are
dictionaries containing session options, just like the top level of the YAML file. Of course, these
session options are only applied when connecting with the given probe. If the probe unique ID
substring listed in the config file matches more than one probe, the corresponding session options
will be applied to all matching probes.

Options set in the config file will override any options set via the command line.

Example config file:
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

- `allow_no_cores`: (bool) Prevents raising an error if no core were found after CoreSight discovery. Default is False.

- `auto_unlock`: (bool) If the target is locked, it will by default be automatically mass erased in
    order to gain debug access. Set this option to False to disable auto unlock. Default is True.

- `chip_erase`: (bool) Whether to perform a chip erase or sector erases when programming
    flash. If not set, pyOCD will use the fastest erase method.

- `config_file`: (str) Relative path to a YAML config file that lets you specify session options
    either globally or per probe. The format of the file is documented above. The default is a
    `pyocd.yaml` or `pyocd.yml` file in the working directory.

- `enable_multicore_debug`: (bool) Whether to put pyOCD into multicore debug mode. The primary effect
    is to modify the default software reset type for secondary cores to use VECTRESET, which will
    fall back to emulated reset if the secondary core is not v7-M.

- `fast_program`: (bool) Setting this option to True will use CRC checks of existing flash sector
    contents to determine whether pages need to be programmed. Default is False.

- `frequency`: (int) SWD/JTAG frequency in Hertz. Default is 1 MHz.

- `halt_on_connect`: (bool) Whether to halt the target immediately upon connecting. Default is True.

- `hide_programming_progress`: (bool) Disables flash programming progress bar when True. Default is
    False.

- `keep_unwritten`: (bool) Whether to load existing flash content for ranges of sectors that will
    be erased but not written with new data. Default is True.

- `no_config`: (bool) Do not use default config file.

- `pack`: (str or list of str) Path or list of paths to CMSIS Device Family Packs. Devices defined
    in the pack(s) are added to the list of available targets.

- `project_dir`: (str) Path to the session's project directory. Defaults to the working directory
    when the pyocd tool was executed.

- `reset_type`: (str) Which type of reset to use by default (one of 'default', 'hw', 'sw', 'sw_sysresetreq',
    'sw_vectreset', 'sw_emulated'). The default is 'sw'.

- `resume_on_disconnect`: (bool) Whether to resume a halted target when disconnecting. Default is True.

- `smart_flash`: (bool) If set to True, the flash loader will attempt to not program pages whose
    contents are not going to change by scanning target flash memory. A value of False will force
    all pages to be erased and programmed. Default is True.

- `target_override`: (str) Target type name to use instead of default board target or default `cortex_m`.

- `test_binary`: (str) Specify the test binary file name used by the functional test suite (in the
    `test/` directory). The binary must be in the `binaries/` directory. This option is most useful
    when set in a board config file for running the functional tests on boards that cannot be
    automatically detected.

- `user_script`: (str) Path of the user script file.


## GDB server options list

These session options are currently only applied when running the GDB server.

- `enable_semihosting`: (bool) Set to True to handle semihosting requests. Also see the
    `semihost_console_type` option. Default is False.

- `enable_swv`: (bool) Whether to enable SWV printf output over the semihosting console. Requires
    the `swv_system_clock` option to be set. The SWO baud rate can be controlled with the `swv_clock`
    option.

- `gdbserver_port`: (int) Base TCP port for the gdbserver. The core number, which is 0 for the
    primary core, will be added to this value. Default is 3333.

- `persist`: (bool) If True, the GDB server will not exit after GDB disconnects. Default is False.

- `report_core_number`: (bool) Whether gdb server should report core number as part of the
    per-thread information. Default is False.

- `semihost_console_type`: (str) If set to "telnet" then the semihosting telnet server will be
    started, otherwise semihosting will print to the console. Default is "telnet".

- `semihost_use_syscalls`: (bool) Whether to use GDB syscalls for semihosting file access operations,
    or to have pyOCD perform the operations. This is most useful if GDB is running on a remote
    system. Default is False.

- `serve_local_only`: (bool) When this option is True, the GDB server and semihosting telnet ports
    are only served on localhost, making them inaccessible across the network. If False, you can
    connect to these ports from any machine that is on the same network. Default is True.

- `soft_bkpt_as_hard`: (bool) Whether to force all breakpoints to be hardware breakpoints. Default
    is False.

- `step_into_interrupt`: (bool) Set this option to True to enable interrupts when performing step
    operations. Otherwise interrupts will be disabled and step operations cannot be interrupted.
    Default is False.

- `swv_clock`: (int) Frequency in Hertz of the SWO baud rate. Default is 1 MHz.

- `swv_system_clock`: (int) Frequency in Hertz of the target's system clock. Used to compute the SWO
    baud rate divider. No default.

- `telnet_port`: (int) Base TCP port number for the semihosting telnet server. The core number,
    which will be 0 for the primary core, is added to this value. Default is 4444.

- `vector_catch`: (str) Enable vector catch sources, one letter per enabled source in any order, or
    `all` or `none`.

    The source letters are:
    - `h`=hard fault
    - `b`=bus fault
    - `m`=mem fault
    - `i`=irq err
    - `s`=state err
    - `c`=check err
    - `p`=nocp
    - `r`=reset
    - `a`=all
    - `n`=none

    Default is only hard fault enabled.
