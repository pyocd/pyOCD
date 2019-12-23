Configuration
=============

This guide documents how to configure pyOCD.

## Introduction

pyOCD allows you to control many aspects of its behaviour by setting user options. There are
multiple ways to set these options.

- Many of the most commonly used user options have dedicated command line arguments.
- Options can be placed in a YAML config file.
- Arbitrary options can be set individually with the `-Ooption=value` command line argument.
- If you are using the Python API, you may pass any option values directly
    to the `ConnectHelper` methods or `Session` constructor as keyword arguments. You can also
    pass a dictionary for the `options` parameter of these methods.

The priorities of the different user option sources, from highest to lowest:

1. Keyword arguments to the `Session` constructor. Applies to most command-line arguments.
2. _options_ parameter to constructor. Applies to `-O` command-line arguments.
3. Probe-specific options from a config file.
4. General options from a config file.
5. _option_defaults_ parameter to constructor. Used only in rare cases.


## Project directory

To help pyOCD automatically find configuration files and other resources, it has the concept of
the project directory. By default this is simply the working directory where you ran the `pyocd`
tool. You can set the project directory explicitly with the `-j` or `--dir` command line
arguments. This can be helpful if you are running pyOCD from another tool or application.

When pyOCD looks for files such as the config file or a user script, it first expands '~'
references to the home directory. Then it checks whether the filename is absolute, and if so, it
uses the filename as-is. Otherwise, it looks for the file in the project directory.

## Config file

pyOCD supports a YAML configuration file that lets you set user options that either apply to
all probes or to a single probe, based on the probe's unique ID.

The easiest way to use a config file is to place a `pyocd.yaml` file in the project directory.
An alternate `.yml` extension and
optional dot prefix on the config file name are allowed. Alternatively, you can use the
`--config` command line option, for instance `--config=myconfig.yaml`. Finally, you can set the
`config_file` option.

The top level of the YAML file is a dictionary. The keys in the top-level dictionary must be names
of user options, or the key `probes`. User options are set to the value corresponding to the
dictionary entry. Unrecognized option names are ignored.

If there is a top-level `probes` key, its value must be a dictionary with keys that match a
substring of debug probe unique IDs. Usually you would just use the complete unique ID shown by
listing connected boards (i.e., `pyocd list`). The values for the unique ID entries are
dictionaries containing user options, just like the top level of the YAML file. Of course, these
options are only applied when connecting with the given probe. If the probe unique ID
substring listed in the config file matches more than one probe, the corresponding options
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


