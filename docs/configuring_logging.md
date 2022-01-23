---
title: Configuring logging
---

## Overview

pyOCD provides extensive control over log output. It uses the standard Python
[logging](https://docs.python.org/3/library/logging.html) package for all its logging. There are several ways
to set log levels, both globally and with precise control.

- Verbosity controls
- Logger-level control
- Advanced configuration


## Log levels

There are multiple log levels, in order from least to most verbose:
- CRITICAL
- ERROR
- WARNING
- INFO
- DEBUG

The CRITICAL level is used only by the `pyocd` tool for reporting fatal errors.

Each subcommand for the `pyocd` tool has a default logging level.

Subcommand     | Default level
---------------|--------------
`commander`    | WARNING
`erase`        | WARNING
`flash`        | WARNING
`gdbserver`    | INFO
`json`         | Logging fully disabled
`list`         | INFO
`pack`         | INFO
`reset`        | WARNING
`rtt`          | INFO
`server`       | INFO


## Basic control

For most users, the command line `--verbose`/`-v` and `--quiet`/`-q` arguments provide sufficient control
over logging. These arguments can be listed multiple times. Each use increases or decreases the
logging verbosity level. For example, a single `--verbose` moves `pyocd flash` from the default
level of WARNING to INFO.


## Color logging

By default, log output to a tty is colorised. Control over colorised log output is possible two ways.

The command-line `--color` argument accepts an optional parameter that must be one of `auto`, `always`, or `never`.
The default is `auto`, which will enable color only when outputting to a tty.

Another option for controlling color output is the `PYOCD_COLOR` environment variable. It should be set to one of the
same values supported by `--color`. This environment variable changes the default color output setting, and is
overridden by `--color` on the command line.


## Loggers

Each module in pyOCD uses its own module-specific logger with a name matching the dotted module
name, for instance `pyocd.coresight.fpb`. This lets you control verbosity at the module level. Even
more advanced configurations, such as routing a particular module's log output to a separate file,
are also possible.

The best way to see which loggers are available is simply to look at the pyOCD source code to see
its package structure.


### Trace loggers

Certain modules define additional sub-module loggers that output debug trace logs. These loggers always have the
suffix ".trace" and are disabled by default. This ensures the trace messages won't be seen unless explicitly enabled by the `--log-level` / `-L` argument described in the following section.

Currently defined trace loggers:

Trace logger                                            | Trace output
--------------------------------------------------------|----------------------------------------------
`pyocd.coresight.ap.trace`                              | AP memory transfers
`pyocd.coresight.dap.trace`                             | AP and DP register accesses
`pyocd.debug.semihost.trace`                            | Semihost file operations
`pyocd.flash.flash.trace`                               | Flash algorithm operations
`pyocd.probe.cmsis_dap_probe.trace`                     | CMSIS-DAP probe API calls
`pyocd.probe.jlink_probe.trace`                         | Log output from JLink library
`pyocd.probe.pydapaccess.dap_access_cmsis_dap.trace`    | CMSIS-DAP packet building
`pyocd.probe.pydapaccess.interface.hidapi_backend.trace` | CMSIS-DAP v1 hidapi backend USB transfers
`pyocd.probe.pydapaccess.interface.pyusb_backend.trace` | CMSIS-DAP v1 pyusb backend USB transfers
`pyocd.probe.pydapaccess.interface.pyusb_v2_backend.trace` | CMSIS-DAP v2 pyusb backend USB transfers
`pyocd.probe.pydapaccess.interface.pywinusb_backend.trace` | CMSIS-DAP v1 pywinusb backend USB transfers
`pyocd.probe.stlink.usb.trace`                          | STLink USB transfers
`pyocd.probe.tcp_client_probe.trace`                    | Remote probe client requests and responses
`pyocd.probe.tcp_probe_server.trace`                    | Remote probe server requests and responses
`pyocd.utility.notification.trace`                      | Sent notifications


## Logger-level control

The `--log-level` / `-L` command line argument makes it easy to control logging at the level of individual loggers
or groups of loggers. The argument accepts a comma-separated list of logger names followed by an "=" sign and a
log level name (case-insensitive).

The logger names are actually glob-style patterns, as supported by many command line shells. This allows use of these
wildcards:

Pattern     | Meaning
------------|-----------------------------------
`*`         | matches everything
`?`         | matches any single character
`[seq]`     | matches any character in seq
`[!seq]`    | matches any character not in seq
`[*]`       | match literal "*"
`[?]`       | match literal "?"

The `--log-level` argument can be used more than once on a command line. The arguments are processed in the order they
appear, so later arguments can refine log level settings made by earlier arguments.

Setting the log level of parent loggers affects the level of all child loggers.

Examples:

- `-L 'pyocd.probe.*=debug'`: set all pyOCD debug probe modules to debug log level
- `-L pyocd.core.session,pyocd.core.options=info`: set two modules to info log level
- `-L '*.trace=debug -L *.jlink=warning'`: enable all trace loggers, but set JLink and its trace logger to warnings
    only

Note that you may need to place the value used with `--log-level` in quotes to prevent the shell from attempting to
expand wildcards as file names.


## Advanced control

Fine-grained control of pyOCD log output is available through logging configuration. The logging
package supports loading a configuration dictionary to control almost all aspects of log output.

The `logging` session option is used to specify the logging configuration. It can be set to either a
logging configuration dictionary or the path to a YAML file containing a configuration dictionary.
Usually it is easiest to include the configuration directly in a `pyocd.yaml` config file. See the
[configuration documentation]({% link _docs/configuration.md %}) for more on config files. The file path is most
useful when passing the `logging` option via the command line, since you can't provide a dictionary
this way.


### Controlling module log levels

A basic logging configuration to control verbosity at the module level looks like this, as shown
in a `pyocd.yaml` config file:

```yaml
logging:
  loggers:
    pyocd.flash.loader:
      level: DEBUG
    pyocd.flash.flash_builder:
      level: DEBUG
```

The top level `logging` key is the session option. Under it must be a `loggers` key, which has the
name of each module you wish to configure as a child key. Then, under each module name, the `level`
key specifies the log level for that module. Due to the way logging propagation works, you do not
need to set the level of parent loggers to match the child levels. In fact, setting the level of a
parent logger
such as `pyocd` will set the level for all children—this is an easy way to control the log level
for all of pyOCD.

Note that because the `logging` option is passed to and handled by the Python logging module, it does not support
wildcard matching against loggers like the `--log-level` argument.


### Full control

The full schema for the logging configuration dictionary is documented in the
[logging.config module documentation](https://docs.python.org/3/library/logging.config.html#logging-config-dictschema).
The logging module's
[advanced tutorial](https://docs.python.org/3/howto/logging.html#logging-advanced-tutorial)
has a good introduction to the features and log output flow, so you can better understand the
configuration schema.

The `version` key described in the schema is optional in pyOCD's logging configuration. If not
present, pyOCD will set the schema version to 1 (currently the only version). In addition, pyOCD
will set the `disabled_existing_loggers` key to false unless it is specified in the configuration
(the default is true).

Note that if you change the configuration for the root logger, you will need to define a handler
and formatter in the configuration (see the example below).

Here is a much more complex example configuration that sets a custom formatter and changes several log
levels:

```yaml
logging:
  formatters:
    brief:
      format: '%(relativeCreated)07d - %(levelname)s - %(name)s - %(message)s'
  handlers:
    console:
      class: logging.StreamHandler
      formatter: brief   # reference to "brief" formatter above
      level: DEBUG
      stream: ext://sys.stdout
  root:
    level: INFO
    handlers:
      - console          # reference to "console" handler above
  loggers:
    pyocd:
      level: INFO        # set all pyocd loggers to INFO level
    pyocd.probe:
      level: DEBUG       # set this logger to DEBUG level
```

This example shows how to direct log output to a log file called `pyocd_log.txt`:

```yaml
logging:
  root:
    handlers: [logfile]
  formatters:
    precise:
      format: "[%(relativeCreated)07d:%(levelname)s:%(module)s] %(message)s"
  handlers:
    logfile:
      class: logging.FileHandler
      formatter: precise
      filename: pyocd_log.txt
      mode: w
      delay: false
```
