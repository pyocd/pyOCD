Configuring Logging
===================

## Overview

pyOCD uses the standard Python [logging](https://docs.python.org/2.7/library/logging.html) package
for all its logging.

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
`list`         | INFO
`json`         | Logging fully disabled
`flash`        | WARNING
`erase`        | WARNING
`gdbserver`    | INFO
`commander`    | WARNING
`pack`         | INFO


## Basic control

For most users, the command line `--verbose`/`-v` and `--quiet`/`-q` arguments provide sufficient control
over logging. These arguments can be listed multiple times. Each use increases or decreases the
logging verbosity level. For example, a single `--verbose` moves `pyocd flash` from the default
level of WARNING to INFO.


## Advanced control

Fine-grained control of pyOCD log output is available through logging configuration. The logging
package supports loading a configuration dictionary to control almost all aspects of log output.

The `logging` user option is used to specify the logging configuration. It can be set to either a
logging configuration dictionary or the path to a YAML file containing a configuration dictionary.
Usually it is easiest to include the configuration directly in a `pyocd.yaml` config file. See the
[configuration documentation](configuration.md) for more on config files. The file path is most
useful when passing the `logging` option via the command line, since you can't provide a dictionary
this way.


### Loggers

Each module in pyOCD uses its own module-specific logger with a name matching the dotted module
name, for instance `pyocd.coresight.fpb`. This lets you control verbosity at the module level. Even
more advanced configurations, such as routing a particular module's log output to a separate file,
are also possible.

The best way to see which loggers are available is simply to look at the pyOCD source code to see
its package structure.


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

The top level `logging` key is the user option. Under it must be a `loggers` key, which has the
name of each module you wish to configure as a child key. Then, under each module name, the `level`
key specifies the log level for that module. Due to the way logging propagation works, you do not
need to set the level of parent loggers to match the child levels. In fact, setting the level of a
parent logger
such as `pyocd` will set the level for all children—this is an easy way to control the log level
for all of pyOCD.


### Full control

The full schema for the logging configuration dictionary is documented in the [logging.config
module
documentation](https://docs.python.org/2.7/library/logging.config.html#logging-config-dictschema).
The logging module's [advanced
tutorial](https://docs.python.org/2.7/howto/logging.html#logging-advanced-tutorial) has a good
introduction to the features and log output flow, so you can better understand the configuration
schema.

The `version` key described in the schema is optional in pyOCD's logging configuration. If not
present, pyOCD will set the schema version to 1 (currently the only version). In addition, pyOCD
will set the `disabled_existing_loggers` key to false unless it is specified in the configuration
(the default is true).

Note that if you change the configuration for the root logger, you will need to define a handler
and formatter in the configuration (see the example below).

Here is a much more complex example configuration that sets a custom formatter:

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
    pyocd.core.coresight_target:
      level: DEBUG       # set this logger to DEBUG level
```

