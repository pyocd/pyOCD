---
title: Using session options
---

Session options are used to configure pyOCD. The [configuration]({% link _docs/configuration.md %}) documentation has user level documentation of how to set session options. For a full list of built-in options see the [session options reference]({% link _docs/options.md %}).


## Accessing options

Options are quite easy to use from within Python code. The `Session` object has an `options` property which returns a dict-like `OptionsManager` object that is used to access options for that session. The `OptionsManager` object supports either slicing or `.get()`/`.set()` methods for reading and writing options.

```py
# Reading an option from the session using two techniques.
value = session.options['reset_type']
value = session.options.get('reset_type')

# Changing the value of an option
session.options['reset_type'] = 'system'
session.options.set('reset_type') = 'system'
```

## Priority layers

Session options have a priority based on their source. The `OptionsManager` class implements these priorities as an ordered sequence of layers from front (high priority) to back (low priority). Each layer is a dict of option name to value. There is also an implicit lowest-priority layer from which default values specified in the option definition are derived.

The priorities of the different sources, from front to back:

1. Keyword arguments to the `Session` constructor. Applies to most command-line arguments.
2. _options_ parameter to `Session` constructor. Applies to `-O` command-line arguments.
3. Probe-specific options from a config file.
4. Global options from a config file.
5. _option_defaults_ parameter to `Session` constructor. Used only in rare cases by subcommands to change the default value of options.
6. Default values from option definitions.

The `.set()` method simply modifies the value of the highest priority (aka front) copy of the option. Additional layers can be added to the front or back using the `.add_front()` and `.add_back()` methods. These methods take a dict of new option values.


## How options are configured

Loading of options from YAML files is handled automatically when the `Session` object is created. Probe-specific options are automatically set, too.

Options set through command line arguments, both dedicated arguments and `-O`, are passed into the `Session` constructor and added as their own layer. The `ConnectHelper` methods that are most often used to create sessions will pass through options related arguments to `Session`.


## Name and value modifications

Several changes are applied to option names and values when they are set. First, the names are normalised.

1. Convert all occurrences of double-underscores to a dot, e.g., `__` changes to a `.` character. Doing this makes it possible to set options with dots in the name using keyword arguments.
2. Change to lower case.

Then, any option set with a value of `None` is ignored. In that case, the option's value from a lower priority layer will take precedence.


## Adding new options

Session options are defined by an instance of `OptionInfo` (from `pyocd.core.options`) that specifies the name, type(s), default value, and a help string. At runtime, the complete set of options is in the `pyocd.core.options.OPTIONS_INFO` dict. Be sure to define any new options so they're documented and get a default and help text.

For example, this is the definition of the `frequency` option:

```py
OptionInfo('frequency', int, 1000000, "SWD/JTAG frequency in Hertz.")
```

There are several places to define a new option.

- Global and gdb server options should be added to the `BUILTIN_OPTIONS` list in `pyocd/core/options.py`
- Plugins can return a list of `OptionInfo` objects from the `.options` property of the `Plugin` subclass.
- Python scripts, including [user scripts]({% link _docs/user_scripts.md %}), can add new option definitions by calling `add_option_set()` (from `pyocd.core.options`) and passing a list of `OptionInfo` objects.

Supported types for options are *bool*, *int*, *float*, and *str*. An option that allows multiple types is specified with a tuple of those types. The `convert_session_options()` function from `pyocd.utility.cmdline` will convert the *bool*, *int*, and *float* options from a string value. However, there is not automatic type conversion when setting options directly on the `OptionsManager`.


