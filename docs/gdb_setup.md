---
title: GDB setup
---

Most users will want to set up the GNU GDB debugger in order to use pyOCD for debugging applications. Either
the command-line GDB or a full IDE can be used.


Standalone GDB server
---------------------

After you install pyOCD via pip or setup.py, you will be able to execute the following in order to
start a GDB server powered by pyOCD:

```
$ pyocd gdbserver
```

You can get additional help by running ``pyocd gdbserver --help``.

Example command line GDB session showing how to connect to a running `pyocd gdbserver` and load
firmware:

```
$ arm-none-eabi-gdb application.elf

<gdb> target remote localhost:3333
<gdb> load
<gdb> monitor reset
```

The `pyocd gdbserver` subcommand is also usable as a drop in place replacement for OpenOCD in
existing setups. The primary difference is the set of gdb monitor commands.


Recommended GDB and IDE setup
-----------------------------

The recommended toolchain for embedded Arm Cortex-M development is [GNU Arm
Embedded](https://developer.arm.com/downloads/-/gnu-rm) (GNU-RM),
provided by Arm. GDB is included with this toolchain.

Note that the version of GDB included with the new, combined Arm GNU Toolchain as of version 11.2-2022.02
_will not_ work with pyOCD. This is because it is currently built without the required support for the XML
target descriptions that pyOCD sends to GDB. Versions later than 11.2-2022.02 may have this bug fixed.

For [Visual Studio Code](https://code.visualstudio.com), the
[cortex-debug](https://marketplace.visualstudio.com/items?itemName=marus25.cortex-debug) plugin is available
that supports pyOCD.

The GDB server also works well with [Eclipse Embedded CDT](https://projects.eclipse.org/projects/iot.embed-cdt),
previously known as [GNU MCU/ARM Eclipse](https://gnu-mcu-eclipse.github.io/). It fully supports pyOCD with
an included pyOCD debugging plugin.

To view peripheral register values either the built-in Eclipse Embedded CDT register view can be used, or
the Embedded System Register Viewer plugin can be installed. The latter can be installed from inside
Eclipse adding `http://embsysregview.sourceforge.net/update` as a software update server URL
under the "Help -> Install New Software..." menu item.
