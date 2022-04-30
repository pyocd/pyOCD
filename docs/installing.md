---
title: Installing
---

PyOCD requires [Python](https://python.org/) 3.6 or later. It runs on macOS,
Linux, FreeBSD, and Windows platforms.

The latest pyOCD package is available [on PyPI](https://pypi.python.org/pypi/pyOCD/). The
[GitHub releases](https://github.com/pyocd/pyOCD/releases) page details changes between versions.

The latest stable version of pyOCD may be installed or upgraded via [pip](https://pip.pypa.io/en/stable/index.html)
as follows:

```
$ python3 -m pip install -U pyocd
```

_Note: depending on your system, you may need to use `python` instead of `python3`._

We also recommend using [pipx](https://pypa.github.io/pipx/) as an excellent method to install pyOCD in an isolated
virtual Python environment.


### PE Micro probe support

Support for Cyclone and/or Multilink debug probes by [PE Micro](https://pemicro.com/) is available in a probe
driver plug-in that is a separate package from pyOCD. There are two ways to install the PE Micro probe plug-in.
Either substitute `pyocd[pemicro]` for `pyocd` in the commands above, or separately install `pyocd-pemicro`
using pip.


### Permissions issues

Note that, depending on your operating system, you may run into permissions issues running these commands.
You have a few options here:

1. Install with [pipx](https://pypa.github.io/pipx/).
2. Run the command in a [virtualenv](https://virtualenv.pypa.io/en/latest/)
   local to a specific project working set.
3. Under Linux, run with `sudo -H` to install pyOCD and dependencies globally. On macOS, installing with sudo
    should never be required, although sometimes permissions/corrupted can become modified such that installing without
    using sudo fails.
4. Specify the `--user` option to install local to your user account.


### Non-x86 systems

For notes about installing and using on non-x86 systems such as Raspberry Pi, see the
[relevant documentation]({% link _docs/installing_on_non_x86.md %}).


### Development versions

To install the latest prerelease version from the HEAD of the `develop` branch, you can do
the following:

```
$ python3 -m pip install --pre -U git+https://github.com/pyocd/pyOCD.git@develop
```

You can also install directly from the source by cloning the [git repository](https://github.com/pyocd/pyOCD) and
running this command from the working copy root directory:

```
$ python3 -m pip install .
```

See the [developer's guide]({% link _docs/developers_guide.md %}) for more about setting up a development
environment for pyOCD.

(Note: Installing by running `setup.py` directly is deprecated since pyOCD migrated to PEP 517 based packaging.
In many cases it will not work at all. Installing with pip or another standards-compliant tool is the only
supported method.)


udev rules on Linux
-------------------

On Linux, particularly Ubuntu 16.04+, you must configure udev rules to allow pyOCD to access debug
probes from user space. Otherwise you will need to run pyOCD as root, using sudo, which is very
highly discouraged. (You should _never_ run pyOCD as root on any OS.)

To help with this, example udev rules files are included with pyOCD in the
[udev](https://github.com/pyocd/pyOCD/tree/main/udev) folder. The
[readme](https://github.com/pyocd/pyOCD/tree/main/udev/README.md) in this folder has detailed
instructions.


Target support
--------------

See the [target support documentation]({% link _docs/target_support.md %}) for information on how to check if
the MCU(s) you are using have built-in support, and how to install support for additional MCUs via
CMSIS-Packs.



