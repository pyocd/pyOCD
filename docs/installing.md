---
title: Installing
---

The latest stable version of pyOCD may be installed via [pip](https://pip.pypa.io/en/stable/index.html)
as follows:

```
$ python3 -mpip install -U pyocd
```

_Note: depending on your system, you may need to use `python` instead of `python3`._

The latest pyOCD package is available [on PyPI](https://pypi.python.org/pypi/pyOCD/) as well as
[on GitHub](https://github.com/pyocd/pyOCD/releases).

To install the latest prerelease version from the HEAD of the master branch, you can do
the following:

```
$ python3 -mpip install --pre -U git+https://github.com/pyocd/pyOCD.git
```

You can also install directly from the source by cloning the git repository and running:

```
$ python3 setup.py install
```

Note that, depending on your operating system, you may run into permissions issues running these commands.
You have a few options here:

1. Under Linux, run with `sudo -H` to install pyOCD and dependencies globally. On macOS, installing with sudo
    should never be required, although sometimes permissions can become modified such that installing without
    using sudo fails.
3. Specify the `--user` option to install local to your user account.
4. Run the command in a [virtualenv](https://virtualenv.pypa.io/en/latest/)
   local to a specific project working set.

For notes about installing and using on non-x86 systems such as Raspberry Pi, see the
[relevant documentation]({% link _docs/installing_on_non_x86.md %}).


udev rules on Linux
-------------------

On Linux, particularly Ubuntu 16.04+, you must configure udev rules to allow pyOCD to access debug
probes from user space. Otherwise you will need to run pyOCD as root, using sudo, which is very
highly discouraged. (You should _never_ run pyOCD as root on any OS.)

To help with this, example udev rules files are included with pyOCD in the
[udev](https://github.com/pyocd/pyOCD/tree/master/udev) folder. The
[readme](https://github.com/pyocd/pyOCD/tree/master/udev/README.md) in this folder has detailed
instructions.


Target support
--------------

See the [target support documentation]({% link _docs/target_support.md %}) for information on how to check if
the MCU(s) you are using have built-in support, and how to install support for additional MCUs via
CMSIS-Packs.



