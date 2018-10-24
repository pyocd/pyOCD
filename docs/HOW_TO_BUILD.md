How to Build pyOCD into Single Executable File
==============================================

This manual provides a step-by-step guide on how to build a single
file executable using
[pyinstaller](http://pythonhosted.org/PyInstaller/).  It should be
possible for PyInstaller to work across all supported operating
system, but these steps have only been tested on Windows 7 64-bit and
Ubuntu 14.04.

pyOCD is an open source GDB server library written in Python and
maintained by pyOCD community, it depends on several libraries like
pyusb under Linux, and pywinusb under Windows. Pyinstaller was chosen
to bundle it into a single executable file, so that the pyOCD
executable produced can be run on any computer, whether python and the
related library are present or not on the system.

Instructions
------------

Follow the following instructions from a fresh checkout of pyOCD to
build a single file executable containing the pyOCD GDB server.  These
instructions assume that you already have Python installed:

The following script shows the basic steps that one must follow:

```bash
# Install pip and virtualenv
sudo apt-get install python-pip python-virtualenv

# Setup a virtualenv and install dependencies
virtualenv env
source env/bin/activate
pip install --editable .

# We need to use upstream version of pyinstaller due to
# http://comments.gmane.org/gmane.comp.python.pyinstaller/6457
pip install https://github.com/pyinstaller/pyinstaller/archive/develop.zip

# Create single-file executables
pyinstaller --onefile pyocd/tools/gdb_server.py
pyinstaller --onefile pyocd/tools/flash_tool.py
pyinstaller --onefile pyocd/tools/pyocd.py
```

In ./dist folder, there will be a single executable file per tool which is
ready to use or distribute it to other library.
