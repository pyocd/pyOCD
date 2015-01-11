pyOCD
=====
pyOCD is an Open Source python 2.7 based library for programming and debugging 
ARM Cortex-M microcontrollers using CMSIS-DAP. Linux, OSX and Windows are supported.

You can use the following interfaces:

1. From a python interpretor:
  * halt, step, resume execution
  * read/write memory
  * read/write block memory
  * read-write core register
  * set/remove hardware breakpoints
  * flash new binary
  * reset

2. From a GDB client, you have all the features provided by gdb:
  * load a .elf file
  * read/write memory
  * read/write core register
  * set/remove hardware breakpoints
  * high level stepping
  * ...

Installation
------------

### Pre-Install 
pyOCD relies on external USB libraries:

* Windows: [pyWinUSB](https://github.com/rene-aguirre/pywinusb):

```Shell
$ cd /path-to-pywinusb/
$ python setup.py install
```

* Linux: [pyUSB](https://github.com/walac/pyusb):

```Shell
$ sudo apt-get install python libusb-1.0-0-dev
$ cd /path-to-pyusb/
$ sudo python setup.py install
```


* Mac: [hidapi](https://github.com/signal11/hidapi), [cython-hidapi](https://github.com/trezor/cython-hidapi)
```Shell
$ brew install hidapi
$ git clone https://github.com/trezor/cython-hidapi.git
$ cd cython-hidapi
$ sudo python setup.py install
```

### Install pyOCD
Clone pyOCD somewhere then run the install script.
```Shell
$ cd /path-to-pyOCD/
$ python setup.py install
```
Test the installation of pyOCD by running the basic test with an mbed enabled board connected to the computer. The basic_test.py will perform a series of tests on the board and leave it with a blinky program running.
```Shell
$ python2.7 pyOCD/test/basic_test.py
```

Standalone GDB Server
---------------------
<p>pyOCD now provide a manual HOW_TO_BUILD.md in root folder to explain how to build pyOCD into single executable gdb server program.</p>
[GCC ARM Toolchain](https://launchpad.net/gcc-arm-embedded) also provided a pre-build version of pyOCD gdb server at [Misc tools related to gcc arm embedded tool chain](https://launchpad.net/gcc-arm-embedded-misc/pyocd-binary)



Examples
--------
### Tests
A series of tests are provided in the test directory:
* basic_test.py: a simple test that checks:
  * read/write core registers
  * read/write memory
  * stop/resume/step the execution
  * reset the target
  * erase pages
  * flash a binary
* gdb_test.py: launch a gdbserver
* gdb_server.py: an enhanced version of gdbserver which provides the following options:
  * "-p", "--port", help = "Write the port number that GDB server will open"
  * "-b", "--board", help = "Write the board id you want to connect"
  * "-l", "--list", help = "List all the connected board"
  * "-d", "--debug", help = "Set the level of system logging output, the available value for DEBUG_LEVEL: debug, info, warning, error, critical"
  * "-t", "--target", help = "Override target to debug"
  * "-n", "--nobreak", help = "Disable halt at hardfault handler."
  * "-r", "--reset-break", help = "Halt the target when reset."
  * "-s", "--step-int", help = "Allow single stepping to step into interrupts."
  * "-f", "--frequency", help = "SWD clock frequency in Hz."


### Hello World example code
```python
from pyOCD.board import MbedBoard

import logging
logging.basicConfig(level=logging.INFO)

board = MbedBoard.chooseBoard()

target = board.target
flash = board.flash
target.resume()
target.halt()

print "pc: 0x%X" % target.readCoreRegister("pc")
    pc: 0xA64

target.step()
print "pc: 0x%X" % target.readCoreRegister("pc")
    pc: 0xA30

target.step()
print "pc: 0x%X" % target.readCoreRegister("pc")
   pc: 0xA32

flash.flashBinary("binaries/l1_lpc1768.bin")
print "pc: 0x%X" % target.readCoreRegister("pc")
   pc: 0x10000000

target.reset()
target.halt()
print "pc: 0x%X" % target.readCoreRegister("pc")
   pc: 0xAAC

board.uninit()
```

### GDB server example
Python:
```python
from pyOCD.gdbserver import GDBServer
from pyOCD.board import MbedBoard

import logging
logging.basicConfig(level=logging.INFO)

board = MbedBoard.chooseBoard()

# start gdbserver
gdb = GDBServer(board, 3333)
```
gdb server:
```
arm-none-eabi-gdb basic.elf

<gdb> target remote localhost:3333
<gdb> load
<gdb> continue

```

Architecture
------------

### Interface
An interface does the link between the target and the computer.
This module contains basic functionalities to write and read data to and from
an interface. You can inherit from ```Interface``` and overwrite ```read()```, ```write()```,...

Then declare your interface in ```INTERFACE``` (in ```pyOCD.interface.__init__.py```)

### Target
A target defines basic functionalities such as ```step```, ```resume```, ```halt```, ```readMemory```,...
You can inherit from Target to implement your own methods.

Then declare your target in TARGET (in ```pyOCD.target.__init__.py```)

### Transport
Defines the transport used to communicate. In particular, you can find CMSIS-DAP. 
Implements methods such as ```memWriteAP```, ```memReadAP```, ```writeDP```, ```readDP```, ...

You can inherit from ```Transport``` and implement your own methods.
Then declare your transport in ```TRANSPORT``` (in ```pyOCD.transport.__init__.py```)

### Flash
Contains flash algorithm in order to flash a new binary into the target.

### gdbserver
Start a GDB server. The server listens on a specific port. You can then
connect a GDB client to it and debug/program the target

Then you can debug a board which is composed by an interface, a target, a transport and a flash
