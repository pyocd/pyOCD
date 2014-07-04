How to Build PyOCD into Single Executable File
==============================================
This manual provides a step-by-step guide on how to ‘build PyOCD’ on Windows 7 32bit or Ubuntu 10.04.
PyOCD is an open source GDB server written in Python and maintained by PyOCD community, it depends on several libraries like pyusb under Linux, and pywinusb under Windows. Pyinstaller was chosen to bundle it into a single executable file, so that the PyOCD executable produced can be run on any computer, whether python and the related library are present or not on the system.

Build PyOCD on Ubuntu 10.04
---------------------------
1. Install Python:
Here on Ubuntu 10.04, this can be done by running the following command:
$ sudo apt-get install python

2. Install PyOCD and related library:
[PyOCD](https://github.com/mbedmicro/pyOCD):
[Pyusb(Linux)](https://github.com/walac/pyusb):
The installation steps are just on the github website, if you have any problem to install them. Please raise an issue ticket on the corresponding github website.

3. Install Pyinstaller:
Pyinstaller is an open source python program which can bundle python library like PyOCD into one executable file. You can get more information on its homepage: http://www.pyinstaller.org/. Although it has its release version 2.1, but there’s a bug related to pyusb interface hasn’t been merged into the release version.
So you still need to download the developing version on the github: https://github.com/pyinstaller/pyinstaller. The installation step is quite simple, and you can just refer to the github website.

4. Bundle PyOCD library into single executable file:
Switch to PyOCD source folder, under its test folder, there’s a py file gdb_server.py you need to bundle it to produce a single gdb server. This can be done by running the following command:
$ pyinstaller gdb_server.py --onefile.
In ./dist folder, there will be a single executable file which is ready to use or distribute it to other library.

Build PyOCD on Windows 7 32bit
------------------------------
1.  Install Python:
Here on Windows 7, you can download msi installer from: https://www.python.org/ftp/python/2.7.7/python-2.7.7.msi.
Remember to check python is added to your system path.

2.  Install PyOCD and related library:
[PyOCD](https://github.com/mbedmicro/pyOCD):
[Pywinusb(Windows)](https://github.com/rene-aguirre/pywinusb):
The installation steps are just on the github website, if you have any problem to install them. Please raise an issue ticket there.  

3. Install Pyinstaller:
Pyinstaller is an open source python program which can bundle python library like PyOCD into one executable file. You can get more information on its homepage: http://www.pyinstaller.org/. Although it has its release version 2.1, but there’s a bug related to pyusb interface hasn’t been merged into the release version.
So you still need to download the developing version on the github: https://github.com/pyinstaller/pyinstaller. The installation step is quite simple, and you can just refer to the github website. Make sure you have add the pyinstaller to your system path.

4.  Bundle PyOCD library into single executable file:
Switch to PyOCD source folder, under its test folder, there’s a py file gdb_server.py you need to bundle it to produce a single gdb server. This can be done by running the following command:
$ pyinstaller gdb_server.py --onefile.
In ./dist folder, there will be a single executable file which is ready to use or distribute it to other library.

Note
----
The steps above may most likely also work on an Ubuntu whose version is not 10.04, and an Windows whose version is not Windows 7 32bit, but it is not guaranteed.
