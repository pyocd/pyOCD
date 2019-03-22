udev rules for Linux
====================

On Linux, permission to access USB devices from user space must be explicitly granted
via udev rules. This directory contains example udev rules to allow pyOCD to access common
debug probes without requiring it to be run as root, something which is very highly
discouraged.

The following debug probes are supported:

- DAPLink
- STLinkV2
- STLinkV2-1
- STLinkV3
- Keil ULINKplus
- NXP LPC-LinkII


To install, copy the rules files in this directory to `/etc/udev/rules.d/` on Ubuntu:

```
$ sudo cp *.rules /etc/udev/rules.d
```

If you use different, but compatible, debug probe from one of those listed above, you can check the
IDs with the ``dmesg`` command.

   -  Run ``dmesg``
   -  Plug in your board
   -  Run ``dmesg`` again and check what was added
   -  Look for line similar to ``usb 2-2.1: New USB device found, idVendor=0d28, idProduct=0204``


To see your changes without a reboot, you can force the udev system to reload:

```
$ sudo udevadm control --reload
$ sudo udevadm trigger
```

By default, the rules provide open access to the debug probes for all users. If you share your Linux
system with other users, or just don't like the idea of write permission for everybody, you can
replace `MODE:="0666"` with `OWNER:="yourusername"` to create the device owned by you, or with
`GROUP:="somegroupname"` and mange access using standard Unix groups.

_Note: STLink rules provided courtesy of STMicroelectronics._
