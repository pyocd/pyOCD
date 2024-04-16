---
title: FAQ
---

### Common issues

##### Debug probe is not available

- Linux: Make sure udev is configured correctly to allow access to USB debug probes. PyOCD includes a set of predefined [udev config files](https://github.com/pyocd/pyOCD/tree/main/udev) for common probe. Alternatively, you can run pyocd using sudo, but this is strongly recommended against.
- MacOS: Make sure another process hasn't taken ownership of the USB device.

##### Getting "No ACK" errors when attempting to connect

- A "No ACK" error means the target is not responding at all to SWD/JTAG transfers. This can be for a few reasons:
    - The target is not powered on. Either the board isn't power up or the target is in a deep sleep mode.
    - The SWD/JTAG pins haved been pinmuxed to different peripherals.
    - The SWD or JTAG wire protocol being used isn't supported by the device.
    - A target-specific reason, such as a proprietary connection procedure that hasn't been performed.
- The method to gain debug control of a powered down or sleeping device is target dependent. However, it generally involves first waking the device, then halting the CPU before the resident firmware can place the device in a low power state. For many MCUs, these steps can be accomplished by telling pyOCD to connect while the reset pin is held asserted, eg connecting under reset. To use this mode, pass `--connect=under-reset`. On certain devices this won't work because the reset pin performs a cold reset that also resets debug logic. For these devices, please refer to the vendor's reference manual or programming manual.
- A similar method to waking a sleeping device is needed to gain control of a device whose firmware changes the SWD/JTAG pinmux after it starts running. Connecting under reset also works in this case, if the device support it.
