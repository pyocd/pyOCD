---
title: Target family usage notes
---

This section documents usage notes for certain target types.


## Nordic Semiconductor

### nRF51 family

See [SoftDevice](#softdevice) for notes about handling firmware containing SoftDevice images.

### nRF52 family

See [SoftDevice](#softdevice) for notes about handling firmware containing SoftDevice images.

Unlocking of flash security, also called APPROTECT, is supported. For more, see the
[security and protection]({% link _docs/security.md %}) documentation.

### SoftDevice

The nRF51 and nRF52 series have support for so-called “SoftDevice” firmware, which implements Nordic's Bluetooth LE or
other wireless protocol API. When firmware containing a SoftDevice is loaded, the SoftDevice region of flash is locked.
In order to reprogram the flash sectors containing the SoftDevice image, a mass erase must first be performed. This can
potentially cause issues with flash programming if one is not aware of this requirement.

For a development workflow with firmware using a SoftDevice, no extra steps are required.

PyOCD will by default scan flash sectors when programming flash in order to only erase and program sectors whose
contents are changing. Since normally the SoftDevice sectors do not change during development, pyOCD will skip over
these sectors.

In addition, a chip erased performed with a SoftDevice in flash will erase only the non-SoftDevice sectors. For example,
running `pyocd erase --chip` on such a device will leave the SoftDevice intact and erase all other sectors.

However, any case where the SoftDevice sectors are being erased requires a prior mass erase. This includes
changing the SoftDevice variant or version, as well as switching to firmware that doesn't include a SoftDevice.
Mass erase is a separate operation. It mostly functions like a chip erase, but can also be used to
[unlock]({% link _docs/security.md %}) devices that have APPROTECT enabled.

To perform a mass erase:

```
pyocd erase --mass
```


## NXP

### Kinetis family

Unlocking of flash security is supported for all Kinetis targets. For more, see the
[security and protection]({% link _docs/security.md %}) documentation.


## HDSC

### HC32L110
The documentation for this chip states that no external pull-up resistors are required on the SWD lines due to the internal pull-up
hardware. Testing has found this to be largely inaccurate. Most debug probes will require an external 4.7k&ohm; pull-up resistor 
between Ports P27/P31 and V+.
