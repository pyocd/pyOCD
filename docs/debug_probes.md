---
title: Debug probes
---

The debug probe is the interface between pyOCD and the target, and it drives the SWD or JTAG signals that control
the target. By way of the connection between the debug probe and target, selecting the debug probe implicitly controls
which target pyOCD debugs.

There are two major flavours of debug probe:

- **On-board probes**. Many evaluation boards include an on-board debug probe, so you can plug it in and start using
    it without needing any other devices.
- **Standalone probes**. For debugging custom hardware you typically need a standalone probe that connects via an
    SWD/JTAG cable. Most commercially available debug probes, such as the SEGGER J-Link or Arm ULINKplus, are standalone.


PyOCD uses debug probe driver plug-ins to enable support for different kinds of debug probes. It comes with plug-ins for
these types of debug probes:

 Plug-in Name        | Debug Probe Type
---------------------|--------------------
`cmsisdap`           | [CMSIS-DAP](http://www.keil.com/pack/doc/CMSIS/DAP/html/index.html)
`picoprobe`          | Raspberry Pi [Picoprobe](https://github.com/raspberrypi/picoprobe)
`jlink`              | [SEGGER](https://segger.com/) [J-Link](https://www.segger.com/products/debug-trace-probes/)
`stlink`             | [STMicro](https://st.com/) [STLinkV2](https://www.st.com/en/development-tools/st-link-v2.html) and [STLinkV3](https://www.st.com/en/development-tools/stlink-v3set.html)
`remote`             | pyOCD [remote debug probe client]({% link _docs/remote_probe_access.md %})

Additional debug probe plugins are available as Python packages through [PyPI](https://pypi.python.org), and
can be installed with pip:

 Plug-in Name   | Package           | Debug Probe Type
----------------|-------------------|--------------------
`pemicro`       | pyocd-pemicro     | [PE Micro](https://pemicro.com/) Cyclone and Multilink.



## Unique IDs

Every debug probe has a **unique ID**. For debug probes that connect with USB, this is nominally the same as
its USB serial number. However, every debug probe plugin determines for itself what the unique ID means. Some
debug probes types are not connected with USB but are accessed across the network. In this case, the unique ID
is the probe's network address.

The unique ID parameter is actually a simple form of URL. It can be prefixed with the name of a debug probe plugin
followed by a colon, e.g. `cmsisdap:`, to restrict the type of debug probe that will match. This form is also a
requirement for certain probe types, such as the remote probe client, where the unique ID is a host address rather than
serial number.


## Auto target type identification

Certain types of on-board debug probes can report the type of the target to which they are connected.

Debug probes that support automatic target type reporting:

- CMSIS-DAP probes supporting v2.1 of the protocol and reporting target type info
- CMSIS-DAP probes based on the DAPLink firmware
- STLinkV2-1 and STLinkV3


## Listing available debug probes

To view the connected probes and their unique IDs, run `pyocd list`. This command will produce output looking like this:

      #   Probe/Board                       Unique ID                                          Target
    --------------------------------------------------------------------------------------------------------------------
      0   Arm DAPLink CMSIS-DAP             02400b0129164e4500440012706e0007f301000097969900   ✔︎ k64f
          NXP                               FRDM-K64F

      1   STLINK-V3                         002500074741500420383733                           ✖︎ stm32u585aiix
          B-U585I-IOT02A

      2   STM32 STLink                      066EFF555051897267233656                           ✔︎ stm32l475xg
          DISCO-L475VG-IOT01A

      3   Segger J-Link OB-K22-NordicSemi   960177309                                          n/a


The output is divided into columns for the probe number, probe name, unique ID, and default target type name.
Probes that have additional board identification will have a second row with the board name and possibly board
vendor.

The "Target" column shows the debug probe's default target type for debug probes that support automatic target
type reporting. Whether that target type is installed and available for use is shown by a check or "X" mark
before the target type name (and in different colours, if colour output is enabled). If an "X" mark is
displayed, see the [target support documentation]({% link _docs/target_support.md %}) for information about
how you can install that the target type.

For debug probes that do not support automatic target type reporting, the Target column will simply display
"n/a". This can be seen above for the "Segger J-Link OB-K22-NordicSemi" probe. The target type must be
specified manually in such cases, otherwise full functionality, such as flash programming, will not be
available.

In any case, whether required because the probe doesn't have a default, or to override the default, the target
type can be specified either on the command line with the `-t` / `--target` argument, or by setting the
`target_override` session option (e.g., in a [config file]({% link _docs/configuration.md %}#config_file)).

Note that the printed list includes only those probes that pyOCD can actively query for, which currently means
only USB based probes.


## Selecting the debug probe

All of the pyOCD subcommands that communicate with a target require the user to either implicitly or
explicitly specify a debug probe.

There are three ways the debug probe is selected:

1. Implicitly, if only one probe is connected to the host, pyOCD can use it automatically without further configuration.

2. If there is more than one probe connected and pyOCD is not told which to use, it will ask on the console. It presents
    the same list of probes reported by `pyocd list`, plus this question:

        Enter the number of the debug probe or 'q' to quit>

    and waits until a probe index is entered.

3. Explicitly, with the use of `-u UID` / `--uid=UID` / `--probe=UID` command line arguments. These arguments accept
    either a whole or partial unique ID.

If no probes are currently connected and pyOCD is executed without explicitly specifying the probe to use, it will
by default print a message asking for a probe to be connected and wait. If the `-W` / `--no-wait` argument is passed,
pyOCD will exit with an error instead.



## Probe driver plug-in notes

This section contains notes on the use of different types of debug probes and the corresponding driver plug-ins.

### CMSIS-DAP

[CMSIS-DAP](https://arm-software.github.io/CMSIS_5/DAP/html/index.html) is a debug probe protocol designed by Arm and released as open source as part of the CMSIS project.
There are two major versions of CMSIS-DAP, which use different USB classes:

- v1: USB HID. This version is slower than v2. Still the most commonly seen version, although it is now deprecated by
    Arm.
- v2: USB vendor-specific using bulk pipes, permitting higher performance than v1. WinUSB-enabled to allow driverless
    usage on Windows 8 and above. (Can be used with Windows 7 if device installation settings are set to automatically
    download and install drivers for new devices from the Internet.)

If a debug probe provides both v1 and v2 interfaces, pyOCD will normally use the v2 interface. (See the `cmsis_dap.prefer_v1` option described below if this needs to be changed.)

These are some of the commercial probes by silicon vendors using the CMSIS-DAP protocol, both standalone and on-board:

- Microchip EDBG and variants
- Microchip Atmel-ICE
- Cypress KitProg3
- Cypress MiniProg4
- Keil ULINKplus
- NXP LPC-LinkII
- NXP MCU-Link
- NXP MCU-Link Pro
- NXP OpenSDA

In addition, there are numerous other commercial and open source debug probes utilising the CMSIS-DAP protocol.

PyOCD supports automatic target type identification for any debug probe supporting CMSIS-DAP v2.1 or later that reports the target type from the DAP_Info command. Automatic target type identification is also supported for the widely used
[DAPLink](https://github.com/ARMmbed/DAPLink) firmware using the [board ID]({% link _docs/developer/board_ids.md %}) system.

DAPLink firmware updates are available on the [daplink.io](https://daplink.io/) site and on the project's
[releases page](https://github.com/ARMmbed/DAPLink/releases) on GitHub.

#### Session options

- `cmsis_dap.deferred_transfers` (bool, default True) Whether to use deferred transfers in the CMSIS-DAP probe backend.
    By disabling deferred transfers, all writes take effect immediately. However, performance is negatively affected.
- `cmsis_dap.limit_packets` (bool, default False) Restrict CMSIS-DAP backend to using a single in-flight command at a
    time. This is useful on some systems where USB is problematic, in particular virtual machines.
- `cmsis_dap.prefer_v1` (bool, default False) Determines whether pyOCD will choose a CMSIS-DAP v1 interface of v2 in cases where a device provides both for backwards compatibility. There is rarely a reason to change this option, except for testing or issues. **Note:** This option can only be set in a default config file (e.g., `pyocd.yaml` in the working directory) because of how options loading is ordered in relation to debug probe enumeration.

#### Microchip EDBG

The Microchip (previously Atmel) EDBG probe firmware, at the time of this writing, provides a CMSIS-DAP v1 interface.
On macOS, reading command responses always times out. The probe works on other OSes, however.


### PE Micro Cyclone and Multilink

The Cyclone and Multilink debug probes from PE Micro are supported through the use of a separate probe driver
plugin called `pyocd-pemicro`. This plugin can be installed at any time using `pip`:

    pip install pyocd-pemicro

It can also be installed at the same time as pyOCD by adding the `pemicro` install extra:

    pip install pyocd[pemicro]

Once the PE Micro probe driver is installed, Cyclone and Multilink probes connected by USB will immediately
be available for use.

Currently, PE Micro probes connected via the network are not accessible.


### STLink

<div class="alert alert-warning">
Recent STLink firmware versions will only allow access to STM32 targets. If you are using a target
from a silicon vendor other than ST Micro, please use a different debug probe.
</div>

No host resident drivers need to be installed to use STLink probes; only libusb is required.

The minimum supported STLink firmware version is V2J24, or any V3 version. However, upgrading to the latest version
is strongly recommended. Numerous bugs have been fixed, and new commands added for feature and performance improvements.

- V2J26: Adds 16-bit transfer support. If not supported, pyOCD will fall back to 8-bit transfers. It is possible this
    will produce unexpected behaviour if used to access Device memory (e.g. memory mapped registers).
- V2J28: Minimum version for multicore target support.
- V2J32/V3J2: Allows access to banked DP registers. Usually not needed.
- V2J32/V3J2: Supports setting the AHB and AXI transfer attributes. See
    [`set hnonsec`]({% link _docs/command_reference.md %}#hnonsec) and
    [`set hprot`]({% link _docs/command_reference.md %}#hprot).

[STLink firmware updates on www.st.com](https://www.st.com/en/development-tools/stsw-link007.html).

PyOCD supports automatic target type identification for on-board STLink probes that report a [board ID]({% link _docs/developer/board_ids.md %}).

#### STLinkV3 SWD/JTAG frequencies

The STLinkV3 has an internal clock frequency control for its HCLK prescaler that allows access to different SWD/JTAG
frequencies. The prescaler can be set from pyOCD with the `stlink.v3_prescaler` session option to 1, 2, or 4. In
addition to changing the available SWD/JTAG frequencies, modifying the prescaler also affects UART baud rates and
frequencies of the serial I/O bridge interfaces.

These are the SWD/JTAG frequencies available with different values of `stlink.v3_prescaler`:

 prescaler=1 (default) | prescaler=2 | prescaler=4
-----------------------|-------------|----------
 24.0 MHz              | 12.0 MHz    | 6.0 MHz
 8.0 MHz               | 4.0 MHz     | 2.0 MHz
 3.3 MHz               | 1.6 MHz     | 850 kHz
 1.0 MHz               | 1.0 MHz     | 520 kHz
 200 kHz               | 200 kHz     | 200 kHz
 50 kHz                | 50 kHz      | 50 kHz

#### Session options

- `stlink.v3_prescaler` (int, must be 1, 2, or 4, default 1)
    Configures the HCLK prescaler of an STLinkV3 to modify the range of available SWD/JTAG frequencies, as described
    above. Affects available frequencies of other peripherals, such as UART, as well.


### J-Link

To use a Segger J-Link probe, the driver package must be installed. Segger makes drivers available for Linux, macOS,
and Windows.

[J-Link firmware and driver installer and updates on www.segger.com](https://www.segger.com/downloads/jlink/)

On macOS, you can install the `segger-jlink` cask with Homebrew to get managed driver updates.

Please note that flash programming performance using a J-Link through pyOCD is currently slower than using the J-Link
software directly (or compared to CMSIS-DAP). This is because pyOCD uses the low-level DAP commands provided by J-Link,
which are inherently slower than higher level commands (which are less flexible and more difficult and complex to
integrate).

#### Serial numbers

The USB serial number for J-Link probes will have leading zeroes. However, the J-Link driver and applications do not
use leading zeroes. PyOCD also does not use leading zeroes, as it interfaces with the J-Link through its driver.

#### Session options

- `jlink.device` (str, no default)
    If this option is set to a supported J-Link device name, then the J-Link will be asked connect
    using this name. Otherwise, the J-Link is configured for only the low-level CoreSight operations
    required by pyOCD. Ordinarily, it does not need to be set.
- `jlink.power` (bool, default True)
    Enable target power when connecting via a J-Link probe, and disable power when
    disconnecting.
- `jlink.non_interactive` (bool, default True)
    Controls whether the J-Link DLL is allowed to present UI dialog boxes and its control
    panel. Note that dialog boxes will actually still be visible, but the default option
    will be chosen automatically after 5 seconds.


