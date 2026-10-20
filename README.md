# pyOCD

[\[pyocd.io\]](https://pyocd.io/) [\[Docs\]](https://pyocd.io/docs) [\[Slack\]](https://join.slack.com/t/pyocd/shared_invite/zt-wmy3zvg5-nRLj1GBWYh708TVfIx9Llg) [\[Mailing list\]](https://groups.google.com/g/pyocd) [\[CI results\]](https://dev.azure.com/pyocd/pyocd/_build?definitionId=1&_a=summary)

<table><tr><td>

### News

The v0.46 release adds enhanced trace support, GDB Server operation without a connected client, and the new pyocd `info` subcommand.

See the [wiki news page](https://github.com/pyocd/pyOCD/wiki/News) for all recent news.

</td></tr></table>

pyOCD is an open source Python based tool and package for programming and debugging Arm Cortex-M microcontrollers
with a wide range of debug probes. It is fully cross-platform, with support for Linux, macOS, Windows, and FreeBSD.

A command line tool is provided that covers most use cases, or you can make use of the Python
API to facilitate custom target control. A common use for the Python API is to run and control CI
tests.

Support for more than 70 popular MCUs is built-in. In addition, through the use of CMSIS Device
Family Packs, [nearly every Cortex-M device](https://www.keil.com/dd2/pack/) on the market is supported.

The `pyocd` command line tool gives you total control over your device with these subcommands:

- `gdbserver`: GDB remote server allows you to debug using gdb via either the console or
    [several GUI debugger options](https://pyocd.io/docs/gdb_setup).
- `load`: Program files of various formats into flash or RAM.
- `erase`: Erase part or all of an MCU's flash memory.
- `run`: Load and run the target.
- `reset`: Hardware or software reset of a device.
- `info`: Display information about the connected target.
- `pack`: Manage [CMSIS Device Family Packs](https://open-cmsis-pack.github.io/Open-CMSIS-Pack-Spec/main/html/index.html)
    that provide additional target device support.
- `commander`: Interactive REPL control and inspection of the MCU.
- `server`: Share a debug probe with a TCP/IP server.
- `rtt`: Stream Segger RTT IO with _any_ debug probe.
- `list`: Show connected devices.

The API and tools provide these features:

- halt, step, resume control
- read/write memory
- read/write core registers
- set/remove hardware and software breakpoints
- set/remove watchpoints
- write to flash memory
- load binary, hex, or ELF files into flash
- reset control
- access CoreSight DP and APs
- SWO and SWV
- and more!

Configuration and customization is supported through [config files](https://pyocd.io/docs/configuration),
[user scripts](https://pyocd.io/docs/user_scripts), and the Python API.

## CMSIS alignment

We are moving towards common CMSIS tooling for pack management and CMSIS-Packs for new target support.
These complementary changes let us share tooling and device information across the CMSIS ecosystem.

### Moving pyOCD pack management towards `cpackget`

As the CMSIS ecosystem evolves, we want to encourage pyOCD contributors to use **`cpackget` for
CMSIS-Pack management** rather than relying on the built-in pack manager.

The built-in pack manager in pyOCD will be deprecated in favor of the CMSIS-Toolbox approach. This aligns
pyOCD with the broader CMSIS tool landscape and promotes a more consistent, interoperable development
experience.

This direction brings several benefits:

- **Less duplication:** Reuse established tooling for CMSIS-Pack management instead of maintaining
  overlapping functionality.

- **Better interoperability:** Align workflows across CMSIS-Toolbox and the wider CMSIS ecosystem.

- **A consistent development experience:** Support the broader family of CMSIS tools, including the
  CMSIS Solution and CMSIS Debugger VS Code extensions.

- **AI-ready information management:** Leverage structured CMSIS information through the CMSIS Developer
  Assistant to support agentic AI workflows.

Our goal is to let pyOCD focus on its core strengths in debugging and target interaction, while pack
management follows the common CMSIS tooling approach.

**For users:** Use `cpackget` when setting up new CMSIS-Toolbox workflows, and plan for the move away
from pyOCD's built-in pack manager.

**For contributors:** Please start using `cpackget` in your development workflows and take this direction
into account when working on pack-related features, tests, and documentation. We should avoid introducing
new dependencies on the built-in pack manager as we move towards its deprecation.

See the [`cpackget` documentation](https://github.com/Open-CMSIS-Pack/cpackget) for installation and usage.

### Supporting new targets through CMSIS-Packs

We are moving towards **[CMSIS Device Family Packs (DFPs)](https://www.keil.arm.com/packs/?q=&pack-search=&contents=devices&sort_by=)
as the preferred way to support new targets** in pyOCD, rather than adding new built-in target support.

pyOCD already uses DFPs to obtain device memory maps, flash programming algorithms, and debug sequences.
Using these descriptions directly lets silicon vendors and pack maintainers deliver device support
through a standard format shared with other CMSIS tools.

There are several benefits when using DFPs:

- **Faster availability:** New device support and device-specific fixes can be delivered through pack
  updates without waiting for a pyOCD release.

- **More consistent device support:** Reuse the same memory maps, flash algorithms, and debug sequences
  across pyOCD and other tools that support CMSIS-Packs.

- **Support closer to the source:** Silicon vendors and pack maintainers can maintain device information
  and fixes in their DFPs, where they can benefit users of multiple tools.

- **Less duplication:** Reduce the need for separate Python target definitions and copied flash
  algorithms in pyOCD, so development can focus on debugging and common pack support.

**For users:** Use a DFP for your device when setting up new projects. See the
[target support documentation](https://pyocd.io/docs/target_support) for how to select and use targets
from packs.

**For contributors:** Please take this direction into account when adding target support, tests, and
documentation. Prefer adding or improving device support in DFPs and improving pyOCD's common pack support
over adding new built-in target definitions.

Thanks for helping keep pyOCD aligned with the evolving CMSIS ecosystem!

## Requirements

- Python 3.9.0 or later.†
- macOS, Linux, Windows 7 or newer, or FreeBSD
- A recent version of [libusb](https://libusb.info/).
- Microcontroller with an Arm Cortex-M CPU
- Supported debug probe
    - [CMSIS-DAP](https://arm-software.github.io/CMSIS_5/DAP/html/index.html) v1 (HID) or v2 (WinUSB), including:
        - Atmel EDBG/nEDBG
        - Atmel-ICE
        - Cypress KitProg3 or MiniProg4
        - [DAPLink](https://github.com/ARMmbed/DAPLink) based debug probe, either on-board or standalone
        - Keil ULINKplus
        - NXP LPC-LinkII
        - NXP MCU-Link
        - WCH-Link (1a86:8011, 2a86:8011 and others)
    - [PE Micro](https://pemicro.com/) Cyclone and Multilink
    - Raspberry Pi Picoprobe
    - SEGGER J-Link
    - STLinkV2 or STLinkV3, either on-board or the standalone versions

† Version [0.29](https://github.com/pyocd/pyOCD/releases/tag/v0.29.0) is the last version to support Python 2.

## Status

PyOCD is beta quality.

The Python API is considered stable for version 0.x, but will be changed in version 1.0.

## Documentation

The pyOCD documentation is available on the [pyocd.io website](https://pyocd.io/docs).

In addition to user guides, you can generate reference documentation using Doxygen with the
supplied [config file](docs/Doxyfile).

## Installing

**The full installation guide is available [in the documentation](https://pyocd.io/docs/installing).**

For notes about installing and using on non-x86 systems such as Raspberry Pi, see the
[relevant documentation](https://pyocd.io/docs/installing_on_non_x86).

The latest stable version of pyOCD may be installed via [pip](https://pip.pypa.io/en/stable/index.html)
as follows:

```sh
python3 -m pip install -U pyocd
```

_Note: depending on your system, you may need to use `python` instead of `python3`._

The latest pyOCD package is available [on PyPI](https://pypi.python.org/pypi/pyOCD/) as well as
[on GitHub](https://github.com/pyocd/pyOCD/releases).

To install the latest prerelease version from the HEAD of the `develop` branch, you can do
the following:

```sh
python3 -m pip install --pre -U git+https://github.com/pyocd/pyOCD.git@develop
```

You can also install directly from the source by cloning the git repository and running:

```sh
python3 -m pip install .
```

Note that, depending on your operating system, you may run into permissions issues running these commands.
You have a few options here:

1. Under Linux, run with `sudo -H` to install pyOCD and dependencies globally. On macOS, installing with sudo
   should never be required, although sometimes permissions can become modified such that installing without
   using sudo fails.
2. Specify the `--user` option to install local to your user account.
3. Run the command in a [virtualenv](https://virtualenv.pypa.io/en/latest/)
   local to a specific project working set.

### udev rules on Linux

On Linux, particularly Ubuntu 16.04+, you must configure udev rules to allow pyOCD to access debug
probes from user space. Otherwise you will need to run pyOCD as root, using sudo, which is very
highly discouraged. (You should _never_ run pyOCD as root on any OS.)

To help with this, example udev rules files are included with pyOCD in the
[udev](https://github.com/pyocd/pyOCD/tree/main/udev) folder. The
[readme](https://github.com/pyocd/pyOCD/tree/main/udev/README.md) in this folder has detailed
instructions.

### Target support

See the [target support documentation](https://pyocd.io/docs/target_support) for information on how to check if
the MCU(s) you are using have built-in support, and how to install support for additional MCUs via
CMSIS-Packs.

## Using GDB

See the [GDB setup](https://pyocd.io/docs/gdb_setup) documentation for a guide for setting up
and using pyocd with gdb and IDEs.

## Community resources

Join the pyOCD community!

[pyocd.io website](https://pyocd.io) \
[Documentation](https://pyocd.io/docs) \
[Issues](https://github.com/pyocd/pyOCD/issues) \
[Discussions](https://github.com/pyocd/pyOCD/discussions) \
[Wiki](https://github.com/pyocd/pyOCD/wiki) \
[Mailing list](https://groups.google.com/g/pyocd) for announcements

In order to foster a healthy and safe environment, we expect contributors and all members of the community to
follow our [Code of Conduct](https://github.com/pyocd/pyOCD/tree/main/CODE_OF_CONDUCT.md).

## Contributions

We welcome contributions in any area, even if you just create an issue. If you would like to get involved but
aren't sure what to start with, just ask on
[Slack](https://join.slack.com/t/pyocd/shared_invite/zt-zqjv6zr5-ZfGAXl_mFCGGmFlB_8riHA) or [GitHub
discussions](https://github.com/pyocd/pyOCD/discussions) and we'll be happy to help you. Or you can look for
an open issue. Any work on major changes should be discussed with the maintainers to make everyone is aligned.

Please see the [contribution guidelines](https://github.com/pyocd/pyOCD/tree/main/CONTRIBUTING.md) for detailed requirements. The [developers'
Guide](https://pyocd.io/docs/developers_guide) has instructions on how to set up a development environment for pyOCD.

New pull requests should be [created](https://github.com/pyocd/pyOCD/pull/new) against the `develop` branch. (You have to change the "base" to `develop`.)

## License

PyOCD is licensed with the permissive Apache 2.0 license. See the
[LICENSE](https://github.com/pyocd/pyOCD/tree/main/LICENSE) file for the full text of the license. All
documentation and the website are licensed with [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Copyright © 2006-2026 PyOCD Authors
