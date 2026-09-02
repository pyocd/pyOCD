---
title: Target support
---

Through both built-in support and CMSIS-Packs, pyOCD supports nearly every Cortex-M MCU that is
available on the market. pyOCD also supports RISC-V targets with built-in target types.

In addition, because pyOCD dynamically inspects the target's debug infrastructure, basic
debug functionality is enabled for any target that correctly implement the CoreSight architecture
or RISC-V debug specification.


## Target types

When pyOCD connects to a device, it needs to know what type of device (target) it is controlling.
The type of device is known as the "target type". The target type defines the flash programming
algorithm and determine the device's memory map and other important information. Each target type is
identified by a short string that is either the full or partial part number for the device. For
example, "k64f" or "stm32l072".

Target types are either built-in to pyOCD or come from CMSIS-Packs. The sections below describe more
about the sources of target support.

To see the available target types you can run `pyocd list --targets`. This command will print a
table of supported target types, including the target name, vendor, and part number. In addition, it
prints whether each target target is built-in or comes from a CMSIS-Pack.


### Generic target type

PyOCD furnishes a generic target type named "cortex_m". This target type will be able to connect to
and debug almost any Cortex-M device that correctly implements the CoreSight architecture. However,
flash memory cannot be programmed, and a memory map is not provided. In addition, it may not work
for certain devices that require special handling of operations such as reset and halt.

Because of the limitations of the generic "cortex_m" target, the warning shown below will be logged
if the target type is "cortex_m".

    0000183:WARNING:board:Generic cortex_m target type is selected; is this intentional? You will be
    able to debug but not program flash. To set the target type use the '--target' argument or
    'target_override' option. Use 'pyocd list --targets' to see available targets.


### Setting the target type

There are two ways to specify the target type.

The first is to pass the `--target` command line argument to the `pyocd` tool and pass the target
type name. This argument must be passed every time you run `pyocd` with a subcommand that connects
to the target.

Another method is to set the `target_override` session option in a `pyocd.yaml` configuration file. The
[configuration file documentation]({% link _docs/configuration.md %}) describes how to do this for a specific debug
probe instead of globally.


### Target type auto-detection

Certain on-board debug probes know the type of target with which they are connected. The Arm DAPLink
and STLinkV2-1 firmwares both support this feature. When using a probe with target type
auto-detection, you do not need to tell pyOCD

To check whether your debug probe supports auto-detection, run `pyocd list`. This command prints
a list of all connected debug probes. If a probe does not support auto-detection, the name of the
probe firmware is printed. Whereas probes that do support auto-detection will show up with the
name of the board plus the target type in brackets.

Example probe listing:

      #   Probe/Board                       Unique ID                                          Target
    --------------------------------------------------------------------------------------------------------------------
      0   Arm DAPLink CMSIS-DAP             02400b0129164e4500440012706e0007f301000097969900   ✔︎ k64f
          NXP                               FRDM-K64F

      1   STLINK-V3                         002500074741500420383733                           ✖︎ stm32u585aiix
          B-U585I-IOT02A

      2   STM32 STLink                      066EFF555051897267233656                           ✔︎ stm32l475xg
          DISCO-L475VG-IOT01A

      3   Segger J-Link OB-K22-NordicSemi   960177309                                          n/a


This example shows several connected debug probes. The first supports extended auto-detection with automatic target type reporting. The second and third support board type detection using pyOCD's built-in table of board types, and show both an installed and uninstalled target type. Finally, the fourth probe does not support auto-detection.
Note how the descriptions of all but the last probe show the name of the board and the target type, for instance
"stm32l475xg" in the "Target" column.

If the target type is *not* auto-detected, it will default to "cortex_m" unless specified as
described above (see [Generic target type](#generic_target_type) above). In this case, the "Target" column will show "n/a".


## RISC-V target support

pyOCD supports RISC-V targets using the RISC-V Debug Specification (version 0.13 and 1.0). RISC-V
target support differs from Arm in several important ways.

### Generic RISC-V target type

pyOCD provides a generic `"riscv"` target type that can connect to any RISC-V device implementing the
debug specification. Like the `"cortex_m"` type, this provides basic debug functionality but no flash
programming or memory map.

### Key differences from Arm targets

- **JTAG only**: RISC-V debug uses JTAG as the transport layer. There is no SWD equivalent for RISC-V.
- **No auto-detection**: RISC-V targets must be explicitly specified via `--target` on the command line
  or in a configuration file. On-board debug probes cannot auto-detect RISC-V target types.
- **No CMSIS-Pack support**: There is no CMSIS Pack standard for RISC-V. All RISC-V targets must be
  added as built-in targets.
- **Hart-based cores**: Each CPU core is a "hart" (hardware thread). Multi-hart targets have multiple
  core instances.

### Built-in RISC-V targets

RISC-V built-in targets are listed alongside Arm targets by `pyocd list --targets`. All current RISC-V targets are from HPMicro Semiconductor, spanning 9 SoC families with AndesCore D25 (single-core) and D45 (single/dual-core) IP.

**Part (chip) targets:**

| Target Type | SoC Family | Core | Notes |
|---|---|---|---|
| `hpm53x0` | HPM5300 | D25 | Base (no internal flash) |
| `hpm53x1` | HPM5300 | D25 | 1 MB internal flash |
| `hpm5ex0` | HPM5E00 | D25 | Hybrid flash, no internal flash |
| `hpm5ex1` | HPM5E00 | D25 | |
| `hpm62x0` | HPM6200 | D45 | Dual-core, no internal flash |
| `hpm62x4` | HPM6200 | D45 | Dual-core, 4 MB internal flash |
| `hpm63x0` | HPM6300 | D45 | No internal flash |
| `hpm63x4` | HPM6300 | D45 | 4 MB internal flash |
| `hpm67x0` | HPM6700 | D45 | Dual-core, no internal flash |
| `hpm67x4` | HPM6700 | D45 | Dual-core, 4 MB internal flash |
| `hpm68x0` | HPM6800 | D45 | No internal flash |
| `hpm6ex0` | HPM6E00 | D45 | Dual-core, no internal flash |
| `hpm6px0` | HPM6P00 | D45 | Dual-core, no internal flash |
| `hpm6px1` | HPM6P00 | D45 | Dual-core, 1 MB internal flash |

**Board targets:**

| Target Type | Board | Notes |
|---|---|---|
| `hpm5300evk` | HPM5300EVK | |
| `hpm5301evklite` | HPM5301EVK-Lite | |
| `hpm5e00evk` | HPM5E00EVK | Hybrid flash |
| `hpm6200evk` | HPM6200EVK | Dual-core |
| `hpm6300evk` | HPM6300EVK | |
| `hpm6750evk2` | HPM6750EVK2 | Dual-core |
| `hpm6750evkmini` | HPM6750EVKMINI | Dual-core |
| `hpm6800evk` | HPM6800EVK | |
| `hpm6e00evk` | HPM6E00EVK | Dual-core |
| `hpm6p00evk` | HPM6P00EVK | Dual-core |

### Multi-core RISC-V targets

Dual-core (or multi-hart) RISC-V targets expose multiple cores through a single Debug Module. Each
core gets its own GDB server port (e.g., core 0 on port 3333, core 1 on port 3334). The JTAG
transport is automatically serialized using a reentrant lock (`RLock`) so concurrent GDB sessions
do not corrupt DMI state.

For SoCs that hold secondary cores in reset after power-on (e.g., HPM6P80), pyOCD releases them
during initialization via the `pre_hart_discover` callback and re-releases them after `ndmreset`
via `post_ndmreset_hooks`.

To add support for additional RISC-V MCUs, see the
[Adding a RISC-V target]({% link _docs/adding_new_targets.md %}#adding-a-risc-v-target) guide.


## Target configuration

PyOCD can be configured using several methods. The [configuration]({% link _docs/configuration.md %}) documentation describes how this is done.

Target types sourced from CMSIS-Packs can define debug variables that the user can configure as needed. See the [debug variables documentation]({% link _docs/open_cmsis_pack_support.md %}#debug_variables) for details.


## Target support sources

### Built-in

PyOCD has built-in support for over 70 popular MCUs from various vendors.

The best way to see the available built-in targets is
by running `pyocd list --targets`. This command will print a table of supported target types.
Built-in targets will be identified as such in the "SOURCE" column.
New built-in targets are added relatively infrequently since the addition of CMSIS-Pack based targets.


### CMSIS-Packs

The [Open-CMSIS-Pack](https://open-cmsis-pack.github.io/Open-CMSIS-Pack-Spec) specification defines the
Device Family Pack (DFP) standard for
distributing device support files. PyOCD uses DFPs as a means to add support for devices that do
not have support built in. This allows pyOCD to support nearly every Cortex-M MCU on the market. It
also means that pyOCD can immediately support newly released devices as soon as the silicon vendor
makes a DFP available.

The [CMSIS-Pack list](http://www.keil.com/dd2/pack/) web page is the official list of all available
packs. You can choose to download individual packs.

There are two methods to use a DFP within pyOCD. First, you can let pyOCD fully manage packs for
you, where all you have to do is tell it the part number(s) for which you wish to install support.
Alternatively, you can manually download packs and tell pyOCD which pack files to use.

*Note:* As with any software release, CMSIS-Packs may be buggy and have incorrect or missing
information about a device. Sometimes memory regions will be missing, attributes of a memory region
or flash algorithm might be wrong, or the flash algorithm itself might be buggy. If you encounter an
issue with a pack, you can report the issue on the [pyOCD GitHub
site](https://www.github.com/pyocd/pyOCD/issues) to let other users know about the problem. You
should also report the issue to the pack vendor so it can be fixed.


#### Managed packs

The `pyocd` tool's `pack` subcommand provides completely automated management of CMSIS-Packs. It
allows you to install new device support with a single command line invocation.

As part of the pack management, pyOCD keeps an index of all available DFPs. The pack index is a two-
level hierarchy of pack lists, with the top level pointing to individual vendor indexes. Once the
index is downloaded, pyOCD can very quickly locate the DFP that provides support for a given
MCU part number. To learn more about the index, see the [Open-CMSIS-Pack index
files](https://open-cmsis-pack.github.io/Open-CMSIS-Pack-Spec/main/html/packIndexFile.html) documentation.

The two most useful subcommands of the `pack` subcommand are `find` and `install`. The options accept a glob-style
pattern that is matched against MCU part numbers in the index. If the index has not been downloaded yet, that will be
done first, or you can run `pyocd pack update` yourself. The `find` subcommand will print out a list of matching part
numbers and the names of the containing DFPs. `install` performs the same match, but downloads and installs the matching
DFPs. The part number patterns are matched case-insensitively and as a contains comparison.

For instance, if you know the specific part number of the device you are using, say STM32L073, you
can run this command to install support:

    $ pyocd pack install stm32l073

This will download the index if required, then download the STM32L0xx_DFP pack. The

As another example, to find which pack(s) support the NXP MK26F family, you could run:

    $ pyocd pack find k26

This will print a table similar to:

      Part             Vendor   Pack          Version
    ---------------------------------------------------
      MK26FN2M0CAC18   NXP      MK26F18_DFP   11.0.1
      MK26FN2M0VLQ18   NXP      MK26F18_DFP   11.0.1
      MK26FN2M0VMD18   NXP      MK26F18_DFP   11.0.1
      MK26FN2M0VMI18   NXP      MK26F18_DFP   11.0.1

Once a DFP is installed, the `pyocd list --targets` command will show the new targets in its output,
and you can immediately begin using the target support with the other `pyocd` subcommands.

To get a list of all installed packs, use the `pack show` subcommand.


#### Manual pack usage

If you prefer to manually manage packs, or if the managed pack system cannot access online packs
from your network, you can download them yourself from the [official CMSIS-Pack
list](http://www.keil.com/dd2/pack/). The downloaded pack files can be stored wherever you like.
Typically you would group them in a single common directory. Another good option is to place the
pack file used with a project in a project-relative location.

There are two ways to use a manually downloaded pack.

The simplest option is to pass the `--pack` option to the `pyocd` tool, specifying the path to the
.pack file. PyOCD does not cache any information about packs used this way, so this argument must be
passed for every invocation in addition to the other arguments. For instance, to run the GDB server,
you might execute `pyocd gdbserver --pack=Keil.STM32L4xx_DFP.2.2.0.pack`. Note that you can pass
multiple `--pack` arguments to pyOCD, which might be useful in a scripted execution of pyOCD.

For a more permanent solution, use a [`pyocd.yaml` configuration file]({% link _docs/configuration.md %}). In the
config file, set the `pack` session option to either a single .pack file path or a list of paths. Now
when you run the `pyocd` tool, it will automatically pick up the pack file(s) to use.

Here is an example config file that lists two packs.
```yaml
pack:
  - /Users/admin/CMSIS-Packs/Keil.STM32L0xx_DFP.2.0.0.pack
  - /Users/admin/CMSIS-Packs/NXP.MKV58F24_DFP.11.0.0.pack
```

To see the targets provided by a .pack file, run `pyocd list --targets` and pass the approprate
`--pack` option or use a config file, as described above.

_Note:_ .pack files are simply zip archives with a different extension. To examine the contents of
a pack, change the extension to .zip and extract.

_Note:_ PyOCD can work with expanded packs just like zipped .pack files. Pass the path to the root directory
of the pack using the `--pack` argument, as above. This is very useful for cases such as development or
debugging of a pack, or for working with other CMSIS-Pack managers that store packs in decompressed form.

#### CMSIS-Toolbox Run and Debug Management

Run and Debug Management is a part of the [CMSIS-Toolbox](https://github.com/Open-CMSIS-Pack/cmsis-toolbox) build
information files when working with CSolution projects. Each `*.cbuild-run.yml` file contains relevant run and
debug information for a single `target-type` defined in a CSolution project. The tool gathers and filters the
target information from the BSP and DFP.

To use the `cbuild-run` target information in PyOCD, pass the `--cbuild-run` option followed by the path to
desired `*.cbuild-run.yml` file. The target information is not cached in PyOCD, which means the command-line
option should always be passed when launching the debugger.

Because a single `target-type` is described in the YAML file, the `--target`
command-line argument is not needed, as the target is automatically selected.

More information on CMSIS-Toolbox and the CSolution project format for Run and Debug Management can be found in the
[CMSIS-Toolbox Documentation](https://open-cmsis-pack.github.io/cmsis-toolbox/YML-CBuild-Format/#run-and-debug-management).
