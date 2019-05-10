Target support
==============

Through both built-in support and CMSIS-Packs, pyOCD supports nearly every Cortex-M MCU that is
available on the market.

In addition, because pyOCD dynamically inspects the target's debug infrastructure, basic
debug functionality is enabled for any target that correctly implement the CoreSight architecture.


## Built-in

PyOCD has built-in support for over 70 popular MCUs from various vendors.

Because new targets are addded fairly often, the best way to see the available built-in targets is
by running `pyocd list --targets`. This command will print a table of supported targets, including
the target name, vendor, and part number.


## CMSIS-Packs

The [CMSIS](http://arm-software.github.io/CMSIS_5/General/html/index.html) specification defines the
[Device Family Pack](http://arm-software.github.io/CMSIS_5/Pack/html/index.html) (DFP) standard for
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
site](https://www.github.com/mbedmicro/pyOCD/issues). You should also report the issue to the pack
vendor.


### Managed packs

The `pyocd` tool's `pack` subcommand provides completely automated management of CMSIS-Packs. It
allows you to install new device support with a single command line invocation.

As part of the pack management, pyOCD keeps an index of all available DFPs. The pack index is a two-
level hierarchy of pack lists, with the top level pointing to individual vendor indexes. Once the
index is downloaded, pyOCD can very quickly locate the DFP that provides support for a given
MCU part number. To learn more about the index, see the [CMSIS-Pack index
files](http://arm-software.github.io/CMSIS_5/Pack/html/packIndexFile.html) documentation.

The two most useful options for the `pack` subcommand are `--find` and `--install`. The options
accept a glob-style pattern that is matched against MCU part numbers in the index. If the index
has not been downloaded yet, that will be done first. `--find` will print out which DFPs provide
support for matching part numbers. `--install` performs the same match, but downloads and installs
the matching DFPs. The patterns are matched case-insensitively and as a starts-with comparison.

For instance, if you know the specific part number of the device you are using, say STM32L073, you
can run this command to install support:

    $ pyocd pack --install stm32l073

This will download the index if required, then download the STM32L0xx_DFP pack.

As another example, to find which pack(s) support the NXP MK26F family, you could run:

    $ pyocd pack --find mk26

This will print a table similar to:

     PART            VENDOR  PACK         VERSION
     MK26FN2M0CAC18  NXP     MK26F18_DFP  11.0.0
     MK26FN2M0VLQ18  NXP     MK26F18_DFP  11.0.0
     MK26FN2M0VMD18  NXP     MK26F18_DFP  11.0.0
     MK26FN2M0VMI18  NXP     MK26F18_DFP  11.0.0

Once a DFP is installed, the `pyocd list --targets` command will show the new targets in its output,
and you can immediately begin using the target support with the other `pyocd` subcommands.


### Manual pack usage

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

For a more permanent solution, use a [`pyocd.yaml` configuration file](configuration.md). In the
config file, set the `pack` user option to either a single .pack file path or a list of paths. Now
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

