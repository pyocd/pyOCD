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
not have support built in. This allows pyOCD to support nearly every Cortex-M MCU on the market.

The [CMSIS-Pack list](http://www.keil.com/dd2/pack/) web page shows all available packs. You can
choose to download individual packs.

There are two methods to use a DFP within pyOCD. First, you can let pyOCD fully manage packs for
you, where all you have to do is tell it the part number(s) for which you wish to install support.
Alternatively, you can manually download packs and tell pyOCD which pack files to use.


### Managed

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

    # pyocd pack --install stm32l073

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


### Manual

If you prefer to manually manage packs, you can download them yourself from the [CMSIS-Pack
list](http://www.keil.com/dd2/pack/). To use a downloaded pack, just pass the `--pack` option to
the `pyocd` tool, specifying the pack to the .pack file. You may also set the `pack` user option
to either a single .pack file path or a list of paths in the [configuration file](configuration.md).

To see the targets provided by a .pack file, run `pyocd list --targets` and pass the approprate
`--pack` option or use the config file, as above.

_Note:_ .pack files are simply zip archives with a different extension. To examine the contents of
a pack, change the extension to .zip and extract.

