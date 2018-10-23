Adding a new target
===================

This guide describes how to manually add support for a new target and/or board to pyOCD.

For background information, review the [architecture overview](ARCHITECTURE.md) document first.

### Steps to add a new target

1. Create a new `CoreSightTarget` subclass and `Flash` subclass in a file under `pyocd/target/`. You can copy one of the existing target files like `pyocd/target/target_ncs36510.py` and rename the classes.

    The target source file name must follow
    the pattern "target\_\<device>.py", where "\<device>" is the device's `Dname` or `Dvariant` part
    number value from the appropriate CMSIS Device Family Pack (DFP). For instance,
    `target_LPC54608J512ET180.py`. You may substitute an "x" for certain fields in the part number,
    such as a package or pin count code, temperature code, or memory size (if multiple memory sizes
    are supported via classes within the one source file).

2. Create the target's memory map from information in the device's reference manual. The memory map
    should be a `memoryMap` class attribute of the target class. Modifying an existing memory map is
    easiest, and there are many examples in the other targets.

3. To create the flash algo, the recommended method is to use the [`tools/generate_blobs.py`](https://github.com/mbedmicro/FlashAlgo/blob/master/scripts/generate_blobs.py) script from the [FlashAlgo](https://github.com/mbedmicro/FlashAlgo) project. This script will
    generate output files in several forms, including Python for pyOCD, from an .FLM file that is
    included as part of a CMSIS DFP.

    1. Locate the correct .FLM file from the DFP for your target.

    2. Run `generate_blobs.py \<path to FLM>`. It will write the output files to the same directory
        containing the source .FLM file.

    3. The `py_blob_orig.py` output file contains the flash algo for pyOCD. Copy the `flash_algo`
        dictionary into the target source file.

    4. Review the addresses in the `flash_algo` dictionary to make sure they are valid. The memory
       layout should look like:

       ```
       |----------------|-------------|------------|-----|-----------------|-----------------|
       |  load_address  | static_base | << (stack) | ... | page_buffers[0] | page_buffers[1] |
       |----------------|-------------|------------|-----|-----------------|-----------------|
       ^                                           ^     ^
       RAM start            begin_stack (grows down)     also begin_data
       ```

       Each of the addresses in the `page_buffers` list points to a buffer of the maximum page
       size of any flash region. If there is not enough RAM to hold two page buffers, then remove
       one of the addresses from the list. This will disable double buffered flash programming.

    5. To enable efficient scanning for modified pages via CRC checking, you can set the
        `analyzer_supported` key to True and the `analyzer_address` to the start address for an
        unused range of (1224 + 4 * number-of-flash-pages) bytes of RAM.

4. Edit `pyocd/target/__init__.py` to import your target source file and add your new target and
    flash classes to the `TARGET` and `FLASH` dicts.

Now your new target is available for use via the `--target` command line option!


### Steps to add a new board

This section only applies if your board has an on-board debug probe that either:

- Uses the [Arm DAPLink](https://github.com/ARMmbed/DAPLink) firmware. DAPLink presents the board ID
    as the first 4 characters of the USB serial number.
- Uses the STLinkV2-1 firmware and the board is Mbed-enabled. STLinkV2-1 presents the board ID
    as the first 4 characters of the code in the HTML file on the USB mass storage volume.

If neither applies, then pyOCD will be unable to automatically detect the board type. However, you
can still use the target.

Follow these steps:

1. Identify the 4-character board ID.

2. Insert a row into the `BOARD_ID_TO_INFO` table in `pyocd/board/board_ids.py` with the board ID,
    board name, target type, and test binary file name.

    The new row should look similar to this:
    ```
        "0205": BoardInfo(  "FRDM-KL28Z",           "kl28z",            "l1_kl28z.bin",         ),
    ```

    Be sure to insert the row in sorted order by board ID.

3. Place a test firmware binary file listed in the board info into the top-level `binaries/`
    directory. The test firmware can be nothing more than an LED blinky demo. It must not require
    any user input, and should provide immediate visual feedback that the code is successfully
    running.
