---
title: Board IDs
---

This page documents the board IDs reported by certain [debug probes]({% link _docs/debug_probes.md %}) with which pyOCD can automatically identify a board and its target type.

## Introduction

Board IDs originally come from Mbed OS and the Mbed Enabled program. (PyOCD was originally an [Arm Mbed](https://mbed.com) project. It is now an independent project and no longer part of Mbed or owned by Arm.)

## Definition

A board ID is a 4-character code that uniquely identifies a board. It also identifies an Mbed platform: the same ID is used for both (which is actually a problem for some use cases).

Board ID definition:
- 4-character code.
  - Board IDs currently are all hex numeric, but it's actually a string.
  - There may be problems raised in some components if you tried to use a non-hex char).
- First 2 characters identify the vendor.
  - There are multiple cases of boards from different vendors being incorrectly allocated in another vendor's namespace, so this cannot solely be relied upon. It's only really useful for grouping of IDs.
- Reserved values::
  - "C0xx" is reserved for "community" boards, i.e. open source hardware and non-commercial projects.
  - "0000" is reserved to mean "no on-board target". That is, the debug probe is standalone must be connected to the target with a cable.

Currently these debug probe firmware support board IDs:
- [DAPLink](https://daplink.io/), via the first 4 chars of the USB serial number
- STLinkV2-1 and V3, via an `.htm` file on the associated USB mass storage volume.

## Lists

The `BOARD_ID_TO_INFO` dict in pyOCD's [`board_ids.py`](https://github.com/pyocd/pyOCD/blob/main/pyocd/board/board_ids.py) source file contains a list of board IDs known to pyOCD, with some extra data such as target type and test firmware file name. This is not a comprehensive list of board IDs, however.

You can see the full list of public Mbed platforms at [https://os.mbed.com/api/v3/platforms/](https://os.mbed.com/api/v3/platforms/). The `productcode` key is the board ID. This list only reports boards that are Mbed platforms. Any non-Mbed-enabled boards with an allocated board ID are marked as hidden (because this database is also used to generate the [Mbed platforms](https://os.mbed.com/platforms/) web site), and thus will not be visible through this API. Be aware that the page take a _long_ time to fully load. A tool like `curl` may be used to download the page as JSON instead.

## Getting a new ID

To request a new board ID, fill out the form here: [https://os.mbed.com/request-board-id](https://os.mbed.com/request-board-id)

## Moving forward

Version 2.1 of the [CMSIS-DAP](https://arm-software.github.io/CMSIS_5/DAP/html/index.html) specification adds support for new [DAP_Info](https://arm-software.github.io/CMSIS_5/DAP/html/group__DAP__Info.html) selectors that identify the board and target. The values returned by these selectors are required to match board and target identifiers in CMSIS-Packs.

PyOCD supports the new CMSIS-DAP v2.1 info selectors and will use them in preference to a board ID if available. This works with any debug probe firmware compatible with CMSIS-DAP. Thus, any new CMSIS-DAP firmware projects should support v2.1 and the new DAP_Info selectors rather than implementing board IDs.
