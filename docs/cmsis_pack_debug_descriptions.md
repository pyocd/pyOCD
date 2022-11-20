---
title: CMSIS-Pack debug descriptions
---

PyOCD supports [debug descriptions](https://open-cmsis-pack.github.io/Open-CMSIS-Pack-Spec/main/html/coresight_setup.html) from [Open-CMSIS-Pack](https://open-cmsis-pack.github.io/Open-CMSIS-Pack-Spec/main/html/index.html) Device Family Packs (DFPs). See the [target support documentation]({% link _docs/target_support.md %}) for how to install and select target types from DFPs.

There are two main components to DFP debug descriptions:

- XML debug description
- Debug access sequences


## Debug description

A Device Family Pack contains an XML description of the device's debug architecture. In pyOCD, this is used primarily to support debug access sequences. For its own use, pyOCD automatically discovers the device's debug architecture via the Arm CoreSight discovery process (e.g., reading ROM tables) since this is usually more reliable (and also works for devices without debug descriptions).

### Reset types

The debug description can set a target's default reset type and disable certain reset types.

### CPU core names



## Debug access sequence support

Debug access sequences (simply called "debug sequences" below) contain a set of instructions to tell the debugger how to perform different debug related activities such as connect, reset, configuring the device for trace, and so on. Silicon vendors can provide debug sequences for cases where their device has special control requirements or nonstandard behaviours. Many devices do not need debug sequences, and they are entirely optional.

A set of standard debug sequences is defined by the Open-CMSIS-Pack specification to be executed by the debugger when performing certain activities. Some of these standard sequences have pre-defined behaviour performed by the debugger if the DFP does not override that sequence. Others sequences exist only to allow the DFP to insert custom actions.

In addition to the standard debug sequences, a DFP can define its own custom sequences. These can be called like subroutines by other sequences.

Any debug sequence can be customised per CPU core.


### Supported debug sequences

PyOCD supports executing the following standard debug sequences:

Sequence name         | Description
----------------------|------------------------------------------------------
DebugPortSetup        | SWJ-DP switch; reading DPIDR; writing the TARGETSEL
DebugPortStart        | Connect to the target debug port and power it up
DebugPortStop         | Power down and disconnect from target debug port
DebugDeviceUnlock     | Ensure the device is accessible
DebugCoreStart        | Initialize core debug
DebugCoreStop         | Uninitialized core debug
ResetSystem           | System-wide reset without debug domain via software mechanisms
ResetProcessor        | Local processor reset without peripherals and debug domains
ResetHardware         | System-wide reset without debug domain via the dedicated debugger reset line, e.g. nRST.
ResetCatchSet         | Configure the vector catch to stop code execution after the reset
ResetCatchClear       | Free hardware resources allocated by ResetCatchSet
TraceStart            | Enable target trace capture.
TraceStop             | Disable target trace capture.

Standard debug sequences not currently supported:

Sequence name         | Description
----------------------|------------------------------------------------------
DebugCodeMemRemap     | Remap memory to execution location
ResetHardwareAssert   | Assert a system-wide reset via the dedicated debugger reset line, e.g. nRST.
ResetHardwareDeassert | De-assert a system-wide reset via the dedicated debugger reset line, e.g. nRST.
FlashInit             | Flash programming
FlashUninit           | Flash programming
FlashEraseSector      | Flash programming
FlashEraseChip        | Flash programming
FlashEraseDone        | Flash programming
FlashProgramPage      | Flash programming
FlashProgramDone      | Flash programming
RecoverySupportStart  | Before step or run command to support recovery from a lost target connection
RecoverySupportStop   | After step or run command in context of the RecoverySupportStart
RecoveryAcknowledge   | Debugger acknowledge after recovering from a lost target connection.


### Disabling debug sequences

Like any software, DFPs and any contained debug sequences can have bugs. There may also be other cases where disabling a debug sequence is useful. PyOCD can be configured to disable debug sequences either as a whole or individually by using the following session options.

#### `pack.debug_sequences.enable`
This boolean session option globally controls debug sequence support. It defaults to True; setting to False will disable running of all debug sequences defined by the DFP for the chosen target.

#### `pack.debug_sequences.disabled_sequences`

If specific debug sequences need to be disabled, they can be specified with this option. From the command line, the value must be a comma-separated list of sequence names. When set in a YAML config file, the value must be a YAML list of sequence names (instead of a single comma-separated string value).

Disabled sequences can be restricted to a given core by appending a colon and processor name to the sequence's name (e.g., "ResetProcessor:cm4").

Only top-level sequences can be disabled individually. If a debug sequence is called from another sequence it will always be executed even if listed in this option.


### CPU-specific DebugPort sequences

Like all other debug sequences, `DebugPortSetup`, `DebugPortStart`, and `DebugPortStop` can be customised per CPU core. If a DFP has multiple CPU-specific instances of these sequences, they may behave differently in pyOCD than other debuggers. Many debuggers only "connect" to a single CPU chosen by the user when debugging or running a project. PyOCD is somewhat different in that it connects to the device as a whole, and then debugs a chosen core after the connection is established (which more closely reflects the hardware situation).

The `primary_core` session option is used to select the CPU-specific instance of the `DebugPortX` sequences (if needed). If `primary_core` is not set, it will default to the core with the lowest AP (Access Port) number.


### Custom default reset sequences

The DFP specification allows the definition of custom (nonstandard) reset sequences, and these can be selected as the default reset sequence for a core. The purpose of this is to keep the standard sequences unmodified and available for user selection. Because pyOCD does not currently support a custom reset type, this DFP feature is not supported. A custom default reset sequence will be replaced with `ResetSystem` and the custom behaviour not performed.

### .dbgconf

*Write me*

### Debug sequences and user scripts or delegates

*Write me*




