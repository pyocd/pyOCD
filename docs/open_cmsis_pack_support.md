---
title: Open-CMSIS-Pack support
---

PyOCD uses device descriptions from [Open-CMSIS-Pack](https://open-cmsis-pack.github.io/Open-CMSIS-Pack-Spec/main/html/index.html) Device Family Packs (DFPs) as a primary method for supporting target types. See the [target support documentation]({% link _docs/target_support.md %}) for how to install and select target types from DFPs.

There are three main components to DFP device descriptions used by pyOCD:

- Memory regions
- Debug description
- Debug access sequences


## Memory regions

A Device Family Pack lists memory regions and contains the algorithms used to program flash memories.

### Flash algorithms

DFPs can specify whether a flash algorithm is default, that is, whether it should be used without user intervention. Some DFPs use the default flag to include more than one flash algorithm for a given memory region, usually multiple part numbers for external memories such as Quad or Octal SPI flash. PyOCD honours this flag, and only loads flash algorithms marked as default. It currently does not have a standard way to list and enable non-default flash algorithms. If required, a [user script]({% link _docs/user_scripts.md %}) can be used to add additional flash algorithms manually extracted from the DFP.

### Limitations

- DFPs can specify a memory region or flash algorithm to apply only to a specific CPU. However, pyOCD currently only supports a single system memory map for all CPUs. This can result in issues if conflicting or overlapping memory regions are defined for more than one CPU.
- PyOCD always runs flash algorithms from the first CPU, even if the DFP says the algorithm should apply to another CPU. On certain devices, this can result in the algorithm failing to run correctly.
- Flash algorithms are handled as a separate list in CMSIS-Packs, while in pyOCD the flash algorithms are associated with flash memory regions. If a DFP defines multiple algorithms with address ranges corresponding to a single region, only the first listed algorithm will be used. (At the time of this writing, there are no known DFPs with such a configuration.)


## Debug description

A Device Family Pack contains a [description](https://open-cmsis-pack.github.io/Open-CMSIS-Pack-Spec/main/html/debug_description.html) of the device's debug architecture. In pyOCD, this is used primarily to support debug access sequences. For its own use, pyOCD automatically discovers the device's debug architecture via the Arm CoreSight discovery process (e.g., reading ROM tables) since this is usually more reliable and also works for devices without debug descriptions.

### Reset types

The debug description can set a target's default reset type and disable certain reset types.


## Debug access sequences

Debug access sequences, simply called "debug sequences" below, contain a set of instructions to tell the debugger how to perform different debug related activities such as connect, reset, configuring the device for trace, and so on. Silicon vendors can provide debug sequences for cases where their device has special control requirements or nonstandard behaviours. Many devices do not need debug sequences, and they are entirely optional.

A set of standard debug sequences is defined by the [Open-CMSIS-Pack](https://open-cmsis-pack.github.io/Open-CMSIS-Pack-Spec) specification to be executed by the debugger when performing certain activities. Some of these standard sequences have pre-defined behaviour performed by the debugger if the DFP does not override that sequence. Others sequences exist only to allow the DFP to insert custom actions.

In addition to the standard debug sequences, a DFP can define its own custom sequences. These can be called like subroutines by other sequences.

Any debug sequence can be customised per CPU core.


### Debug variables

Debug sequences frequently make use of configurable variables called debug variables, or debugvars for short. Depending on the debug sequence, these variables can be modified to change the values written into registers, adjust timeouts, or for other, similar purposes. In other debuggers such as Keil MDK, debugvars are read from a `.dbgconf` file. In pyOCD, this is handled through the `pack.debug_sequences.debugvars` session option described below.

The `pack.debug_sequences.debugvars` session option must be set to a string containing C-style variable assignment statements. C-compatible integer expressions are allowed, and can refer to previously defined variables. Only those debug variables whose value is being changed need to be assigned a value; others will retain their default value. This option is one that you'd normally set in a yaml config file rather than the command line.

All debugvars defined by the CMSIS-Pack and their configured value are logged (at the Info log level) during target connection.

This is an example of output for an ST Microelectronics STM32H750 MCU (target type name `stm32h750ibtx`) from the Keil.STM32H7_DFP pack:

```
0001360 I debugvar 'DbgMCU_APB1L_Fz1' = 0xffffffff (4294967295) [pack_target]
0001360 I debugvar 'DbgMCU_APB2_Fz1' = 0xffffffff (4294967295) [pack_target]
0001360 I debugvar 'DbgMCU_APB3_Fz1' = 0xffffffff (4294967295) [pack_target]
0001360 I debugvar 'DbgMCU_APB4_Fz1' = 0xffffffff (4294967295) [pack_target]
0001361 I debugvar 'DbgMCU_CR' = 0x7 (7) [pack_target]
0001361 I debugvar 'TraceClk_Pin' = 0x40002 (262146) [pack_target]
0001361 I debugvar 'TraceD0_Pin' = 0x40003 (262147) [pack_target]
0001361 I debugvar 'TraceD1_Pin' = 0x40004 (262148) [pack_target]
0001361 I debugvar 'TraceD2_Pin' = 0x40005 (262149) [pack_target]
0001361 I debugvar 'TraceD3_Pin' = 0x40006 (262150) [pack_target]
```

To override some `DBGMCU` register values configured by the above target, this could be added to the `pyocd.yaml` [configuration file]({% link _docs/configuration.md %}):

```yaml
pack.debug_sequences.debugvars: |
  DbgMCU_APB1L_Fz1 = 0xffffffff;
  DbgMCU_APB2_Fz1 = 0xffffffff;
  DbgMCU_APB3_Fz1 = 0xffffffff;
  DbgMCU_APB4_Fz1 = 0xffffffff;
```

If the `pack.debug_sequences.debugvars` session option is modified during a connection, the new debugvar values will be used for any further debug sequence invocations. However, changes to a configuration file on disk will not be reloaded at runtime.


### Disabling debug sequences

Like any software, DFPs and any contained debug sequences can have bugs. There may also be other cases where disabling a debug sequence is useful. PyOCD can be configured to disable debug sequences either as a whole or individually by using the following session options.

#### `pack.debug_sequences.enable`

This boolean session option globally controls debug sequence support. It defaults to True; setting to False will disable running of all debug sequences defined by the DFP for the chosen target.

#### `pack.debug_sequences.disabled_sequences`

If specific debug sequences need to be disabled, they can be specified with this option. From the command line, the value must be a comma-separated list of sequence names. When set in a YAML config file, the value must be a YAML list of sequence names (instead of a single comma-separated string value).

Disabled sequences can be restricted to a given core by appending a colon and processor name to the sequence's name (e.g., "ResetProcessor:cm4").

Only top-level sequences can be disabled individually. If a debug sequence is called from another sequence it will always be executed even if listed in this option.



## PyOCD's debug sequence implementation

This section documents details of the debug sequence engine provided by pyOCD, supported features, and any notable differences with other debuggers (primarily Keil MDK, which provided the first implementation and against which Packs are generally most thoroughly tested by their authors).


### CPU-specific DebugPort sequences

Like all other debug sequences, `DebugPortSetup`, `DebugPortStart`, and `DebugPortStop` can be customised per CPU core. If a DFP has multiple CPU-specific instances of these sequences, they may behave differently in pyOCD than other debuggers. Many debuggers only "connect" to a single CPU chosen by the user when debugging or running a project. PyOCD is somewhat different in that it connects to the device as a whole, and then debugs a chosen core after the connection is established (which more closely reflects the hardware situation).


### Custom default reset sequences

The DFP specification allows the definition of custom (nonstandard) reset sequences, and these can be selected as the default reset sequence for a core. The purpose of this is to keep the standard sequences unmodified and available for user selection. Because pyOCD does not currently support a custom reset type, this DFP feature is not supported. A custom default reset sequence will be replaced with `ResetSystem` and the custom behaviour not performed.


### Debug sequences and delegate functions

Effectively, debug sequences are handled as pre-defined [delegate functions]({% link _docs/user_scripts.md %}#delegate-functions). For most standard debug sequence, there is a corresponding delegate function. This means that a delegate function in a user script (or delegate class, if using the Python API) will override the corresponding debug sequence provided by the target's DFP.


### Supported debug sequences

The following standard debug sequences are supported and will by called by pyOCD. The corresponding delegate function is listed for each.

Sequence name         | Delegate function   | Description
----------------------|---------------------|------------------------------------------------------
`DebugPortSetup`      | -                   | SWJ-DP switch; reading `DPIDR`; writing `TARGETSEL`.
`DebugPortStart`      | -                   | Connect to the target debug port and power it up.
`DebugPortStop`       | -                   | Power down and disconnect from target debug port.
`DebugDeviceUnlock`   | `unlock_device`     | Ensure the device is accessible.
`DebugCoreStart`      | `start_debug_core`  | Initialize core debug.
`DebugCoreStop`       | `stop_debug_core`   | Uninitialized core debug.
`ResetSystem`         | `will_reset`        | System-wide reset without debug domain via software mechanisms.
`ResetProcessor`      | `will_reset`        | Local processor reset without peripherals and debug domains.
`ResetHardware`       | `will_reset`        | System-wide reset without debug domain via the dedicated debugger reset line, e.g. nRST.
`ResetCatchSet`       | `set_reset_catch`   | Configure the vector catch to stop code execution after the reset.
`ResetCatchClear`     | `clear_reset_catch` | Free hardware resources allocated by `ResetCatchSet`.
`TraceStart`          | `trace_start`       | Enable target trace capture.
`TraceStop`           | `trace_stop`        | Disable target trace capture.

Standard debug sequences not currently supported:

Sequence name         | Description
----------------------|------------------------------------------------------
`DebugCodeMemRemap`     | Remap memory to execution location.
`ResetHardwareAssert`   | Assert a system-wide reset via the dedicated debugger reset line, e.g. nRST.
`ResetHardwareDeassert` | De-assert a system-wide reset via the dedicated debugger reset line, e.g. nRST.
`FlashInit`             | Flash programming
`FlashUninit`           | Flash programming
`FlashEraseSector`      | Flash programming
`FlashEraseChip`        | Flash programming
`FlashEraseDone`        | Flash programming
`FlashProgramPage`      | Flash programming
`FlashProgramDone`      | Flash programming
`RecoverySupportStart`  | Before step or run command to support recovery from a lost target connection.
`RecoverySupportStop`   | After step or run command in context of the `RecoverySupportStart`.
`RecoveryAcknowledge`   | Debugger acknowledge after recovering from a lost target connection.




