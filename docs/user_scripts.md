User Scripts
============

## Introduction

pyOCD has support for customization through what are called user scripts. These are Python scripts
that are loaded by pyOCD before it connects to the target. A user script can define functions that
are called as hooks at certain points in the connection lifetime, and can extend, modify, or
completely override the default behaviour.

If a file named `pyocd_user.py` or `.pyocd_user.py` is placed in the project directory, pyOCD will
automatically detect it and load it as a user script. If you prefer another name, you can set the
`user_script` option. Another alternative is to provide the filename using the `--script` command
line argument. If a relative path is set either with the option or command line, it will be searched
for in the project directory.

The arguments for hook functions defined in user scripts are the same arguments accepted by delegate
methods. However, all arguments to user script functions are optional. If provided, the argument
names must match the specification. But you can specify arguments in any order, and exclude any or
all arguments if they are not needed. In fact, most arguments are not required because the same
objects are available as script globals, for instance `board` and `target`.


## Examples

This example user script shows how to add a new memory region.

```py
# This example applies to the Nordic nRF52 devices.

def will_connect(board):
    # Create the new ROM region for the FICR.
    ficr = pyocd.core.memory_map.RomRegion(
                                        name="ficr",
                                        start=0x10000000,
                                        length=0x460
                                        )

    # Add the FICR region to the memory map.
    target.memory_map.add_region(ficr)
```

This example shows how to override the flash algorithm for an external flash memory.

```py
# This example applies to the NXP i.MX RT10x0 devices.

# Unlike the previous example, the board argument is excluded here.
def will_connect():
    # Look up the external flash memory region.
    extFlash = target.memory_map.get_region_by_name("flexspi")

    # Set the path to an .FLM flash algorithm.
    extFlash.flm = "MIMXRT105x_QuadSPI_4KB_SEC.FLM"
```

This example demonstrates setting the DBGMCU_CR register on reset for STM32 devices.

```py
# This example applies to the ST STM32L0x1 devicess.

DBG_CR = 0x40015804

def did_reset():
    # Set STANDBY, STOP, and SLEEP bits all to 1.
    target.write32(DBG_CR, 0x7)
```

Another common use for a script is to initialize external memory such as SDRAM.

## Script globals

A number of useful symbols are made available in the global namespace of user scripts. These include
both target related objects, as well as parts of the pyOCD Python API.

| Symbol | Description |
|--------|-------------|
| `aps` | Dictionary of CoreSight Access Port (AP) objects. The keys are the APSEL value. |
| `board` | The `Board` object. |
| `dp` | The CoreSight Debug Port (DP) object. |
| `FileProgrammer` | Utility class to program files to target flash. |
| `FlashEraser` | Utility class to erase target flash. |
| `FlashLoader` | Utility class to program raw binary data to target flash. |
| `LOG` | `Logger` object for the user script. |
| `MemoryType` | Memory region type enumeration. |
| `options` | The user options dictionary. |
| `probe` | The connected debug probe object. |
| `pyocd` | The root pyOCD package. |
| `ResetType` | Reset type enumeration. |
| `session` | The session object, which is the root of the connection object graph. |
| `Target` | Base class, mostly useful for numerous constants that are defined within the class. |
| `target` | The `CoreSightTarget` or subclass instance representing the MCU. |


## Script functions

This section documents all functions that user scripts can provide to modify pyOCD's behaviour.

- `will_connect(board)`<br/>
    Pre-init hook for the board.

    *board* - A `Board` instance that is about to be initialized.<br/>
    **Result** - Ignored.

- `did_connect(board)`<br/>
    Post-initialization hook for the board.

    *board* - A `Board` instance.<br/>
    **Result** - Ignored.

- `will_init_target(target, init_sequence)`<br/>
    Hook to review and modify init call sequence prior to execution.

    *target* - A `CoreSightTarget` object about to be initialized.<br/>
    *init_sequence* - The `CallSequence` that will be invoked. Because call sequences are
        mutable, this parameter can be modified before return to change the init calls.<br/>
    **Result** - Ignored.

- `did_init_target(target)`<br/>
    Post-initialization hook.

    *target* - Either a `CoreSightTarget` or `CortexM` object.<br/>
    **Result** - Ignored.

- `will_start_debug_core(core)`<br/>
    Hook to enable debug for the given core.

    *core* - A `CortexM` object about to be initialized.<br/>
    **Result** - *True* Do not perform the normal procedure to start core debug.
        *False/None* Continue with normal behaviour.

- `did_start_debug_core(core)`<br/>
    Post-initialization hook.

    *core* - A `CortexM` object.<br/>
    **Result** - Ignored.

- `will_stop_debug_core(core)`<br/>
    Pre-cleanup hook for the core.

    *core* - A `CortexM` object.<br/>
    **Result** - *True* Do not perform the normal procedure to disable core debug.
        *False/None* Continue with normal behaviour.

- `did_stop_debug_core(core)`<br/>
    Post-cleanup hook for the core.

    *core* - A `CortexM` object.<br/>
    **Result** - Ignored.

- `will_disconnect(target, resume)`<br/>
    Pre-disconnect hook.

    *target* - Either a `CoreSightTarget` or `CortexM` object.<br/>
    *resume* - The value of the `disconnect_on_resume` option.<br/>
    **Result** - Ignored.

- `did_disconnect(target, resume)`<br/>
    Post-disconnect hook.

    *target* - Either a `CoreSightTarget` or `CortexM` object.<br/>
    *resume* - The value of the `disconnect_on_resume` option.<br/>
    **Result** - Ignored.

- `will_reset(core, reset_type)`<br/>
    Pre-reset hook.

    *core* - A CortexM instance.<br/>
    *reset_type* - One of the `Target.ResetType` enumerations.<br/>
    **Result** - *True* The hook performed the reset. *False/None* Caller should perform the normal
        reset procedure.

- `did_reset(core, reset_type)`<br/>
    Post-reset hook.

    *core* - A CortexM instance.<br/>
    *reset_type* - One of the `Target.ResetType` enumerations.<br/>
    **Result** - Ignored.

- `set_reset_catch(core, reset_type)`<br/>
    Hook to prepare target for halting on reset.

    *core* - A CortexM instance.<br/>
    *reset_type* - One of the `Target.ResetType` enumerations.<br/>
    **Result** - *True* This hook handled setting up reset catch, caller should do nothing.
                *False/None* Perform the default reset catch set using vector catch.

- `clear_reset_catch(core, reset_type)`<br/>
    Hook to clean up target after a reset and halt.

    *core* - A `CortexM` instance.<br/>
    *reset_type* - One of the `Target.ResetType` enumerations.<br/>
    **Result** - Ignored.

- `mass_erase(target)`<br/>
    Hook to override mass erase.

    *target* - A `CoreSightTarget` object.<br/>
    **Result** - *True* Indicate that mass erase was performed by the hook.
                *False/None* Mass erase was not overridden and the caller should proceed with the
                    standard mass erase procedure.

- `trace_start(self, target, mode)`<br/>
    Hook to prepare for tracing the target.

    *target* - A CoreSightTarget object.<br/>
    *mode* - The trace mode. Currently always 0 to indicate SWO.<br/>
    *Result* - Ignored.

- `trace_stop(self, target, mode)`<br/>
    Hook to clean up after tracing the target.

    *target* - A CoreSightTarget object.<br/>
    *mode* - The trace mode. Currently always 0 to indicate SWO.<br/>
    *Result* - Ignored.
