Python API Examples
===================


### Hello World example code

This example shows basic connection, loading a firmware binary, and some simple target control.

```python
from pyocd.core.helpers import ConnectHelper

import logging
logging.basicConfig(level=logging.INFO)

with ConnectHelper.session_with_chosen_probe() as session:

    board = session.board
    target = board.target
    flash = board.flash

    # Load firmware into device.
    flash.flashBinary("my_firmware.bin")

    # Reset, run.
    target.resetStopOnReset()
    target.resume()

    # Read some registers.
    print("pc: 0x%X" % target.readCoreRegister("pc"))

    target.step()
    print("pc: 0x%X" % target.readCoreRegister("pc"))

    target.resume()
    target.halt()
    print("pc: 0x%X" % target.readCoreRegister("pc"))

    flash.flashBinary("binaries/l1_lpc1768.bin")
    print("pc: 0x%X" % target.readCoreRegister("pc"))

    target.resetStopOnReset()

    print("pc: 0x%X" % target.readCoreRegister("pc"))

```

### ELF files and breakpoints

Expanding on the above example, this code demonstrates reading a symbol address from an ELF file
and setting a breakpoint. Then the target is reset and run until the breakpoint is hit.

```python
    from pyocd.core.target import Target
    from pyocd.debug.elf.symbols import ELFSymbolProvider

    # Set ELF file on target.
    target.elf = "my_firmware.elf"

    # Look up address of main().
    provider = ELFSymbolProvider(target.elf)
    addr = provider.get_symbol_value("main")
    print("main() address: 0x%X" % addr)

    # Set breakpoint.
    target.setBreakpoint(addr)

    # Reset and run.
    target.reset()

    # Wait until breakpoint is hit.
    while target.getState() != Target.TARGET_HALTED:
        pass

    # Print PC.
    pc = target.readCoreRegister("pc")
    print("pc: 0x%X" % pc)

    assert pc == addr

    # Remove breakpoint.
    target.removeBreakpoint()
```

