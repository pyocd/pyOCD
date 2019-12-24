Python API Examples
===================


### Hello World example code

This example shows basic connection, loading a firmware binary, and some simple target control.

```python
from pyocd.core.helpers import ConnectHelper
from pyocd.flash.file_programmer import FileProgrammer

import logging
logging.basicConfig(level=logging.INFO)

with ConnectHelper.session_with_chosen_probe() as session:

    board = session.board
    target = board.target
    flash = target.memory_map.get_boot_memory()

    # Load firmware into device.
    FileProgrammer(session).program("my_firmware.bin")

    # Reset, run.
    target.reset_and_halt()
    target.resume()

    # Read some registers.
    print("pc: 0x%X" % target.read_core_register("pc"))

    target.step()
    print("pc: 0x%X" % target.read_core_register("pc"))

    target.resume()
    target.halt()
    print("pc: 0x%X" % target.read_core_register("pc"))

    target.reset_and_halt()

    print("pc: 0x%X" % target.read_core_register("pc"))

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
    target.set_breakpoint(addr)

    # Reset and run.
    target.reset()

    # Wait until breakpoint is hit.
    while target.get_state() != Target.State.HALTED:
        pass

    # Print PC.
    pc = target.read_core_register("pc")
    print("pc: 0x%X" % pc)

    assert pc == addr

    # Remove breakpoint.
    target.remove_breakpoint()
```

