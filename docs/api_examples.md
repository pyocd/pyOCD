---
title: Python API examples
---

## Hello World example code

This example shows basic connection, loading a firmware binary, and some simple target control.

```python
#!/usr/bin/env python3
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

    # Reset
    target.reset_and_halt()
    
    # Read some registers.
    print("pc: 0x%X" % target.read_core_register("pc"))

    target.step()
    print("pc: 0x%X" % target.read_core_register("pc"))

    target.resume()
    time.sleep(0.2)
    target.halt()
    print("pc: 0x%X" % target.read_core_register("pc"))

    target.reset_and_halt()

    print("pc: 0x%X" % target.read_core_register("pc"))
```


## ELF files and breakpoints

Expanding on the above example, this code demonstrates reading a symbol address from an ELF file
and setting a breakpoint. Then the target is reset and run until the breakpoint is hit.

```python
#!/usr/bin/env python3
from pyocd.core.helpers import ConnectHelper
from pyocd.core.target import Target
from pyocd.debug.elf.symbols import ELFSymbolProvider

# Connect to the target.
with ConnectHelper.session_with_chosen_probe() as session:
    target = session.target

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

    assert pc == addr & ~0x01                         # mask off LSB

    # Remove breakpoint.
    target.remove_breakpoint()
```

Note that you currently need to manually remove a breakpoint in order to step or run over it.


## Alternative ways to create a session

It's important to understand that the `ConnectHelper.session_with_chosen_probe()` method doesn't
itself open the session for you. Instead, it's using the session object as a context manager that
does this.

Here is an example where the `with` statement is separated from the creation of the session.

```python
# Connect to the target.
session = ConnectHelper.session_with_chosen_probe()

# Manually open the session. When the 'with' statement exits, the session is closed.
with session:
    # ... control the target
```

This example demonstrates complete manual control of session opening and closing.

```python
# Connect to the target.
session = ConnectHelper.session_with_chosen_probe()

# Manually open the session.
session.open()

# ... control the target

# Close the session and connection.
session.close()
```

In reality you might want to put the call to `close()` in a `finally` clause of an exception handler.

The example here shows how the `auto_open` parameter can be used to achieve a combination of the
above approaches. When set to False, the session will _not_ be opened upon entry into a `with`
statement. This allows using a `with` statement to ensure the session is properly closed, but with
manual opening so you could, perhaps, further configure the session before it is opened.

```python
# Here we set auto_open to False, so the 'with' statement won't open the session.
session = ConnectHelper.session_with_chosen_probe(auto_open=False)

# When the 'with' statement exits, the session is closed.
with session:
    # ... modify the session

    # Manually open the session.
    session.open()

    # ... control the target
```

Selecting a probe and configuring the target connection is done as follows:

```python
# Connect to the target with some options.
session = ConnectHelper.session_with_chosen_probe(unique_id = "E6616407E3646B29", options = {"frequency": 4000000, "target_override": "nrf52840"})

with session:
    # ...
```

More options can be found [here](options.md).


## Semihosting

For in-target tests it is sometimes convenient to use semihosting, e.g. write coverage data into the hosts file system.
To execute semihosting requests a `wait_for_halt()` function must be implemented.  If writing the profile data is
explicitly done at end of `main()`, a breakpoint on return is also helpful.  Implementation could be like this:

```python
#!/usr/bin/env python3
from pyocd.core.helpers import ConnectHelper
from pyocd.core.target import Target
from pyocd.debug.elf.symbols import ELFSymbolProvider
from pyocd.flash.file_programmer import FileProgrammer
from pyocd.debug import semihost
import time

import traceback
import logging
logging.basicConfig(level=logging.INFO)


image_name = "profiling.elf"


def wait_for_halt(target, semihost):
    go_on = True
    while go_on:
        state = target.get_state()
        if state == Target.State.HALTED:
            try:
                # Handle semihosting
                go_on = semihost.check_and_handle_semihost_request()
                if go_on:
                    # target was halted due to semihosting request
                    target.resume()
            except Exception as e:
                print("semihost exception/resume------", e)
                print(traceback.format_exc())
                target.resume()
                go_on = True
        else:
            time.sleep(0.01)

    
session = ConnectHelper.session_with_chosen_probe(unique_id = "E6616407E3646B29", options = {"frequency": 4000000, 
                                                                                             "target_override": "nrf52840",
                                                                                             "enable_semihosting": True,
                                                                                             "semihost_use_syscalls": False})

with session:
    target = session.target
    target_context = target.get_target_context()
    semihost_io_handler = semihost.InternalSemihostIOHandler()
    semihost = semihost.SemihostAgent(target_context, io_handler=semihost_io_handler, console=semihost_io_handler)

    # Load firmware into device.
    FileProgrammer(session).program(image_name)
    
    # Set ELF file on target.
    target.elf = image_name
    provider = ELFSymbolProvider(target.elf)
    
    # Look up address of main().
    addr = provider.get_symbol_value("main")
    print("main() address: 0x%X" % addr)

    # Set breakpoint.
    print("set breakpoint to entry of main()")
    target.set_breakpoint(addr)

    target.reset_and_halt()
    print("execute")
    target.resume()

    # Wait until breakpoint is hit.
    wait_for_halt(target, semihost)

    # Print PC.
    pc = target.read_core_register("pc")
    print("  pc: 0x%X" % pc)
    assert pc == addr & ~0x01                    # mask off LSB
    target.remove_breakpoint(addr)

    # set breakpoint to return address and execute til there
    lr = target.read_core_register("lr")
    print("  lr: 0x%X (return address)" % lr)
    print("set breakpoint to return of main()")
    target.set_breakpoint(lr)
    print("execute")
    target.resume()
    wait_for_halt(target, semihost)

    pc = target.read_core_register("pc")
    print("  pc: 0x%X" % pc)
    assert pc == lr & ~0x01                      # mask off LSB
    target.remove_breakpoint(lr)
```
