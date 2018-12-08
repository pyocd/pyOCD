Introduction to pyOCD API
=========================

Using pyOCD's Python API, you have extreme flexibility and precise control, and can do anything
SWD allows, at the expense of more complexity compared to `pyocd commander`. Using pyOCD like this is
particularly useful for situations where other debuggers become ineffective, such as device and
board bringup, or automated testing.

This document assumes familiarity with the Arm CoreSight debug architecture.

See the [architecture](ARCHITECTURE.md) documentation for an overview of the classes and how
they are connected.

## Connecting

pyOCD provides a handful of helper routines that make it very easy to enumerate and connect to
available debug probes. These routines are all available as static methods on the `ConnectHelper`
class in `pyocd.core.helpers`.

`ConnectHelper.session_with_chosen_probe()` is the primary connection helper. This method returns
a single `Session` object, or None. If only a single probe is available, a new session for that
probe is returned immediately. But if there are multiple probes available, then by default, it will
present a simple console UI that lets the user select which probe they want to use. Other options
allow automatically picking the first available probe.

One of the most useful parameters for `session_with_chosen_probe()` is `unique_id`. Pass whole or
part of a probe's unique ID (aka serial number) to programmatically select a specific probe.

User session options may be passed to `session_with_chosen_probe()` in two ways. The `options`
parameter accepts a dictionary of session options. Or, you may pass options as keyword parameters.
The two methods may be combined.


## DP access

The DP is controlled through an instance of the `DebugPort` class (in `pyocd.coresight.dap`). You
get the `DebugPort` object via the 'dp' attribute of the target instance, i.e., `session.board.target.dp`.

The `DebugPort` class has `read_reg(addr)` and `write_reg(addr, data)` methods. 'addr' must be an
integer in the set (0x0, 0x4, 0x8, 0xC).

Example:
```py
x = session.board.target.dp.read_reg(0x4)
session.board.target.dp.write_reg(0x8, 0x1)
```

For completeness, the DebugPort class also has `readDP(addr)`, `writeDP(addr, data)`, `readAP(addr)`, and
`writeAP(addr, data)` methods. They work as described below, except that the `readAP()` and `writeAP()` methods
require the APSEL in the address (i.e., 0x010000fc to read ID of APSEL=1). The AP will automatically be
selected.


## AP access

CoreSight APs are represented with `AccessPort` classes defined in `pyocd.coresight.ap`. These include
the `MEM_AP` subclass and `AHB_AP` subclass of that.

To get the AP objects you can use the 'aps' attribute of the `DebugPort`. This attribute is a dict
with the keys being the APSEL number and values being AccessPort instances. For instance, use
`session.board.target.aps[1]` to get the AP with APSEL=1, assuming it exists (if not, you'll get an
`IndexError` exception).

`AccessPort` also has `read_reg(addr)` and `write_reg(addr, data)` methods. For these methods, `addr` is
an integer of the register offset. Note that you do not need to include the APSEL in the address, and
you do not need to modify the DP's SELECT register prior to accessing AP registers. The AP will
automatically be selected in the DP as required.

The `MEM_AP`/`AHB_AP` class has the memory access methods that are available on
the target, but the access is, of course, performed through that specific AP. This is particularly
useful for multicore devices or Cortex-A class devices.

Example showing access of the proprietary MDM-AP of NXP Kinetis MCUs:
```py
mdm_ap = session.board.target.dp.aps[1]
idr = mdm_ap.read_reg(0xfc) # Read IDR.
mdm_ap.write_reg(0x4, 0x1)
```


## Reset control

To control reset, there are several options.

`DebugPort` methods for performing hardware reset:
- `DebugPort.reset()`, asks the debug probe to perform a hardware reset of the target.
- `DebugPort.assert_reset(asserted)` to directly control the nRESET signal. Pass True to drive
  nRESET low, False to drive high.

`Target` methods:
- `Target.reset(software_reset=None)`. Normally performs a software reset unless the optional parameter
  is set to False.
- `Target.resetStopOnReset(software_reset=None)` to perform a halting reset. Again, the reset defaults
  to software but may be set to hardware.

Another option for performing a halting reset is by setting vector catch with the target's `setVectorCatch()`
method, then using a normal reset. This has the benefit of always halting at reset, if you leave the
vector catch enabled.

Example timed reset using the DP:
```
import time

dp = session.board.target.dp

# Timed reset.
dp.assert_reset(True)
time.sleep(1.0)
dp.assert_reset(False)
```


## Notes

NXP Kinetis targets will normally automatically perform a mass erase upon connect if flash security is
enabled. This can be disabled, but requires slightly different connect code.

You are encouraged to look through the code to see what additional functionality is available. The
most interesting places to look at are:

- `pyocd.core.target`: defines Target class, which is the main API.
- `pyocd.coresight.cortex_m`: CortexM class to control a core, implements Target API and adds
some stuff.
- `pyocd.flash.flash`: flash programming API in the `Flash` class, accessible from the 'flash'
attribute on a target (i.e., `session.board.target.flash`).


