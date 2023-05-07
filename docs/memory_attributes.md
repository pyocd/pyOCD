---
title: Memory transfer attributes
---

By default, pyOCD (and most other debuggers) will show the current memory contents regardless of the presence of a data and/or instruction cache. Yet, sometimes it is desirable to view the cache contents in the debugger. That is, to see the CPU's view of memory through the cache. Other memory transfer attributes can also be useful to control is certain, complex debugging scenarios.

## Memory transfer attributes

For Arm devices, the MEM-AP used to perform memory transfers is responsible for specifying what attributes are set when the transfer is performed. The AHB and AXI bus protocol standards define the set of possible transfer attributes. Then, which attributes are actually implemented varies greatly depending on the CPU type and MEM-AP type and variant.

The AHB-AP HPROT bits used with Cortex-M devices are shown here. "HPROT" is the name of the AHB protocol bus that carries the attributes along with the memory transfer request.

  HPROT      | (1) Enabled | (0) Disabled
-------------|-------------|-----------------
  `HPROT[0]` | data access | instr fetch
  `HPROT[1]` | privileged | user
  `HPROT[2]` | bufferable | non bufferable
  `HPROT[3]` | cacheable/modifable | non cacheable
  `HPROT[4]` | lookup in cache | no cache
  `HPROT[5]` | allocate in cache | no allocate in cache
  `HPROT[6]` | shareable | non shareable

Not all bits are implemented on all core/MEM-AP variants; each MEM-AP version implements slightly different sets of these options. For instance, the standard CM3 and CM4 MEM-AP only implements `HPROT[1]` (privileged/user). Check the documentation for your target and CPU(s) to verify available attributes.

AXI-AP attributes are much more complex and are not documented here.

Note that Cortex-M7 and other M-profile cores that use an AXI bus use an AHB-AP as the debugger interface, so the table above still applies. The core converts AHB attributes to AXI attributes internally if the debugger's memory transfer request needs to be sent on the downstream AXI bus.


## Controlling attributes

In pyOCD, the HPROT value for memory transactions is set using the `set hprot <value>` command, and `show hprot` to view the current setting. These modify/view the currently selected MEM-AP (`set/show mem-ap`), which is independent of the gdbserver's core (not something to worry about if you are only debugging core #0).

As a reminder, these commands can be executed from gdb by prefixing them with the gdb `monitor` command. For example, to enable cacheable transfers from gdb, you'd run `monitor set hprot 0xb`. This can be placed in a connect script if you want cacheable transfers all the time.

To configure the used attributes in a pyOCD [user script]({% link _docs/user_scripts.md %}), a snippet such as this is can be used:

```py
def did_connect():
    target.aps[0].hprot = 0xb
```

And if using pyOCD via a Python script, mirror the statement inside `did_connect()` above using your target object.

In the above commands, 0xb == data (hprot[0]) | privileged (hprot[1]) | cacheable (hprot[3]).



