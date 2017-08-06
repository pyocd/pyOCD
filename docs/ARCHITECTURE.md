Architecture
============

## Object graph

The diagram below shows the most interesting parts of the pyOCD object graph, i.e. those parts
that a user of the Python API will interact with.

```
          Session
             |
             |-----> DebugProbe
             |
           Board
             |
       CoreSightTarget
             |
   /---------|-----------\
   |         |           |
 Flash   CortexM[]   DebugPort
             |           |
         MemoryMap  AccessPort[]
```

The root of the object graph is a `Session` object. This object holds references to the debug
probe and the board. It is also responsible for managing per-session user options that control
various features and settings.

Attached to the board is a `CoreSightTarget` instance, which represents an MCU. This owns the
CoreSight related objects for communicating with the DP and APs, the flash programming interface,
and a `CortexM` object for each CPU core on the device. Both `CoreSightTarget` and `CortexM` are
subclasses of the abstract `Target` class, which is referenced below, and share most of the same
APIs.

