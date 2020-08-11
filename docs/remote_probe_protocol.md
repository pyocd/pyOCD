Remote Probe Protocol
=====================

PyOCD provides a server and client for sharing and accessing debug probes across a TCP/IP
network connection. This document describes the protocol design, available commands, and semantics.

Protocol
--------

The protocol is very simple. Each request from the client is a single line comprised of the
request encoded as JSON and followed by a single LF character (0x0A). The response from the server
is the same format, with a JSON encoded reply plus LF.

A unique request ID is sent with every request. The response includes the ID of the request to
which it belongs.

All requests are sent by the client. (A notification system from server to client may be added.)

### Request structure

```
{
  "id": <int>,
  "request": <str>,
  "arguments": [
  ]
}
```

The `arguments` key is a list of any arguments for the command. It may be elided if there are no
arguments required.

### Response structure

```
{
  "id": <int>,
  "status": <int>,
  ["error": <str>,]
  ["result": <value>]
}
```

A successful response must have a `status` value of 0. A non-zero `status` indicates that an error
occurred, and must be accompanied by an `error` key with an error message (may be the empty string).
If the response is successful, then a `result` key may be included with the return value of the
command. If there is no return value, then `result` is excluded.

Commands
--------

The commands in the table below correspond directly to the methods of `DebugProbe`.


Command                  | Arguments                                          | Result
-------------------------|----------------------------------------------------|----------------
`hello`                  | version:int                                        |
`readprop`               |                                                    |
`open`                   |                                                    |
`close`                  |                                                    |
`lock`                   |                                                    |
`unlock`                 |                                                    |
`connect`                | protocol:str                                       |
`disconnect`             |                                                    |
`swj_sequence`           | length:int, bits:int                               |
`set_clock`              | freq:int                                           |
`reset`                  |                                                    |
`assert_reset`           | asserted:bool                                      |
`is_reset_asserted`      |                                                    |
`flush`                  |                                                    |
`read_dp`                | addr:int                                           | int
`write_dp`               | addr:int, data:int                                 |
`read_ap`                | addr:int                                           | int
`write_ap`               | addr:int, data:int                                 |
`read_ap_multiple`       | addr:int, count:int                                | List[int]
`write_ap_multiple`      | addr:int, data:List[int]                           |
`swo_start`              | baudrate:int                                       |
`swo_stop`               |                                                    |
`swo_read`               |                                                    | List[int]
`get_memory_interface_for_ap` | ap_address_version:int, ap_nominal_address:int | Option[int]
`read_mem`               | handle:int, addr:int, xfer_size:int                | int
`write_mem`              | handle:int, addr:int, value:int, xfer_size:int     |
`read_block32`           | handle:int, addr:int, word_count:int               | List[int]
`write_block32`          | handle:int, addr:int, data:List[int]               |
`read_block8`            | handle:int, addr:int, word_count:int               | List[int]
`write_block8`           | handle:int, addr:int, data:List[int]               |


Semantics
---------

The `hello` command includes the version of the remote probe protocol supported by the client. The
server will return an error if this version doesn't match the version of the protocol supported by
the server.

Multiple clients may connect to a single remote probe. The server manages the requests to ensure
that the underlying probe is only opened and connected once. The first client to connect a probe
gets to choose the wire protocol (e.g., SWD or JTAG); subsequent connect are effectively ignored.
Counts of clients who have opened and connected the probe are maintained so it is disconnected
and closed when the last client disconnects and closes.


