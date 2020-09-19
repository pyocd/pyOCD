---
title: Remote probe access
---

PyOCD provides a server and client for sharing and accessing debug probes across a TCP/IP
network connection. This can be used to provide shared debug access for multiple developers, to
simplify CI configurations, or simply to enable multiple applications or tools to simultaneously
access a probe.

Here are some example use cases for remote probe access.

1. Debug a device that is in your office across a VPN connection from home.

2. Access a device from across the room while using a laptop on your couch.

3. While connected with pyOCD commander, upload new target firmware using the `pyocd flash`
    subcommand.


Server
------

The server side is quite simple. The `pyocd server` subcommand starts the server running for the
specified probe.

The probe is selected via the usual connection-related command line arguments,
such as `--uid`. Also as usual, a console menu will be printed to allow you to choose a probe to
serve if multiple are available and a unique ID is not specified.

The probe server's default port number is 5555. You can change the port by passing the `--port`
argument. The port the server uses will appear in the log when the server starts running.

By default, the server disallows remote connections. That is, other devices on the network are not allowed to connect to
the server. This is fine if you don't need remote access to the server, for example if you are only connecting from
other processes running on the same computer as the server. It's also a secure default.

To allow remote clients to connect, pass the `--allow-remote` argument. Be aware that if the server is exposed on the
Internet, then any other node on the Internet can connect to it, so please take appropriate protective measures. You
may want to ensure that your network's firewall blocks the port being used (default 5555). 

Example command line to start the server and allow remote connections:

```
$ pyocd server --allow-remote
```

This command does not specify a unique ID for a probe, so it will show the console probe selection
menu if there is more than one available.


Client
------

Access to remote probes is available from all pyOCD commands. When using a remote probe, the
behaviour should be exactly as if the probe were being controlled directly. Of course, there may
be additional latency depending on network performance. For localhost-served probes, the connection
is nearly transparent.

The remote probe is selected by specifying a unique ID with a prefix of "remote:", followed by the server IP address or
domain name. The port can be included by appending another colon and the port number. For instance, to connect to a
probe being served on the same computer, pass `--uid=remote:localhost` on the command line. With a custom port, this
would be `--uid=remote:localhost:1234`.

**Important:** Currently you must always specify the target type for the remote device, even in
cases where the target type is automatically detected when you use the probe directly. To do this,
pass the `--target` argument followed by the target type. See [Target support]({% link _docs/target_support.md %})
for more information about target types.

Note that remote probes will not appear in the list when you run `pyocd list --probes`.

Example command line for running the gdbserver locally for a probe on a remote machine:

```
$ pyocd gdbserver -uremote:myserver.example.com
```

