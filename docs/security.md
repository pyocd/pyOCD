# Security and Protection Features

Many targets support some way of disabling JTAG/SWD access or protecting the flash from read-back or write.
In the text below, this is called a "locked" target, though each silicon vendor tends to have their
own terminology for this feature.

## Supported Targets

pyOCD currently supports the security features of these target families:
- NXP Kinetis
- Nordic Semiconductor nRF52 families

Both built-in and CMSIS-Pack based targets from these families support security features.

## Connecting to a locked target

If you attempt to run pyOCD Commander against a locked target, you'll encounter a message like this:

``` bash
(venv) ~/devel/contrib/pyocd$ pyocd commander --target nrf52
0000265:WARNING:target_nRF52:NRF52832 APPROTECT enabled: not automatically unlocking
Exception while initing board: No cores were discovered!
Traceback (most recent call last):
  File "devel/contrib/pyocd/pyocd/tools/pyocd.py", line 769, in connect
    self.session.open(init_board=not self.args.no_init)
  File "devel/contrib/pyocd/pyocd/core/session.py", line 371, in open
    self._board.init()
  File "devel/contrib/pyocd/pyocd/board/board.py", line 83, in init
    self.target.init()
  File "devel/contrib/pyocd/pyocd/core/coresight_target.py", line 164, in init
    seq.invoke()
  File "devel/contrib/pyocd/pyocd/utility/sequencer.py", line 208, in invoke
    resultSequence = call()
  File "devel/contrib/pyocd/pyocd/core/coresight_target.py", line 298, in check_for_cores
    raise exceptions.DebugError("No cores were discovered!")
pyocd.core.exceptions.DebugError: No cores were discovered!
```

pyOCD has noticed that the chip is locked. It attempts routine initialization anyway, but fails to find any cores.

For all other pyOCD commands that connect to the target, pyOCD will, by default, attempt to
automatically unlock the target.

Disabling the security features on supported targets is very straight-forward. It typically requires
performing a mass erase of all device memory. For those pyOCD targets with support for security
features, pyOCD can perform this unlock procedure for you.

***WARNING:** Unlocking a locked device will erase all data on the chip!*

You can add the option `auto_unlock` to your [configuration](/configuration.md):

```bash
(venv) ~/devel/contrib/pyocd$ pyocd commander --target nrf52 -O auto_unlock
0000264:WARNING:target_nRF52:NRF52832 APPROTECT enabled: will try to unlock via mass erase
Connected to NRF52832 [Halted]: I3FSNZOV
>>>
```

Note that the default for `auto_unlock` is True. Only in pyOCD Commander is this default changed,
because of how Commander is intended to be used for low-level interaction and inspection of the
target.

You can also do this interactively with pyOCD Commander:

```
(venv) $ pyocd commander --target nrf52840 -N
>>> initdp
>>> makeap 1
>>> status
Security:       Locked
>>> unlock
>>> status
Security:       Unlocked
>>> reinit
>>> status
Security:       Unlocked
Core 0 status:  Halted
>>>
```

An explanation of some of the commands and options appears below.

## Unsupported targets

If pyOCD doesn't support the security features of your MCU, you can still likely access them with
pyOCD Commander with the `no-init` option. A common pattern is that the security function locks out
the fully-functional AHB-AP, but leaves a second, proprietary AP unlocked. The second AP usually has
very few functions, mostly related to management (reset) or erase/unlock of the chip. Another method
used by some device families is to use only the standard AHB-AP, but when the device is locked the
accessible address range is limited to a small handful of registers.

Starting pyOCD Commander in `--no-init` mode is intended to help in these situations. It intentionally doesn't attempt
to interact with the target on startup. Without initialization, most commands will not work. You'll need to do some
manual initialization.

The usefulness of `--no-init` mode is that it allows Commander to start when initialization would
normally fail due to missing support for the target or security features of the MCU.

### Useful Options

Once you've started Commander `--no-init`, the following commands are most useful.

<dl>
<dt><em>initdp</em></dt>
<dd>Powers on and initializes the on-chip *Debug Port*, allowing Commander to issue commands to the
target</dd>

<dt><em>makeap &lt;ap num&gt;</em></dt>
<dd>Targets have at least one, but sometimes more, *Access Ports*. Access port #0 is usually an AHB-AP that allows
debugging of the target. Access port #1, if it exists, is often proprietary to the vendor and allows
for certain functions to proceed *even if AP #0 is locked*.</dd>

<dt><em>readap &lt;APSEL&gt; &lt;address&gt;</em></dt>
<dd>Read from an AP register</dd>

<dt><em>writeap &lt;APSEL&gt; &lt;address&gt; &lt;value&gt;</em></dt>
<dd>Write to an AP register</dd>

<dt><em>status</em></dt>
<dd>Will show security status for supported targets. If the target is unlocked and the AHB-AP is
initialized, it will also show status for any cores detected (Running, Halted, &c)</dd>

<dt><em>reinit</em></dt>
<dd>This command will attempt to perform the normal initialization steps for the selected target. If you
manually unlock a target, you may want to run `reinit` so that the cores are accessible *without* restarting
Commander in normal mode (without `--no-init`)</dd>
</dl>

### Example

Let's pretend the nRF52 family is unsupported. Here's an example session where we'll use `no-init` mode to manually
unlock the target:

```
(venv) nock@nocko-wired:~/devel/contrib/pyocd$ pyocd commander -N
0000136:WARNING:board:Generic 'cortex_m' target type is selected; is this intentional? You will be able to debug but not program flash. To set the target type use the '--target' argument or 'target_override' option. Use 'pyocd list --targets' to see available targets types.
>>> initdp
```
We use `initdp` to initialize the *Debug Port* and power on the on-chip debug hardware.

The [nRF52 Product Specification](https://infocenter.nordicsemi.com/pdf/nRF52832_PS_v1.1.pdf) says that the chip has a
proprietary *CTRL-AP* at index 1 that supports a few operations even if the main AP is locked.

Let's let pyOCD know about it with `makeap`:

```
>>> makeap 1
AP#1 IDR = 0x02880000
```

The IDR register matches the datasheet! The datasheet says that CTRL-AP (AP #1) has the following registers:

<dl>
<dt><em>RESET</em> (0x000)</dt>
<dd>Writing 1 to this register asserts reset on the chip. Writing 0 takes is out of reset</dd>

<dt><em>ERASEALL</em> (0x004)</dt>
<dd>Writing 1 to this register starts a mass erase of the chip <i>and removes APPROTECT</i> unlocking the chip</dd>

<dt><em>ERASEALLSTATUS</em> (0x008)</dt>
<dd>While the chip is busy doing a mass erase, this register will read 1. When the mass erase is complete, the register
will read 0.</dd>

<dt><em>APPROTECTSTATUS</em> (0x00C)</dt>
<dd>If this register is 0, then APPROTECT is enabled (chip is locked), if 1 the chip is unlocked</dd>
</dl>

We can read the register value with `readap` and write a new value with `writeap`. Let's see if the chip is locked by
reading *APPROTECTSTATUS* on AP #1:

```
>>> readap 1 0x00C
AP register 0x100000c = 0x00000000
```

This chip is locked! Let's unlock it. We need to write a 1 to *ERASEALL* (on AP #1) to start the mass erase:

```
>>> writeap 1 0x004 1
```

Let's see if it has finished, by reading *ERASEALLSTATUS*:

```
>>> readap 1 0x008
AP register 0x1000008 = 0x00000001
>>> readap 1 0x008
AP register 0x1000008 = 0x00000000
```

After the first `readap` it was still erasing, but by the time the second `readap` was issued it was complete.
Let's check the security status by reading *APPROTECTSTATUS* again:

```
>>> readap 1 0x00C
AP register 0x100000c = 0x00000001
```

It's unlocked! Let's check the `status`:

```
>>> status
Security:       Unlocked
>>> reinit
>>> status
Security:       Unlocked
Core 0 status:  Halted
>>>
```

The security was unlocked, but there are no cores (many commands like halt, reset, and so on need a core). It doesn't exist
since we started Commander in `no-init` mode. Running `reinit` from the CLI finishes the initialization that's
possible now that the chip is unlocked.
