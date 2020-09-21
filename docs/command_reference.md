---
title: Command reference
---
Command reference
=================

PyOCD has a simple command processor that is accessible from the console via the commander subcommand,
or from gdb as remote monitor commands.

The syntax for the commands is straightforward. The command line is first split into individual
commands separated by `;` (semicolon). Each command is then split into words separated by
whitespace. The whitespace characters are space, tab, CR, and LF. Words can be quoted with either a
single or double quote to include whitespace (or quotes) in the word.

Any prefix of a command name is accepted as long as it is unique. If a command prefix is entered
that ambiguous because it matches multiple commands, an error will be reported showing the matched
command names. In addition, commonly used commands often have a short alias. The alias takes
precedence even when it is a prefix of multiple other commands.

<!-- Maintainer note: the following is auto-generated. Edit the command INFO source material. -->


All commands
------------

<table>

<tr><th>Command</th><th>Arguments</th><th>Description</th></tr>

<tr><td colspan="3"><b>Breakpoints</b></tr>

<tr><td>
<a href="#break"><tt>break</tt></a>
</td><td>
ADDR
</td><td>
Set a breakpoint address.
</td></tr>

<tr><td>
<a href="#lsbreak"><tt>lsbreak</tt></a>
</td><td>
</td><td>
List breakpoints.
</td></tr>

<tr><td>
<a href="#lswatch"><tt>lswatch</tt></a>
</td><td>
</td><td>
List watchpoints.
</td></tr>

<tr><td>
<a href="#rmbreak"><tt>rmbreak</tt></a>
</td><td>
ADDR
</td><td>
Remove a breakpoint.
</td></tr>

<tr><td>
<a href="#rmwatch"><tt>rmwatch</tt></a>
</td><td>
ADDR
</td><td>
Remove a watchpoint.
</td></tr>

<tr><td>
<a href="#watch"><tt>watch</tt></a>
</td><td>
ADDR [r|w|rw] [1|2|4]
</td><td>
Set a watchpoint address, and optional access type (default rw) and size (4).
</td></tr>

<tr><td colspan="3"><b>Bringup</b></tr>

<tr><td>
<a href="#initdp"><tt>initdp</tt></a>
</td><td>
</td><td>
Init DP and power up debug.
</td></tr>

<tr><td>
<a href="#makeap"><tt>makeap</tt></a>
</td><td>
APSEL
</td><td>
Creates a new AP object for the given APSEL.
</td></tr>

<tr><td>
<a href="#reinit"><tt>reinit</tt></a>
</td><td>
</td><td>
Reinitialize the target object.
</td></tr>

<tr><td colspan="3"><b>Commander</b></tr>

<tr><td>
<a href="#exit"><tt>exit</tt></a>,
<a href="#exit"><tt>quit</tt></a>
</td><td>
</td><td>
Quit pyocd commander.
</td></tr>

<tr><td>
<a href="#list"><tt>list</tt></a>
</td><td>
</td><td>
Show available targets.
</td></tr>

<tr><td colspan="3"><b>Core</b></tr>

<tr><td>
<a href="#continue"><tt>continue</tt></a>,
<a href="#continue"><tt>c</tt></a>,
<a href="#continue"><tt>go</tt></a>,
<a href="#continue"><tt>g</tt></a>
</td><td>
</td><td>
Resume execution of the target.
</td></tr>

<tr><td>
<a href="#core"><tt>core</tt></a>
</td><td>
[NUM]
</td><td>
Select CPU core by number or print selected core.
</td></tr>

<tr><td>
<a href="#halt"><tt>halt</tt></a>,
<a href="#halt"><tt>h</tt></a>
</td><td>
</td><td>
Halt the target.
</td></tr>

<tr><td>
<a href="#step"><tt>step</tt></a>,
<a href="#step"><tt>s</tt></a>
</td><td>
[COUNT]
</td><td>
Step one or more instructions.
</td></tr>

<tr><td colspan="3"><b>Dap</b></tr>

<tr><td>
<a href="#readap"><tt>readap</tt></a>,
<a href="#readap"><tt>rap</tt></a>
</td><td>
[APSEL] ADDR
</td><td>
Read AP register.
</td></tr>

<tr><td>
<a href="#readdp"><tt>readdp</tt></a>,
<a href="#readdp"><tt>rdp</tt></a>
</td><td>
ADDR
</td><td>
Read DP register.
</td></tr>

<tr><td>
<a href="#writeap"><tt>writeap</tt></a>,
<a href="#writeap"><tt>wap</tt></a>
</td><td>
[APSEL] ADDR DATA
</td><td>
Write AP register.
</td></tr>

<tr><td>
<a href="#writedp"><tt>writedp</tt></a>,
<a href="#writedp"><tt>wdp</tt></a>
</td><td>
ADDR DATA
</td><td>
Write DP register.
</td></tr>

<tr><td colspan="3"><b>Device</b></tr>

<tr><td>
<a href="#reset"><tt>reset</tt></a>
</td><td>
[halt|-halt|-h]
</td><td>
Reset the target.
</td></tr>

<tr><td>
<a href="#unlock"><tt>unlock</tt></a>
</td><td>
</td><td>
Unlock security on the target.
</td></tr>

<tr><td colspan="3"><b>General</b></tr>

<tr><td>
<a href="#help"><tt>help</tt></a>,
<a href="#help"><tt>?</tt></a>
</td><td>
[CMD]
</td><td>
Show help for commands.
</td></tr>

<tr><td colspan="3"><b>Memory</b></tr>

<tr><td>
<a href="#compare"><tt>compare</tt></a>,
<a href="#compare"><tt>cmp</tt></a>
</td><td>
ADDR [LEN] FILENAME
</td><td>
Compare a memory range against a binary file.
</td></tr>

<tr><td>
<a href="#disasm"><tt>disasm</tt></a>,
<a href="#disasm"><tt>d</tt></a>
</td><td>
[-c/--center] ADDR [LEN]
</td><td>
Disassemble instructions at an address.
</td></tr>

<tr><td>
<a href="#erase"><tt>erase</tt></a>
</td><td>
[ADDR] [COUNT]
</td><td>
Erase all internal flash or a range of sectors.
</td></tr>

<tr><td>
<a href="#fill"><tt>fill</tt></a>
</td><td>
[SIZE] ADDR LEN PATTERN
</td><td>
Fill a range of memory with a pattern.
</td></tr>

<tr><td>
<a href="#find"><tt>find</tt></a>
</td><td>
ADDR LEN BYTE+
</td><td>
Search for a value in memory within the given address range.
</td></tr>

<tr><td>
<a href="#load"><tt>load</tt></a>
</td><td>
FILENAME [ADDR]
</td><td>
Load a binary, hex, or elf file with optional base address.
</td></tr>

<tr><td>
<a href="#loadmem"><tt>loadmem</tt></a>
</td><td>
ADDR FILENAME
</td><td>
Load a binary file to an address in memory (RAM or flash).
</td></tr>

<tr><td>
<a href="#read16"><tt>read16</tt></a>,
<a href="#read16"><tt>rh</tt></a>
</td><td>
ADDR [LEN]
</td><td>
Read 16-bit halfwords.
</td></tr>

<tr><td>
<a href="#read32"><tt>read32</tt></a>,
<a href="#read32"><tt>rw</tt></a>
</td><td>
ADDR [LEN]
</td><td>
Read 32-bit words.
</td></tr>

<tr><td>
<a href="#read8"><tt>read8</tt></a>,
<a href="#read8"><tt>rb</tt></a>
</td><td>
ADDR [LEN]
</td><td>
Read 8-bit bytes.
</td></tr>

<tr><td>
<a href="#savemem"><tt>savemem</tt></a>
</td><td>
ADDR LEN FILENAME
</td><td>
Save a range of memory to a binary file.
</td></tr>

<tr><td>
<a href="#write16"><tt>write16</tt></a>,
<a href="#write16"><tt>wh</tt></a>
</td><td>
ADDR DATA+
</td><td>
Write 16-bit halfwords to memory.
</td></tr>

<tr><td>
<a href="#write32"><tt>write32</tt></a>,
<a href="#write32"><tt>ww</tt></a>
</td><td>
ADDR DATA+
</td><td>
Write 32-bit words to memory.
</td></tr>

<tr><td>
<a href="#write8"><tt>write8</tt></a>,
<a href="#write8"><tt>wb</tt></a>
</td><td>
ADDR DATA+
</td><td>
Write 8-bit bytes to memory.
</td></tr>

<tr><td colspan="3"><b>Registers</b></tr>

<tr><td>
<a href="#reg"><tt>reg</tt></a>
</td><td>
[-f] [REG]
</td><td>
Print core or peripheral register(s).
</td></tr>

<tr><td>
<a href="#wreg"><tt>wreg</tt></a>
</td><td>
[-r] REG VALUE
</td><td>
Set the value of a core or peripheral register.
</td></tr>

<tr><td colspan="3"><b>Semihosting</b></tr>

<tr><td>
<a href="#arm"><tt>arm</tt></a>
</td><td>
semihosting {enable,disable}
</td><td>
Enable or disable semihosting.
</td></tr>

<tr><td colspan="3"><b>Servers</b></tr>

<tr><td>
<a href="#gdbserver"><tt>gdbserver</tt></a>
</td><td>
{start,stop,status}
</td><td>
Control the gdbserver for the selected core.
</td></tr>

<tr><td>
<a href="#probeserver"><tt>probeserver</tt></a>
</td><td>
{start,stop,status}
</td><td>
Control the debug probe server.
</td></tr>

<tr><td colspan="3"><b>Symbols</b></tr>

<tr><td>
<a href="#symbol"><tt>symbol</tt></a>
</td><td>
NAME
</td><td>
Show a symbol's value.
</td></tr>

<tr><td>
<a href="#where"><tt>where</tt></a>
</td><td>
[ADDR]
</td><td>
Show symbol, file, and line for address.
</td></tr>

<tr><td colspan="3"><b>Target</b></tr>

<tr><td>
<a href="#status"><tt>status</tt></a>,
<a href="#status"><tt>st</tt></a>
</td><td>
</td><td>
Show the target's current state.
</td></tr>

<tr><td colspan="3"><b>Threads</b></tr>

<tr><td>
<a href="#threads"><tt>threads</tt></a>
</td><td>
{flush,enable,disable,status}
</td><td>
Control thread awareness.
</td></tr>

<tr><td colspan="3"><b>Values</b></tr>

<tr><td>
<a href="#set"><tt>set</tt></a>
</td><td>
NAME VALUE
</td><td>
Set a value.
</td></tr>

<tr><td>
<a href="#show"><tt>show</tt></a>
</td><td>
NAME
</td><td>
Display a value.
</td></tr>


</table>


All values
----------

Values represent a setting or piece of information that can be read and/or changed. They are accessed with
the [`show`](#show) and [`set`](#set) commands. The "Access" column of the table below shows whether the
command can be read, written, or both.

<table>

<tr><th>Value</th><th>Access</th><th>Description</th></tr>

<tr><td>
<a href="#cores"><tt>cores</tt></a>
</td><td>
read-only
</td><td>
Information about CPU cores in the target.
</td></tr>

<tr><td>
<a href="#fault"><tt>fault</tt></a>
</td><td>
read-only
</td><td>
Fault status information.
</td></tr>

<tr><td>
<a href="#frequency"><tt>frequency</tt></a>
</td><td>
write-only
</td><td>
Set SWD or JTAG clock frequency in Hertz.
</td></tr>

<tr><td>
<a href="#graph"><tt>graph</tt></a>
</td><td>
read-only
</td><td>
Print the target object graph.
</td></tr>

<tr><td>
<a href="#hnonsec"><tt>hnonsec</tt></a>
</td><td>
read-write
</td><td>
The current HNONSEC value used by the selected MEM-AP.
</td></tr>

<tr><td>
<a href="#hprot"><tt>hprot</tt></a>
</td><td>
read-write
</td><td>
The current HPROT value used by the selected MEM-AP.
</td></tr>

<tr><td>
<a href="#locked"><tt>locked</tt></a>
</td><td>
read-only
</td><td>
Report whether the target is locked.
</td></tr>

<tr><td>
<a href="#log"><tt>log</tt></a>
</td><td>
write-only
</td><td>
Set log level to one of 'debug', 'info', 'warning', 'error', 'critical'.
</td></tr>

<tr><td>
<a href="#map"><tt>map</tt></a>
</td><td>
read-only
</td><td>
Target memory map.
</td></tr>

<tr><td>
<a href="#mem-ap"><tt>mem-ap</tt></a>
</td><td>
read-write
</td><td>
The currently selected MEM-AP used for memory read/write commands.
</td></tr>

<tr><td>
<a href="#nreset"><tt>nreset</tt></a>
</td><td>
read-write
</td><td>
Current nRESET signal state.
</td></tr>

<tr><td>
<a href="#option"><tt>option</tt></a>
</td><td>
read-write
</td><td>
The current value of one or more session options.
</td></tr>

<tr><td>
<a href="#peripherals"><tt>peripherals</tt></a>
</td><td>
read-only
</td><td>
List of target peripheral instances.
</td></tr>

<tr><td>
<a href="#probe-uid"><tt>probe-uid</tt></a>,
<a href="#probe-uid"><tt>uid</tt></a>
</td><td>
read-only
</td><td>
Target's unique ID.
</td></tr>

<tr><td>
<a href="#register-groups"><tt>register-groups</tt></a>
</td><td>
read-only
</td><td>
Display available register groups for the selected core.
</td></tr>

<tr><td>
<a href="#step-into-interrupts"><tt>step-into-interrupts</tt></a>,
<a href="#step-into-interrupts"><tt>si</tt></a>
</td><td>
read-write
</td><td>
Display whether interrupts are enabled when single stepping.
</td></tr>

<tr><td>
<a href="#target"><tt>target</tt></a>
</td><td>
read-only
</td><td>
General target information.
</td></tr>

<tr><td>
<a href="#vector-catch"><tt>vector-catch</tt></a>,
<a href="#vector-catch"><tt>vc</tt></a>
</td><td>
read-write
</td><td>
Show current vector catch settings.
</td></tr>


</table>


Commands
--------

### Breakpoints

##### `break`

**Usage**: ADDR \
Set a breakpoint address.


##### `lsbreak`

**Usage**:  \
List breakpoints.


##### `lswatch`

**Usage**:  \
List watchpoints.


##### `rmbreak`

**Usage**: ADDR \
Remove a breakpoint.


##### `rmwatch`

**Usage**: ADDR \
Remove a watchpoint.


##### `watch`

**Usage**: ADDR [r|w|rw] [1|2|4] \
Set a watchpoint address, and optional access type (default rw) and size (4).


### Bringup
These commands are meant to be used when starting up Commander in no-init mode. They are primarily useful for low-level debugging of debug infrastructure on a new chip.

##### `initdp`

**Usage**:  \
Init DP and power up debug.


##### `makeap`

**Usage**: APSEL \
Creates a new AP object for the given APSEL. The type of AP, MEM-AP or generic, is autodetected.


##### `reinit`

**Usage**:  \
Reinitialize the target object.


### Commander

##### `exit`

**Aliases**: `quit` \
**Usage**:  \
Quit pyocd commander.


##### `list`

**Usage**:  \
Show available targets.


### Core

##### `continue`

**Aliases**: `c`, `go`, `g` \
**Usage**:  \
Resume execution of the target. The target's state is read back after resuming. If the target is not running, then it's state is reported. For instance, if the target is halted immediately after resuming, a debug event such as a breakpoint most likely occurred.


##### `core`

**Usage**: [NUM] \
Select CPU core by number or print selected core.


##### `halt`

**Aliases**: `h` \
**Usage**:  \
Halt the target.


##### `step`

**Aliases**: `s` \
**Usage**: [COUNT] \
Step one or more instructions.


### Dap

##### `readap`

**Aliases**: `rap` \
**Usage**: [APSEL] ADDR \
Read AP register.


##### `readdp`

**Aliases**: `rdp` \
**Usage**: ADDR \
Read DP register.


##### `writeap`

**Aliases**: `wap` \
**Usage**: [APSEL] ADDR DATA \
Write AP register.


##### `writedp`

**Aliases**: `wdp` \
**Usage**: ADDR DATA \
Write DP register.


### Device

##### `reset`

**Usage**: [halt|-halt|-h] \
Reset the target.


##### `unlock`

**Usage**:  \
Unlock security on the target.


### General

##### `help`

**Aliases**: `?` \
**Usage**: [CMD] \
Show help for commands.


### Memory

##### `compare`

**Aliases**: `cmp` \
**Usage**: ADDR [LEN] FILENAME \
Compare a memory range against a binary file. If the length is not provided, then the length of the file is used.


##### `disasm`

**Aliases**: `d` \
**Usage**: [-c/--center] ADDR [LEN] \
Disassemble instructions at an address. Only available if the capstone library is installed. To install capstone, run 'pip install capstone'.


##### `erase`

**Usage**: [ADDR] [COUNT] \
Erase all internal flash or a range of sectors.


##### `fill`

**Usage**: [SIZE] ADDR LEN PATTERN \
Fill a range of memory with a pattern. The optional SIZE parameter must be one of 8, 16, or 32. If not provided, the size is determined by the pattern value's most significant set bit. Only RAM regions may be filled.


##### `find`

**Usage**: ADDR LEN BYTE+ \
Search for a value in memory within the given address range. A pattern of any number of bytes can be searched for. Each BYTE parameter must be an 8-bit value.


##### `load`

**Usage**: FILENAME [ADDR] \
Load a binary, hex, or elf file with optional base address.


##### `loadmem`

**Usage**: ADDR FILENAME \
Load a binary file to an address in memory (RAM or flash). This command is deprecated in favour of the more flexible 'load'.


##### `read16`

**Aliases**: `rh` \
**Usage**: ADDR [LEN] \
Read 16-bit halfwords. Optional length parameter is the number of bytes to read. It must be divisible by 2. If the length is not provided, one halfword is read. The address may be unaligned.


##### `read32`

**Aliases**: `rw` \
**Usage**: ADDR [LEN] \
Read 32-bit words. Optional length parameter is the number of bytes to read. It must be divisible by 4. If the length is not provided, one word is read. The address may be unaligned.


##### `read8`

**Aliases**: `rb` \
**Usage**: ADDR [LEN] \
Read 8-bit bytes. Optional length parameter is the number of bytes to read. If the length is not provided, one byte is read.


##### `savemem`

**Usage**: ADDR LEN FILENAME \
Save a range of memory to a binary file.


##### `write16`

**Aliases**: `wh` \
**Usage**: ADDR DATA+ \
Write 16-bit halfwords to memory. The data arguments are 16-bit halfwords in big-endian format and are written as little-endian. The address may be unaligned. Can write to both RAM and flash. Flash writes are subject to minimum write size and alignment, and the flash page must have been previously erased.


##### `write32`

**Aliases**: `ww` \
**Usage**: ADDR DATA+ \
Write 32-bit words to memory. The data arguments are 32-bit words in big-endian format and are written as little-endian. The address may be unaligned. Can write to both RAM and flash. Flash writes are subject to minimum write size and alignment, and the flash page must have been previously erased.


##### `write8`

**Aliases**: `wb` \
**Usage**: ADDR DATA+ \
Write 8-bit bytes to memory. The data arguments are 8-bit bytes. Can write to both RAM and flash. Flash writes are subject to minimum write size and alignment, and the flash page must have been previously erased.


### Registers

##### `reg`

**Usage**: [-f] [REG] \
Print core or peripheral register(s). If no arguments are provided, all core registers will be printed. Either a core register name, the name of a peripheral, or a peripheral.register can be provided. When a peripheral name is provided without a register, all registers in the peripheral will be printed. If the -f option is passed, then individual fields of peripheral registers will be printed in addition to the full value.


##### `wreg`

**Usage**: [-r] REG VALUE \
Set the value of a core or peripheral register. The REG parameter must be a core register name or a peripheral.register. When a peripheral register is written, if the -r option is passed then it is read back and the updated value printed.


### Semihosting

##### `arm`

**Usage**: semihosting {enable,disable} \
Enable or disable semihosting. Provided for compatibility with OpenOCD. The same functionality can be achieved by setting the 'enable_semihosting' session option.


### Servers

##### `gdbserver`

**Usage**: {start,stop,status} \
Control the gdbserver for the selected core. The action argument should be either 'start', 'stop', or 'status'. Use the 'gdbserver_port' and 'telnet_port' session options to control the ports the gdbserver uses.


##### `probeserver`

**Usage**: {start,stop,status} \
Control the debug probe server. The action argument should be either 'start', 'stop', or 'status. Use the 'probeserver.port' option to control the TCP port the server uses.


### Symbols
These commands require an ELF to be set.

##### `symbol`

**Usage**: NAME \
Show a symbol's value. An ELF file must have been specified with the --elf option.


##### `where`

**Usage**: [ADDR] \
Show symbol, file, and line for address. The symbol name, source file path, and line number are displayed for the specified address. If no address is given then current PC is used. An ELF file must have been specified with the --elf option.


### Target

##### `status`

**Aliases**: `st` \
**Usage**:  \
Show the target's current state.


### Threads

##### `threads`

**Usage**: {flush,enable,disable,status} \
Control thread awareness.


### Values

##### `set`

**Usage**: NAME VALUE \
Set a value.


##### `show`

**Usage**: NAME \
Display a value.

