#!/bin/bash

# Run through all pyocd-tool commands.
pyocd-tool -tcortex_m -dinfo <<EOF
help
clock 1000
disasm 0x410 16
reset -h
disasm -c pc 16
go
halt
show target
show cores
show map
show uid
show peripherals
log debug
read 0 16
read16 0 16
read32 0 16
reg
reset
reset -h
pc
step
pc
step
pc
write 0x20000000 0xaa
read 0x20000000 1
write16 0x20000000 0xabcd
read16 0x20000000 2
write32 0x20000000 0x01020304
read32 0x20000000 4
wreg r0 0xabcd1234
r0
reset -h
show cores
reg
EOF

