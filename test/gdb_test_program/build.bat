arm-none-eabi-gcc.exe -O0 -fno-common -ffunction-sections -fdata-sections -Wall -mcpu=cortex-m0 -mthumb -mfloat-abi=soft -g3 -gdwarf-2 -gstrict-dwarf -T"linker_script.ld" -Wl,-Map,gdb_test.map,--gc-sections,-emain -nostdlib -fpie main.c -o gdb_test.elf
arm-none-eabi-objcopy.exe --output-target binary gdb_test.elf gdb_test.bin
