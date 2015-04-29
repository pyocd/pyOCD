set path=%path%;C:\Program Files (x86)\GNU Tools ARM Embedded\4.9 2014q4\bin
arm-none-eabi-gcc.exe -O3 -ffunction-sections -fdata-sections -Wall -mcpu=cortex-m0 -mthumb -mfloat-abi=soft -g3 -gdwarf-2 -gstrict-dwarf -T"linker_script.ld" -Wl,-Map,main.map,--gc-sections,-ecompute_crc -n -mcpu=cortex-m0 -mthumb -mfloat-abi=soft -g3 -nostdlib -fpic -ffixed-r9 main.c -o main.elf
arm-none-eabi-objcopy.exe --output-target binary main.elf main.bin
python.exe generate_python.py
