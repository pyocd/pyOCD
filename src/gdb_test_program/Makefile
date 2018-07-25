# pyOCD debugger
# Copyright (c) 2018 Arm Limited
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

PREFIX = arm-none-eabi-
CC = $(PREFIX)gcc
OBJCOPY = $(PREFIX)objcopy

TARGET = gdb_test.elf
TARGET_BIN = gdb_test.bin

OBJECTS = main.o

LIBRARIES =

INCLUDES =

CFLAGS = -std=gnu11 -MMD -MP $(INCLUDES) -O0 -fno-common -ffunction-sections \
		-fdata-sections -Wall -Werror -mcpu=cortex-m0 -mthumb -mfloat-abi=soft -g3 -gdwarf-2 \
		-gstrict-dwarf -nostdlib -fpie

LDFLAGS = -T"linker_script.ld" -Wl,-Map,gdb_test.map,--gc-sections,-emain  -nostdlib -fpie

.PHONY: all
all: $(TARGET) $(TARGET_BIN)

.PHONY: clean
clean:
# 	@echo "Cleaning output..."
	rm -f *.o *.d $(TARGET) $(TARGET_BIN)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBRARIES) -o $@

$(TARGET_BIN): $(TARGET)
	$(OBJCOPY) -O binary $(TARGET) $(TARGET_BIN)

# Include dependency files.
-include $(OBJECTS:.o=.d)
