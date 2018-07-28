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

TARGET = main.elf
TARGET_BIN = main.bin
TARGET_PY = main.py

OBJECTS = main.o

LIBRARIES =

INCLUDES =

CFLAGS = -std=gnu11 -MMD -MP $(INCLUDES) -O3 -fno-common -ffunction-sections \
		-fdata-sections -Wall -Werror -mcpu=cortex-m0 -mthumb -mfloat-abi=soft -g3 -gdwarf-2 \
		-gstrict-dwarf -nostdlib -fpic -ffixed-r9

LDFLAGS = -T"linker_script.ld" -Wl,-Map,gdb_test.map,--gc-sections,-ecompute_crc \
		-n -nostdlib -fpic -ffixed-r9

.PHONY: all
all: $(TARGET_PY)

.PHONY: clean
clean:
	rm -f *.o *.d $(TARGET) $(TARGET_BIN) $(TARGET_PY)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBRARIES) -o $@

$(TARGET_BIN): $(TARGET)
	$(OBJCOPY) -O binary $(TARGET) $(TARGET_BIN)

$(TARGET_PY): $(TARGET_BIN)
	python generate_python.py $(TARGET_BIN) $(TARGET_PY)

# Include dependency files.
-include $(OBJECTS:.o=.d)
