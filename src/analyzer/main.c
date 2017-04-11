/*
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2015 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#include<stdint.h>

typedef struct {
    uint16_t size;
    uint16_t addr;
} sector_info_t;

static uint32_t crc32_tab[256];

static uint32_t crc32(uint32_t crc, const void *buf, uint32_t size) {
	const uint8_t *p;

	p = buf;
	crc = crc ^ ~0U;

	while (size--) {
		crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    }

	return crc ^ ~0U;
}

static void fill_table(void) {
    int i;
    uint32_t byte, crc, mask;
    for (byte = 0; byte <= 255; byte++) {
        crc = byte;
        for (i = 7; i >= 0; i--) {    // Do eight times.
            mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
        crc32_tab[byte] = crc;
    }
}

int compute_crc(void * data, uint32_t num) {
    sector_info_t * sectors = data;
    uint32_t * crcs = data;
    uint32_t i;
    uint32_t crc;
    uint32_t addr;
    uint32_t size;
    fill_table();
    for (i = 0; i < num; i++) {
        size = 1 << sectors[i].size;
        addr = size * sectors[i].addr;
        crc = crc32(0, (void*)addr, size);
        crcs[i] = crc;
    }
    size = 1 << num;
    return 0;
}
