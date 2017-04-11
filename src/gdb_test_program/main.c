/*
 mbed CMSIS-DAP debugger
 Copyright (c) 2015-2015 ARM Limited

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

volatile uint8_t run_breakpoint_test;
volatile uint8_t watchpoint_write;
volatile uint8_t watchpoint_read;
volatile uint8_t watchpoint_size;
void * volatile write_address;

volatile uint32_t watchpoint_write_buffer[3];


void function_1()
{
    
}

void function_2()
{
    
}

void function_3()
{
    
}

void breakpoint_test()
{
    
}

void watchpoint_test()
{
    if (1 == watchpoint_size) {
        if (watchpoint_read) {
            *(volatile uint8_t*) write_address;
        }
        if (watchpoint_write) {
            *(volatile uint8_t*) write_address = 42;
        }
    } else if (2 == watchpoint_size) {
        if (watchpoint_read) {
            *(volatile uint16_t*) write_address;
        }
        if (watchpoint_write) {
            *(volatile uint16_t*) write_address = 42;
        }
    } else if (4 == watchpoint_size) {
        if (watchpoint_read) {
            *(volatile uint32_t*) write_address;
        }
        if (watchpoint_write) {
            *(volatile uint32_t*) write_address = 42;
        }
    }
}

int main()
{
    int i;
    
    // Initialize variables
    run_breakpoint_test = 0;
    watchpoint_write = 0;
    watchpoint_read = 0;
    watchpoint_size = 0;
    write_address = 0;
    for (i = 0; i < sizeof(watchpoint_write_buffer) /
         sizeof(watchpoint_write_buffer[0]); i++) {
        watchpoint_write_buffer[i] = 0;
    }

    while(1) {
        function_1();
        function_2();
        function_3();
        if (run_breakpoint_test) {
            breakpoint_test();
        }
        if (watchpoint_size) {
            watchpoint_test();
        }
    }
}
