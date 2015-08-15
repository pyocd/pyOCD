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

/* Memory regions */
MEMORY
{
  /* Ram configurations are for smallest KL25 in family - 4K */
  m_all        (rwx) : ORIGIN = 0x00000000, LENGTH = 0x600
}

/* Define output sections */
SECTIONS
{

  .text :
  {
    . = ALIGN(4);

    /* Entry point */
    KEEP(*(.text.main))

    *(.text)           /* .text sections (code) */
    *(.text*)          /* .text* sections (code) */

    . = ALIGN(4);
    *(.data)           /* .data sections */
    *(.data*)          /* .data* sections */
    
    . = ALIGN(4);
    *(.bss)
    *(.bss*)
    *(COMMON)
    
    . = ALIGN(4);
    *(.rodata)         /* .rodata sections (constants, strings, etc.) */
    *(.rodata*)        /* .rodata* sections (constants, strings, etc.) */

  } >m_all

}
