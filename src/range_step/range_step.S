// Copyright (c) 2020 Arm Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

            .syntax unified
            .text
            .thumb
            .align 3
            .cfi_sections .debug_frame

            .thumb_func
            .type range_step_test,%function
            .global range_step_test
            .fnstart
            .cfi_startproc
range_step_test:

            // Ridiculously simple (and random) instruction sequence.
            // Importantly, there are no branches.
            adds    r0, #1
            mvns    r1, r0
            adds    r1, #1
            movs    r2, r0, lsl #4
            movs    r3, r2
            eors    r3, r1
            adds    r0, r1
            adds    r0, r2
            subs    r0, r3
            bkpt    #0

            .cfi_endproc
            .cantunwind
            .fnend
            .size range_step_test, . - range_step_test


