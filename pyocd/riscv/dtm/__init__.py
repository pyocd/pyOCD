# pyOCD debugger
# Copyright (c) 2026 Ryan QIAN
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

"""
RISC-V Debug Transport Module (DTM) support.

This package provides JTAG-based DTM access for RISC-V debug.
"""

from .jtag_dtm import (
    JtagDtm,
    DtmState,
    DmiOperation,
    DmiOperationStatus,
    DTMCS_ADDRESS,
    DTMCS_WIDTH,
    DMI_ADDRESS,
    DMI_ADDRESS_BIT_OFFSET,
    DMI_VALUE_BIT_OFFSET,
    DMI_OP_MASK,
)

__all__ = [
    'JtagDtm',
    'DtmState',
    'DmiOperation',
    'DmiOperationStatus',
    'DTMCS_ADDRESS',
    'DTMCS_WIDTH',
    'DMI_ADDRESS',
    'DMI_ADDRESS_BIT_OFFSET',
    'DMI_VALUE_BIT_OFFSET',
    'DMI_OP_MASK',
]
