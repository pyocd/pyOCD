# pyOCD debugger
# Copyright (c) 2022 Chris Reed
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

from ...core.target import Target

## Map from DFP reset sequence names to our reset types.
RESET_SEQUENCE_TO_TYPE_MAP = {
    'ResetHardware':    Target.ResetType.HW,
    'ResetSystem':      Target.ResetType.SW_SYSTEM,
    'ResetProcessor':   Target.ResetType.SW_CORE,
}

## Map from DFP reset sequence names to our reset types.
#
# ResetType.SW is expected to have been mapped to its actual value before using this map.
# ResetType.SW_EMULATED doesn't have a corresponding reset sequence, so it must be handled
# in another way.
RESET_TYPE_TO_SEQUENCE_MAP = {
    Target.ResetType.HW:        'ResetHardware',
    Target.ResetType.SW_SYSTEM: 'ResetSystem',
    Target.ResetType.SW_CORE:   'ResetProcessor',
}
