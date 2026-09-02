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

from ....core.options import OptionInfo, add_option_set

# HPMicro vendor-specific session options. Registered here (not in common
# options.py) to keep vendor details out of the common namespace. The import
# chain (pyocd -> target -> builtin -> hpmicro) runs at import time,
# before command-line -O options are parsed, so -O hpmicro.* does not warn.
add_option_set([
    OptionInfo('hpmicro.algo_type', str, None,
        "Flash algo selection override: 'custom' (pyOCD builtin blob) or 'flm' (FLM loader). "
        "Overrides the target's hardcoded algo_type at runtime (-O hpmicro.algo_type=flm)."),
    OptionInfo('hpmicro.nor_config_opt0', int, None,
        "Override NOR config option[0] for add_xpi_flash (board revision flash pin group etc)."),
    OptionInfo('hpmicro.nor_config_opt1', int, None,
        "Override NOR config option[1] for add_xpi_flash."),
])
