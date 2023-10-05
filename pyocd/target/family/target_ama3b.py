# pyOCD debugger
# Copyright (c) 2023 Northern Mechatronics, Inc.
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

import logging

from ...core import exceptions
from ...coresight.coresight_target import CoreSightTarget
from ...coresight.cortex_m import CortexM

LOG = logging.getLogger(__name__)

class AMA3BFamily(CoreSightTarget):

    VENDOR = "Ambiq"

    def create_init_sequence(self):
        seq = super(AMA3BFamily, self).create_init_sequence()
        seq.wrap_task('discovery',
            lambda seq: seq.replace_task('create_cores', self.create_cores)
            )
        return seq

    def create_cores(self):
        try:
            core = CortexM(self.session, self.aps[0], self.memory_map, 0)
            core.default_reset_type = self.ResetType.SW_SYSRESETREQ
            self.aps[0].core = core
            core.init()
            self.add_core(core)
        except exceptions.Error:
            LOG.error("No Apollo3 were discovered")
