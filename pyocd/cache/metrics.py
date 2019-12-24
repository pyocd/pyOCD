# pyOCD debugger
# Copyright (c) 2016-2019 Arm Limited
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

class CacheMetrics(object):
    """! @brief Holds hit ratio metrics for the caches."""
    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.reads = 0
        self.writes = 0

    @property
    def total(self):
        return self.hits + self.misses

    @property
    def percent_hit(self):
        if self.total > 0:
            return self.hits * 100.0 / self.total
        else:
            return 0

    @property
    def percent_miss(self):
        if self.total > 0:
            return self.misses * 100.0 / self.total
        else:
            return 0

