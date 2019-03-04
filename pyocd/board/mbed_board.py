# pyOCD debugger
# Copyright (c) 2006-2019 Arm Limited
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

from .board import Board
from .board_ids import BOARD_ID_TO_INFO
import logging

LOG = logging.getLogger(__name__)

class MbedBoard(Board):
    """! @brief Mbed board class.
    
    This class inherits from Board and is specific to mbed boards. Particularly, this class
    will dynamically determine the type of connected board based on the board ID encoded in
    the debug probe's serial number.
    """
    def __init__(self, session, target=None):
        """! @brief Constructor.
        
        This constructor attempts to use the board ID from the serial number to determine
        the target type. See #BOARD_ID_TO_INFO.
        """
        target = session.options.get('target_override', target)
        unique_id = session.probe.unique_id
        try:
            board_id = unique_id[0:4]
            board_info = BOARD_ID_TO_INFO[board_id]
            self._name = board_info.name
            self.native_target = board_info.target
        except KeyError:
            board_info = None
            self._name = "Unknown Board"
            self.native_target = None

        # Unless overridden use the native target
        if target is None:
            target = self.native_target

        if target is None:
            LOG.warning("Board ID %s is not recognized; you will be able to use pyOCD but not program flash.", board_id)
            target = "cortex_m"

        super(MbedBoard, self).__init__(session, target)

        # Set test binary if not already set.
        if (board_info is not None) and (self._test_binary is None):
            self._test_binary = board_info.binary

    @property
    def name(self):
        """! @brief Return board name."""
        return self._name

    @property
    def description(self):
        """! @brief Return description of the board."""
        return self.name + " [" + self.target_type + "]"

