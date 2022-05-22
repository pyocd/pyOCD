# pyOCD debugger
# Copyright (c) 2006-2019 Arm Limited
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

import logging
from typing import (Optional, TYPE_CHECKING)

from .board import Board
from .board_ids import (BoardInfo, BOARD_ID_TO_INFO)

if TYPE_CHECKING:
    from ..core.session import Session

LOG = logging.getLogger(__name__)

class MbedBoard(Board):
    """@brief Mbed board class.

    This class used to implement the lookup of board name and other info based on the board ID contained
    in the probe's serial number string. With CMSIS-DAP v2.1 now having support for reporting the board
    and target info, the logic is much more complex and is mostly performed in CMSISDAPProbe. This
    class now simply verifies that the given board_id is known and logs a warning if not.

    If the board ID is all "0" characters, it indicates the firmware is generic and doesn't have an
    associated board.
    """
    def __init__(self,
            session: "Session",
            target: Optional[str] = None,
            board_info: Optional["BoardInfo"] = None,
            board_id: Optional[str] = None,
            ) -> None:
        """@brief Constructor.

        Validates the given board_id, if any.
        """
        # Check for an all-zero board ID. This indicates a standalone probe or generic firmware.
        if board_id == "0000":
            pass
        elif board_id:
            # Attempt to look up the board ID in our table.
            try:
                info_from_table = BOARD_ID_TO_INFO[board_id]
                if not board_info:
                    board_info = info_from_table
            except KeyError:
                LOG.warning("Board ID %s is not recognized", board_id)

                # If we don't have board info, then construct one indicating the board is unknown.
                if not board_info:
                    board_info = BoardInfo("Unknown Board")

        self._board_id = board_id

        super().__init__(session, target, board_info)

    @property
    def board_id(self) -> Optional[str]:
        return self._board_id
