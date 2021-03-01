# pyOCD debugger
# Copyright (c) 2020 Arm Limited
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

import sys
import logging
from shutil import get_terminal_size

LOG = logging.getLogger(__name__)

class ColumnFormatter(object):
    """! @brief Formats a set of values in multiple columns.
    
    The value_list must be a list of bi-tuples (name, value) sorted in the desired display order.
    
    The number of columns will be determined by the terminal width and maximum value width. The values
    will be printed in column major order.
    """
    
    def __init__(self, maxwidth=None, inset=2):
        """! @brief Constructor.
        @param self The object.
        @param maxwidth Number of characters to which the output width must be constrained. If not provided,
            then the width of the stdout terminal is used. If getting the terminal width fails, for instance
            if stdout is not a terminal, then a default of 80 characters is used.
        @param inset Number of characters to inset on each side of every column. Defaults to 2 characters.
        """
        self._inset = inset
        self._term_width = (maxwidth or get_terminal_size()[0]) - inset * 4
        self._items = []
        self._max_name_width = 0
        self._max_value_width = 0
    
    def add_items(self, item_list):
        """! @brief Add items to the output.
        @param self The object.
        @param item_list Must be a list of bi-tuples (name, value) sorted in the desired display order.
        """
        self._items.extend(item_list)
        
        # Update max widths.
        for name, value in item_list:
            self._max_name_width = max(self._max_name_width, len(name))
            self._max_value_width = max(self._max_value_width, len(value))
    
    def format(self):
        """! @brief Return the formatted columns as a string.
        @param self The object.
        @return String containing the output of the column printer.
        """
        item_width = self._max_name_width + self._max_value_width  + self._inset * 2 + 2
        column_count = self._term_width // item_width
        row_count = (len(self._items) + column_count - 1) // column_count
        
        rows = [[i for i in self._items[r::row_count]]
                for r in range(row_count)]

        txt = ""
        for r in rows:
            txt += " " * self._inset
            for i in r:
                txt += "{inset}{name:>{name_width}}: {value:<{value_width}}{inset}".format(
                    name=i[0], name_width=self._max_name_width,
                    value=i[1], value_width=self._max_value_width,
                    inset=(" " * self._inset))
            txt += "\n"
        return txt
    
    def write(self, output_file=None):
        """! @brief Write the formatted columns to stdout or the specified file.
        @param self The object.
        @param output_file Optional file to which the column printer output will be written. If no specified,
            then sys.stdout is used.
        """
        if output_file is None:
            output_file = sys.stdout
        output_file.write(self.format())
        

