# pyOCD debugger
# Copyright (c) 2018 Arm Limited
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

from enum import Enum

## @brief Abstract debug probe class.
class DebugProbe(object):

    ## @brief Debug wire protocols.
    class Protocol(Enum):
        DEFAULT = 0
        SWD = 1
        JTAG = 2
    
    @classmethod
    def get_all_connected_probes(cls):
        raise NotImplementedError()
    
    @classmethod
    def get_probe_with_id(cls, unique_id):
        raise NotImplementedError()
    
    @property
    def description(self):
        return self.vendor_name + " " + self.product_name
    
    @property
    def vendor_name(self):
        raise NotImplementedError()
    
    @property
    def product_name(self):
        raise NotImplementedError()
    
    @property
    def supported_wire_protocols(self):
        raise NotImplementedError()

    ## @brief The unique ID of this device.
    #
    # This property will be valid before open() is called. This value can be passed to
    # get_probe_with_id().
    @property
    def unique_id(self):
        raise NotImplementedError()

    ## @brief Currently selected wire protocol.
    #
    # If the probe is not connected, i.e., connect() has not been called, then this
    # property will be None.
    @property
    def wire_protocol(self):
        raise NotImplementedError()
    
    @property
    def is_open(self):
        raise NotImplementedError()

    ## @brief Create a board instance representing the board of which the probe is a component.
    #
    # If the probe is part of a board, then this property will be a Board instance that represents
    # the associated board. Usually, for an on-board debug probe, this would be the Board that
    # the probe physically is part of. If the probe does not have an associated board, then this
    # method returns None.
    #
    # @param session Session to pass to the board upon construction.
    def create_associated_board(self, session):
        return None

    def open(self):
        raise NotImplementedError()
    
    def close(self):
        raise NotImplementedError()

    # ------------------------------------------- #
    #          Target control functions
    # ------------------------------------------- #
    def connect(self, protocol=None):
        """Initailize DAP IO pins for JTAG or SWD"""
        raise NotImplementedError()

    def disconnect(self):
        """Deinitialize the DAP I/O pins"""
        raise NotImplementedError()

    def set_clock(self, frequency):
        """Set the frequency for JTAG and SWD in Hz

        This function is safe to call before connect is called.
        """
        raise NotImplementedError()

    def reset(self):
        """Reset the target"""
        raise NotImplementedError()

    def assert_reset(self, asserted):
        """Assert or de-assert target reset line"""
        raise NotImplementedError()
    
    def is_reset_asserted(self):
        """Returns True if the target reset line is asserted or False if de-asserted"""
        raise NotImplementedError()

    def flush(self):
        """Write out all unsent commands"""
        raise NotImplementedError()

    def read_dp(self, addr, now=True):
        raise NotImplementedError()

    def write_dp(self, addr, data):
        raise NotImplementedError()

    def read_ap(self, addr, now=True):
        raise NotImplementedError()

    def write_ap(self, addr, data):
        raise NotImplementedError()

    def read_ap_multiple(self, addr, count=1, now=True):
        raise NotImplementedError()

    def write_ap_multiple(self, addr, values):
        raise NotImplementedError()
    
    def get_memory_interface_for_ap(self, apsel):
        return None
    
    def has_swo(self):
        """! @brief Returns bool indicating whether the link supports SWO."""
        raise NotImplementedError()

    def swo_start(self, baudrate):
        """! @brief Start receiving SWO data at the given baudrate."""
        raise NotImplementedError()

    def swo_stop(self):
        """! @brief Stop receiving SWO data."""
        raise NotImplementedError()

    def swo_read(self):
        """! @brief Read buffered SWO data from the target.
        
        @eturn Bytearray of the received data.
        """
        raise NotImplementedError()
    
    def __repr__(self):
        return "<{}@{:x} {}>".format(self.__class__.__name__, id(self), self.description)
  

