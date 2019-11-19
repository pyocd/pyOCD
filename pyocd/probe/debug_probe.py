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

class DebugProbe(object):
    """! @brief Abstract debug probe class."""

    class Protocol(Enum):
        """! @brief Debug wire protocols."""
        DEFAULT = 0
        SWD = 1
        JTAG = 2
    
    @classmethod
    def get_all_connected_probes(cls):
        """! @brief Returns a list of DebugProbe instances."""
        raise NotImplementedError()
    
    @classmethod
    def get_probe_with_id(cls, unique_id):
        """! @brief Returns a DebugProbe instance for a probe with the given unique ID.
        
        If no probe is connected with a matching unique ID, then None will be returned.
        """
        raise NotImplementedError()

    def __init__(self):
        """! @brief Constructor."""
        self._session = None

    @property
    def session(self):
        """! @brief Session associated with this probe."""
        return self._session
    
    @session.setter
    def session(self, the_session):
        self._session = the_session
    
    @property
    def description(self):
        """! @brief Combined description of the debug probe and/or associated board."""
        return self.vendor_name + " " + self.product_name
    
    @property
    def vendor_name(self):
        """! @brief Name of the debug probe's manufacturer."""
        raise NotImplementedError()
    
    @property
    def product_name(self):
        """! @brief Name of the debug probe."""
        raise NotImplementedError()
    
    @property
    def supported_wire_protocols(self):
        """! @brief List of DebugProbe.Protocol supported by the probe.
        
        Only one of the values returned from this property may be passed to connect().
        """
        raise NotImplementedError()

    @property
    def unique_id(self):
        """! @brief The unique ID of this device.
        
        This property will be valid before open() is called. This value can be passed to
        get_probe_with_id().
        """
        raise NotImplementedError()

    @property
    def wire_protocol(self):
        """! @brief Currently selected wire protocol.
        
        If the probe is not open and connected, i.e., open() and connect() have not been called,
        then this property will be None.
        """
        raise NotImplementedError()
    
    @property
    def is_open(self):
        """! @brief Whether the probe is currently open.
        
        To open the probe, call the open() method.
        """
        raise NotImplementedError()
    
    @property
    def supports_swj_sequence(self):
        """! @brief Whether the probe supports the swj_sequence() API.
        
        If this property is True, then the swj_sequence() method is used to move between protocols.
        If False, it is assumed the probe firmware automatically manages the protocol switch.
        """
        raise NotImplementedError()

    def create_associated_board(self):
        """! @brief Create a board instance representing the board of which the probe is a component.
        
        If the probe is part of a board, then this method will create a Board instance that
        represents the associated board. Usually, for an on-board debug probe, this would be the
        Board that the probe physically is part of, and will also set the target type. If the probe
        does not have an associated board, then this method returns None.
        
        @param self
        @param session Session to pass to the board upon construction.
        """
        return None

    def open(self):
        """! @brief Open the USB interface to the probe for sending commands."""
        raise NotImplementedError()
    
    def close(self):
        """! @brief Close the probe's USB interface."""
        raise NotImplementedError()

    ## @name Target control
    ##@{

    def connect(self, protocol=None):
        """! @brief Initialize DAP IO pins for JTAG or SWD"""
        raise NotImplementedError()

    def disconnect(self):
        """! @brief Deinitialize the DAP I/O pins"""
        raise NotImplementedError()

    def swj_sequence(self, length, bits):
        """! @brief Transfer some number of bits on SWDIO/TMS.
        
        @param self
        @param length Number of bits to transfer. Must be less than or equal to 256.
        @param bits Integer of the bit values to send on SWDIO/TMS. The LSB is transmitted first.
        """
        pass

    def set_clock(self, frequency):
        """! @brief Set the frequency for JTAG and SWD in Hz.

        This function is safe to call before connect is called.
        """
        raise NotImplementedError()

    def reset(self):
        """! @brief Perform a hardware reset of the target."""
        raise NotImplementedError()

    def assert_reset(self, asserted):
        """! @brief Assert or de-assert target's nRESET signal.
        
        Because nRESET is negative logic and usually open drain, passing True will drive it low, and
        pasing False will stop driving so nRESET will be pulled up.
        """
        raise NotImplementedError()
    
    def is_reset_asserted(self):
        """! @brief Returns True if nRESET is asserted or False if de-asserted.
        
        If the debug probe cannot actively read the reset signal, the value returned will be the
        last value passed to assert_reset().
        """
        raise NotImplementedError()

    def flush(self):
        """! @brief Write out all unsent commands.
        
        This API may be a no-op for certain debug probe types.
        """
        raise NotImplementedError()

    ##@}

    ## @name DAP access
    ##@{

    def read_dp(self, addr, now=True):
        """! @brief Read a DP register.
        
        @param self
        @param addr Integer register address being one of (0x0, 0x4, 0x8, 0xC).
        @param now Boolean specifying whether the read is synchronous (True) or asynchronous.
        @return If _now_ is True, the register's 32-bit value is returned as an integer. When _now_
            is False, a callable is returned that when invoked will return the register's value.
        """
        raise NotImplementedError()

    def write_dp(self, addr, data):
        """! @brief Write a DP register.
        
        @param self
        @param addr Integer register address being one of (0x0, 0x4, 0x8, 0xC).
        @param data Integer register value.
        """
        raise NotImplementedError()

    def read_ap(self, addr, now=True):
        """! @brief Read an AP register."""
        raise NotImplementedError()

    def write_ap(self, addr, data):
        """! @brief Write an AP register."""
        raise NotImplementedError()

    def read_ap_multiple(self, addr, count=1, now=True):
        """! @brief Read one AP register multiple times."""
        raise NotImplementedError()

    def write_ap_multiple(self, addr, values):
        """! @brief Write one AP register multiple times."""
        raise NotImplementedError()
    
    def get_memory_interface_for_ap(self, apsel):
        """! @brief Returns a @ref pyocd.core.memory_interface.MemoryInterface "MemoryInterface" for
            the specified AP.
        
        Some debug probe types have accelerated memory read and write commands. This method is used
        to get a concrete @ref pyocd.core.memory_interface.MemoryInterface "MemoryInterface"
        instance that is specific to the AP identified by the _apsel_ parameter. If the probe does
        not provide an accelerated memory interface, None will be returned.
        """
        return None
    
    ##@}

    ## @name SWO
    ##@{

    def has_swo(self):
        """! @brief Returns bool indicating whether the probe supports SWO."""
        raise NotImplementedError()

    def swo_start(self, baudrate):
        """! @brief Start receiving SWO data at the given baudrate.
        
        Once SWO reception has started, the swo_read() method must be called at regular intervals
        to receive SWO data. If this is not done, the probe's internal SWO data buffer may overflow
        and data will be lost.
        """
        raise NotImplementedError()

    def swo_stop(self):
        """! @brief Stop receiving SWO data."""
        raise NotImplementedError()

    def swo_read(self):
        """! @brief Read buffered SWO data from the target.
        
        @eturn Bytearray of the received data. May be 0 bytes in length if no SWO data is buffered
            at the probe.
        """
        raise NotImplementedError()

    ##@}
    
    def __repr__(self):
        return "<{}@{:x} {}>".format(self.__class__.__name__, id(self), self.description)
  

