# pyOCD debugger
# Copyright (c) 2020 Arm Limited
# Copyright (c) 2021 Chris Reed
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
from enum import Enum

from .component import CoreSightComponent
from ..core import exceptions
from ..utility.timeout import Timeout

LOG = logging.getLogger(__name__)

class ComPortError(exceptions.Error):
    """! @brief Base class for SDC-600 exceptions."""
    pass

class UnexpectedFlagError(ComPortError):
    """! @brief Received an unexpected or out of order flag byte."""
    pass

class LinkError(ComPortError):
    """! @brief Received a link error flag (LERR)."""
    pass

class LinkClosedException(ComPortError):
    """! @brief Received an unexpected or out of order flag byte."""
    def __init__(self, phase):
        self._phase = phase
    
    @property
    def phase(self):
        """! @brief The link phase that was closed from the other side."""
        return self._phase

class SDC600(CoreSightComponent):
    """! @brief SDC-600 component.
    """
    
    ## Default timeout for an operation or packet transfer.
    TRANSFER_TIMEOUT = 30.0
    
    class LinkPhase(Enum):
        """! @brief COM Port link phases."""
        ## Hardware-defined link phase.
        PHASE1 = 1
        ## Software-defiend link phase.
        PHASE2 = 2
    
    class Register:
        """! @brief Namespace for SDC-600 register offset constants."""
        # Register offsets.
        VIDR        = 0xD00
        FIDTXR      = 0xD08
        FIDRXR      = 0xD0C
        ICSR        = 0xD10
        DR          = 0xD20
        SR          = 0xD2C
        DBR         = 0xD30
        SR_ALIAS    = 0xD3C

        # FIDTXR and FIDRXR bit definitions.
        FIDxXR_xXI_MASK     = (0x00000001)
        FIDxXR_xXI_SHIFT    = (0)
        FIDxXR_xXINT_MASK   = (0x00000002)
        FIDxXR_xXINT_SHIFT  = (1)
        FIDxXR_xXW_MASK     = (0x000000f0)
        FIDxXR_xXW_SHIFT    = (4)
        FIDxXR_xXSZ8_MASK   = (0x00000100)
        FIDxXR_xXSZ8_SHIFT  = (8)
        FIDxXR_xXSZ16_MASK  = (0x00000200)
        FIDxXR_xXSZ16_SHIFT = (9)
        FIDxXR_xXSZ32_MASK  = (0x00000400)
        FIDxXR_xXSZ32_SHIFT = (10)
        FIDxXR_xXFD_MASK    = (0x000f0000)
        FIDxXR_xXFD_SHIFT   = (16)
        
        # SR bit definitions.
        SR_TXS_MASK         = (0x000000ff)
        SR_TXS_SHIFT        = (0)
        SR_RRDIS_MASK       = (0x00001000)
        SR_RRDIS_SHIFT      = (12)
        SR_TXOE_MASK        = (0x00002000)
        SR_TXOE_SHIFT       = (13)
        SR_TXLE_MASK        = (0x00004000)
        SR_TXLE_SHIFT       = (14)
        SR_TRINPROG_MASK    = (0x00008000)
        SR_TRINPROG_SHIFT   = (18)
        SR_RXF_MASK         = (0x00ff0000)
        SR_RXF_SHIFT        = (16)
        SR_RXLE_MASK        = (0x40000000)
        SR_RXLE_SHIFT       = (30)
        SR_PEN_MASK         = (0x80000000)
        SR_PEN_SHIFT        = (31)
    
    class Flag:
        """! @brief Namespace with SDC-600 flag byte constants."""
        IDR     = 0xA0
        IDA     = 0xA1
        LPH1RA  = 0xA6
        LPH1RL  = 0xA7
        LPH2RA  = 0xA8
        LPH2RL  = 0xA9
        LPH2RR  = 0xAA
        LERR    = 0xAB
        START   = 0xAC
        END     = 0xAD
        ESC     = 0xAE
        NULL    = 0xAF
        
        # All bytes with 0b101 in bits [7:5] are flag bytes.
        MASK = 0xE0
        IDENTIFIER = 0b10100000
        
        ## Map from flag value to name.
        NAME = {
            IDR     : "IDR",
            IDA     : "IDA",
            LPH1RA  : "LPH1RA",
            LPH1RL  : "LPH1RL",
            LPH2RA  : "LPH2RA",
            LPH2RL  : "LPH2RL",
            LPH2RR  : "LPH2RR",
            LERR    : "LERR",
            START   : "START",
            END     : "END",
            ESC     : "ESC",
            NULL    : "NULL",
            }
    
    ## NULL bytes must be written to the upper bytes, and will be present in the upper bytes
    # when read.
    NULL_FILL = 0xAFAFAF00
    
    def __init__(self, ap, cmpid=None, addr=None):
        super(SDC600, self).__init__(ap, cmpid, addr)
        self._tx_width = 0
        self._rx_width = 0
        self._current_link_phase = None

    def init(self):
        """! @brief Inits the component.
        
        Reads the RX and TX widths and whether the SDC-600 is enabled. All error flags are cleared.
        """
        fidtx = self.ap.read32(self.Register.FIDTXR)
        LOG.debug("fidtx=0x%08x", fidtx)
        fidrx = self.ap.read32(self.Register.FIDRXR)
        LOG.debug("fidrx=0x%08x", fidrx)
        
        self._tx_width = (fidtx & self.Register.FIDxXR_xXW_MASK) >> self.Register.FIDxXR_xXW_SHIFT
        
        self._rx_width = (fidrx & self.Register.FIDxXR_xXW_MASK) >> self.Register.FIDxXR_xXW_SHIFT
        
        status = self.ap.read32(self.Register.SR)
        LOG.debug("status=0x%08x", status)
        self._is_enabled = (status & self.Register.SR_PEN_MASK) != 0
        
        # Clear any error flags.
        error_flags = status & (self.Register.SR_TXOE_MASK | self.Register.SR_TXLE_MASK)
        if error_flags:
            self.ap.write32(self.Register.SR, error_flags)
    
    @property
    def is_enabled(self):
        """! @brief Whether the SDC-600 is enabled."""
        return self._is_enabled
    
    @property
    def is_reboot_request_enabled(self):
        """! @brief Whether the Reboot Request feature is enabled in the SDC-600."""
        return (self.ap.read32(self.Register.SR) & self.Register.SR_RRDIS_MASK) == 0
    
    @property
    def current_link_phase(self):
        """! @brief Currently established link phase.
        @return Either None or one of the SDC600.LinkPhase enums.
        """
        return self._current_link_phase

    def _read1(self, to_):
        """! @brief Read a single byte.
        
        If a NULL byte is received, it is ignored and another byte is read. No other flag bytes
        are processed.
        
        @exception TimeoutError
        """
        while True:
            # Wait until a byte is ready in the receive FIFO.
            while to_.check():
                if (self.ap.read32(self.Register.SR) & self.Register.SR_RXF_MASK) != 0:
                    break
            else:
                raise exceptions.TimeoutError("timeout while reading from SDC-600")

            # Read the data register and strip off NULL bytes in high bytes.
            value = self.ap.read32(self.Register.DR) & 0xFF

            # Ignore NULL flag bytes.
            if value == self.Flag.NULL:
                continue
            
            return value
        
    def _write1(self, value, to_):
        """! @brief Write one or more bytes.
        @exception TimeoutError
        """
        # Wait until room is available in the transmit FIFO.
        while to_.check():
            if (self.ap.read32(self.Register.SR) & self.Register.SR_TXS_MASK) != 0:
                break
        else:
            raise exceptions.TimeoutError("timeout while writing to SDC-600")

        # Write this byte to the transmit FIFO.
        dbr_value = self.NULL_FILL | (value & 0xFF)
        self.ap.write32(self.Register.DR, dbr_value)

    def _check_flags(self, value, to_):
        """! @brief Handle link and error related flag bytes.
        @param self
        @param value Integer byte value to check.
        @param to_ Timeout object.
        @exception UnexpectedFlagError
        @exception LinkClosedException
        @exception LinkError
        @exception TimeoutError
        """
        if value == self.Flag.LPH1RL:
            LOG.debug("got LPH1RL!")
            self._current_link_phase = None
            raise LinkClosedException(self.LinkPhase.PHASE1)
        elif value == self.Flag.LPH2RL:
            LOG.debug("got LPH2RL!")
            # Target killed the phase 2 connection. Send required reply.
            self._current_link_phase = self.LinkPhase.PHASE1
            self._write1(self.Flag.LPH2RL, to_)
            raise LinkClosedException(self.LinkPhase.PHASE2)
        elif value == self.Flag.LERR:
            LOG.debug("got LERR!")
            raise LinkError()
        # Catch reserved flags.
        elif (0xA2 <= value <= 0xA5) or (0xB0 <= value <= 0xBF):
            raise UnexpectedFlagError("received reserved flag value ({:#04x})".format(value))

    def _expect_flag(self, flag, to_):
        """! @brief Read a byte and compare to expected value.
        @param self
        @param flag Integer flag byte value to match.
        @param to_ Timeout object.
        @exception UnexpectedFlagError
        @exception LinkClosedException
        @exception TimeoutError
        """
        value = self._read1(to_)
        if value != flag:
            # Check certain flags we have to handle. This will raise if a flag is handled.
            self._check_flags(value, to_)
            # _check_flags() did not raise, so we should .
            raise UnexpectedFlagError("got {:#04x} instead of expected {} ({:#04x})".format(
                        value, self.Flag.NAME[flag], flag))
        else:
            LOG.debug("got expected %s", self.Flag.NAME[value])

    def _stuff(self, data):
        """! @brief Perform COM Encapsulation byte stuffing.
        @param self
        @param data List of integers of the original data.
        @return List of integers for the escaped version of _data_.
        """
        result = []
        for value in data:
            # Values matching flag bytes just get copied to output.
            if (value & self.Flag.MASK) == self.Flag.IDENTIFIER:
                # Insert escape flag.
                result.append(self.Flag.ESC)
                
                # Invert high bit.
                value ^= 0x80
            
            result.append(value)
        return result

    def _destuff(self, data):
        """! @brief Remove COM Encapsulation byte stuffing.
        @param self
        @param data List of integers. The only acceptable flag byte is ESC.
        @return List of integers properly de-stuffed.
        """
        result = []
        i = 0
        while i < len(data):
            value = data[i]
            
            # Check for escaped bytes.
            if value == self.Flag.ESC:
                # Skip over escape.
                i += 1
                
                # Get escaped byte and invert high bit to destuff it.
                value = data[i] ^ 0x80
            
            result.append(value)
            
            i += 1
        return result

    def _read_packet_data_to_end(self, to_):
        """! @brief Read an escaped packet from the first message byte to the end.
        @exception UnexpectedFlagError
        @exception LinkClosedException
        @exception TimeoutError
        """
        result = []
        while to_.check():
            value = self._read1(to_)
            
            # Check for the packet end marker flag.
            if value == self.Flag.END:
                break
            # Handle other flag bytes. This will raise on any detected flags.
            elif (value & self.Flag.MASK) == self.Flag.IDENTIFIER:
                self._check_flags(value, to_)

            # Append data bytes.
            result.append(value)
        else:
            raise exceptions.TimeoutError("timeout while reading from SDC-600")
        
        return self._destuff(result)

    def receive_packet(self, timeout=TRANSFER_TIMEOUT):
        """! @brief Read a data packet.
        
        Reads a packet (PDU) from the target and removes byte stuffing. The timeout for reading the
        entire packet can be set via the _timeout_ parameter.
        
        As data is read from the target, special flags for link errors or to close either phase of
        the link are handled and an appropriate exception is raised.
        
        The connection must be in link phase 2.
        
        @param self
        @param timeout Optional timeout for reading the entire packet. If reading times out, a
            TimeoutError exception is raised.
        @return List of integer byte values of the de-escaped packet contents.
        
        @exception UnexpectedFlagError
        @exception LinkClosedException
        @exception TimeoutError
        """
        assert self._current_link_phase == self.LinkPhase.PHASE2
        with Timeout(timeout) as to_:
            self._expect_flag(self.Flag.START, to_)
            return self._read_packet_data_to_end(to_)
    
    def send_packet(self, data, timeout=TRANSFER_TIMEOUT):
        """! @brief Send a data packet.
        
        Sends the provided data to the target as a single packet (PDU), escaping bytes as necessary.
        No data is read while the packet is sent, so if the target closes the connection it will
        not be detected.
        
        The connection must be in link phase 2.
        
        @param self
        @param data List of integer byte values to send. Must not be pre-escaped.
        @param timeout Optional timeout for reading the entire packet. If reading times out, a
            TimeoutError exception is raised.
        
        @exception UnexpectedFlagError
        @exception TimeoutError
        """
        assert self._current_link_phase == self.LinkPhase.PHASE2
        with Timeout(timeout) as to_:
            self._write1(self.Flag.START, to_)
            for value in self._stuff(data):
                self._write1(value, to_)
            self._write1(self.Flag.END, to_)
    
    def open_link(self, phase, timeout=TRANSFER_TIMEOUT):
        """! @brief Send the LPH1RA or LPH2RA flag.
        @exception UnexpectedFlagError
        @exception LinkClosedException
        @exception TimeoutError
        """
        with Timeout(timeout) as to_:
            if phase == self.LinkPhase.PHASE1:
                assert self._current_link_phase is None

                # Close link phase 1 first, to put it in a known state.
                self.close_link(self.LinkPhase.PHASE1)
        
                LOG.debug("sending LPH1RA")
                self._write1(self.Flag.LPH1RA, to_)
                self._expect_flag(self.Flag.LPH1RA, to_)
                
                self._current_link_phase = self.LinkPhase.PHASE1
            elif phase == self.LinkPhase.PHASE2:
                assert self._current_link_phase == self.LinkPhase.PHASE1

                LOG.debug("sending LPH2RA")
                self._write1(self.Flag.LPH2RA, to_)
                self._expect_flag(self.Flag.LPH2RA, to_)
                
                self._current_link_phase = self.LinkPhase.PHASE2
            else:
                raise ValueError("unrecognized phase value")

    def close_link(self, phase, timeout=TRANSFER_TIMEOUT):
        """! @brief Send the LPH1RL or LPH2RL flag.
        
        Link phase 1 can be closed from any state. Link phase 2 can only be closed when the
        connection is already in that phase.
        
        @exception UnexpectedFlagError
        @exception TimeoutError
        """
        with Timeout(timeout) as to_:
            if phase == self.LinkPhase.PHASE1:
                # Link phase 1 can be closed from any state, so we don't assert here.
                LOG.debug("sending LPH1RL")
                self._write1(self.Flag.LPH1RL, to_)
                self._expect_flag(self.Flag.LPH1RL, to_)
            
                self._current_link_phase = None
            elif phase == self.LinkPhase.PHASE2:
                assert self._current_link_phase == self.LinkPhase.PHASE2

                LOG.debug("sending LPH2RL")
                self._write1(self.Flag.LPH2RL, to_)
                self._expect_flag(self.Flag.LPH2RL, to_)
            
                self._current_link_phase = self.LinkPhase.PHASE1
            else:
                raise ValueError("unrecognized phase value")

    def _log_status(self):
        status = self.ap.read32(self.Register.SR)
        LOG.info("status=0x%08x phase=%s", status, self._current_link_phase)

    def read_protocol_id(self, timeout=TRANSFER_TIMEOUT):
        """! @brief Read and return the 6-byte protocol ID.
        @exception UnexpectedFlagError
        @exception LinkClosedException
        @exception TimeoutError
        """
        with Timeout(timeout) as to_:
            self._write1(self.Flag.IDR, to_)
            self._expect_flag(self.Flag.IDA, to_)
            return self._read_packet_data_to_end(to_)
    
    def send_reboot_request(self, timeout=TRANSFER_TIMEOUT):
        """! @brief Send remote reboot request."""
        with Timeout(timeout) as to_:
            self._write1(self.Flag.LPH2RR, to_)
    
    def __repr__(self):
        return "<SDC-600@{:x}: en={} txw={} rxw={} phase={}>".format(id(self),
            self._is_enabled, self._tx_width, self._rx_width, self._current_link_phase)
        


