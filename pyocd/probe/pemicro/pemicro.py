#!/usr/bin/env python
#
# Copyright (c) 2020 P&E Microcomputer Systems, Inc
# All rights reserved.
# Visit us at www.pemicro.com
#
# SPDX-License-Identifier:
# BSD-3-Clause
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# o Redistributions of source code must retain the above copyright notice, this list
#   of conditions and the following disclaimer.
#
# o Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
# o Neither the names of the copyright holders nor the names of the
#   contributors may be used to endorse or promote products derived from this
#   software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# This file has been modified by NXP 2020 to implement into PyOCD project


import ctypes
import logging
import os.path
import platform
import sys
import time
from ctypes import *
from enum import IntEnum


# Enumeration of all PEMicro port types
class PEMicroPortType(IntEnum):
    AUTODETECT = 99
    PARALLEL_PORT_CABLE = 1
    PCIBDM_LIGHTNING = 2
    USB_MULTILINK = 3
    CYCLONE_PRO_MAX_SERIAL = 4
    CYCLONE_PRO_MAX_USB = 5
    CYCLONE_PRO_MAX_ETHERNET = 6
    OPENSDA_USB = 9

# Enumeration of all PEMicro Special features
class PEMicroSpecialFeatures(IntEnum):
    # Special Features for Power Management
    PE_PWR_SET_POWER_OPTIONS = 0X38000001      
    PE_PWR_TURN_POWER_ON = 0X38000011
    PE_PWR_TURN_POWER_OFF = 0X38000012

    # Special Features for debug communications mode
    PE_ARM_SET_COMMUNICATIONS_MODE = 0X44000001
    PE_ARM_SET_DEBUG_COMM_SWD = 0X00000000
    PE_ARM_SET_DEBUG_COMM_JTAG = 0X00000001

    PE_ARM_ENABLE_DEBUG_MODULE = 0X44000002
    PE_ARM_WRITE_AP_REGISTER = 0X44000003
    PE_ARM_READ_AP_REGISTER = 0X44000004
    PE_ARM_WRITE_DP_REGISTER = 0X44000007
    PE_ARM_READ_DP_REGISTER = 0X44000008
    PE_ARM_FLUSH_ANY_QUEUED_DATA = 0X44000005

    # SWD control special features
    PE_ARM_GET_LAST_SWD_STATUS = 0X44000006
    PE_ARM_SWD_STATUS_ACK = 0X04
    PE_ARM_SWD_STATUS_WAIT = 0X02
    PE_ARM_SWD_STATUS_FAULT = 0X01

    # Special Features for Setting current device and core
    PE_GENERIC_GET_DEVICE_LIST = 0X58004000
    PE_GENERIC_SELECT_DEVICE = 0X58004001
    PE_GENERIC_GET_CORE_LIST = 0X58004002
    PE_GENERIC_SELECT_CORE = 0X58004003
    PE_SET_DEFAULT_APPLICATION_FILES_DIRECTORY = 0X58006000

logger = logging.getLogger(__name__)

class PEMicroInterfaces():
    """Target interfaces for the PEMicro."""
    JTAG = 0
    SWD = 1

    @classmethod
    def get_str(cls, interface):

        if not isinstance(interface, cls):
            return "Not selected"
        else: 
            return "SWD" if interface is self.SWD else "JTAG"



class PEMicroException(Exception):
    def __init__(self, code):
        """Generates an exception by coercing the given ``code`` to an error
        string if is a number, otherwise assumes it is the message.

        Args:
          self (PEMicroException): the 'PEMicroException' instance
          code (object): message or error code

        Returns:
          ``None``
        """
        def is_integer(val):
            """Returns whether the given value is an integer.

            Args:
            val (object): value to check

            Returns:
            ``True`` if the given value is an integer, otherwise ``False``.
            """
            try:
                val += 1
            except TypeError:
                return False
            return T

        message = code

        self.code = None

        if is_integer(code):
            message = "PEMicro Exception with error code:{err:d}".format(err=code)
            self.code = code

        super(PEMicroException, self).__init__(message)
        self.message = message

class PEMicroTransferException(PEMicroException):
    """PEMicro Transfer exception."""
    pass

class PEMicroUnitAcmp():

    @staticmethod
    def get_user_friendly_library_name():
        systems = {"Windows":"Windows",
                   ("Linux", "Linux2"):"Linux",
                   "Darwin":"MacOS"}
        return systems[platform.system()]

    @staticmethod
    def get_library_name():
        libs = {"Windows"           :{"32bit":"unitacmp-32.dll", "64bit":"unitacmp-64.dll"},
                ("Linux", "Linux2") :{("32bit","64bit")                 :"unitacmp-64.so"},
                ("Darwin")          :{("32bit","64bit")                 :"unitacmp-64.dylib"}}

        return libs[platform.system()][platform.architecture()[0]]

    @staticmethod
    def free_library(handle):
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32.FreeLibrary.argtypes = [ctypes.wintypes.HMODULE]
        kernel32.FreeLibrary(handle)

    def __init__(self, dllpath=None, log_info=None, log_war=None, log_err=None, log_debug=None):
        
        # Initialize the basic objects
        self.__open_ref_count = 0
        self.library_loaded = False
        self.lib = None

        #register logging objects
        self._log_info = lambda s:(log_info or logger.info)(s)
        self._log_warning = lambda s:(log_war or logger.warning)(s)
        self._log_error = lambda s:(log_err or logger.error)(s)
        self._log_debug = lambda s:(log_debug or logger.debug)(s)

        if dllpath is None:
            osUtilityPath = os.path.join("libs", PEMicroUnitAcmp.get_user_friendly_library_name())
            
            # Get the name of PEMicro dynamic library
            self.name = self.get_library_name()

            if self.name is None:
                raise PEMicroException("unable to determinate running operation system")

            # load the library
            try:
                # Look in System Folders
                self.library_path = ''
                self.lib = cdll.LoadLibrary(self.name)
            except:
                try:
                    # Look in the folder with .py file
                    self.library_path = os.path.dirname(__file__)
                    self.lib = cdll.LoadLibrary(os.path.join(self.library_path,self.name))
                except:
                    # Look in a structured subfolder
                    self.library_path = os.path.join(os.path.dirname(__file__),osUtilityPath)
                    self.lib = cdll.LoadLibrary(os.path.join(self.library_path,self.name))

        if self.lib:
            self.library_loaded = True
            self.lib.pe_special_features.argtypes = [c_ulong,c_bool,c_ulong,c_ulong,c_ulong,c_void_p,c_void_p]
            self.lib.pe_special_features.restype = c_bool

            # bool open_port(unsigned int PortType, unsigned int PortNum);
            self.lib.open_port.argtypes = [c_ulong,c_ulong]
            self.lib.open_port.restype = c_bool

            # void close_port(void);
            #  No parameters and return value

            self.lib.open_port_by_identifier.argtypes = [c_char_p]
            self.lib.open_port_by_identifier.restype = c_bool

            # bool reenumerate_all_port_types(void);
            self.lib.reenumerate_all_port_types.restype = c_bool

            # unsigned int get_enumerated_number_of_ports(unsigned int PortType);
            self.lib.get_enumerated_number_of_ports.argtypes = [c_ulong]
            self.lib.get_enumerated_number_of_ports.restype = c_ulong

            # char * get_port_descriptor(unsigned int PortType, unsigned int PortNum);
            self.lib.get_port_descriptor.argtypes = [c_ulong,c_ulong]
            self.lib.get_port_descriptor.restype = c_char_p

            # char * get_port_descriptor_short(unsigned int PortType, unsigned int PortNum);
            self.lib.get_port_descriptor_short.argtypes = [c_ulong,c_ulong]
            self.lib.get_port_descriptor_short.restype = c_char_p


            # void reset_hardware_interface(void);
            #  No parameters and return value

            # unsigned char check_critical_error(void);
            self.lib.check_critical_error.restype = c_byte

            # char * version(void);
            self.lib.version.restype = c_char_p

            # unsigned short get_dll_version(void);
            self.lib.get_dll_version.restype = c_ushort

            # void set_debug_shift_frequency (signed long shift_speed_in_hz);
            self.lib.set_debug_shift_frequency.argtypes = [c_ulong]

            # void set_reset_delay_in_ms(unsigned int delaylength);
            self.lib.set_reset_delay_in_ms.argtypes = [c_ulong]

            # bool target_reset(void);
            self.lib.target_reset.restype = c_bool

            # bool target_resume(void);
            self.lib.target_resume.restype = c_bool

            # void set_reset_pin_state(unsigned char state)
            self.lib.set_reset_pin_state.argtypes = [c_byte]

            self._special_features(PEMicroSpecialFeatures.PE_SET_DEFAULT_APPLICATION_FILES_DIRECTORY,ref1=c_char_p(self.library_path.encode('utf-8')))

    def _special_features(self, featurenum, fset=True, par1=0, par2=0, par3=0, ref1=None, ref2=None):
        
        if not self.library_loaded:
            raise PEMicroException("Library is not loaded")

        if not isinstance(featurenum, PEMicroSpecialFeatures):
            raise PEMicroException("Invalide argument to do special feature")

        if self.lib.pe_special_features(featurenum, fset, par1, par2, par3, ref1, ref2) is False:
            raise PEMicroException("The special feature command hasn't accepted")


    def open(self, debug_hardware_name_ip_or_serialnum=None):
        """ This function opens the connection to PEMicro debug probe

        Args:
            self(PEMicroUnitAcmp): the "PEMicroUnitAcmp" Instance
            debug_hardware_name_ip_or_serialnum: Hardware identifier of PEMicro debug probe

        Returns:
            "None"

        Raises:
            ProbeError : With any problem with probe itself

        """
        if not self.library_loaded:
            raise PEMicroException("Library is not loaded")

        if self.__open_ref_count > 0:
            self.__open_ref_count += 1
            return None

        if debug_hardware_name_ip_or_serialnum==None:
            # USB1 is a generic identifier which will select the first autodetected USB pemicro device
            port_name = c_char_p('USB1'.encode('utf-8'))
        else:
            # This identifier can be the debug hardware's IP address, assigned name, serial number, or generic identifier (USB1, ETHERNET1)
            port_name = c_char_p(debug_hardware_name_ip_or_serialnum.encode('utf-8'))
        
        if not self.lib.open_port_by_identifier(port_name):
            raise PEMicroException("Cannot connect to debug probe")
        
        self.__open_ref_count = 1

        # Connect and initialize the P&E hardware interface. This does not attempt to reset the target.
        self.lib.reset_hardware_interface()
        
        # Verify that the connection to the P&E hardware interface is good.
        probe_error = self.lib.check_critical_error()

        if probe_error:
            raise PEMicroException("Probe error has been detected during open operation. Error: 0x{err=2X}".format(err=probe_error))
      
        # cable_version = self.lib.get_cable_version()
        # print(cable_version.decode('utf-8'))

        return None

    @property
    def opened(self):
        return True if self.__open_ref_count > 0 else False            

    def close(self):
        if self.__open_ref_count == 0:
            # Do nothing if .open() has not been called.
            return None

        self.__open_ref_count -= 1

        if self.__open_ref_count > 0:
            return None

        # Close any open connections to hardware
        self._special_features(PEMicroSpecialFeatures.PE_ARM_FLUSH_ANY_QUEUED_DATA)
        self.lib.close_port()

        return

    def __del__(self):
        # Cloase the possibly opened connection 
        self.close()
        # Unload the library if neccessary
        if self.lib is not None:
            libHandle = self.lib._handle
            del self.lib
            PEMicroUnitAcmp.free_library(libHandle)

    def power_on(self):
        self._log_debug("Power on target")

        self._special_features(PEMicroSpecialFeatures.PE_PWR_TURN_POWER_ON)

    def power_off(self):
        self._log_debug("Power off target")

        self._special_features(PEMicroSpecialFeatures.PE_PWR_TURN_POWER_OFF)

    def reset_target(self):
        if not self.library_loaded:
            raise PEMicroException("Library is not loaded,yet")

        self._log_debug("Reset target")
        
        if self.lib.target_reset() is not True:
            raise PEMicroException("Reset target sequence failed")

        # if self.lib.target_resume() is not True:
        #     raise PEMicroException("Resume after reset of target sequence failed")    
        
    def set_reset_delay_in_ms(self, delay):
        if not self.library_loaded:
            raise PEMicroException("Library is not loaded,yet")

        self._log_debug("Reset target delay has been set to {t}ms".format(t=delay))

        self.lib.set_reset_delay_in_ms(delay)        

    def flush_any_queued_data(self):
        if self.__open_ref_count == 0:
            raise PEMicroException("The connection is not active")

        self._log_debug("All queued data has been flushed")

        self._special_features(PEMicroSpecialFeatures.PE_ARM_FLUSH_ANY_QUEUED_DATA)

    def set_device_name(self, device_name="Cortex-M4"):
        if self.__open_ref_count > 0:
            raise PEMicroException("The connection is already opened, can't change the device name")

        self._log_debug("The device name is set to {name}".format(name=device_name))

        self._special_features(PEMicroSpecialFeatures.PE_GENERIC_SELECT_DEVICE, ref1=device_name.encode('utf-8'))

    def version(self):
        version = self.lib.version().decode('utf-8') if self.library_loaded else "Unknown"
        self._log_debug("Getting version: {ver}".format(ver=version))
        return version


    def version_dll(self):
        version = self.lib.get_dll_version()  if self.library_loaded else "Unknown"
        self._log_debug("Getting DLL version: {ver}".format(ver=version))
        return version 


    def listPortsDescription(self):
        if not self.library_loaded:
            raise PEMicroException("No PEMicro Library is loaded!")
            return
        numports = self.lib.get_enumerated_number_of_ports(PEMicroPortType.AUTODETECT)
        if numports == 0:
            self._log_info('No hardware detected locally.')
        for i in range(numports):
            self._log_info(self.lib.get_port_descriptor_short(PEMicroPortType.AUTODETECT,i+1).decode("utf-8") + ' : ' + self.lib.get_port_descriptor(PEMicroPortType.AUTODETECT,i+1).decode("utf-8"))
        

    def listPorts(self):
        if not self.library_loaded:
            raise PEMicroException("No PEMicro Library is loaded!")
        numports = self.lib.get_enumerated_number_of_ports(PEMicroPortType.AUTODETECT)
        if numports == 0:
            return None
        ports = list()
        for i in range(numports):
            ports.append({"id":self.lib.get_port_descriptor_short(PEMicroPortType.AUTODETECT,i+1).decode("utf-8"), "description":self.lib.get_port_descriptor(PEMicroPortType.AUTODETECT,i+1).decode("utf-8")})
        return ports

    def print_ports(self, ports):
        if ports == None or len(ports) == 0:
            self._log_info('No hardware detected locally.')
        i=0
        for port in ports:
            self._log_info("{ix:>2}: {id} => {desc}".format(ix=i, id=port["id"], desc=port["description"]))
            i += 1

    def list_ports_name(self):
        if not self.library_loaded:
            raise PEMicroException("No PEMicro Library is loaded!")
        numports = self.lib.get_enumerated_number_of_ports(PEMicroPortType.AUTODETECT)
        if numports == 0:
            self._log_info('No hardware detected locally.')
        for i in range(numports):
            self._log_info(self.lib.get_port_descriptor_short(PEMicroPortType.AUTODETECT,i+1).decode("utf-8"))
        return    

    def connect(self, interface=PEMicroInterfaces.SWD, shiftSpeed=1000000):
        # connectToDebugCable must be used first to connect to the debug hardware
        if not self.library_loaded:
            raise PEMicroException("No PEMicro Library is loaded!")
        if self.__open_ref_count == 0:
            raise PEMicroException("The connection is not opened, can't connect to target")
        self._log_debug("Selecting the communication interface to {intf}".format(intf=PEMicroInterfaces().get_str(interface)))   
        if interface is PEMicroInterfaces.SWD:
            self._special_features(PEMicroSpecialFeatures.PE_ARM_SET_COMMUNICATIONS_MODE, par1=PEMicroSpecialFeatures.PE_ARM_SET_DEBUG_COMM_SWD)
        else:       
            self._special_features(PEMicroSpecialFeatures.PE_ARM_SET_COMMUNICATIONS_MODE, par1=PEMicroSpecialFeatures.PE_ARM_SET_DEBUG_COMM_JTAG)
        # Set 1Mhz as a default or given value by parameter shiftSpeed for communication speed
        self.lib.set_debug_shift_frequency(shiftSpeed)
        # Communicate to the target, power up debug module, check  (powering it up). Looks for arm IDCODE to verify connection.
        try:
            self._special_features(PEMicroSpecialFeatures.PE_ARM_ENABLE_DEBUG_MODULE)
        except:
            self._log_error("Failed to connect to target")    
        
        self._log_info("Connected to target over {intf} with clock {clk}Hz".format(intf=PEMicroInterfaces.get_str(interface), clk=shiftSpeed))

    def set_debug_frequency(self, freq):
        if not self.library_loaded:
            raise PEMicroException("No PEMicro Library is loaded!")
        if self.__open_ref_count == 0:
            raise PEMicroException("The communication interface is not opened")
        self._log_debug("The communication speed has been switched to {clk}Hz".format(clk=freq))

        # Set Shift Rate
        self.lib.set_debug_shift_frequency(freq)

    def control_reset_line(self, assert_reset=True):
        self._log_debug("{0}Asserting RESET signal".format("De-" if not assert_reset else ""))

        self.lib.set_reset_pin_state(0 if assert_reset else 1)        

    def __check_swd_error(self):
        swd_status = self.last_swd_status()

        if swd_status not in [PEMicroSpecialFeatures.PE_ARM_SWD_STATUS_ACK, PEMicroSpecialFeatures.PE_ARM_SWD_STATUS_WAIT]:
            # Verify that the connection to the P&E hardware interface is good.
            probe_error = self.lib.check_critical_error()
            
            if probe_error & 0x08:
                # Connect and initialize the P&E hardware interface. This does not attempt to reset the target.
                self.lib.reset_hardware_interface()
            self._log_error("SWD Status failed during IO operation. status: 0x{err:02X}".format(err=swd_status))
            raise PEMicroTransferException("SWD Status failed during IO operation. status: 0x{err:02X}".format(err=swd_status))


    def write_ap_register(self, apselect, addr, value, now=False):
        if self.__open_ref_count == 0:
            raise PEMicroException("There is NO opened connection with target")

        self._log_debug("Writing into AP register: Addr: 0x{addr:08X}, Value:{val}, 0x{val:08X}, mode:{when}".format(addr=addr, val=value, when="Now" if now else "Delayed"))

        self._special_features(PEMicroSpecialFeatures.PE_ARM_WRITE_AP_REGISTER, fset=now, par1=apselect, par2=addr, par3=value)

        # Check the status of SWD    
        self.__check_swd_error()


    def read_ap_register(self, apselect, addr, now=True, requiresDelay=False):
        if self.__open_ref_count == 0:
            raise PEMicroException("There is NO opened connection with target")
        ret_val = c_ulong()
        self._special_features(PEMicroSpecialFeatures.PE_ARM_READ_AP_REGISTER,fset=now, par1=apselect, par2=addr, ref1=byref(ret_val))
        
        self._log_debug("Read AP register: Addr: 0x{addr:08X}, Value:{val}, 0x{val:08X}".format(addr=addr, val=ret_val.value))
        # Check the status of SWD    
        self.__check_swd_error()

        return ret_val.value
    
    def write_dp_register(self, addr, value, now=False):
        if self.__open_ref_count == 0:
            raise PEMicroException("There is NO opened connection with target")
        
        self._log_debug("Writing into DP register: Addr: 0x{addr:08X}, Value:{val}, 0x{val:08X}, mode:{when}".format(addr=addr, val=value, when="Now" if now else "Delayed"))
    
        self._special_features(PEMicroSpecialFeatures.PE_ARM_WRITE_DP_REGISTER, fset=now, par1=addr, par2=value)

        # Check the status of SWD    
        self.__check_swd_error()
        

    def read_dp_register(self, addr, now=True, requiresDelay=False):
        if self.__open_ref_count == 0:
            raise PEMicroException("There is NO opened connection with target")
        ret_val = c_ulong()
        self._special_features(PEMicroSpecialFeatures.PE_ARM_READ_DP_REGISTER, fset=now, par1=addr, ref1=byref(ret_val))

        self._log_debug("Read DP register: Addr: 0x{addr:08X}, Value:{val}, 0x{val:08X}".format(addr=addr, val=ret_val.value))

        # Check the status of SWD    
        self.__check_swd_error()
        
        return ret_val.value
    
    def last_swd_status(self):
        ret_val = c_ulong()
        self._special_features(PEMicroSpecialFeatures.PE_ARM_GET_LAST_SWD_STATUS, ref1=byref(ret_val))
        self._log_debug("Got last SWD status:{val}, 0x{val:08X}".format(val=ret_val.value))
        return ret_val.value


# All functions names in DLL
# pe_special_features
# clr_brkpt
# set_inst_brkpt
# check_number_of_queued_exchanges
# get_exchange16_result
# process_all_queued_exchanges
# queue_data_exchange16
# get_mcu_register
# set_mcu_register
# load_srec_file
# load_bin_file
# write_64bit_value
# write_32bit_value
# write_16bit_value
# write_8bit_value
# read_64bit_value
# read_32bit_value
# read_16bit_value
# read_8bit_value
# put_block
# get_block
# target_step
# target_resume
# target_check_if_halted
# target_halt
# target_reset
# get_cable_version
# set_reset_delay_in_ms
# set_debug_shift_frequency
# check_critical_error
# reset_hardware_interface
# close_port
# open_port_by_identifier
# open_port
# get_port_descriptor_short
# get_port_descriptor
# get_enumerated_number_of_ports
# reenumerate_all_port_types
# set_local_machine_ip_number
# close_debug_file
# open_debug_file
# get_dll_version
# version
