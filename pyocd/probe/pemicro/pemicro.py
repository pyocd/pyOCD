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


import time
import platform
import ctypes
import sys
import os.path
from ctypes import *
import logging

PortType_Autodetect = 99
PortType_ParallelPortCable = 1
PortType_PCIBDMLightning = 2
PortType_USBMultilink = 3
PortType_CycloneProMaxSerial = 4
PortType_CycloneProMaxUSB = 5
PortType_CycloneProMaxEthernet = 6
PortType_OpenSDAUSB = 9

# Special Features for Power Management
pwr_set_power_options = 0x38000001      
pwr_turn_power_on = 0x38000011
pwr_turn_power_off = 0x38000012

# Special Features for debug communications mode
pe_arm_set_communications_mode = 0x44000001
pe_arm_set_debug_comm_swd = 0x00000000
pe_arm_set_debug_comm_jtag = 0x00000001

pe_arm_enable_debug_module = 0x44000002
pe_arm_write_ap_register = 0x44000003
pe_arm_read_ap_register = 0x44000004
pe_arm_write_dp_register = 0x44000007
pe_arm_read_dp_register = 0x44000008
pe_arm_flush_any_queued_data = 0x44000005

pe_arm_get_last_swd_status = 0x44000006
pe_arm_swd_status_ack = 0x04
pe_arm_swd_status_wait = 0x02
pe_arm_swd_status_fault = 0x01

  
# Special Features for Setting current device and core
pe_generic_get_device_list = 0x58004000
pe_generic_select_device = 0x58004001
pe_generic_get_core_list = 0x58004002
pe_generic_select_core = 0x58004003
pe_set_default_application_files_directory = 0x58006000

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

class pemicroUnitAcmp():

    @staticmethod
    def get_user_friendly_library_name():
        systems = {"Windows":"Windows",
                   ("Linux", "Linux2"):"Linux",
                   "Darwin":"MacOS"}
        return systems[platform.system()]

    @staticmethod
    def getLibraryName():
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
        self.__openRefCount = 0
        self.libraryLoaded = False
        self.lib = None

        #register logging objects
        self._log_info = lambda s:(log_info or logger.info)(s)
        self._log_warning = lambda s:(log_war or logger.warning)(s)
        self._log_error = lambda s:(log_err or logger.error)(s)
        self._log_debug = lambda s:(log_debug or logger.debug)(s)

        if dllpath is None:
            osUtilityPath = os.path.join("libs", pemicroUnitAcmp.get_user_friendly_library_name())
            
            # Get the name of PEMicro dynamic library
            self.name = self.getLibraryName()

            if self.name is None:
                raise PEMicroException("unable to determinate running operation system")

            # load the library
            try:
                # Look in System Folders
                self.libraryPath = ''
                self.lib = cdll.LoadLibrary(self.name)
            except:
                try:
                    # Look in the folder with .py file
                    self.libraryPath = os.path.dirname(__file__)
                    self.lib = cdll.LoadLibrary(os.path.join(self.libraryPath,self.name))
                except:
                    # Look in a structured subfolder
                    self.libraryPath = os.path.join(os.path.dirname(__file__),osUtilityPath)
                    self.lib = cdll.LoadLibrary(os.path.join(self.libraryPath,self.name))

        if self.lib:
            self.libraryLoaded = True
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

            self.lib.pe_special_features(pe_set_default_application_files_directory,True,0,0,0,c_char_p(self.libraryPath.encode('utf-8')),0)

    def open(self, debugHardwareNameIpOrSerialnum=None):
        """ This function opens the connection to PEMicro debug probe

        Args:
            self(pemicroUnitAcmp): the "pemicroUnitAcmp" Instance
            hardwareId: Hardware identifier of PEMicro debug probe

        Returns:
            "None"

        Raises:
            ProbeError : With any problem with probe itself

        """
        if not self.libraryLoaded:
            raise PEMicroException("Library is not loaded")

        if self.__openRefCount > 0:
            self.__openRefCount += 1
            return None

        if debugHardwareNameIpOrSerialnum==None:
            # USB1 is a generic identifier which will select the first autodetected USB pemicro device
            portName = c_char_p('USB1'.encode('utf-8'))
        else:
            # This identifier can be the debug hardware's IP address, assigned name, serial number, or generic identifier (USB1, ETHERNET1)
            portName = c_char_p(debugHardwareNameIpOrSerialnum.encode('utf-8'))
        
        
        if not self.lib.open_port_by_identifier(portName):
            raise PEMicroException("Cannot connect to debug probe")
        
        self.__openRefCount = 1

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
        return True if self.__openRefCount > 0 else False            

    def close(self):
        if self.__openRefCount == 0:
            # Do nothing if .open() has not been called.
            return None

        self.__openRefCount -= 1

        if self.__openRefCount > 0:
            return None

        # Close any open connections to hardware
        self.lib.pe_special_features(pe_arm_flush_any_queued_data,True,0,0,0,0,0)
        self.lib.close_port()

        return

    def __del__(self):
        # Cloase the possibly opened connection 
        self.close()
        # Unload the library if neccessary
        if self.lib is not None:
            libHandle = self.lib._handle
            del self.lib
            pemicroUnitAcmp.free_library(libHandle)


    def power_on(self):
        if not self.libraryLoaded:
            raise PEMicroException("Library is not loaded,yet")

        self._log_debug("Power on target")

        if self.lib.pe_special_features(pwr_turn_power_on,True,0,0,0,0,0) == False:
            self._log_error('Power ON command has NOT been accepted.')    
            return False

        return True

    def power_off(self):
        if not self.libraryLoaded:
            raise PEMicroException("Library is not loaded,yet")

        self._log_debug("Power off target")

        if self.lib.pe_special_features(pwr_turn_power_off,True,0,0,0,0,0) == False:
            self._log_error('Power OFF command has NOT been accepted.')    
            return False

        return True

    def reset_target(self):
        if not self.libraryLoaded:
            raise PEMicroException("Library is not loaded,yet")

        self._log_debug("Reset target")
        
        if self.lib.target_reset() is not True:
            raise PEMicroException("Reset target sequence failed")

        # if self.lib.target_resume() is not True:
        #     raise PEMicroException("Resume after reset of target sequence failed")    
        


    def set_reset_delay_in_ms(self, delay):
        if not self.libraryLoaded:
            raise PEMicroException("Library is not loaded,yet")

        self._log_debug("Reset target delay has been set to {t}ms".format(t=delay))

        self.lib.set_reset_delay_in_ms(delay)        

    def flush_any_queued_data(self):
        if not self.libraryLoaded:
            raise PEMicroException("Library is not loaded,yet")
        if self.__openRefCount == 0:
            raise PEMicroException("The connection is not active")

        self._log_debug("All queued data has been flushed")

        if self.lib.pe_special_features(pe_arm_flush_any_queued_data,True,0,0,0,0,0) == False:
            raise PEMicroException("Can't Flush queued data")

    def set_device_name(self, device_name="Cortex-M4"):
        if not self.libraryLoaded:
            raise PEMicroException("Library is not loaded,yet")
    
        if self.__openRefCount > 0:
            raise PEMicroException("The connection is already opened, can't change the device name")

        self._log_debug("The device name is set to {name}".format(name=device_name))

        if self.lib.pe_special_features(pe_generic_select_device,True,0,0,0,device_name.encode('utf-8'),0) == False:
            self._log_error('Set device name command has not been accepted.')    
            return False

        return True

    def version(self):
        version = self.lib.version().decode('utf-8') if self.libraryLoaded else "Unknown"
        self._log_debug("Getting version: {ver}".format(ver=version))
        return version


    def version_dll(self):
        version = self.lib.get_dll_version()  if self.libraryLoaded else "Unknown"
        self._log_debug("Getting DLL version: {ver}".format(ver=version))
        return version 


    def listPortsDescription(self):
        if not self.libraryLoaded:
            return
        numports = self.lib.get_enumerated_number_of_ports(PortType_Autodetect)
        if numports == 0:
            self._log_warning('No hardware detected locally.')
        for i in range(numports):
            self._log_info(self.lib.get_port_descriptor_short(PortType_Autodetect,i+1).decode("utf-8") + ' : ' + self.lib.get_port_descriptor(PortType_Autodetect,i+1).decode("utf-8"))
        return

    def listPorts(self):
        if not self.libraryLoaded:
            raise PEMicroException("No PEMicro Library is loaded!")
        numports = self.lib.get_enumerated_number_of_ports(PortType_Autodetect)
        if numports == 0:
            return None
        ports = list()

        for i in range(numports):
            ports.append({"id":self.lib.get_port_descriptor_short(PortType_Autodetect,i+1).decode("utf-8"), "description":self.lib.get_port_descriptor(PortType_Autodetect,i+1).decode("utf-8")})
        return ports

    def printPorts(self, ports):
        if ports == None or len(ports) == 0:
            self._log_warning('No hardware detected locally.')
        i=0
        for port in ports:
            self._log_info("{ix:>2}: {id} => {desc}".format(ix=i, id=port["id"], desc=port["description"]))
            i += 1

    def listPortsName(self):
        if not self.libraryLoaded:
            return
        numports = self.lib.get_enumerated_number_of_ports(PortType_Autodetect)
        if numports == 0:
            self._log_warning('No hardware detected locally.')
        for i in range(numports):
            self._log_info(self.lib.get_port_descriptor_short(PortType_Autodetect,i+1).decode("utf-8"))
        return    

    def connect(self, interface=PEMicroInterfaces.SWD, shiftSpeed=1000000):
        # connectToDebugCable must be used first to connect to the debug hardware
        if not self.libraryLoaded:
            return False
        if self.__openRefCount == 0:
            return False
        if interface is PEMicroInterfaces.SWD:
            ret = self.lib.pe_special_features(pe_arm_set_communications_mode,True,pe_arm_set_debug_comm_swd,0,0,0,0)
        else:       
            ret = self.lib.pe_special_features(pe_arm_set_communications_mode,True,pe_arm_set_debug_comm_jtag,0,0,0,0)
        if ret is False:
            self._log_error("Can't select the communication interface to {intf}".format(intf=PEMicroInterfaces().get_str(interface)))    
        # Set 1Mhz as a default or given value by parameter shiftSpeed for communication speed
        self.lib.set_debug_shift_frequency(shiftSpeed)
        # Communicate to the target, power up debug module, check  (powering it up). Looks for arm IDCODE to verify connection.
        ret = self.lib.pe_special_features(pe_arm_enable_debug_module,True,0,0,0,0,0)
        if ret:
            self._log_info("Connected to target over {intf} with clock {clk}Hz".format(intf=PEMicroInterfaces.get_str(interface), clk=shiftSpeed))
        else:
            self._log_error("Failed to connect to target")    
        return 

    def set_debug_frequency(self, freq):
        if not self.libraryLoaded:
            return False
        if self.__openRefCount == 0:
            return False
        self._log_debug("The communication speed has been switched to {clk}Hz".format(clk=freq))

        # Set Shift Rate
        self.lib.set_debug_shift_frequency(freq)
        
    def __check_swd_error(self):
        swd_status = self.lastSwdStatus()

        if swd_status is not pe_arm_swd_status_ack:
            # Verify that the connection to the P&E hardware interface is good.
            probe_error = self.lib.check_critical_error()
            
            if probe_error & 0x08:
                # Connect and initialize the P&E hardware interface. This does not attempt to reset the target.
                self.lib.reset_hardware_interface()
            self._log_error("SWD Status failed during IO operation. status: 0x{err:02X}".format(err=swd_status))
            raise PEMicroTransferException("SWD Status failed during IO operation. status: 0x{err:02X}".format(err=swd_status))


    def writeApRegister(self, apselect, addr, value, now=False):
        if self.__openRefCount == 0:
            return

        self._log_debug("Writing into AP register: Addr: 0x{addr:08X}, Value:{val}, 0x{val:08X}, mode:{when}".format(addr=addr, val=value, when="Now" if now else "Delayed"))

        if self.lib.pe_special_features(pe_arm_write_ap_register, now, apselect,addr,value,0,0) is False:
            raise PEMicroException("Unable to Write AP Register")

        # Check the status of SWD    
        self.__check_swd_error()

        return

    def readApRegister(self, apselect, addr, now=True, requiresDelay=False):
        if self.__openRefCount == 0:
            return 0
        retVal = c_ulong()
        if self.lib.pe_special_features(pe_arm_read_ap_register,True,apselect,addr,0,byref(retVal),0) is False:
            raise PEMicroException("Unable to Read AP Register")
        
        self._log_debug("Read AP register: Addr: 0x{addr:08X}, Value:{val}, 0x{val:08X}".format(addr=addr, val=retVal.value))
        # Check the status of SWD    
        self.__check_swd_error()

        return retVal.value
    
    def writeDpRegister(self, addr, value, now=False):
        if self.__openRefCount == 0:
            return
        
        self._log_debug("Writing into DP register: Addr: 0x{addr:08X}, Value:{val}, 0x{val:08X}, mode:{when}".format(addr=addr, val=value, when="Now" if now else "Delayed"))
    
        if self.lib.pe_special_features(pe_arm_write_dp_register, now, addr,value,0,0,0) is False:
            raise PEMicroException("Unable to Write DP Register")

        # Check the status of SWD    
        self.__check_swd_error()
        
        return

    def readDpRegister(self, addr, now=True, requiresDelay=False):
        if self.__openRefCount == 0:
            return 0
        retVal = c_ulong()
        if self.lib.pe_special_features(pe_arm_read_dp_register,True,addr,0,0,byref(retVal),0) is False:
            raise PEMicroException("Unable to Read DP Register")

        self._log_debug("Read DP register: Addr: 0x{addr:08X}, Value:{val}, 0x{val:08X}".format(addr=addr, val=retVal.value))

        # Check the status of SWD    
        self.__check_swd_error()
        
        return retVal.value
    
    def lastSwdStatus(self):
        if not self.libraryLoaded:
            return 0
        retVal = c_ulong()
        self.lib.pe_special_features(pe_arm_get_last_swd_status,True,0,0,0,byref(retVal),0)
        self._log_debug("Got last SWD status:{val}, 0x{val:08X}".format(val=retVal.value))
        return retVal.value


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

