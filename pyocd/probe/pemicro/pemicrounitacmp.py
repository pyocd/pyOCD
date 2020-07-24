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

class PEMicroInterfaces():
    """Target interfaces for the PEMicro."""
    JTAG = 0
    SWD = 1

class pemicroUnitAcmp():

    @staticmethod
    def getLibraryName():
        libs = {"Windows"           :{"32bit":"unitacmp-32.dll", "64bit":"unitacmp-64.dll"},
                ("Linux", "Linux2") :{("32bit","64bit")                 :"unitacmp-64.so"},
                ("Darwin")          :{("32bit","64bit")                 :"unitacmp-64.dylib"}}

        return libs[platform.system()].[platform.architecture()[0]]

    @staticmethod
    def free_library(handle):
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32.FreeLibrary.argtypes = [ctypes.wintypes.HMODULE]
        kernel32.FreeLibrary(handle)

    def __init__(self):
        osUtilityPath = os.path.join("libs",self.getUserFriendlySystemName())
        
        # Get the name of PEMicro dynamic library
        self.name = self.getLibraryName()

        if self.name is None
            raise exceptions.ProbeError("unable to determinate running operation system")

        self.__openRefCount = 0

        # load the library
        self.libraryLoaded = False

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

            # This function is not described in documentation but is available in DLL's
            #   Probably the definition is: char* get_cable_version(void);
            self.lib.get_cable_version.restype = c_char_p


            # void reset_hardware_interface(void);
            #  No parameters and return value

            # unsigned char check_critical_error(void);
            self.lib.check_critical_error.restype = c_uchar

            # char * version(void);
            self.lib.version.restype = c_char_p

            # unsigned short get_dll_version(void);
            self.lib.get_dll_version.restype = c_ushort

            # void set_debug_shift_frequency (signed long shift_speed_in_hz);
            self.lib.set_debug_shift_frequency.argtypes = [c_ulong]

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
            raise exceptions.ProbeError("Library is not loaded")

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
            raise exceptions.ProbeError("Cannot connect to debug probe")
        
        self.__openRefCount = 1

        # Connect and initialize the P&E hardware interface. This does not attempt to reset the target.
        self.lib.reset_hardware_interface
        
        # Verify that the connection to the P&E hardware interface is good.
        probe_error = self.lib.check_critical_error

        if probe_error:
            raise exceptions.ProbeError("Probe error has been detected during open operation. Error: 0x{err=2X}".format(err=probe_error))
      
        cable_version = self.lib.get_cable_version
        print(cable_version.decode('utf-8'))

        return None


    def close(self):
        if self._open_refcount == 0:
            # Do nothing if .open() has not been called.
            return None

        self._open_refcount -= 1

        if self.__openRefCount > 0:
            return None

        # Close any open connections to hardware
        self.lib.pe_special_features(pe_arm_flush_any_queued_data,True,0,0,0,0,0)
        self.lib.close_port()

        return

    def __del__(self):
        # Cloase the possibly opened connection 
        self.close()
        # Unload the library
        libHandle = self.lib._handle
        del self.lib
        pemicroUnitAcmp().free_library(libHandle)


    def power_on(self):
        if not self.libraryLoaded:
            raise exceptions.ProbeError("Library is not loaded,yet")

        if self.lib.pe_special_features(pwr_turn_power_on,True,0,0,0,0,0) == False:
            print('Power ON command has NOT been accepted.')    
            return False

         return True

    def power_off(self):
        if not self.libraryLoaded:
            raise exceptions.ProbeError("Library is not loaded,yet")

        if self.lib.pe_special_features(pwr_turn_power_off,True,0,0,0,0,0) == False:
            print('Power OFF command has NOT been accepted.')    
            return False

         return True

    def set_device_name(self, device_name="Cortex-M4")
        if not self.libraryLoaded:
            raise exceptions.ProbeError("Library is not loaded,yet")
    
        if self.__openRefCount > 0:
            raise exceptions.ProbeError("The connection is already opened, can't change the device name")

        if self.lib.pe_special_features(pe_generic_select_device,True,0,0,0,device_name.encode('utf-8'),0) == False:
            print('Set device name command has not been accepted.')    
            return False

        return True

    def version(self)
        if not self.libraryLoaded:
            raise exceptions.ProbeError("Library is not loaded,yet")
        return self.lib.version().decode('utf-8')


    def version_dll(self)
        if not self.libraryLoaded:
            raise exceptions.ProbeError("Library is not loaded,yet")
        return self.lib.get_dll_version()


    def listPortsDescription(self):
        if not self.libraryLoaded:
            return
        numports = self.lib.get_enumerated_number_of_ports(PortType_Autodetect)
        if numports == 0:
            print('No hardware detected locally.')
        for i in range(numports):
            print(self.lib.get_port_descriptor_short(PortType_Autodetect,i+1).decode("utf-8") + ' : ' + self.lib.get_port_descriptor(PortType_Autodetect,i+1).decode("utf-8"))
        return

    def listPorts(self):
        if not self.libraryLoaded:
            raise ProbeError("No PEMicro Library is loaded!")
        numports = self.lib.get_enumerated_number_of_ports(PortType_Autodetect)
        if numports == 0:
            return None
        ports = list()

        for i in range(numports):
            ports.append({"id":self.lib.get_port_descriptor_short(PortType_Autodetect,i+1).decode("utf-8"), "description":self.lib.get_port_descriptor(PortType_Autodetect,i+1).decode("utf-8")})
        return ports

    def printPorts(self, ports):
        if ports == None or len(ports) == 0:
            print('No hardware detected locally.')
        i=0
        for port in ports:
            print("{ix:>2}: {id} => {desc}".format(ix=i, id=port["id"], desc=port["description"]))
            i += 1

    def listPortsName(self):
        if not self.libraryLoaded:
            return
        numports = self.lib.get_enumerated_number_of_ports(PortType_Autodetect)
        if numports == 0:
            print('No hardware detected locally.')
        for i in range(numports):
            print(self.lib.get_port_descriptor_short(PortType_Autodetect,i+1).decode("utf-8"))
        return    

    def establishCommunicationsWithTarget(self, interface=PEMicroInterfaces.SWD, shiftSpeed=1000000):
        # connectToDebugCable must be used first to connect to the debug hardware
        if not self.libraryLoaded:
            return False
        if self.__openRefCount == 0:
            return False
        if interface is PEMicroInterfaces.SWD:
            self.lib.pe_special_features(pe_arm_set_communications_mode,True,pe_arm_set_debug_comm_swd,0,0,0,0)
        else:       
            self.lib.pe_special_features(pe_arm_set_communications_mode,True,pe_arm_set_debug_comm_jtag,0,0,0,0)
        # Set 1Mhz Shift Rate
        self.lib.set_debug_shift_frequency(shiftSpeed)
        # Communicate to the target, power up debug module, check  (powering it up). Looks for arm IDCODE to verify connection.
        return self.lib.pe_special_features(pe_arm_enable_debug_module,True,0,0,0,0,0)

    def writeApRegister(self, apselect, addr, value, now=False):
        if self.__openRefCount == 0:
            return
        self.lib.pe_special_features(pe_arm_write_ap_register, now, apselect,addr,value,0,0)
        return

    def readApRegister(self, apselect, addr, now=True, requiresDelay=False):
        if self.__openRefCount == 0:
            return 0
        retVal = c_ulong()
        self.lib.pe_special_features(pe_arm_read_ap_register,True,apselect,addr,0,byref(retVal),0)
        return retVal.value
    
    def writeDpRegister(self, addr, value, now=False):
        if self.__openRefCount == 0:
            return
        self.lib.pe_special_features(pe_arm_write_dp_register, now, addr,value,0,0,0)
        return

    def readDpRegister(self, addr, now=True, requiresDelay=False):
        if self.__openRefCount == 0:
            return 0
        retVal = c_ulong()
        self.lib.pe_special_features(pe_arm_read_dp_register,True,addr,0,0,byref(retVal),0)
        return retVal.value
    
    def lastSwdStatus(self):
        if not self.libraryLoaded:
            return 0
        retVal = c_ulong()
        self.lib.pe_special_features(pe_arm_get_last_swd_status,True,0,0,0,byref(retVal),0)
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

