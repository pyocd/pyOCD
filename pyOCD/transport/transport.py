"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2013 ARM Limited

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""
# Read modes:
# Start a read.  This must be followed by READ_END of the
# same type and in the same order
READ_START = 1
# Read immediately
READ_NOW = 2
# Get the result of a read started with READ_START
READ_END = 3

class TransferError(ValueError):
    pass

class Transport(object):

    def __init__(self, interface):
        self.interface = interface
        return

    def init(self):
        return

    def uninit(self):
        return

    def info(self, request):
        return

    def readDP(self, addr, mode=READ_NOW):
        return

    def writeDP(self, addr, data):
        return

    def writeAP(self, addr, data):
        return

    def readAP(self, addr, mode=READ_NOW):
        return

    def writeMem(self, addr, data, transfer_size = 32):
        return

    def readMem(self, addr, transfer_size = 32, mode=READ_NOW):
        return

    def writeBlock32(self, addr, data):
        return

    def readBlock32(self, addr, data):
        return

    def assertReset(self, asserted):
        return

    def getUniqueID(self):
        return

    def reset(self):
        return

    def setClock(self, frequency):
        return

    def setDeferredTransfer(self, enable):
        return
