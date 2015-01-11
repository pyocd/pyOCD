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

from pyOCD.target import TARGET
from pyOCD.transport import TRANSPORT
from pyOCD.interface import INTERFACE
from pyOCD.flash import FLASH

import logging

class Board(object):
    """
    This class associates a target, a flash, a transport and an interface
    to create a board
    """
    def __init__(self, target, flash, interface, transport = "cmsis_dap", frequency = 1000000):
        if isinstance(interface, str) == False:
            self.interface = interface
        else:
            self.interface = INTERFACE[interface].chooseInterface(INTERFACE[interface])
        self.transport = TRANSPORT[transport](self.interface)
        self.target = TARGET[target](self.transport)
        self.flash = FLASH[flash](self.target)
        self.target.setFlash(self.flash)
        self.debug_clock_frequency = frequency
        self.closed = False
        return
        
    def __enter__(self):
        return self
    
    def __exit__(self, type, value, traceback):
        self.uninit()
        return False
    
    def init(self):
        """
        Initialize the board: interface, transport and target
        """
        logging.debug("init board %s", self)
        self.interface.init()
        self.transport.init(self.debug_clock_frequency)
        self.target.init()
        
    def uninit(self, resume = True ):
        """
        Uninitialize the board: interface, transport and target.
        This function resumes the target
        """
        if self.closed:
            return
        self.closed = True
            
        logging.debug("uninit board %s", self)
        try:
            if resume:
                try:
                    self.target.resume()
                except:
                    logging.error("exception during uninit")
                    pass
            self.transport.uninit()
        finally:
            self.interface.close()
    
    def getInfo(self):
        return self.interface.getInfo()
