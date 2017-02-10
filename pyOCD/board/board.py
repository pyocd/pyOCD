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

from pyOCD.target import (TARGET, FLASH)

import logging
import traceback

class Board(object):
    """
    This class associates a target, a flash and a link to create a board
    """
    def __init__(self, target, link, frequency=1000000):
        self.link = link
        self.target = TARGET[target.lower()](self.link)
        self.flash = FLASH[target.lower()](self.target)
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
        Initialize the board
        """
        logging.debug("init board %s", self)
        self.link.set_clock(self.debug_clock_frequency)
        self.link.set_deferred_transfer(True)
        self.target.init()

    def uninit(self, resume=True):
        """
        Uninitialize the board: link and target.
        This function resumes the target
        """
        if self.closed:
            return
        self.closed = True

        logging.debug("uninit board %s", self)
        if resume:
            try:
                self.target.resume()
            except:
                logging.error("target exception during uninit:")
                traceback.print_exc()
        try:
            self.target.disconnect()
        except:
            logging.error("link exception during target disconnect:")
            traceback.print_exc()
        try:
            self.link.disconnect()
        except:
            logging.error("link exception during link disconnect:")
            traceback.print_exc()
        try:
            self.link.close()
        except:
            logging.error("link exception during uninit:")
            traceback.print_exc()

    def getInfo(self):
        return ""
