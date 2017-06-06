"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2015 ARM Limited

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

import threading
import logging
# Make cmsis_svd optional.
try:
    from cmsis_svd.parser import SVDParser
    isCmsisSvdAvailable = True
except ImportError:
    isCmsisSvdAvailable = False

class SVDFile(object):
    def __init__(self, filename=None, vendor=None, is_local=False):
        self.filename = filename
        self.vendor = vendor
        self.is_local = is_local
        self.device = None

    def load(self):
        if not isCmsisSvdAvailable:
            return

        if self.is_local:
            self.device = SVDParser.for_xml_file(self.filename).get_device()
        else:
            self.device = SVDParser.for_packaged_svd(self.vendor, self.filename).get_device()

## @brief Thread to read an SVD file in the background.
class SVDLoader(threading.Thread):
    def __init__(self, svdFile, completionCallback):
        super(SVDLoader, self).__init__(name='load-svd')
        self.daemon = True
        self._svd_location = svdFile
        self._svd_device = None
        self._callback = completionCallback

    @property
    def device(self):
        if not self._svd_device:
            self.join()
        return self._svd_device

    def load(self):
        if not self._svd_device and self._svd_location:
            self.start()

    def run(self):
        try:
            self._svd_location.load()
            self._svd_device = self._svd_location.device
            if self._callback:
                self._callback(self._svd_device)
        except IOError:
            logging.warning("Failed to load SVD file %s", self._svd_location.filename)
