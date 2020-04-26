# pyOCD debugger
# Copyright (c) 2017-2019 Arm Limited
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

import os
import sys
import logging

LOG = logging.getLogger(__name__)

class ProgressReport(object):
    """!
    @brief Base progress report class.
    
    This base class implements the logic but no output.
    """
    def __init__(self, file=None):
        self._file = file or sys.stdout
        self.prev_progress = 0
        self.backwards_progress = False
        self.done = False
        self.last = 0
    
    def __call__(self, progress):
        assert progress >= 0.0

        # Cap progress at 1.0.        
        if progress > 1.0:
            progress = 1.0
            LOG.debug("progress out of bounds: %.3f", progress)

        # Reset state on 0.0
        if progress == 0.0:
            self._start()

        # Check for backwards progress
        if progress < self.prev_progress:
            self.backwards_progress = True
        self.prev_progress = progress

        # print progress bar
        if not self.done:
            self._update(progress)

            # Finish on 1.0
            if progress >= 1.0:
                self.done = True
                self._finish()
                if self.backwards_progress:
                    LOG.debug("Progress went backwards!")
    
    def _start(self):
        self.prev_progress = 0
        self.backwards_progress = False
        self.done = False
        self.last = 0

    def _update(self, progress):
        raise NotImplementedError()

    def _finish(self):
        raise NotImplementedError()

class ProgressReportTTY(ProgressReport):
    """!
    @brief Progress report subclass for TTYs.
    
    The progress bar is fully redrawn onscreen as progress is updated to give the
    impression of animation.
    """

    ## These width constants can't be changed yet without changing the code below to match.
    WIDTH = 20
    
    def _update(self, progress):
        self._file.write('\r')
        i = int(progress * self.WIDTH)
        self._file.write("[%-20s] %3d%%" % ('=' * i, round(progress * 100)))
        self._file.flush()

    def _finish(self):
        self._file.write("\n")

class ProgressReportNoTTY(ProgressReport):
    """!
    @brief Progress report subclass for non-TTY output.
    
    A simpler progress bar is used than for the TTY version. Only the difference between
    the previous and current progress is drawn for each update, making the output suitable
    for piping to a file or similar output.
    """

    ## These width constants can't be changed yet without changing the code below to match.
    WIDTH = 40
    
    def _start(self):
        super(ProgressReportNoTTY, self)._start()

        self._file.write('[' + '---|' * 9 + '----]\n[')
        self._file.flush()

    def _update(self, progress):
        i = int(progress * self.WIDTH)
        delta = i - self.last
        self._file.write('=' * delta)
        self._file.flush()
        self.last = i

    def _finish(self):
        self._file.write("]\n")
        self._file.flush()

def print_progress(file=None):
    """!
    @brief Progress printer factory.
    
    This factory function checks whether the output file is a TTY, and instantiates the
    appropriate subclass of ProgressReport.
    
    @param file The output file. Optional. If not provided, or if set to None, then sys.stdout
          will be used automatically.
    """
    
    if file is None:
        file = sys.stdout
    try:
        istty = os.isatty(file.fileno())
    except (OSError, AttributeError):
        # Either the file doesn't have a fileno method, or calling it returned an
        # error. In either case, just assume we're not connected to a TTY.
        istty = False
    
    klass = ProgressReportTTY if istty else ProgressReportNoTTY
    return klass(file)

