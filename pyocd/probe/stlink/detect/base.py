# Copyright (c) 2018-2019, Arm Limited and affiliates.
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

import re
from abc import ABCMeta, abstractmethod
from io import open
from os import listdir
from os.path import expanduser, isfile, join, exists, isdir
import logging
import functools

LOG = logging.getLogger(__name__)


class StlinkDetectBase(object):
    """ Base class for stlink detection, defines public interface for
    mbed-enabled stlink devices detection for various hosts
    """

    __metaclass__ = ABCMeta

    MBED_HTM_NAME = "mbed.htm"

    def __init__(self):
        """ ctor
        """
        pass

    @abstractmethod
    def find_candidates(self):
        """Find all candidate devices connected to this computer

        Note: Should not open any files

        @return A dict with the keys 'mount_point', 'serial_port' and 'target_id_usb_id'
        """
        raise NotImplementedError

    def list_mbeds(self):
        """ List details of connected devices
        @return Returns list of structures with detailed info about each mbed
        @details Function returns list of dictionaries with mbed attributes
          'mount_point', TargetID name etc.
        Function returns mbed list with platform names if possible
        """
        platform_count = {}
        candidates = list(self.find_candidates())
        result = []
        for device in candidates:
            if not device.get("mount_point", None):
                continue
            device["target_id"] = device["target_id_usb_id"]
            self._update_device_from_fs(device)
            result.append(device)

        return result

    def _update_device_from_fs(self, device):
        """ Updates the device information based on files from its 'mount_point'
            @param device Dictionary containing device information
        """
        try:
            directory_entries = listdir(device["mount_point"])

            # Always try to update using daplink compatible boards processself.
            # This is done for backwards compatibility.
            lowercase_directory_entries = [e.lower() for e in directory_entries]
            if self.MBED_HTM_NAME.lower() in lowercase_directory_entries:
                self._update_device_from_htm(device)

        except (OSError, IOError) as e:
            LOG.warning(
                'Marking device with mount point "%s" as unmounted due to the '
                "following error: %s",
                device["mount_point"],
                e,
            )
            device["mount_point"] = None

    def _update_device_from_htm(self, device):
        """Set the 'target_id', 'target_id_mbed_htm', 'platform_name' and
        'daplink_*' attributes by reading from mbed.htm on the device
        """
        htm_target_id, daplink_info = self._read_htm_ids(device["mount_point"])
        if htm_target_id:
            device["target_id"] = htm_target_id
        else:
            LOG.debug(
                "Could not read htm on from usb id %s. Falling back to usb id",
                device["target_id_usb_id"],
            )
            device["target_id"] = device["target_id_usb_id"]
        device["target_id_mbed_htm"] = htm_target_id

    # Private functions supporting API
    def _read_htm_ids(self, mount_point):
        """! Function scans mbed.htm to get information about TargetID.
        @param mount_point mbed mount point (disk / drive letter)
        @return Function returns targetID, in case of failure returns None.
        @details Note: This function should be improved to scan variety of boards'
          mbed.htm files
        """
        result = {}
        target_id = None
        for line in self._htm_lines(mount_point):
            target_id = target_id or self._target_id_from_htm(line)
        return target_id, result

    def _htm_lines(self, mount_point):
        if mount_point:
            mbed_htm_path = join(mount_point, self.MBED_HTM_NAME)
            with open(mbed_htm_path, "r") as f:
                return f.readlines()

    def _target_id_from_htm(self, line):
        """! Extract Target id from htm line.
        @return Target id or None
        """
        # Detecting modern mbed.htm file format
        m = re.search("\\?code=([a-fA-F0-9]+)", line)
        if m:
            result = m.groups()[0]
            return result
        # Last resort, we can try to see if old mbed.htm format is there
        m = re.search("\\?auth=([a-fA-F0-9]+)", line)
        if m:
            result = m.groups()[0]
            return result

        return None

    def mount_point_ready(self, path):
        """! Check if a mount point is ready for file operations
        """
        return exists(path) and isdir(path)

    @staticmethod
    def _run_cli_process(cmd, shell=True):
        """! Runs command as a process and return stdout, stderr and ret code
        @param cmd Command to execute
        @return Tuple of (stdout, stderr, returncode)
        """
        from subprocess import Popen, PIPE

        p = Popen(cmd, shell=shell, stdout=PIPE, stderr=PIPE)
        _stdout, _stderr = p.communicate()
        return _stdout, _stderr, p.returncode

