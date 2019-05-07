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
import subprocess
import platform
import logging

try:
    from plistlib import loads
except ImportError:
    from plistlib import readPlistFromString as loads
from xml.parsers.expat import ExpatError

from .base import StlinkDetectBase


LOG = logging.getLogger(__name__)

mbed_volume_name_match = re.compile(r"\b(mbed)\b", re.I)


def _plist_from_popen(popen):
    out, _ = popen.communicate()
    if not out:
        return []
    try:
        return loads(out)
    except ExpatError:
        return []


def _prune(current, keys):
    """ Reduce the amount of data we have to sift through to only
        include the specified keys, and children that contain the
        specified keys
    """
    pruned_current = {k: current[k] for k in keys if k in current}
    pruned_children = list(
        filter(
            None, [_prune(c, keys) for c in current.get("IORegistryEntryChildren", [])]
        )
    )
    keep_current = any(k in current for k in keys) or pruned_children
    if keep_current:
        if pruned_children:
            pruned_current["IORegistryEntryChildren"] = pruned_children
        return pruned_current
    else:
        return {}


def _dfs_usb_info(obj, parents):
    """ Find all of the usb info that we can from this particular IORegistry
        tree with depth first search (and searching the parent stack....)
    """
    output = {}
    if (
        "BSD Name" in obj
        and obj["BSD Name"].startswith("disk")
        and mbed_volume_name_match.search(obj["IORegistryEntryName"])
    ):
        disk_id = obj["BSD Name"]
        usb_info = {"serial": None}
        for parent in [obj] + parents:
            if "USB Serial Number" in parent:
                usb_info["serial"] = parent["USB Serial Number"]
                break
        output[disk_id] = usb_info
    for child in obj.get("IORegistryEntryChildren", []):
        output.update(_dfs_usb_info(child, [obj] + parents))
    return output


class StlinkDetectDarwin(StlinkDetectBase):
    """ mbed-enabled platform detection on Mac OS X
    """

    def __init__(self, **kwargs):
        StlinkDetectBase.__init__(self, **kwargs)
        self.mac_version = float(".".join(platform.mac_ver()[0].split(".")[:2]))

    def find_candidates(self):
        # {volume_id: {serial:, vendor_id:, product_id:, tty:}}
        volumes = self._volumes()

        # {volume_id: mount_point}
        mounts = self._mount_points()
        return [
            {
                "mount_point": mounts[v],
                "target_id_usb_id": volumes[v].get("serial"),
                "vendor_id": volumes[v].get("vendor_id"),
                "product_id": volumes[v].get("product_id"),
            }
            for v in set(volumes.keys()) and set(mounts.keys())
            if v in mounts and v in volumes
        ]

    def _mount_points(self):
        """ Returns map {volume_id: mount_point} """
        diskutil_ls = subprocess.Popen(
            ["diskutil", "list", "-plist"], stdout=subprocess.PIPE
        )
        disks = _plist_from_popen(diskutil_ls)

        return {
            disk["DeviceIdentifier"]: disk.get("MountPoint", None)
            for disk in disks["AllDisksAndPartitions"]
        }

    def _volumes(self):
        """ returns a map {volume_id: {serial:, vendor_id:, product_id:, tty:}"""

        # to find all the possible mbed volumes, we look for registry entries
        # under all possible USB tree which have a "BSD Name" that starts with
        # "disk" # (i.e. this is a USB disk), and have a IORegistryEntryName that
        # matches /\cmbed/
        # Once we've found a disk, we can search up for a parent with a valid
        # serial number, and then search down again to find a tty that's part
        # of the same composite device
        # ioreg -a -r -n <usb_controller_name> -l
        usb_controllers = [
            # Leaving these here for reference. The code nominally scanned each controller,
            # but a bug (?) caused it to only pay attention to the last one. That seems to
            # work fine, so the others are commented out.
#             "AppleUSBXHCI",
#             "AppleUSBUHCI",
#             "AppleUSBEHCI",
#             "AppleUSBOHCI",
            "IOUSBHostDevice",
        ]

        cmp_par = "-n"
        # For El Captain we need to list all the instances of (-c) rather than
        # compare names (-n)
        if self.mac_version >= 10.11:
            cmp_par = "-c"

        for usb_controller in usb_controllers:
            ioreg_usb = subprocess.Popen(
                ["ioreg", "-a", "-r", cmp_par, usb_controller, "-l"],
                stdout=subprocess.PIPE,
            )
            usb_tree = _plist_from_popen(ioreg_usb)

        r = {}

        for name, obj in enumerate(usb_tree):
            pruned_obj = _prune(
                obj,
                [
                    "USB Serial Number",
                    "idVendor",
                    "BSD Name",
                    "IORegistryEntryName",
                    "idProduct",
                ],
            )
            r.update(_dfs_usb_info(pruned_obj, []))

        return r
