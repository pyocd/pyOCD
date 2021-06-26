# pyOCD debugger
# Copyright (c) 2020-2021 Arm Limited
# Copyright (c) 2021 Chris Reed
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

import logging
import json
import threading

from .debug_probe import DebugProbe
from ..core import exceptions
from ..core.memory_interface import MemoryInterface
from ..core.plugin import Plugin
from ..utility.sockets import ClientSocket

LOG = logging.getLogger(__name__)

TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

class TCPClientProbe(DebugProbe):
    """! @brief Probe class that connects to a debug probe server."""
    
    DEFAULT_PORT = 5555
    
    PROTOCOL_VERSION = 1

    class StatusCode:
        """! @brief Constants for errors reported from the server."""
        GENERAL_ERROR = 1
        PROBE_DISCONNECTED = 2
        PROBE_ERROR = 3
        TRANSFER_ERROR = 10
        TRANSFER_TIMEOUT = 11
        TRANSFER_FAULT = 12
    
    ## Map from status code to exception class.
    STATUS_CODE_CLASS_MAP = {
        StatusCode.GENERAL_ERROR: exceptions.Error,
        StatusCode.PROBE_DISCONNECTED: exceptions.ProbeDisconnected,
        StatusCode.PROBE_ERROR: exceptions.ProbeError,
        StatusCode.TRANSFER_ERROR: exceptions.TransferError,
        StatusCode.TRANSFER_TIMEOUT: exceptions.TransferTimeoutError,
        StatusCode.TRANSFER_FAULT: exceptions.TransferFaultError,
        }
    
    @classmethod
    def _extract_address(cls, unique_id):
        parts = unique_id.split(':', 1)
        if len(parts) == 1:
            port = cls.DEFAULT_PORT
        else:
            port = int(parts[1])
        return parts[0], port
    
    @classmethod
    def get_all_connected_probes(cls, unique_id=None, is_explicit=False):
        if is_explicit and unique_id is not None:
            return [cls(unique_id)]
        else:
            return []
    
    @classmethod
    def get_probe_with_id(cls, unique_id, is_explicit=False):
        return cls(unique_id) if is_explicit else None

    def __init__(self, unique_id):
        """! @brief Constructor."""
        super(TCPClientProbe, self).__init__()
        self._uid = unique_id
        hostname, port = self._extract_address(unique_id)
        self._socket = ClientSocket(hostname, port)
        self._is_open = False
        self._request_id = 0
        self._lock_count = 0
        self._lock_count_lock = threading.RLock()
    
    @property
    def vendor_name(self):
        return self._read_property('vendor_name', "vendor")
    
    @property
    def product_name(self):
        return self._read_property('product_name', "product")
    
    @property
    def supported_wire_protocols(self):
        return self._read_property('supported_wire_protocols')

    @property
    def unique_id(self):
        return self._uid

    @property
    def wire_protocol(self):
        return self._read_property('wire_protocol')
    
    @property
    def is_open(self):
        return self._is_open
    
    @property
    def capabilities(self):
        return self._read_property('capabilities')
    
    @property
    def request_id(self):
        """! @brief Generate a new request ID."""
        rid = self._request_id
        self._request_id += 1
        return rid
    
    def _perform_request(self, request, *args):
        """! Execute a request-reply transaction with the server.

        Request:
        
        ````
        {
          "id": <int>,
          "request": <str>,
          ["arguments": <list>]
        }
        ````

        Response:
        
        ````
        {
          "id": <int>,
          "status": <int>,
          ["error": <str>,]
          ["result": <value>]
        }
        ````
        """
        # Protect requests with the local lock.
        with self._lock:
            rq = {
                    "id": self.request_id,
                    "request": request,
                }
            if len(args):
                rq["arguments"] = args
            formatted_request = json.dumps(rq)
            TRACE.debug("Request: %s", formatted_request)
        
            # Send request to server.
            self._socket.write(formatted_request.encode('utf-8') + b"\n")
        
            # Read response.
            response_data = self._socket.readline().decode('utf-8').strip()
            decoded_response = json.loads(response_data)
            TRACE.debug("decoded_response = %s", decoded_response)
        
            # Check for required keys.
            if ('id' not in decoded_response) or ('status' not in decoded_response):
                raise exceptions.ProbeError("malformed response from server; missing required field")
        
            # Check response status.
            status = decoded_response['status']
            if status != 0:
                # Get the error message.
                error = decoded_response.get('error', "(missing error message key)")
                LOG.debug("error received from server for command %s (status code %i): %s",
                        request, status, error)
            
                # Create an appropriate local exception based on the status code.
                exc = self._create_exception_from_status_code(status,
                        "error received from server for command %s (status code %i): %s"
                        % (request, status, error))
                raise exc
        
            # Get response value. If not present then there was no return value from the command
            result = decoded_response.get('result', None)
        
            return result
    
    def _create_exception_from_status_code(self, status, message):
        """! @brief Convert a status code into an exception instance."""
        # Other status codes can use the map.
        return self.STATUS_CODE_CLASS_MAP.get(status, exceptions.ProbeError)(message)

    _PROPERTY_CONVERTERS = {
            'capabilities':                 lambda value: [DebugProbe.Capability[v] for v in value],
            'supported_wire_protocols':     lambda value: [DebugProbe.Protocol[v] for v in value],
            'wire_protocol':                lambda value: DebugProbe.Protocol[value] if (value is not None) else None,
        }

    def _read_property(self, name, default=None):
        if not self.is_open:
            return default
        result = self._perform_request('readprop', name)
        if name in self._PROPERTY_CONVERTERS:
            result = self._PROPERTY_CONVERTERS[name](result)
        return result

    def open(self):
        if not self._is_open:
            self._socket.connect()
            self._is_open = True
            self._socket.set_timeout(0.1)
        
        # Send hello message.
        self._perform_request('hello', self.PROTOCOL_VERSION)
        
        self._perform_request('open')
    
    def close(self):
        if self._is_open:
            self._perform_request('close')
            self._socket.close()
            self._is_open = False
    
    def lock(self):
        # The lock count is then used to only send the remote lock request once.
        with self._lock_count_lock:
            if self._lock_count == 0:
                self._perform_request('lock')
            self._lock_count += 1
    
    def unlock(self):
        # The remote unlock request is only sent when the outermost nested locking is unlocked.
        with self._lock_count_lock:
            assert self._lock_count > 0
            self._lock_count -= 1
            if self._lock_count == 0:
                self._perform_request('unlock')

    ## @name Target control
    ##@{

    def connect(self, protocol=None):
        self._perform_request('connect', protocol.name)

    def disconnect(self):
        self._perform_request('disconnect')

    def swj_sequence(self, length, bits):
        self._perform_request('swj_sequence', length, bits)

    def swd_sequence(self, sequences):
        return self._perform_request('swd_sequence', sequences)

    def jtag_sequence(self, cycles, tms, read_tdo, tdi):
        return self._perform_request('jtag_sequence', cycles, tms, read_tdo, tdi)

    def set_clock(self, frequency):
        self._perform_request('set_clock', frequency)

    def reset(self):
        self._perform_request('reset')

    def assert_reset(self, asserted):
        self._perform_request('assert_reset', asserted)
    
    def is_reset_asserted(self):
        return self._perform_request('is_reset_asserted')

    def flush(self):
        self._perform_request('flush')

    ##@}

    ## @name DAP access
    ##@{

    def read_dp(self, addr, now=True):
        result = self._perform_request('read_dp', addr)
        
        def read_dp_cb():
            # TODO need to raise any exception from here
            return result
        
        return result if now else read_dp_cb

    def write_dp(self, addr, data):
        self._perform_request('write_dp', addr, data)

    def read_ap(self, addr, now=True):
        result = self._perform_request('read_ap', addr)
        
        def read_ap_cb():
            # TODO need to raise any exception from here
            return result
        
        return result if now else read_ap_cb

    def write_ap(self, addr, data):
        self._perform_request('write_ap', addr, data)

    def read_ap_multiple(self, addr, count=1, now=True):
        results = self._perform_request('read_ap_multiple', addr, count)
        
        def read_ap_multiple_cb():
            # TODO need to raise any exception from here
            return results
        
        return results if now else read_ap_multiple_cb

    def write_ap_multiple(self, addr, values):
        self._perform_request('write_ap_multiple', addr, values)
    
    def get_memory_interface_for_ap(self, ap_address):
        handle = self._perform_request('get_memory_interface_for_ap',
                ap_address.ap_version.value, ap_address.nominal_address)
        if handle is None:
            return None
        return RemoteMemoryInterface(self, handle)
    
    ##@}

    ## @name SWO
    ##@{

    def has_swo(self):
        return self._perform_request('has_swo')

    def swo_start(self, baudrate):
        self._perform_request('swo_start', baudrate)

    def swo_stop(self):
        self._perform_request('swo_stop')

    def swo_read(self):
        return self._perform_request('swo_read')

    ##@}
    
class RemoteMemoryInterface(MemoryInterface):
    """! @brief Local proxy for a remote memory interface."""
    
    def __init__(self, remote_probe, handle):
        self._remote_probe = remote_probe
        self._handle = handle

    def write_memory(self, addr, data, transfer_size=32):
        assert transfer_size in (8, 16, 32)
        self._remote_probe._perform_request('write_mem', self._handle, addr, data, transfer_size)
        
    def read_memory(self, addr, transfer_size=32, now=True):
        assert transfer_size in (8, 16, 32)
        result = self._remote_probe._perform_request('read_mem', self._handle, addr, transfer_size)
        
        def read_callback():
            return result
        return result if now else read_callback

    def write_memory_block32(self, addr, data):
        self._remote_probe._perform_request('write_block32', self._handle, addr, data)

    def read_memory_block32(self, addr, size):
        return self._remote_probe._perform_request('read_block32', self._handle, addr, size)

    def write_memory_block8(self, addr, data):
        self._remote_probe._perform_request('write_block8', self._handle, addr, data)

    def read_memory_block8(self, addr, size):
        return self._remote_probe._perform_request('read_block8', self._handle, addr, size)

class TCPClientProbePlugin(Plugin):
    """! @brief Plugin class for TCPClientProbePlugin."""
    
    def load(self):
        return TCPClientProbe
    
    @property
    def name(self):
        return "remote"
    
    @property
    def description(self):
        return "Client for the pyOCD debug probe server"

