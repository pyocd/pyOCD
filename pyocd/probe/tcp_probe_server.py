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
import threading
import json
import socket
from socketserver import (ThreadingTCPServer, StreamRequestHandler)

from .shared_probe_proxy import SharedDebugProbeProxy
from ..core import exceptions
from .debug_probe import DebugProbe
from ..coresight.ap import (APVersion, APv1Address, APv2Address)

LOG = logging.getLogger(__name__)

TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

class DebugProbeServer(threading.Thread):
    """! @brief Shares a debug probe over a TCP server.
    
    When the start() method is called, a new daemon thread is created to run the server. The server
    can be terminated by calling the stop() method, which will also kill the server thread.
    """
    
    def __init__(self, session, probe, port=None, serve_local_only=None):
        """! @brief Constructor.
        
        @param self The object.
        @param session A @ref pyocd.core.session.Session "Session" object. Does not need to have a
            probe assigned to it.
        @param probe Either the @ref pyocd.probe.debug_probe.DebugProbe "DebugProbe" object to serve
            or a @ref pyocd.probe.shared_probe_proxy.SharedDebugProbeProxy "SharedDebugProbeProxy".
            Doesn't have to be associated with a session, and should not be opened already. If not
            already an instance of
            @ref pyocd.probe.shared_probe_proxy.SharedDebugProbeProxy "SharedDebugProbeProxy"
            then a new proxy is created to allow the probe to be shared by multiple connections.
        @param port The TCP port number. Defaults to the 'probeserver.port' option if not provided.
        @param serve_local_only Optional Boolean. Whether to restrict the server to be accessible only from
            localhost. If not specified (set to None), then the 'serve_local_only' session option is used.
        """
        super(DebugProbeServer, self).__init__()
        
        # Configure the server thread.
        self.name = "debug probe %s server" % probe.unique_id
        self.daemon = True
        
        # Init instance variables.
        self._session = session
        self._probe = probe
        self._is_running = False
        
        # Make sure we have a shared proxy for the probe.
        if isinstance(probe, SharedDebugProbeProxy):
            self._proxy = probe
        else:
            self._proxy = SharedDebugProbeProxy(probe)
        
        # Get the port from options if not specified.
        if port is None:
            self._port = session.options.get('probeserver.port')
        else:
            self._port = port
        
        # Default to the serve_local_only session option.
        if serve_local_only is None:
            serve_local_only = session.options.get('serve_local_only')
        
        host = 'localhost' if serve_local_only else ''
        address = (host, self._port)
        
        # Create the server and bind to the address, but don't start running yet.
        self._server = TCPProbeServer(address, session, self._proxy)
        self._server.server_bind()
        
    def start(self):
        """! @brief Start the server thread and begin listening."""
        self._server.server_activate()
        super(DebugProbeServer, self).start()
    
    def stop(self):
        """! @brief Shut down the server.
        
        Any open connections will be forcibly closed. This function does not return until the
        server thread has exited.
        """
        self._server.shutdown()
        self.join()
    
    @property
    def is_running(self):
        """! @brief Whether the server thread is running."""
        return self._is_running
    
    @property
    def port(self):
        """! @brief The server's port.
        
        If port 0 was specified in the constructor, then, after start() is called, this will reflect the actual port
        on which the server is listening.
        """
        return self._port
    
    def run(self):
        """! @brief The server thread implementation."""
        self._is_running = True
        
        # Read back the actual port if 0 was specified.
        if self._port == 0:
            self._port = self._server.socket.getsockname()[1]
        
        LOG.info("Serving debug probe %s (%s) on port %i",
                self._probe.description, self._probe.unique_id, self._port)
        self._server.serve_forever()
        self._is_running = False

class TCPProbeServer(ThreadingTCPServer):
    """! @brief TCP server subclass that carries the session and probe being served."""
    
    # Change the default SO_REUSEADDR setting.
    allow_reuse_address = True
    
    def __init__(self, server_address, session, probe):
        self._session = session
        self._probe = probe
        ThreadingTCPServer.__init__(self, server_address, DebugProbeRequestHandler,
            bind_and_activate=False)
    
    @property
    def session(self):
        return self._session
    
    @property
    def probe(self):
        return self._probe
    
    def handle_error(self, request, client_address):
        LOG.error("Error while handling client request (client address %s):", client_address,
            exc_info=self._session.log_tracebacks)

class DebugProbeRequestHandler(StreamRequestHandler):
    """!
    @brief Probe server request handler.
    
    This class implements the server side for the remote probe protocol.

    request:
    ````
    {
      "id": <int>,
      "request": <str>,
      ["arguments": <list>]
    }
    ````

    response:
    ````
    {
      "id": <int>,
      "status": <int>,
      ["error": <str>,]
      ["response": <value>]
    }
    ````
    """
    
    ## Current version of the remote probe protocol.
    PROTOCOL_VERSION = 1
    
    class StatusCode:
        """! @brief Constants for errors reported from the server."""
        GENERAL_ERROR = 1
        PROBE_DISCONNECTED = 2
        PROBE_ERROR = 3
        TRANSFER_ERROR = 10
        TRANSFER_TIMEOUT = 11
        TRANSFER_FAULT = 12

    def setup(self):
        # Do a DNS lookup on the client.
        try:
            info = socket.gethostbyaddr(self.client_address[0])
            self._client_domain = info[0]
        except socket.herror:
            self._client_domain = self.client_address[0]
        
        LOG.info("Remote probe client connected (%s from port %i)", self._client_domain, self.client_address[1])
        
        # Get the session and probe we're serving from the server.
        self._session = self.server.session
        self._probe = self.server.probe
        
        # Give the probe a session if it doesn't have one, in case it needs to access settings.
        # TODO: create a session proxy so client-side options can be accessed
        if self._probe.session is None:
            self._probe.session = self._session
        
        # Dict to store handles for AP memory interfaces.
        self._next_ap_memif_handle = 0
        self._ap_memif_handles = {}
    
        # Create the request handlers dict here so we can reference bound probe methods.
        self._REQUEST_HANDLERS = {
                # Command                Handler                            Arg count
                'hello':                (self._request__hello,              1   ),
                'readprop':             (self._request__read_property,      1   ),
                'open':                 (self._probe.open,                  0   ), # 'open'
                'close':                (self._probe.close,                 0   ), # 'close'
                'lock':                 (self._probe.lock,                  0   ), # 'lock'
                'unlock':               (self._probe.unlock,                0   ), # 'unlock'
                'connect':              (self._request__connect,            1   ), # 'connect', protocol:str
                'disconnect':           (self._probe.disconnect,            0   ), # 'disconnect'
                'swj_sequence':         (self._probe.swj_sequence,          2   ), # 'swj_sequence', length:int, bits:int
                'swd_sequence':         (self._probe.swd_sequence,          1   ), # 'swd_sequence', sequences:List[Union[Tuple[int], Tuple[int, int]]] -> Tuple[int, List[bytes]]
                'jtag_sequence':        (self._probe.jtag_sequence,         4   ), # 'jtag_sequence', cycles:int, tms:int, read_tdo:bool, tdi:int -> Union[None, int]
                'set_clock':            (self._probe.set_clock,             1   ), # 'set_clock', freq:int
                'reset':                (self._probe.reset,                 0   ), # 'reset'
                'assert_reset':         (self._probe.assert_reset,          1   ), # 'assert_reset', asserted:bool
                'is_reset_asserted':    (self._probe.is_reset_asserted,     0   ), # 'is_reset_asserted'
                'flush':                (self._probe.flush,                 0   ), # 'flush'
                'read_dp':              (self._probe.read_dp,               1   ), # 'read_dp', addr:int -> int
                'write_dp':             (self._probe.write_dp,              2   ), # 'write_dp', addr:int, data:int
                'read_ap':              (self._probe.read_ap,               1   ), # 'read_ap', addr:int -> int
                'write_ap':             (self._probe.write_ap,              2   ), # 'write_ap', addr:int, data:int
                'read_ap_multiple':     (self._probe.read_ap_multiple,      2   ), # 'read_ap_multiple', addr:int, count:int -> List[int]
                'write_ap_multiple':    (self._probe.write_ap_multiple,     2   ), # 'write_ap_multiple', addr:int, data:List[int]
                'get_memory_interface_for_ap': (self._request__get_memory_interface_for_ap, 2), # 'get_memory_interface_for_ap', ap_address_version:int, ap_nominal_address:int -> handle:int|null
                'swo_start':            (self._probe.swo_start,             1   ), # 'swo_start', baudrate:int
                'swo_stop':             (self._probe.swo_stop,              0   ), # 'swo_stop'
                'swo_read':             (self._request__swo_read,           0   ), # 'swo_read' -> List[int]
                'read_mem':             (self._request__read_mem,           3   ), # 'read_mem', handle:int, addr:int, xfer_size:int -> int
                'write_mem':            (self._request__write_mem,          4   ), # 'write_mem', handle:int, addr:int, value:int, xfer_size:int
                'read_block32':         (self._request__read_block32,       3   ), # 'read_block32', handle:int, addr:int, word_count:int -> List[int]
                'write_block32':        (self._request__write_block32,      3   ), # 'write_block32', handle:int, addr:int, data:List[int]
                'read_block8':          (self._request__read_block8,        3   ), # 'read_block8', handle:int, addr:int, word_count:int -> List[int]
                'write_block8':         (self._request__write_block8,       3   ), # 'write_block8', handle:int, addr:int, data:List[int]
            }
        
        # Let superclass do its thing. (Can't use super() here because the superclass isn't derived
        # from object in Py2.)
        StreamRequestHandler.setup(self)
    
    def finish(self):
        LOG.info("Remote probe client disconnected (%s from port %i)", self._client_domain, self.client_address[1])
        
        self._session = None
        StreamRequestHandler.finish(self)
    
    def _send_error_response(self, status=1, message=""):
        response_dict = {
                "id": self._current_request_id,
                "status": status,
                "error": message,
            }
        response = json.dumps(response_dict)
        TRACE.debug("response: %s", response)
        response_encoded = response.encode('utf-8')
        self.wfile.write(response_encoded + b"\n")
        
    def _send_response(self, result):
        response_dict = {
                "id": self._current_request_id,
                "status": 0,
            }
        if result is not None:
            response_dict["result"] = result
        response = json.dumps(response_dict)
        TRACE.debug("response: %s", response)
        response_encoded = response.encode('utf-8')
        self.wfile.write(response_encoded + b"\n")
        
    def handle(self):
        # Process requests until the connection is closed.
        while True:
            try:
                request = None
                request_dict = None
                self._current_request_id = -1
                
                # Read request line.
                request = self.rfile.readline()
                TRACE.debug("request: %s", request)
                if len(request) == 0:
                    LOG.debug("empty request, closing connection")
                    return
                
                try:
                    request_dict = json.loads(request)
                except json.JSONDecodeError:
                    self._send_error_response(message="invalid request format")
                    continue
            
                if not isinstance(request_dict, dict):
                    self._send_error_response(message="invalid request format")
                    continue
                    
                if 'id' not in request_dict:
                    self._send_error_response(message="missing request ID")
                    continue
                self._current_request_id = request_dict['id']
                
                if 'request' not in request_dict:
                    self._send_error_response(message="missing request field")
                    continue
                request_type = request_dict['request']
                
                # Get arguments. If the key isn't present then there are no arguments.
                request_args = request_dict.get('arguments', [])
            
                if not isinstance(request_args, list):
                    self._send_error_response(message="invalid request arguments format")
                    continue
                
                if request_type not in self._REQUEST_HANDLERS:
                    self._send_error_response(message="unknown request type")
                    continue
                handler, arg_count = self._REQUEST_HANDLERS[request_type]
                self._check_args(request_args, arg_count)
                result = handler(*request_args)
                
                # Send a success response.
                self._send_response(result)
            # Catch all exceptions so that an error response can be returned, to not leave the client hanging.
            except Exception as err:
                # Only send an error response if we received an request.
                if request is not None:
                    LOG.error("Error while processing %s request from client: %s", request, err,
                            exc_info=self._session.log_tracebacks)
                    self._send_error_response(status=self._get_exception_status_code(err),
                            message=str(err))
                else:
                    LOG.error("Error before request was received: %s", err,
                            exc_info=self._session.log_tracebacks)
                # Reraise non-pyocd errors.
                if not isinstance(err, exceptions.Error):
                    raise
    
    def _get_exception_status_code(self, err):
        """! @brief Convert an exception class into a status code."""
        # Must test the exception class in order of specific to general.
        if isinstance(err, exceptions.ProbeDisconnected):
            return self.StatusCode.PROBE_DISCONNECTED
        elif isinstance(err, exceptions.ProbeError):
            return self.StatusCode.PROBE_ERROR
        elif isinstance(err, exceptions.TransferFaultError):
            return self.StatusCode.TRANSFER_FAULT
        elif isinstance(err, exceptions.TransferTimeoutError):
            return self.StatusCode.TRANSFER_TIMEOUT
        elif isinstance(err, exceptions.TransferError):
            return self.StatusCode.TRANSFER_ERROR
        else:
            return self.StatusCode.GENERAL_ERROR
    
    def _check_args(self, args, count):
        if len(args) != count:
            raise exceptions.Error("malformed request; invalid number of arguments")
    
    def _request__hello(self, version):
        # 'hello', protocol-version:int
        if version != self.PROTOCOL_VERSION:
            raise exceptions.Error("client requested unsupported protocol version %i (expected %i)" %
                    (version, self.PROTOCOL_VERSION))
    
    def _request__read_property(self, name):
        # 'readprop', name:str
        if not hasattr(self._probe, name):
            raise exceptions.Error("unknown property name '%s' requested" % name)
        value = getattr(self._probe, name)
        # Run the property value through a value transformer if one is defined for this property.
        if name in self._PROPERTY_CONVERTERS:
            value = self._PROPERTY_CONVERTERS[name](value)
        return value
    
    def _request__connect(self, protocol_name):
        # 'connect', protocol:str
        try:
            protocol = DebugProbe.Protocol[protocol_name]
        except KeyError:
            raise exceptions.Error("invalid protocol name %s" % protocol_name)
        self._probe.connect(protocol)
    
    def _request__get_memory_interface_for_ap(self, ap_address_version, ap_nominal_address):
        # 'get_memory_interface_for_ap', ap_address_version:int, ap_nominal_address:int -> handle:int|null
        ap_version = APVersion(ap_address_version)
        if ap_version == APVersion.APv1:
            ap_address = APv1Address(ap_nominal_address)
        elif ap_version == APVersion.APv2:
            ap_address = APv2Address(ap_nominal_address)
        else:
            raise exceptions.Error("invalid AP version in remote get_memory_interface_for_ap request")

        memif = self._probe.get_memory_interface_for_ap(ap_address)
        if memif is not None:
            handle = self._next_ap_memif_handle
            self._next_ap_memif_handle += 1
            self._ap_memif_handles[handle] = memif
            LOG.debug("creating memif for AP%s (handle %i)", ap_address, handle)
        else:
            handle = None
        return handle
    
    def _request__swo_read(self):
        return list(self._probe.swo_read())

    def _request__read_mem(self, handle, addr, xfer_size):
        # 'read_mem', handle:int, addr:int, xfer_size:int -> int
        if handle not in self._ap_memif_handles:
            raise exceptions.Error("invalid handle received from remote memory access")
        return self._ap_memif_handles[handle].read_memory(addr, xfer_size, now=True)
    
    def _request__write_mem(self, handle, addr, value, xfer_size):
        # 'write_mem', handle:int, addr:int, value:int, xfer_size:int
        if handle not in self._ap_memif_handles:
            raise exceptions.Error("invalid handle received from remote memory access")
        self._ap_memif_handles[handle].write_memory(addr, value, xfer_size)
    
    def _request__read_block32(self, handle, addr, word_count):
        # 'read_block32', handle:int, addr:int, word_count:int -> List[int]
        # TODO use base64 data
        if handle not in self._ap_memif_handles:
            raise exceptions.Error("invalid handle received from remote memory access")
        return self._ap_memif_handles[handle].read_memory_block32(addr, word_count)
    
    def _request__write_block32(self, handle, addr, data):
        # 'write_block32', handle:int, addr:int, data:List[int]
        # TODO use base64 data
        if handle not in self._ap_memif_handles:
            raise exceptions.Error("invalid handle received from remote memory access")
        self._ap_memif_handles[handle].write_memory_block32(addr, data)
    
    def _request__read_block8(self, handle, addr, word_count):
        # 'read_block8', handle:int, addr:int, word_count:int -> List[int]
        # TODO use base64 data
        if handle not in self._ap_memif_handles:
            raise exceptions.Error("invalid handle received from remote memory access")
        return self._ap_memif_handles[handle].read_memory_block8(addr, word_count)
    
    def _request__write_block8(self, handle, addr, data):
        # 'write_block8', handle:int, addr:int, data:List[int]
        # TODO use base64 data
        if handle not in self._ap_memif_handles:
            raise exceptions.Error("invalid handle received from remote memory access")
        self._ap_memif_handles[handle].write_memory_block8(addr, data)

    _PROPERTY_CONVERTERS = {
            'capabilities':                 lambda value: [v.name for v in value],
            'supported_wire_protocols':     lambda value: [v.name for v in value],
            'wire_protocol':                lambda value: value.name if (value is not None) else None,
        }

