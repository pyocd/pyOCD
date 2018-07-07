
from future.utils import bytes_to_native_str
from future.builtins import bytes

from base64 import b64encode, b64decode
from websocket import create_connection
from .interface import Interface

class WebSocketInterface(Interface):
    def __init__(self, host='localhost', port=8081):
        super(WebSocketInterface,self).__init__()
        self.connected = False
        try:
            self.ws = create_connection('ws://%s:%i' % (host, port))
            self.ws.settimeout(None)
            self.connected = True
        except:
            self.connected = False

    def write(self, data):
        self.ws.send(b64encode(bytes_to_native_str(bytes(data))))

    def read(self):
        #It will wait on recv() until data is sent over websocket
        rawdata = self.ws.recv()
        #Data is sent in base64 string
        data = b64decode(rawdata)
        data = [ord(c) for c in data]
        return data

    def setPacketCount(self, count):
        self.packet_count = count

    def close(self):
        self.ws.close()
        
    def getUniqueId(self):
        """Get the unique id from an interface"""
        self.write([0x80])
        raw_id = bytearray(self.read())
        id_start = 2
        id_size = raw_id[1]
        unique_id = str(raw_id[id_start:id_start + id_size])
        return unique_id

    def getSerialNumber(self):
        return self.getUniqueId()

    @staticmethod
    def getAllConnectedInterface(host,port):
        ws = WebSocketInterface(host,port)
        if ws.connected:
            return [ws]
        else:
            return []
