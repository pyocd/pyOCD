"""
 mbed CMSIS-DAP debugger
 Copyright (c) 2006-2015 ARM Limited

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

import logging, threading, socket
from pyOCD.target.target import TARGET_HALTED, WATCHPOINT_READ, WATCHPOINT_WRITE, WATCHPOINT_READ_WRITE
from pyOCD.transport import TransferError
from struct import unpack
from time import sleep, time
import sys
from gdb_socket import GDBSocket
from gdb_websocket import GDBWebSocket

class GDBServer(threading.Thread):
    """
    This class start a GDB server listening a gdb connection on a specific port.
    It implements the RSP (Remote Serial Protocol).
    """
    def __init__(self, board, port_urlWSS, options = {}):
        threading.Thread.__init__(self)
        self.board = board
        self.target = board.target
        self.flash = board.flash
        self.abstract_socket = None
        self.wss_server = None
        self.port = 0
        if isinstance(port_urlWSS, str) == True:
            self.wss_server = port_urlWSS
        else:
            self.port = port_urlWSS
        self.break_at_hardfault = bool(options.get('break_at_hardfault', True))
        self.board.target.setVectorCatchFault(self.break_at_hardfault)
        self.break_on_reset = options.get('break_on_reset', False)
        self.board.target.setVectorCatchReset(self.break_on_reset)
        self.step_into_interrupt = options.get('step_into_interrupt', False)
        self.packet_size = 2048
        self.flashData = list()
        self.flashOffset = None
        self.conn = None
        self.lock = threading.Lock()
        self.shutdown_event = threading.Event()
        self.detach_event = threading.Event()
        self.quit = False
        if self.wss_server == None:
            self.abstract_socket = GDBSocket(self.port, self.packet_size)
        else:
            self.abstract_socket = GDBWebSocket(self.wss_server)
        self.setDaemon(True)
        self.start()
    
    def restart(self):
        if self.isAlive():
            self.detach_event.set()
    
    def stop(self):
        if self.isAlive():
            self.shutdown_event.set()
            while self.isAlive():
                pass
            logging.info("GDB server thread killed")
        self.board.uninit()
        
    def setBoard(self, board, stop = True):
        self.lock.acquire()
        if stop:
            self.restart()
        self.board = board
        self.target = board.target
        self.flash = board.flash
        self.lock.release()
        return
        
    def run(self):
        self.timeOfLastPacket = time()
        while True:
            new_command = False
            data = ""
            logging.info('GDB server started at port:%d',self.port)
            
            self.shutdown_event.clear()
            self.detach_event.clear()
                
            while not self.shutdown_event.isSet() and not self.detach_event.isSet():
                connected = self.abstract_socket.connect()
                if connected != None:
                    break
            
            if self.shutdown_event.isSet():
                return
            
            if self.detach_event.isSet():
                continue
            
            logging.info("One client connected!")
            
            while True:
                
                if self.shutdown_event.isSet():
                    return
            
                if self.detach_event.isSet():
                    continue
                
                # read command
                while True:
                    if (new_command == True):
                        new_command = False
                        break

                    # Reduce CPU usage by sleep()ing once we know that the
                    # debugger doesn't have a queue of commands that we should
                    # execute as quickly as possible.
                    if time() - self.timeOfLastPacket > 0.5:
                        sleep(0.1)
                    try:
                        if self.shutdown_event.isSet() or self.detach_event.isSet():
                            break
                        self.abstract_socket.setBlocking(0)
                        data += self.abstract_socket.read()
                        if data.index("$") >= 0 and data.index("#") >= 0:
                            break
                    except (ValueError, socket.error):
                        pass
                
                if self.shutdown_event.isSet():
                    return
            
                if self.detach_event.isSet():
                    continue
                
                self.abstract_socket.setBlocking(1)
                    
                data = data[data.index("$"):]
                
                self.lock.acquire()
            
                if len(data) != 0:
                    # decode and prepare resp
                    [resp, ack, detach] = self.handleMsg(data)
            
                    if resp is not None:
                        # ack
                        if ack:
                            resp = "+" + resp
                        # send resp
                        self.abstract_socket.write(resp)
                        # wait a '+' from the client
                        try:
                            data = self.abstract_socket.read()
                            if data[0] != '+':
                                logging.debug('gdb client has not ack!')
                            else:
                                logging.debug('gdb client has ack!')
                            if data.index("$") >= 0 and data.index("#") >= 0:
                                new_command = True
                        except:
                            pass
                        
                    if detach:
                        self.abstract_socket.close()
                        self.lock.release()
                        break

                    self.timeOfLastPacket = time()

                self.lock.release()
        
        
    def handleMsg(self, msg):
        
        if msg[0] != '$':
            logging.debug('msg ignored: first char != $')
            return None, 0, 0
        
        #logging.debug('-->>>>>>>>>>>> GDB rsp packet: %s', msg)
        
        # query command
        if msg[1] == 'q':
            return self.handleQuery(msg[2:]), 1, 0
            
        elif msg[1] == 'H':
            return self.createRSPPacket(''), 1, 0
        
        elif msg[1] == '?':
            return self.createRSPPacket(self.target.getTResponse()), 1, 0

        elif msg[1] == 'g':
            return self.getRegisters(), 1, 0

        elif msg[1] == 'G':
            return self.setRegisters(msg[2:]), 1, 0

        elif msg[1] == 'P':
            return self.writeRegister(msg[2:]), 1, 0

        elif msg[1] == 'm':
            return self.getMemory(msg[2:]), 1, 0
        
        elif msg[1] == 'X':
            return self.writeMemory(msg[2:]), 1, 0
        
        elif msg[1] == 'v':
            return self.flashOp(msg[2:]), 1, 0
        
        # we don't send immediately the response for C and S commands
        elif msg[1] == 'C' or msg[1] == 'c':
            return self.resume()
        
        elif msg[1] == 'S' or msg[1] == 's':
            return self.step()
        
        elif msg[1] == 'Z' or msg[1] == 'z':
            return self.breakpoint(msg[1:]), 1, 0
        
        elif msg[1] == 'D':
            return self.detach(msg[1:]), 1, 1
        
        elif msg[1] == 'k':
            return self.kill(), 1, 1
        
        else:
            logging.error("Unknown RSP packet: %s", msg)
            return self.createRSPPacket(""), 1, 0
        
    def detach(self, data):
        resp = "OK"
        return self.createRSPPacket(resp)
    
    def kill(self):
        return self.createRSPPacket("")
        
    def breakpoint(self, data):
        # handle breakpoint/watchpoint commands
        split = data.split('#')[0].split(',')
        addr = int(split[1], 16)

        # handle hardware breakpoint Z1/z1
        # and software breakpoint Z0/z0
        if data[1] == '1' or data[1] == '0':
            #TODO - add support for real software breakpoints
            if data[0] == 'Z':
                if self.target.setBreakpoint(addr) == False:
                    return self.createRSPPacket('E01') #EPERM
            else:
                self.target.removeBreakpoint(addr)
            return self.createRSPPacket("OK")

        # handle hardware watchpoint Z2/z2/Z3/z3/Z4/z4
        if data[1] == '2':
            # Write-only watch
            watchpoint_type = WATCHPOINT_WRITE
        elif data[1] == '3':
            # Read-only watch
            watchpoint_type = WATCHPOINT_READ
        elif data[1] == '4':
            # Read-Write watch
            watchpoint_type = WATCHPOINT_READ_WRITE
        else:
            return self.createRSPPacket('E01') #EPERM
        size = int(split[2], 16)
        if data[0] == 'Z':
            if self.target.setWatchpoint(addr, size, watchpoint_type) == False:
                return self.createRSPPacket('E01') #EPERM
        else:
            self.target.removeWatchpoint(addr, size, watchpoint_type)
        return self.createRSPPacket("OK")

    def resume(self):
        self.ack()
        self.abstract_socket.setBlocking(0)

        self.target.resume()
        
        val = ''

        self.timeOfLastPacket = time()
        while True:
            if self.shutdown_event.isSet():
                return self.createRSPPacket(val), 0, 0

            # Introduce a delay between non-blocking socket reads once we know
            # that the CPU isn't going to halt quickly.
            if time() - self.timeOfLastPacket > 0.5:
                sleep(0.1)
            try:
                data = self.abstract_socket.read()
                if (data[0] == '\x03'):
                    self.target.halt()
                    val = self.target.getTResponse(True)
                    logging.debug("receive CTRL-C")
                    break
            except:
                pass

            try:
                if self.target.getState() == TARGET_HALTED:
                    logging.debug("state halted")
                    val = self.target.getTResponse()
                    break
            except:
                logging.debug('Target is unavailable temporary.')

        self.abstract_socket.setBlocking(1)
        return self.createRSPPacket(val), 0, 0

    def step(self):
        self.ack()
        self.target.step(not self.step_into_interrupt)
        return self.createRSPPacket(self.target.getTResponse()), 0, 0

    def halt(self):
        self.ack()
        self.target.halt()
        return self.createRSPPacket(self.target.getTResponse()), 0, 0

    def flashOp(self, data):
        ops = data.split(':')[0]
        logging.debug("flash op: %s", ops)
        
        if ops == 'FlashErase':
            return self.createRSPPacket("OK")
        
        elif ops == 'FlashWrite':
            write_addr = int(data.split(':')[1], 16)
            logging.debug("flash write addr: 0x%x", write_addr)
            # search for second ':' (beginning of data encoded in the message)
            second_colon = 0
            idx_begin = 0
            while second_colon != 2:
                if data[idx_begin] == ':':
                    second_colon += 1
                idx_begin += 1

            # determine the address to start flashing
            if self.flashOffset == None:
                # flash offset must be a multiple of the page size
                self.flashOffset = write_addr - ( write_addr % self.flash.page_size )

            # if there's gap between sections, fill it
            flash_watermark = len(self.flashData) + self.flashOffset
            pad_size = write_addr - flash_watermark
            if pad_size > 0:
                self.flashData += [0xFF] * pad_size
            
            # append the new data if it doesn't overlap existing data
            if write_addr >= flash_watermark:
                self.flashData += self.unescape(data[idx_begin:len(data) - 3])
            else:
                logging.error("Invalid FlashWrite address %d overlaps current data of size %d", write_addr, flash_watermark)
                
            return self.createRSPPacket("OK")
        
        # we need to flash everything
        elif 'FlashDone' in ops :
            bytes_to_be_written = len(self.flashData)
            flashPtr = self.flashOffset
            
            self.flash.init()

            # use mass erase if the address starts at 0
            mass_erase = flashPtr == 0
            if mass_erase:
                logging.debug("Erasing entire flash")
                self.flash.eraseAll()

            while len(self.flashData) > 0:
                size_to_write = min(self.flash.page_size, len(self.flashData))
                
                #Erase Page if flash has not been erased
                if not mass_erase:
                    logging.debug("Erasing page 0x%x", flashPtr)
                    self.flash.erasePage(flashPtr)

                #ProgramPage
                self.flash.programPage(flashPtr, self.flashData[:size_to_write])
                flashPtr += size_to_write

                self.flashData = self.flashData[size_to_write:]

                # print progress bar
                sys.stdout.write('\r')
                i = int((float(flashPtr - self.flashOffset)/float(bytes_to_be_written))*20.0)
                # the exact output you're looking for:
                sys.stdout.write("[%-20s] %d%%" % ('='*i, 5*i))
                sys.stdout.flush()
                
            sys.stdout.write("\n\r")
            
            self.flashData = []
            self.flashOffset = None

            # reset and stop on reset handler
            self.target.resetStopOnReset()
            
            return self.createRSPPacket("OK")
        
        elif 'Cont' in ops:
            if 'Cont?' in ops:
                return self.createRSPPacket("vCont;c;s;t")
                
        return None
    
    def unescape(self, data):
        data_idx = 0
    
        # unpack the data into binary array
        str_unpack = str(len(data)) + 'B'
        data = unpack(str_unpack, data)
        data = list(data)
    
        # check for escaped characters
        while data_idx < len(data):
            if data[data_idx] == 0x7d:
                data.pop(data_idx)
                data[data_idx] = data[data_idx] ^ 0x20
            data_idx += 1
            
        return data
            
        
    def getMemory(self, data):
        split = data.split(',')
        addr = int(split[0], 16)
        length = split[1]
        length = int(length[:len(length)-3],16)
        
        try:
            val = ''
            mem = self.target.readBlockMemoryUnaligned8(addr, length)
            for x in mem:
                if x >= 0x10:
                    val += hex(x)[2:4]
                else:
                    val += '0' + hex(x)[2:3]
        except TransferError:
            logging.debug("getMemory failed at 0x%x" % addr)
            val = 'E01' #EPERM
        return self.createRSPPacket(val)
    
    def writeMemory(self, data):
        split = data.split(',')
        addr = int(split[0], 16)
        length = int(split[1].split(':')[0], 16)
        
        idx_begin = 0
        for i in range(len(data)):
            if data[i] == ':':
                idx_begin += 1
                break
            idx_begin += 1
        
        data = data[idx_begin:len(data) - 3]
        data = self.unescape(data)
        
        try:
            if length > 0:
                self.target.writeBlockMemoryUnaligned8(addr, data)
            resp = "OK"
        except TransferError:
            logging.debug("writeMemory failed at 0x%x" % addr)
            resp = 'E01' #EPERM
        
        return self.createRSPPacket(resp)

    def writeRegister(self, data):
        reg = int(data.split('=')[0], 16)
        val = data.split('=')[1].split('#')[0]
        self.target.setRegister(reg, val)
        return self.createRSPPacket("OK")

    def getRegisters(self):
        return self.createRSPPacket(self.target.getRegisterContext())

    def setRegisters(self, data):
        self.target.setRegisterContext(data)
        return self.createRSPPacket("OK")

    def handleQuery(self, msg):
        query = msg.split(':')
        logging.debug('GDB received query: %s', query)

        if query is None:
            logging.error('GDB received query packet malformed')
            return None
        
        if query[0] == 'Supported':
            resp = "qXfer:memory-map:read+;qXfer:features:read+;PacketSize="
            resp += hex(self.packet_size)[2:]
            return self.createRSPPacket(resp)
            
        elif query[0] == 'Xfer':
            
            if query[1] == 'features' and query[2] == 'read' and \
               query[3] == 'target.xml':
                data = query[4].split(',')
                resp = self.handleQueryXML('read_feature', int(data[0], 16), int(data[1].split('#')[0], 16))
                return self.createRSPPacket(resp)
            
            elif query[1] == 'memory-map' and query[2] == 'read':
                data = query[4].split(',')
                resp = self.handleQueryXML('memory_map', int(data[0], 16), int(data[1].split('#')[0], 16))
                return self.createRSPPacket(resp)
                
            else:
                return None
            
        elif query[0] == 'C#b4':
            return self.createRSPPacket("")
        
        elif query[0].find('Attached') != -1:
            return self.createRSPPacket("1")
        
        elif query[0].find('TStatus') != -1:
            return self.createRSPPacket("")
        
        elif query[0].find('Tf') != -1:
            return self.createRSPPacket("")
        
        elif 'Offsets' in query[0]:
            resp = "Text=0;Data=0;Bss=0"
            return self.createRSPPacket(resp)
        
        elif 'Symbol' in query[0]:
            resp = "OK"
            return self.createRSPPacket(resp)

        elif query[0].startswith('Rcmd,'):
            cmd = self.hexDecode(query[0][5:].split('#')[0])
            logging.debug('Remote command: %s', cmd)

            safecmd = {
                'reset' : ['Reset target', 0x1],
                'halt'  : ['Halt target', 0x2],
                'resume': ['Resume target', 0x4],
                'help'  : ['Display this help', 0x80],
            }
            resultMask = 0x00
            if cmd == 'help':
                resp = ''
                for k,v in safecmd.items():
                    resp += '%s\t%s\n' % (k,v)
                resp = self.hexEncode(resp)
            else:
                cmdList = cmd.split(' ')
                #check whether all the cmds is valid cmd for monitor
                for cmd_sub in cmdList:
                    if not cmd_sub in safecmd:
                        #error cmd for monitor, just return directly
                        resp = ''
                        return self.createRSPPacket(resp)
                    else:
                        resultMask = resultMask | safecmd[cmd_sub][1]
                #if it's a single cmd, just launch it!
                if len(cmdList) == 1:
                    tmp = eval ('self.target.%s()' % cmd_sub)
                    logging.debug(tmp)
                    resp = "OK"
                else:
                    #10000001 for help reset, so output reset cmd help information
                    if resultMask == 0x81:
                        resp = 'Reset the target\n'
                        resp = self.hexEncode(resp)
                    #10000010 for help halt, so output halt cmd help information
                    elif resultMask == 0x82:
                        resp = 'Halt the target\n'
                        resp = self.hexEncode(resp)
                    #10000100 for help resume, so output resume cmd help information
                    elif resultMask == 0x84:
                        resp = 'Resume the target\n'
                        resp = self.hexEncode(resp)
                    #11 for reset halt cmd, so launch self.target.resetStopOnReset()
                    elif resultMask == 0x3:
                        resp = "OK"
                        self.target.resetStopOnReset()
                    #111 for reset halt resume cmd, so launch self.target.resetStopOnReset() and self.target.resume()
                    elif resultMask == 0x7:
                        resp = "OK"
                        self.target.resetStopOnReset()
                        self.target.resume()
                    else:
                        resp = ''
            return self.createRSPPacket(resp)

        else:
            return self.createRSPPacket("")
            
    def handleQueryXML(self, query, offset, size):
        logging.debug('GDB query %s: offset: %s, size: %s', query, offset, size)
        xml = ''
        if query == 'memory_map':
            xml = self.target.memoryMapXML
        elif query == 'read_feature':
            xml = self.target.getTargetXML()

        size_xml = len(xml)
        
        prefix = 'm'
        
        if offset > size_xml:
            logging.error('GDB: offset target.xml > size!')
            return
        
        if size > (self.packet_size - 4):
            size = self.packet_size - 4
        
        nbBytesAvailable = size_xml - offset
        
        if size > nbBytesAvailable:
            prefix = 'l'
            size = nbBytesAvailable
        
        resp = prefix + xml[offset:offset + size]
        
        return resp
            
            
    def createRSPPacket(self, data):
        resp = '$' + data + '#'
        
        c = 0
        checksum = 0
        for c in data:
            checksum += ord(c)
        checksum = checksum % 256
        checksum = hex(checksum)

        if int(checksum[2:], 16) < 0x10:
            resp += '0'
        resp += checksum[2:]
        
        #logging.debug('--<<<<<<<<<<<< GDB rsp packet: %s', resp)
        return resp
    
    def ack(self):
        self.abstract_socket.write("+")

    def hexDecode(self, cmd):
        return ''.join([ chr(int(cmd[i:i+2], 16)) for i in range(0, len(cmd), 2)])

    def hexEncode(self, string):
        return ''.join(['%02x' % ord(i) for i in string])

