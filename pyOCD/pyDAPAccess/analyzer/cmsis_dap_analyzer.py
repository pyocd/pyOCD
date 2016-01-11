import logging
from pyOCD.pyDAPAccess.cmsis_dap_core import COMMAND_ID, ID_INFO
from pyOCD.target.dap import AP_REG, CSW_SIZE, CSW_ADDRINC
from transport_analyzer import TransportAnalyzer
from collections import deque

DP_RREG = {  0x00: 'IDCODE'
           , 0x04: 'CTRL/STAT'
           , 0x08: 'RESEND'
           , 0x0C: 'RDBUFF' }
DP_WREG = {  0x00: 'ABORT'
           , 0x04: 'CTRL/STAT'
           , 0x08: 'SELECT' }

DAP_MODE = {  0x0: 'DAP_DEFAULT_PORT'
            , 0x1: 'SWD'
            , 0x2: 'JTAG' }

TRANSFER_RESP = {  0b000: 'ACK'
                 , 0b001: 'OK'
                 , 0b010: 'WAIT'
                 , 0b100: 'FAULT'}

REG_MAP = {  0xE000EDFC: 'DEMCR'
           , 0xE000EDF0: 'DHCSR'
           , 0xE000EDF4: 'DCRSR'
           , 0xE000EDF8: 'DCRDR' 
           , 0xE000ED0C: 'AIRCR'}

MEM_MAP = {   (0xE0040000, 0xE0041000): 'TPIU'
            , (0xE0041000, 0xE0042000): 'ETM'
            , (0xE0042000, 0xE00FF000): 'EPPB'
            , (0xE00FF000, 0xE00FFFFF): 'ROM_TABLE'
            , (0xE0000000, 0xE0001000): 'ITM'
            , (0xE0001000, 0xE0002000): 'DWT'
            , (0xE0002000, 0xE0003000): 'FPB'            
            , (0xE000E000, 0xE000F000): 'SCS'}

BIT_MAPS = \
{  
  'DEMCR': 
    {   
          0x01000000: ('TRCENA',       24)
        , 0x00080000: ('MON_REQ',      19)
        , 0x00040000: ('MON_STEP',     18)
        , 0x00020000: ('MON_PEND',     17)
        , 0x00010000: ('MON_EN',       16) 
        , 0x00000400: ('VC_HARDERR',   10)
        , 0x00000200: ('VC_INTERR',     9)
        , 0x00000100: ('VC_BUSERR',     8)
        , 0x00000080: ('VC_STATERR',    7)
        , 0x00000040: ('VC_CHKERR',     6)
        , 0x00000020: ('VC_NOCPERR',    5)
        , 0x00000010: ('VC_MMERR',      4)
        , 0x00000001: ('VC_CORERESET',  0)
    }
, 'DFSR':
    {
        0x00000010: ('EXTERNAL',      4)
      , 0x00000008: ('VCATCH',        3)
      , 0x00000004: ('DWTTRAP',       2)
      , 0x00000002: ('BKPT',          1)
      , 0x00000001: ('HALTED',        0)
    }
, 'DCRSR': 
    {   
        0x00010000: ('REGWnR',       16)
      , 0x0000007F: ('REGSEL',        0)
    }
, 'DCRDR':
    {
        0xFFFFFFFF: ('DBGTMP',        0)
    }
, 'DHCSR':
    {
        0x02000000: ('S_RESET_ST',   25)
      , 0x01000000: ('S_RETIRE_ST',  24) 
      , 0x00080000: ('S_LOCKUP',     19)
      , 0x00040000: ('S_SLEEP',      18)
      , 0x00020000: ('S_HALT',       17)
      , 0x00010000: ('S_REGRDY',     16)
      , 0x00000020: ('C_SNAPSTALL',   5)
      , 0x00000008: ('C_MASKINTS',    3)
      , 0x00000004: ('C_STEP',        2)
      , 0x00000002: ('C_HALT',        1)
      , 0x00000001: ('C_DEBUGEN',     0)
    }
, 'AIRCR': 
    {   
        0x00008000: ('ENDIANNESS',   15)
      , 0x00000700: ('PRIGROUP',      8)
      , 0x00000004: ('SYSRESETREQ',   2)
      , 0x00000002: ('VECTCLRACTIVE', 1) 
      , 0x00000001: ('VECTRESET',     0)
    }
}


RESP_STATUS = {  0xff: 'DAP_ERROR'
               , 0x00: 'DAP_OK'}
CONN_RESP = {0x0: 'FAILED', 0x1: 'SWD', 0x2: 'JTAG'}

invmap = lambda d: {v:k for k,v in d.iteritems()}
AP_REG = invmap(AP_REG)
COMMAND_ID = invmap(COMMAND_ID)
ID_INFO = invmap(ID_INFO)

lookup_code = lambda d,k: d.get(k, "UNKNOWN_CODE(0x%02x)" % k)
lookup_cmd = lambda cmd: COMMAND_ID.get(cmd, "UNKNOWN_CMD(0x%02x)" % cmd)
reverse_bits = lambda b,width=0: bin(b)[2:].zfill(width)[::-1]

TXFMT = "{rw:5s} {dapreg}[            |, 0x{dword:08X}] ; [\*| ]{dapreg} = {addr:10s}\( <{pphaddr}>\)?"
RXFMT = "{addr:10s} {ddir} 0x{dword:08X}\( ; {bitdiff}\)?"

def get_word(data,index=0,pop=False):
    d1,d2,d3,d4 = data[index:index+4]
    if pop: del data[index:index+4]
    return d4 << 24 | d3 << 16 | d2 << 8 | d1

class CMSIS_DAPAnalyzer(TransportAnalyzer):
    def __init__(self, interface):
        super(CMSIS_DAPAnalyzer, self).__init__(interface)
        self.last_rqst = deque()
        self.last_blktransfer = []
        self._cache = {}

    def default_trace(self, data):
        ncols = 16
        nlines, r = divmod(len(data),ncols)
        
        lines = ''
        if nlines > 0: 
            lines += '\n\t' + '\n\t'.join([' '.join(['0x{:02x}']*ncols)]*nlines)
        if r > 0: 
            lines += '\n\t' + ' '.join(['0x{:02x}']*r)

        return lines.format(*data)

    def get_rqst_translater(self, cmd):
        return getattr(self, cmd.lower()+'_rqst', None)

    def get_resp_translater(self, cmd):
        return getattr(self, cmd.lower()+'_resp', None)

    def trace_write(self, data, **kwargs):
        cmd = lookup_cmd(data[0])
        if cmd == 'DAP_TRANSFER':
            (dapidx, tcnt), xfers = data[1:3], data[3:]

            header = " (dap_idx=0x{:02x}, xfer_cnt=0x{:02x})".format(dapidx,tcnt)
            trace = header + self._xrqst(tcnt, xfers)
        elif cmd == 'DAP_TRANSFER_BLOCK':
            dapidx, (tcntL, tcntH), treq, xfers = data[1], data[2:4], data[4], data[5:]
            tcnt = tcntH << 8 | tcntL

            header = " (dap_idx=0x{:02x}, xfer_cnt=0x{:02x})".format(dapidx,tcnt)
            trace = header + self._xrqst_block(tcnt, treq, xfers)
        else:
            tracer = self.get_rqst_translater(cmd)
            trace = tracer(data) if tracer is not None else ""

        logging.debug(("trace_tx:%s" % cmd.lower()) + trace)

    def trace_read(self, data, **kwargs):
        cmd = lookup_cmd(data[0])
        if cmd == 'DAP_TRANSFER':
            tcnt, tresp, xfers = data[1], data[2]&0x1F, data[3:]
            swderr = (tresp&0b01000) >> 3
            vmm    = (tresp&0b10000) >> 4

            header = " (xfer_cnt=0x{:02x}, resp={:s}, swderr={:d}, vmismatch={:d})"
            header = header.format(tcnt,lookup_code(TRANSFER_RESP,tresp),swderr,vmm)
            trace = header + self._xresp(tcnt, tresp, xfers)
        elif cmd == 'DAP_TRANSFER_BLOCK':
            (tcntL,tcntH), tresp, xfers = data[1:3], data[3]&0xF, data[4:]
            tcnt = tcntH << 8 | tcntL
            swderr = (tresp&0b01000) >> 3

            header = " (xfer_cnt=0x{:02x}, resp={:s}, swderr={:d})"
            header = header.format(tcnt,lookup_code(TRANSFER_RESP,tresp),swderr)
            trace = header + self._xresp_block(tcnt, tresp, xfers)
        else:
            tracer = self.get_resp_translater(cmd)
            trace = tracer(data) if tracer is not None else ""

        logging.debug(("trace_rx:%s" % cmd.lower()) + trace)
        
    def dap_response(self, data):
        return " (resp=%s)" % lookup_code(RESP_STATUS, data[1])

    def _xrqst(self, tcnt, xfers):
        # for each block transfer, a single transfer request byte is sent that
        # applies to all data sent/received
        lines = ''
        expr = "{cmd:5s} {dapreg:6s}{optdword:12s}{optcomment}"
        for i in range(tcnt):
            treq = xfers.pop(0)&0x3F
            apndp = (treq&0b000001)
            rnw =   (treq&0b000010) >> 1
            a23 =   (treq&0b001100)
            vm =    (treq&0b010000) >> 4
            mm =    (treq&0b100000) >> 5

            dapregmap = AP_REG if apndp else DP_RREG if rnw else DP_WREG
            dapreg = ('AP' if apndp else 'DP') + '.' + dapregmap[a23]

            dword = None if rnw else get_word(xfers, pop=True)
            comment = dwordstr = ''
            if not rnw:
                comment = "{apreg:>4s} = {dword:11s}"
                reg = dapregmap[a23]
                dwordstr = "0x{:08X}".format(dword)
                if reg == 'TAR' and dword in REG_MAP:
                    dwordstr = "&" + REG_MAP[dword]
                elif reg == 'DRW':
                    reg = '*' + reg
                comment = comment.format(apreg=reg, dword=dwordstr)
                # Add the peripheral space this is in
                # regs = sorted([(a,b) for (a,b) in MEM_MAP if a <= dword < b])
                # if regs:
                #     base = regs[-1]
                #     comment += " <%s+%d>" % (".".join(map(MEM_MAP.get, regs)), dword-base[0])
            elif dapregmap[a23] == 'DRW':
                comment = "{apreg:>4s} = {dword:11s}".format(apreg='DRW', dword='*TAR')

            lines += '\n\t' + expr.format(cmd='READ' if rnw else 'WRITE', 
                                          dapreg=dapreg, 
                                          optdword=", 0x{:08X}".format(dword) if dword is not None else '',
                                          optcomment=" ; {}".format(comment) if comment else '')

            if vm != 0 or mm != 0:
                lines += " (vmatch={:d}, mmask={:d})".format(vm,mm)

            self.last_rqst.append([treq, dapreg, dword])

        return lines

    def _xrqst_block(self, tcnt, treq, xfers):
        # for each transfer, a single transfer request byte is sent and
        # optionally a set of data words to write
        apndp = (treq&0b000001)
        rnw =   (treq&0b000010) >> 1
        a23 =   (treq&0b001100)

        dapregmap = AP_REG if apndp else DP_RREG if rnw else DP_WREG
        dapreg = ('AP' if apndp else 'DP') + '.' + dapregmap[a23]
        lines = ''

        data = []
        for i in range(tcnt):
            lines += '\n\t' + ('READ ' if rnw else 'WRITE') + ' ' + dapreg
            if not rnw:
                dword = get_word(xfers, pop=True)
                data.append(dword)

                lines += ", 0x{:08X}".format(dword)
                if dapregmap[a23] == 'DRW':
                    lines += " ; *TAR++ = 0x{:08X}".format(dword)
            elif dapregmap[a23] == 'DRW':
                lines += " "*12 + " ;  DRW = *TAR++"
        self.last_blktransfer.append([treq, dapreg, data])

        return lines

    def _bitdiff(self, sysreg, dword, rnw, dmask=0xffffffff):
        if sysreg not in BIT_MAPS:
            return []

        if (sysreg == 'DHCSR' and not rnw) or sysreg == 'AIRCR':
            dmask &= 0xFFFF # Ignore VECTKEY bits

        fields = []
        cachedword = self._cache.get(sysreg)
        for bitmask, (fieldname, offset) in BIT_MAPS[sysreg].iteritems():
            bitfield = dword&bitmask
            if cachedword is not None:
                diffmask = bitfield ^ (cachedword&bitmask)
            else:
                diffmask = bitmask
            diffmask &= dmask

            if diffmask == 0:
                continue

            if (bitmask >> offset) > 1:
                fields.append((fieldname, "0x{:X}".format(bitfield >> offset)))
            else:
                fields.append((fieldname, "{:d}".format((bitfield & diffmask) >> offset)))

        return fields

    def _swd_bits(self, treq, tresp, dword):
        rqstbits = treq & 0xF

        p = rqstbits
        p ^= p >> 1
        p ^= p >> 2

        pword = dword ^ (dword >> 1)
        pword ^= pword >> 2
        pword ^= pword >> 4
        pword ^= pword >> 8
        pword ^= pword >>16

        swrqst = 1 << 7 | 0 << 6 | (p&1) << 5 | rqstbits << 1 | 1
        swdword = (pword&1) << 32 | dword
        swack = tresp & 3

        return map(reverse_bits, (swrqst, swack, swdword), (8,3,33))

    def _xresp(self, tcnt, tresp, xfers):
        lines = ''
        xferok = lookup_code(TRANSFER_RESP, tresp) in ('OK','ACK')
        expr = "{addr:10s} {ddir:3s} {dword:10s}{comment}"
        swdexpr = "{:10s} {:3s} {}"
        for i in range(tcnt):
            treq, dapreg, dword = self.last_rqst.popleft()
            rnw = (treq&0b000010) >> 1

            if rnw: 
                dword = get_word(xfers, pop=True)
                ddir = '=>' if xferok else '=>X'
            else:
                ddir = '<=' if xferok else 'X<='

            dwordstr = "0x%08X" % dword
            dmask = 0xffffffff
            addr = dapreg
            comment = ''
            if dapreg == 'AP.DRW':
                tar = self._cache.get('AP.TAR')
                if tar is not None:
                    addr = REG_MAP.get(tar, "0x%08X" % tar)
                elif 'AP.CSW' in self._cache and tar is not None:
                    xfersz = self._cache['AP.CSW'] & CSW_SIZE
                    bitoffset = (tar % 4) << 3
                    dmask = ((1 << (8 << xfersz)) - 1) << bitoffset
                    dword &= dmask
                    dwordstr = ("0x{:0%dX}" % (2 << xfersz)).format(dword >> bitoffset).rjust(10)
                if xferok:
                    comment = self._drw_access(rnw, dword, dmask)
            lines += '\n\t' + expr.format(addr=addr, ddir=ddir, dword=dwordstr, comment=" ; "+comment if comment else '')

            # Give the bits from the equivalent SWD transaction
            # lines += "\n\t" + swdexpr.format(*self._swd_bits(treq, tresp, dword))

            if xferok: self._cache[dapreg] = (self._cache.get(dapreg, 0) & ~dmask) | dword
        return lines

    def _drw_access(self, rnw, dword, dmask):
        try:
            tar = self._cache['AP.TAR']
        except KeyError:
            logging.warning("Attempting to access memory without first setting TAR")
            return ''

        # handle auto-incrementing TAR
        if 'AP.CSW' in self._cache and self._cache['AP.CSW'] & CSW_ADDRINC:
            self._cache['AP.TAR'] += 1 << (self._cache['AP.CSW'] & CSW_SIZE)

        if tar not in REG_MAP: # we only care about core memory space
            return ''

        sysreg = REG_MAP[tar]
        bitdiff = self._bitdiff(sysreg, dword, rnw, dmask)
        self._cache[sysreg] = (self._cache.get(sysreg, 0) & ~dmask) | dword

        return ", ".join(k + '=' + v for k,v in bitdiff)

    def _xresp_block(self, tcnt, tresp, xfers):
        treq, dapreg, txdword = self.last_blktransfer.pop(0)
        tar = self._cache.get('AP.TAR',None) if dapreg == 'AP.DRW' else None
        if dapreg == 'AP.DRW' and tar is None:
            logging.warning("Attempting a R/W when TAR has not been set")
        rnw = (treq&0b000010) >> 1

        if rnw: 
            ddir = '=>' if lookup_code(TRANSFER_RESP, tresp) in ('OK','ACK') else '=>X'
        else:
            ddir = '<=' if lookup_code(TRANSFER_RESP, tresp) in ('OK','ACK') else 'X<='

        lines = ''
        for i in range(tcnt):
            dword = get_word(xfers, pop=True) if rnw else txdword.pop(0)

            lines += '\n\t' + "{:s} {:s} 0x{:08X}".format(dapreg, ddir, dword)
            if tar is not None:
                addr = "0x{:08X}".format(tar)
                tar += 4 # assume WORD size memory accesses
            else:
                addr = '0x??'

            if not rnw: 
                addr = '*'+addr

            lines += " ; " + "{:s} {:s} 0x{:08X}".format(addr, ddir, dword)

            # Give the bits from the equivalent SWD transaction
            # lines += "\n\t{:s} {:s} {:s}".format(*self._swd_bits(treq, tresp, dword))
        self._cache[dapreg] = dword # cache the last transmitted word
        if tar is not None: 
            self._cache['AP.TAR'] = tar

        return lines

    def dap_disconnect_rqst(self, data):
        return ""

    def dap_write_abort_rqst(self, data):
        dapidx, word = data[1], get_word(data,2)
        header = " (dap_index=0x{:02x}, word=0x{:08X})".format(dapidx,word)
        return header

    def dap_connect_rqst(self, data):
        return " (port={:s})".format(lookup_code(DAP_MODE, data[1]))

    def dap_connect_resp(self, data):
        mode = lookup_code(DAP_MODE, data[1])
        if mode not in ('JTAG','SWD'):
            mode = "FAILED"
        return " (resp=%s)" % mode

    def dap_swj_clock_rqst(self, data):
        return " (freq={:d})".format(get_word(data,1))

    dap_disconnect_resp = dap_response
    dap_write_abort_resp = dap_response
    dap_swj_clock_resp = dap_response

    def dap_info_rqst(self, data):
        self.info_rqst = lookup_code(ID_INFO,data[1])
        return " (id=%s)" % self.info_rqst

    def dap_info_resp(self, data):
        dlen = data[1]

        if dlen == 0:
            info = 0
        elif self.info_rqst in ('CAPABILITIES', 'PACKET_COUNT', 'PACKET_SIZE'):
            if dlen == 1:
                info = data[2]
            if dlen == 2:
                info = (data[3] << 8) | data[2]
        else:
            info = 0
            for i, b in enumerate(dlen[2:2+dlen]):
                info |= b << (8*i)

        return " (len=0x{:x}, info=0x{:x})".format(dlen,info)
