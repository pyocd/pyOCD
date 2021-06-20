# pyOCD debugger
# Copyright (c) 2015-2020 Arm Limited
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
from contextlib import contextmanager
from functools import total_ordering
from enum import Enum

from ..core import (exceptions, memory_interface)
from ..core.target import Target
from ..utility.concurrency import locked

LOG = logging.getLogger(__name__)

TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

## Offset of IDR register in an APv1.
AP_IDR = 0xFC
## Offset of IDR register in an APv2.
APv2_IDR = 0xDFC

A32 = 0x0c
APSEL_SHIFT = 24
APSEL = 0xff000000
APBANKSEL = 0x000000f0
APSEL_APBANKSEL = APSEL | APBANKSEL

## @brief Mask for register address within the AP address space.
#
# v1 APs have a 256 byte register space. v2 APs have a 4 kB register space. This mask is
# larger than the APv1 register space, but this is not problematic because v1 APs only have
# the 8-bit APSEL in bits 31:24 of the address, thus no possibility of conflict.
APREG_MASK = 0x00000ffc

# AP BASE register masks
AP_BASE_FORMAT_MASK = 0x2
AP_BASE_ENTRY_PRESENT_MASK = 0x1
AP_BASE_BASEADDR_MASK = 0xfffffffc
AP_BASE_LEGACY_NOTPRESENT = 0xffffffff # Legacy not present value
AP_BASE_LEGACY_BASEADDR_MASK = 0xfffff000

# AP IDR bitfields:
# [31:28] Revision
# [27:24] JEP106 continuation (0x4 for ARM)
# [23:17] JEP106 vendor ID (0x3B for ARM)
# [16:13] Class (0b1000=Mem-AP)
# [12:8]  Reserved
# [7:4]   AP Variant (non-zero for JTAG-AP)
# [3:0]   AP Type
AP_IDR_REVISION_MASK = 0xf0000000
AP_IDR_REVISION_SHIFT = 28
AP_IDR_JEP106_MASK = 0x0ffe0000
AP_IDR_JEP106_SHIFT = 17
AP_IDR_CLASS_MASK = 0x0001e000
AP_IDR_CLASS_SHIFT = 13
AP_IDR_VARIANT_MASK = 0x000000f0
AP_IDR_VARIANT_SHIFT = 4
AP_IDR_TYPE_MASK = 0x0000000f

# The CoreSight ARCHID value for the CSSOC-600 APv1 Adapter.
UNKNOWN_AP_ARCHID = 0x0a47

## The control registers for a v2 MEM-AP start at an offset.
MEM_APv2_CONTROL_REG_OFFSET = 0xD00

# MEM-AP register addresses
MEM_AP_CSW = 0x00
MEM_AP_TAR = 0x04
MEM_AP_DRW = 0x0C
MEM_AP_TRR = 0x24 # Only APv2 with ERRv1
MEM_AP_BASE_HI = 0xF0
MEM_AP_CFG = 0xF4
MEM_AP_BASE = 0xF8

MEM_AP_CFG_TARINC_MASK = 0x000f0000
MEM_AP_CFG_TARINC_SHIFT = 16
MEM_AP_CFG_ERR_MASK = 0x00000f00
MEM_AP_CFG_ERR_SHIFT = 8
MEM_AP_CFG_DARSIZE_MASK = 0x000000f0
MEM_AP_CFG_DARSIZE_SHIFT = 4
MEM_AP_CFG_LD_MASK = 0x00000004
MEM_AP_CFG_LA_MASK = 0x00000002

MEM_AP_CFG_ERR_V1 = 1

MEM_AP_TRR_ERR_MASK = 0x00000001

# AP Control and Status Word definitions
CSW_SIZE     =  0x00000007
CSW_SIZE8    =  0x00000000
CSW_SIZE16   =  0x00000001
CSW_SIZE32   =  0x00000002
CSW_SIZE64   =  0x00000003
CSW_SIZE128  =  0x00000004
CSW_SIZE256  =  0x00000005
CSW_ADDRINC  =  0x00000030
CSW_NADDRINC =  0x00000000 # No increment
CSW_SADDRINC =  0x00000010 # Single increment by SIZE field
CSW_PADDRINC =  0x00000020 # Packed increment, supported only on M3/M3 AP
CSW_DEVICEEN =  0x00000040
CSW_TINPROG  =  0x00000080 # Not implemented on M33 AHB5-AP
CSW_ERRNPASS =  0x00010000 # MEM-APv2 only
CSW_ERRSTOP  =  0x00020000 # MEM-APv2 only
CSW_SDEVICEEN = 0x00800000 # Also called SPIDEN in ADIv5
CSW_HPROT    =  0x0f000000
CSW_MSTRTYPE =  0x20000000 # Only present in M3/M3 AHB-AP, RES0 in others
CSW_MSTRCORE =  0x00000000
CSW_MSTRDBG  =  0x20000000

DEFAULT_CSW_VALUE = CSW_SADDRINC

TRANSFER_SIZE = {8: CSW_SIZE8,
                 16: CSW_SIZE16,
                 32: CSW_SIZE32,
                 64: CSW_SIZE64,
                 128: CSW_SIZE128,
                 256: CSW_SIZE256,
                 }

CSW_HPROT_MASK = 0x0f000000 # HPROT[3:0]
CSW_HPROT_SHIFT = 24

CSW_HNONSEC_MASK = 0x40000000
CSW_HNONSEC_SHIFT = 30

# HNONSECURE bits
SECURE = 0
NONSECURE = 1

# HPROT bits
HPROT_DATA = 0x01
HPROT_INSTR = 0x00
HPROT_PRIVILEGED = 0x02
HPROT_USER = 0x00
HPROT_BUFFERABLE = 0x04
HPROT_NONBUFFERABLE = 0x00
HPROT_CACHEABLE = 0x08
HPROT_NONCACHEABLE = 0x00
HPROT_LOOKUP = 0x10
HPROT_NO_LOOKUP = 0x00
HPROT_ALLOCATE = 0x20
HPROT_NO_ALLOCATE = 0x00
HPROT_SHAREABLE = 0x40
HPROT_NONSHAREABLE = 0x00

# Debug Exception and Monitor Control Register
DEMCR = 0xE000EDFC
# DWTENA in armv6 architecture reference manual
DEMCR_TRCENA = (1 << 24)

class APVersion(Enum):
    """! @brief Supported versions of APs."""
    ## APv1 from ADIv5.x.
    APv1 = 1
    ## APv2 from ADIv6.
    APv2 = 2

@total_ordering
class APAddressBase(object):
    """! @brief Base class for AP addresses.
    
    An instance of this class has a "nominal address", which is an integer address in terms of how
    it is typically referenced. For instance, for an APv1, the nominal address is the unshifted
    APSEL, e.g. 0, 1, 2, and so on. This value is accessible by the _nominal_address_ property. It
    is also used for hashing and ordering. One intentional side effect of this is that APAddress
    instances match against the integer value of their nominal address, which is particularly useful
    when they are keys in a dictionary.
    
    In addition to the nominal address, there is an abstract _address_ property implemented by the
    version-specific subclasses. This is the value used by the DP hardware and passed to the
    DebugPort's read_ap() and write_ap() methods.
    
    The class also indicates which version of AP is targeted: either APv1 or APv2. The _ap_version_
    property reports this version number, though it is also encoded by the subclass. The AP version
    is coupled with the address because the two are intrinsically connected; the version defines the
    address format.
    """
    
    def __init__(self, address):
        """! @brief Constructor accepting the nominal address."""
        self._nominal_address = address
    
    @property
    def ap_version(self):
        """! @brief Version of the AP, as an APVersion enum."""
        raise NotImplementedError()
    
    @property
    def nominal_address(self):
        """! @brief Integer AP address in the form in which one speaks about it.
        
        This value is used for comparisons and hashing."""
        return self._nominal_address
    
    @property
    def address(self):
        """! @brief Integer AP address used as a base for register accesses.
        
        This value can be passed to the DebugPort's read_ap() or write_ap() methods. Offsets of
        registers can be added to this value to create register addresses."""
        raise NotImplementedError()
    
    @property
    def idr_address(self):
        """! @brief Address of the IDR register."""
        raise NotImplementedError()
    
    def __hash__(self):
        return hash(self.nominal_address)
    
    def __eq__(self, other):
        return (self.nominal_address == other.nominal_address) \
                if isinstance(other, APAddressBase) else (self.nominal_address == other)
    
    def __lt__(self, other):
        return (self.nominal_address < other.nominal_address) \
                if isinstance(other, APAddressBase) else (self.nominal_address < other)
    
    def __repr__(self):
        return "<{}@{:#x} {}>".format(self.__class__.__name__, id(self), str(self))

class APv1Address(APAddressBase):
    """! @brief Represents the address for an APv1.
    
    The nominal address is the 8-bit APSEL value. This is written into the top byte of
    the DP SELECT register to select the AP to communicate with.
    """
    
    @property
    def ap_version(self):
        """! @brief APVersion.APv1."""
        return APVersion.APv1
    
    @property
    def apsel(self):
        """! @brief Alias for the _nominal_address_ property."""
        return self._nominal_address
    
    @property
    def address(self):
        return self.apsel << APSEL_SHIFT
    
    @property
    def idr_address(self):
        """! @brief Address of the IDR register."""
        return AP_IDR
    
    def __str__(self):
        return "#%d" % self.apsel

class APv2Address(APAddressBase):
    """! @brief Represents the address for an APv2.
    
    ADIv6 uses an APB bus to communicate with APv2 instances. The nominal address is simply the base
    address of the APB slave. The APB bus address width is variable from 12-52 bits in 8-bit steps.
    This address is written the DP SELECT and possibly SELECT1 (for greater than 32 bit addresses)
    registers to choose the AP to communicate with.
    """
    
    @property
    def ap_version(self):
        """! @brief Returns APVersion.APv2."""
        return APVersion.APv2
    
    @property
    def address(self):
        return self._nominal_address
    
    @property
    def idr_address(self):
        """! @brief Address of the IDR register."""
        return APv2_IDR
    
    def __str__(self):
        return "@0x%x" % self.address

class AccessPort(object):
    """! @brief Base class for a CoreSight Access Port (AP) instance."""

    @staticmethod
    def probe(dp, ap_num):
        """! @brief Determine if an AP exists with the given AP number.
        
        Only applicable for ADIv5.
        
        @param dp DebugPort instance.
        @param ap_num The AP number (APSEL) to probe.
        @return Boolean indicating if a valid AP exists with APSEL=ap_num.
        """
        idr = dp.read_ap((ap_num << APSEL_SHIFT) | AP_IDR)
        return idr != 0
    
    @staticmethod
    def create(dp, ap_address, cmpid=None):
        """! @brief Create a new AP object.
        
        Determines the type of the AP by examining the IDR value and creates a new
        AP object of the appropriate class. See #AP_TYPE_MAP for the mapping of IDR
        fields to class.
        
        @param dp DebugPort instance.
        @param ap_address An instance of either APv1Address or APv2Address.
        @return An AccessPort subclass instance.
        
        @exception TargetError Raised if there is not a valid AP for the ap_num.
        """
        # Attempt to read the IDR for this APSEL. If we get a zero back then there is
        # no AP present, so we return None.
        # Check AP version and set the offset to the control and status registers.
        idr = dp.read_ap(ap_address.address + ap_address.idr_address)
        if idr == 0:
            raise exceptions.TargetError("Invalid AP address (%s)" % ap_address)
        
        # Extract IDR fields used for lookup.
        designer = (idr & AP_IDR_JEP106_MASK) >> AP_IDR_JEP106_SHIFT
        apClass = (idr & AP_IDR_CLASS_MASK) >> AP_IDR_CLASS_SHIFT
        variant = (idr & AP_IDR_VARIANT_MASK) >> AP_IDR_VARIANT_SHIFT
        apType = idr & AP_IDR_TYPE_MASK

        # Get the AccessPort class to instantiate.
        key = (designer, apClass, variant, apType)
        try:
            name, klass, flags = AP_TYPE_MAP[key]
        except KeyError:
            # The AP ID doesn't match, but we can recognize unknown MEM-APs.
            if apClass == AP_CLASS_MEM_AP:
                name = "MEM-AP"
                klass = MEM_AP
            else:
                name = None
                klass = AccessPort
            flags = 0
        
        ap = klass(dp, ap_address, idr, name, flags, cmpid)
        ap.init()
        return ap
    
    def __init__(self, dp, ap_address, idr=None, name="", flags=0, cmpid=None):
        """! @brief AP constructor.
        @param self
        @param dp The DebugPort object.
        @param ap_address APAddress object with address of this AP.
        @param idr This AP's IDR register value. If not provided, the IDR will be read by init().
        @param name Name for the AP type, such as "AHB5-AP". If not provided, the type name will be
            set to "AP".
        @param flags Bit mask with extra information about this AP.
        """
        self.dp = dp
        self.address = ap_address
        self._ap_version = ap_address.ap_version
        self.idr = idr
        self.type_name = name or "AP"
        self.rom_addr = 0
        self.has_rom_table = False
        self.rom_table = None
        self.core = None
        self._flags = flags
        self._cmpid = cmpid
    
    @property
    def short_description(self):
        return self.type_name + str(self.address)
    
    @property
    def ap_version(self):
        """! @brief The AP's major version determined by ADI version.
        @retval APVersion.APv1
        @retval APVersion.APv2
        """
        return self._ap_version

    @locked
    def init(self):
        # Read IDR if it wasn't given to us in the ctor.
        if self.idr is None:
            self.idr = self.read_reg(AP_IDR)
        
        self.variant = (self.idr & AP_IDR_VARIANT_MASK) >> AP_IDR_VARIANT_SHIFT
        self.revision = (self.idr & AP_IDR_REVISION_MASK) >> AP_IDR_REVISION_SHIFT
        
        # Get the type name for this AP.
        self.ap_class = (self.idr & AP_IDR_CLASS_MASK) >> AP_IDR_CLASS_SHIFT
        self.ap_type = self.idr & AP_IDR_TYPE_MASK
        if self.type_name is not None:
            desc = "{} var{} rev{}".format(self.type_name, self.variant, self.revision)
        else:
            desc = "proprietary"

        LOG.info("%s IDR = 0x%08x (%s)", self.short_description, self.idr, desc)
 
    def find_components(self):
        """! @brief Find CoreSight components attached to this AP."""
        pass

    @locked
    def read_reg(self, addr, now=True):
        return self.dp.read_ap(self.address.address + addr, now)

    @locked
    def write_reg(self, addr, data):
        self.dp.write_ap(self.address.address + addr, data)
    
    def lock(self):
        """! @brief Lock the AP from access by other threads."""
        self.dp.probe.lock()
    
    def unlock(self):
        """! @brief Unlock the AP."""
        self.dp.probe.unlock()
    
    @contextmanager
    def locked(self):
        """! @brief Context manager for locking the AP using a with statement.
        
        All public methods of AccessPort and its subclasses are automatically locked, so manual
        locking usually is not necessary unless you need to hold the lock across multiple AP
        accesses.
        """
        self.lock()
        yield
        self.unlock()
    
    def __repr__(self):
        return "<{}@{:x} {} idr={:08x} rom={:08x}>".format(
            self.__class__.__name__, id(self), self.short_description, self.idr, self.rom_addr)

class MEM_AP(AccessPort, memory_interface.MemoryInterface):
    """! @brief MEM-AP component.
    
    This class supports MEM-AP v1 and v2.
    
    The bits of HPROT have the following meaning. Not all bits are implemented in all
    MEM-APs. AHB-Lite only implements HPROT[3:0].
    
    HPROT[0] = 1 data access, 0 instr fetch<br/>
    HPROT[1] = 1 priviledge, 0 user<br/>
    HPROT[2] = 1 bufferable, 0 non bufferable<br/>
    HPROT[3] = 1 cacheable/modifable, 0 non cacheable<br/>
    HPROT[4] = 1 lookupincache, 0 no cache<br/>
    HPROT[5] = 1 allocate in cache, 0 no allocate in cache<br/>
    HPROT[6] = 1 shareable, 0 non shareable<br/>
    
    Extensions not supported:
    - Large Data Extension
    - Large Physical Address Extension
    - Barrier Operation Extension
    """

    def __init__(self, dp, ap_address, idr=None, name="", flags=0, cmpid=None):
        super(MEM_AP, self).__init__(dp, ap_address, idr, name, flags, cmpid)
        
        # Check AP version and set the offset to the control and status registers.
        if self.ap_version == APVersion.APv1:
            self._reg_offset = 0
        elif self.ap_version == APVersion.APv2:
            self._reg_offset = MEM_APv2_CONTROL_REG_OFFSET
        else:
            assert False, "Unrecognized AP version %s" % self.ap_version
        
        self._impl_hprot = 0
        self._impl_hnonsec = 0
        
        ## Default HPROT value for CSW.
        self._hprot = HPROT_DATA | HPROT_PRIVILEGED
        
        ## Default HNONSEC value for CSW.
        self._hnonsec = SECURE
        
        ## Base CSW value to use.
        self._csw = DEFAULT_CSW_VALUE
        
        ## Cached current CSW value.
        self._cached_csw = -1
        
        ## Supported transfer sizes.
        self._transfer_sizes = (32,)

        ## Auto-increment wrap modulus.
        #
        # The AP_4K_WRAP flag indicates a 4 kB wrap size. Otherwise it defaults to the smallest
        # size supported by all targets. A size smaller than the supported size will decrease
        # performance due to the extra address writes, but will not create any read/write errors.
        self.auto_increment_page_size = 0x1000 if (self._flags & AP_4K_WRAP) else 0x400
        
        ## Number of DAR registers.
        self._dar_count = 0
        
        ## Mask of addresses. This indicates whether 32-bit or 64-bit addresses are supported.
        self._address_mask = 0xffffffff
        
        ## Whether the Large Data extension is supported.
        self._has_large_data = False
        
        # Ask the probe for an accelerated memory interface for this AP. If it provides one,
        # then bind our memory interface APIs to its methods. Otherwise use our standard
        # memory interface based on AP register accesses.
        memoryInterface = self.dp.probe.get_memory_interface_for_ap(self.address)
        if memoryInterface is not None:
            LOG.debug("Using accelerated memory access interface")
            self.write_memory = memoryInterface.write_memory
            self.read_memory = memoryInterface.read_memory
            self.write_memory_block32 = memoryInterface.write_memory_block32
            self.read_memory_block32 = memoryInterface.read_memory_block32
        else:
            self.write_memory = self._write_memory
            self.read_memory = self._read_memory
            self.write_memory_block32 = self._write_memory_block32
            self.read_memory_block32 = self._read_memory_block32
        
        # Subscribe to reset events.
        self.dp.session.subscribe(self._reset_did_occur, (Target.Event.PRE_RESET, Target.Event.POST_RESET))

    @property
    def supported_transfer_sizes(self):
        """! @brief Tuple of transfer sizes supported by this AP."""
        return self._transfer_sizes
    
    @property
    def is_enabled(self):
        """! @brief Whether any memory transfers are allowed by this AP.
        
        Memory transfers may be disabled by an input signal to the AP. This is often done when debug security
        is enabled on the device, to disallow debugger access to internal memory.
        """
        return self.is_enabled_for(Target.SecurityState.NONSECURE)
    
    def is_enabled_for(self, security_state):
        """! @brief Checks whether memory transfers are allowed by this AP for the given security state.
        
        Memory transfers may be disabled by an input signal to the AP. This is often done when debug security
        is enabled on the device, to disallow debugger access to internal memory.
        
        @param self The AP instance.
        @param security_state One of the @ref pyocd.core.target.Target.SecurityState "SecurityState" enums.
        @return Boolean indicating whether memory transfers can be performed in the requested security state. You
            may change the security state used for transfers with the hnonsec property and hnonsec_lock() method.
        """
        assert isinstance(security_state, Target.SecurityState)
        
        # Call to superclass to read CSW. We want to bypass our CSW cache since the enable signal can change
        # asynchronously.
        csw = AccessPort.read_reg(self, self._reg_offset + MEM_AP_CSW)
        if security_state is Target.SecurityState.NONSECURE:
            # Nonsecure transfers are always allowed when security transfers are enabled.
            return (csw & (CSW_DEVICEEN | CSW_SDEVICEEN)) != 0
        elif security_state is Target.SecurityState.SECURE:
            return (csw & CSW_SDEVICEEN) != 0
        else:
            assert False, "unsupported security state"

    @locked
    def init(self):
        """! @brief Initialize the MEM-AP.
        
        This method interrogates the MEM-AP to determine its capabilities, and performs any initial setup
        that is required.
        
        It performs these checks:
        - Check for Long Address extension.
        - Check for Large Data extension.
        - (v2 only) Get the auto-increment page size.
        - (v2 only) Determine supported error mode.
        - (v2 only) Get the size of the DAR register window.
        - Determine supported transfer sizes.
        - Determine the implemented HPROT and HNONSEC controls.
        - Read the ROM table base address.

        These controls are configured.
        - (v2 only) Configure the error mode.
        """
        super(MEM_AP, self).init()
        
        # Read initial CSW. Superclass register access methods are used to avoid the CSW cache.
        original_csw = AccessPort.read_reg(self, self._reg_offset + MEM_AP_CSW)
    
        def _init_cfg():
            """! @brief Read MEM-AP CFG register."""
            cfg = self.read_reg(self._reg_offset + MEM_AP_CFG)
        
            # Check for 64-bit address support.
            if cfg & MEM_AP_CFG_LA_MASK:
                self._address_mask = 0xffffffffffffffff
        
            # Check for Large Data extension.
            if cfg & MEM_AP_CFG_LD_MASK:
                self._has_large_data = True
        
            # Check v2 MEM-AP CFG fields.
            if self.ap_version == APVersion.APv2:
                # Set autoinc page size if TARINC is non-zero. Otherwise we've already set the
                # default of 1 kB in the ctor.
                tarinc = (cfg & MEM_AP_CFG_TARINC_MASK) >> MEM_AP_CFG_TARINC_SHIFT
                if tarinc != 0:
                    self.auto_increment_page_size = 1 << (9 + tarinc)
        
                # Determine supported err mode.
                err = (cfg & MEM_AP_CFG_ERR_MASK) >> MEM_AP_CFG_ERR_SHIFT
                if err == MEM_AP_CFG_ERR_V1:
                    # Configure the error mode such that errors are passed upstream, but they don't
                    # prevent future transactions.
                    self._csw &= ~(CSW_ERRSTOP | CSW_ERRNPASS)
            
                    # Clear TRR in case we attach to a device with a sticky error already set.
                    self.write_reg(self._reg_offset + MEM_AP_TRR, MEM_AP_TRR_ERR_MASK)
        
                # Init size of DAR register window.
                darsize = (cfg & MEM_AP_CFG_DARSIZE_MASK) >> MEM_AP_CFG_DARSIZE_SHIFT
                self._dar_count = (1 << darsize) // 4

        def _init_transfer_sizes():
            """! @brief Determine supported transfer sizes.
        
            If the #AP_ALL_TX_SZ flag is set, then we know a priori that this AP implementation
            supports 8-, 16- and 32- transfer sizes. If the Large Data extension is implemented, then this
            flag is ignored.
        
            Note in ADIv6: "If a MEM-AP implementation does not support the Large Data Extension, but does
            support various access sizes, it must support word, halfword, and byte accesses."

            So, if the Large Data extension is present, then we have to individually test each
            transfer size (aside from the required 32-bit).
            
            If Large Data is not present, then only one non-32-bit transfer size needs to be tested to
            determine if the AP supports both 8- and 16-bit transfers in addition to the required 32-bit.
            """
            # If AP_ALL_TX_SZ is set, we can skip the test. Double check this by ensuring that LD is not
            # enabled.
            if (self._flags & AP_ALL_TX_SZ) and not self._has_large_data:
                self._transfer_sizes = (8, 16, 32)
                return
        
            def _test_transfer_size(sz):
                """! @brief Utility to verify whether the MEM-AP supports a given transfer size.
                
                From ADIv6:
                If the CSW.Size field is written with a value corresponding to a size that is not supported,
                or with a reserved value: A read of the field returns a value corresponding to a supported
                size.
                """
                # Write CSW_SIZE to select requested transfer size.
                AccessPort.write_reg(self, self._reg_offset + MEM_AP_CSW, original_csw & ~CSW_SIZE | sz)
        
                # Read back CSW and see if SIZE matches what we wrote.
                csw_cb = AccessPort.read_reg(self, self._reg_offset + MEM_AP_CSW, now=False)
                
                return lambda: (csw_cb() & CSW_SIZE) == sz
            
            # Thus if LD ext is not present, we only need to test one size.

            if self._has_large_data:
                # Need to scan all sizes except 32-bit, which is required.
                SIZES_TO_TEST = (CSW_SIZE8, CSW_SIZE16, CSW_SIZE64, CSW_SIZE128, CSW_SIZE256)
                
                sz_result_cbs = ((sz, _test_transfer_size(sz)) for sz in SIZES_TO_TEST)
                self._transfer_sizes = ([32] + [(8 * (1 << sz)) for sz, cb in sz_result_cbs if cb()])
                self._transfer_sizes.sort()
                
            elif _test_transfer_size(CSW_SIZE16)():
                self._transfer_sizes = (8, 16, 32)

        def _init_hprot():
            """! @brief Init HPROT HNONSEC.
        
            Determines the implemented bits of HPROT and HNONSEC in this MEM-AP. The defaults for these
            fields of the CSW are based on the implemented bits.
            """
            default_hprot = (original_csw & CSW_HPROT_MASK) >> CSW_HPROT_SHIFT
            default_hnonsec = (original_csw & CSW_HNONSEC_MASK) >> CSW_HNONSEC_SHIFT
            LOG.debug("%s default HPROT=%x HNONSEC=%x", self.short_description, default_hprot, default_hnonsec)
        
            # Now attempt to see which HPROT and HNONSEC bits are implemented.
            AccessPort.write_reg(self, self._reg_offset + MEM_AP_CSW,
                    original_csw | CSW_HNONSEC_MASK | CSW_HPROT_MASK)
            csw = AccessPort.read_reg(self, self._reg_offset + MEM_AP_CSW)
        
            self._impl_hprot = (csw & CSW_HPROT_MASK) >> CSW_HPROT_SHIFT
            self._impl_hnonsec = (csw & CSW_HNONSEC_MASK) >> CSW_HNONSEC_SHIFT
            LOG.debug("%s implemented HPROT=%x HNONSEC=%x", self.short_description, self._impl_hprot,
                    self._impl_hnonsec)
        
            # Update current HPROT and HNONSEC, and the current base CSW value.
            self.hprot = self._hprot & self._impl_hprot
            self.hnonsec = self._hnonsec & self._impl_hnonsec

        def _init_rom_table_base():
            """! @brief Read ROM table base address."""
            base = self.read_reg(self._reg_offset + MEM_AP_BASE)
            is_adiv5_base = (base & AP_BASE_FORMAT_MASK) != 0
            is_base_present = (base & AP_BASE_ENTRY_PRESENT_MASK) != 0
            is_legacy_base_present = not is_adiv5_base and not is_base_present
            if is_legacy_base_present:
                self.has_rom_table = True
                self.rom_addr = base & AP_BASE_LEGACY_BASEADDR_MASK # clear format and present bits
            elif (base == AP_BASE_LEGACY_NOTPRESENT) or (not is_base_present):
                self.has_rom_table = False
                self.rom_addr = 0
            elif is_adiv5_base and is_base_present:
                self.has_rom_table = True
                self.rom_addr = base & AP_BASE_BASEADDR_MASK # clear format and present bits
            else:
                raise exceptions.TargetError("invalid AP BASE value 0x%08x" % base)
        
        # Run the init tests.
        _init_cfg()
        _init_transfer_sizes()
        _init_hprot()
        _init_rom_table_base()
 
        # Restore unmodified value of CSW.
        AccessPort.write_reg(self, self._reg_offset + MEM_AP_CSW, original_csw)

    @locked
    def find_components(self):
        try:
            if self.has_rom_table:
                if not self.is_enabled:
                    LOG.warning("Skipping CoreSight discovery for %s because it is disabled", self.short_description)
                    return
                
                # Import locally to work around circular import.
                from .rom_table import (CoreSightComponentID, ROMTable)
                
                # Read the ROM table component IDs.
                cmpid = CoreSightComponentID(None, self, self.rom_addr)
                cmpid.read_id_registers()

                # Instantiate the ROM table and parse it.
                if cmpid.is_rom_table:
                    self.rom_table = ROMTable.create(self, cmpid, self.rom_addr)
                    self.rom_table.init()
        except exceptions.TransferError as error:
            LOG.error("Transfer error while reading %s ROM table: %s", self.short_description, error,
                exc_info=self.dp.session.log_tracebacks)

    @property
    def implemented_hprot_mask(self):
        return self._impl_hprot
    
    @property
    def implemented_hnonsec_mask(self):
        return self._impl_hnonsec

    @property
    def hprot(self):
        return self._hprot
    
    @hprot.setter
    @locked
    def hprot(self, value):
        """! @brief Setter for current HPROT value used for memory transactions.
    
        The bits of HPROT have the following meaning. Not all bits are implemented in all
        MEM-APs. AHB-Lite only implements HPROT[3:0].
        
        HPROT[0] = 1 data access, 0 instr fetch<br/>
        HPROT[1] = 1 priviledge, 0 user<br/>
        HPROT[2] = 1 bufferable, 0 non bufferable<br/>
        HPROT[3] = 1 cacheable/modifable, 0 non cacheable<br/>
        HPROT[4] = 1 lookup in cache, 0 no cache<br/>
        HPROT[5] = 1 allocate in cache, 0 no allocate in cache<br/>
        HPROT[6] = 1 shareable, 0 non shareable<br/>
        """
        self._hprot = value & (CSW_HPROT_MASK >> CSW_HPROT_SHIFT)
        
        self._csw = ((self._csw & ~CSW_HPROT_MASK)
                            | (self._hprot << CSW_HPROT_SHIFT))
    
    @property
    def hnonsec(self):
        return self._hnonsec
    
    @hnonsec.setter
    @locked
    def hnonsec(self, value):
        """! @brief Setter for current HNONSEC value used for memory transactions.
        
        Not all MEM-APs support control of HNONSEC. In particular, only the AHB5-AP used for
        v8-M Cortex-M systems does. The AXI-AP for Cortex-A systems also allows this control.
    
        @param value 0 is secure, 1 is non-secure.
        """
        self._hnonsec = value & (CSW_HNONSEC_MASK >> CSW_HNONSEC_SHIFT)
        
        self._csw = ((self._csw & ~CSW_HNONSEC_MASK)
                            | (self._hnonsec << CSW_HNONSEC_SHIFT))
    
    class _MemAttrContext(object):
        """! @brief Context manager for temporarily setting HPROT and/or HNONSEC.
        
        The AP is locked during the lifetime of the context manager. This means that only the
        calling thread can perform memory transactions.
        """
        def __init__(self, ap, hprot=None, hnonsec=None):
            self._ap = ap
            self._hprot = hprot
            self._saved_hprot = None
            self._hnonsec = hnonsec
            self._saved_hnonsec = None
            
        def __enter__(self):
            self._ap.lock()
            if self._hprot is not None:
                self._saved_hprot = self._ap.hprot
                self._ap.hprot = self._hprot
            if self._hnonsec is not None:
                self._saved_hnonsec = self._ap.hnonsec
                self._ap.hnonsec = self._hnonsec
            return self
            
        def __exit__(self, type, value, traceback):
            if self._saved_hprot is not None:
                self._ap.hprot = self._saved_hprot
            if self._saved_hnonsec is not None:
                self._ap.hnonsec = self._saved_hnonsec
            self._ap.unlock()
            return False

    def hprot_lock(self, hprot):
        """! @brief Context manager to temporarily change HPROT."""
        return self._MemAttrContext(self, hprot=hprot)
    
    def hnonsec_lock(self, hnonsec):
        """! @brief Context manager to temporarily change HNONSEC.
        
        @see secure_lock(), nonsecure_lock()
        """
        return self._MemAttrContext(self, hnonsec=hnonsec)
    
    def secure_lock(self):
        """! @brief Context manager to temporarily set the AP to use secure memory transfers."""
        return self.hnonsec_lock(SECURE)
    
    def nonsecure_lock(self):
        """! @brief Context manager to temporarily set AP to use non-secure memory transfers."""
        return self.hnonsec_lock(NONSECURE)

    @locked
    def read_reg(self, addr, now=True):
        ap_regaddr = addr & APREG_MASK
        if ap_regaddr == self._reg_offset + MEM_AP_CSW and self._cached_csw != -1 and now:
            return self._cached_csw
        return self.dp.read_ap(self.address.address + addr, now)

    @locked
    def write_reg(self, addr, data):
        ap_regaddr = addr & APREG_MASK

        # Don't need to write CSW if it's not changing value.
        if ap_regaddr == self._reg_offset + MEM_AP_CSW:
            if data == self._cached_csw:
                if TRACE.isEnabledFor(logging.INFO):
                    num = self.dp.next_access_number
                    TRACE.debug("write_ap:%06d cached (ap=0x%x; addr=0x%08x) = 0x%08x",
                        num, self.address.nominal_address, addr, data)
                return
            self._cached_csw = data

        try:
            self.dp.write_ap(self.address.address + addr, data)
        except exceptions.ProbeError:
            # Invalidate cached CSW on exception.
            if ap_regaddr == self._reg_offset + MEM_AP_CSW:
                self._invalidate_cache()
            raise
    
    def _invalidate_cache(self):
        """! @brief Invalidate cached registers associated with this AP."""
        self._cached_csw = -1
    
    def _reset_did_occur(self, notification):
        """! @brief Handles reset notifications to invalidate CSW cache."""
        # We clear the cache on all resets just to be safe.
        self._invalidate_cache()

    @locked
    def _write_memory(self, addr, data, transfer_size=32):
        """! @brief Write a single memory location.
        
        By default the transfer size is a word
        
        @exception TransferError Raised if the requested transfer size is not supported by the AP.
        """
        assert (addr & (transfer_size // 8 - 1)) == 0
        addr &= self._address_mask
        if transfer_size not in self._transfer_sizes:
            raise exceptions.TransferError("%d-bit transfers are not supported by %s"
                % (transfer_size, self.short_description))
        num = self.dp.next_access_number
        TRACE.debug("write_mem:%06d (ap=0x%x; addr=0x%08x, size=%d) = 0x%08x {",
            num, self.address.nominal_address, addr, transfer_size, data)
        self.write_reg(self._reg_offset + MEM_AP_CSW, self._csw | TRANSFER_SIZE[transfer_size])
        if transfer_size == 8:
            data = data << ((addr & 0x03) << 3)
        elif transfer_size == 16:
            data = data << ((addr & 0x02) << 3)
        elif transfer_size > 32:
            # Split the value into a tuple of 32-bit words, least-significant first.
            data = (((data >> (32 * i)) & 0xffffffff) for i in range(transfer_size // 32))

        try:
            self.write_reg(self._reg_offset + MEM_AP_TAR, addr)
            
            if transfer_size <= 32:
                self.write_reg(self._reg_offset + MEM_AP_DRW, data)
            else:
                # Multi-word transfer.
                self.dp.write_ap_multiple(self.address.address + self._reg_offset + MEM_AP_DRW, data)
        except exceptions.TransferFaultError as error:
            # Annotate error with target address.
            self._handle_error(error, num)
            error.fault_address = addr
            error.fault_length = transfer_size // 8
            raise
        except exceptions.Error as error:
            self._handle_error(error, num)
            raise
        TRACE.debug("write_mem:%06d }", num)

    @locked
    def _read_memory(self, addr, transfer_size=32, now=True):
        """! @brief Read a memory location.
        
        By default, a word will be read.
        
        @exception TransferError Raised if the requested transfer size is not supported by the AP.
        """
        assert (addr & (transfer_size // 8 - 1)) == 0
        addr &= self._address_mask
        if transfer_size not in self._transfer_sizes:
            raise exceptions.TransferError("%d-bit transfers are not supported by %s"
                % (transfer_size, self.short_description))
        num = self.dp.next_access_number
        TRACE.debug("read_mem:%06d (ap=0x%x; addr=0x%08x, size=%d) {",
            num, self.address.nominal_address, addr, transfer_size)
        try:
            self.write_reg(self._reg_offset + MEM_AP_CSW, self._csw | TRANSFER_SIZE[transfer_size])
            self.write_reg(self._reg_offset + MEM_AP_TAR, addr)
            
            if transfer_size <= 32:
                result_cb = self.read_reg(self._reg_offset + MEM_AP_DRW, now=False)
            else:
                # Multi-word transfer.
                result_cb = self.dp.read_ap_multiple(self.address.address + self._reg_offset + MEM_AP_DRW,
                        transfer_size // 32, now=False)
        except exceptions.TransferFaultError as error:
            # Annotate error with target address.
            self._handle_error(error, num)
            error.fault_address = addr
            error.fault_length = transfer_size // 8
            raise
        except exceptions.Error as error:
            self._handle_error(error, num)
            raise

        def read_mem_cb():
            res = None
            try:
                res = result_cb()
                if transfer_size == 8:
                    res = (res >> ((addr & 0x03) << 3) & 0xff)
                elif transfer_size == 16:
                    res = (res >> ((addr & 0x02) << 3) & 0xffff)
                elif transfer_size > 32:
                    res = sum((w << (32 * i)) for i, w in enumerate(res))
                TRACE.debug("read_mem:%06d %s(ap=0x%x; addr=0x%08x, size=%d) -> 0x%08x }",
                    num, "" if now else "...", self.address.nominal_address, addr, transfer_size, res)
            except exceptions.TransferFaultError as error:
                # Annotate error with target address.
                self._handle_error(error, num)
                error.fault_address = addr
                error.fault_length = transfer_size // 8
                raise
            except exceptions.Error as error:
                self._handle_error(error, num)
                raise
            return res

        if now:
            result = read_mem_cb()
            return result
        else:
            return read_mem_cb

    def _write_block32_page(self, addr, data):
        """! @brief Write a single transaction's worth of aligned words.
        
        The transaction must not cross the MEM-AP's auto-increment boundary.

        This method is not locked because it is only called by _write_memory_block32(), which is locked.
        """
        assert (addr & 0x3) == 0
        num = self.dp.next_access_number
        TRACE.debug("_write_block32:%06d (ap=0x%x; addr=0x%08x, size=%d) {",
            num, self.address.nominal_address, addr, len(data))
        # put address in TAR
        self.write_reg(self._reg_offset + MEM_AP_CSW, self._csw | CSW_SIZE32)
        self.write_reg(self._reg_offset + MEM_AP_TAR, addr)
        try:
            self.dp.write_ap_multiple(self.address.address + self._reg_offset + MEM_AP_DRW, data)
        except exceptions.TransferFaultError as error:
            # Annotate error with target address.
            self._handle_error(error, num)
            error.fault_address = addr
            error.fault_length = len(data) * 4
            raise
        except exceptions.Error as error:
            self._handle_error(error, num)
            raise
        TRACE.debug("_write_block32:%06d }", num)

    def _read_block32_page(self, addr, size):
        """! @brief Read a single transaction's worth of aligned words.
        
        The transaction must not cross the MEM-AP's auto-increment boundary.

        This method is not locked because it is only called by _read_memory_block32(), which is locked.
        """
        assert (addr & 0x3) == 0
        num = self.dp.next_access_number
        TRACE.debug("_read_block32:%06d (ap=0x%x; addr=0x%08x, size=%d) {",
            num, self.address.nominal_address, addr, size)
        # put address in TAR
        self.write_reg(self._reg_offset + MEM_AP_CSW, self._csw | CSW_SIZE32)
        self.write_reg(self._reg_offset + MEM_AP_TAR, addr)
        try:
            resp = self.dp.read_ap_multiple(self.address.address + self._reg_offset + MEM_AP_DRW, size)
        except exceptions.TransferFaultError as error:
            # Annotate error with target address.
            self._handle_error(error, num)
            error.fault_address = addr
            error.fault_length = size * 4
            raise
        except exceptions.Error as error:
            self._handle_error(error, num)
            raise
        TRACE.debug("_read_block32:%06d }", num)
        return resp

    @locked
    def _write_memory_block32(self, addr, data):
        """! @brief Write a block of aligned words in memory."""
        assert (addr & 0x3) == 0
        addr &= self._address_mask
        size = len(data)
        while size > 0:
            n = self.auto_increment_page_size - (addr & (self.auto_increment_page_size - 1))
            if size*4 < n:
                n = (size*4) & 0xfffffffc
            self._write_block32_page(addr, data[:n//4])
            data = data[n//4:]
            size -= n//4
            addr += n
        return

    @locked
    def _read_memory_block32(self, addr, size):
        """! @brief Read a block of aligned words in memory.
        
        @return A list of word values.
        """
        assert (addr & 0x3) == 0
        addr &= self._address_mask
        resp = []
        while size > 0:
            n = self.auto_increment_page_size - (addr & (self.auto_increment_page_size - 1))
            if size*4 < n:
                n = (size*4) & 0xfffffffc
            resp += self._read_block32_page(addr, n//4)
            size -= n//4
            addr += n
        return resp

    def _handle_error(self, error, num):
        self.dp._handle_error(error, num)
        self._invalidate_cache()

class AHB_AP(MEM_AP):
    """! @brief AHB-AP access port subclass.
    
    This subclass checks for the AP_MSTRTYPE flag, and if set configures that field in the CSW
    register to use debugger transactions. Only the M3 and M4 AHB-AP implements MSTRTYPE.
    
    Another AHB-AP specific addition is that an attempt is made to set the TRCENA bit in the DEMCR
    register before reading the ROM table. This is required on some Cortex-M devices, otherwise
    certain ROM table entries will read as zeroes or other garbage.
    """

    @locked
    def init(self):
        super(AHB_AP, self).init()

        # Check for and enable the Master Type bit on AHB-APs where it might be implemented.
        if self._flags & AP_MSTRTYPE:
            self._init_mstrtype()
        
    def _init_mstrtype(self):
        """! @brief Set master type control in CSW.
        
        Only the v1 AHB-AP from Cortex-M3 and Cortex-M4 implements the MSTRTYPE flag to control
        whether transactions appear as debugger or internal accesses.
        """
        # Set the master type to "debugger" for AP's that support this field.
        self._csw |= CSW_MSTRDBG

    def find_components(self):
        # Turn on DEMCR.TRCENA before reading the ROM table. Some ROM table entries can
        # come back as garbage if TRCENA is not set.
        try:
            demcr = self.read32(DEMCR)
            self.write32(DEMCR, demcr | DEMCR_TRCENA)
            self.dp.flush()
        except exceptions.TransferError:
            # Ignore exception and read whatever we can of the ROM table.
            pass

        # Invoke superclass.
        super(AHB_AP, self).find_components()

## @brief Arm JEP106 code
#
# - [6:0] = 0x3B, Arm's JEP106 identification code
# - [12:7] = 4, the number of JEP106 continuation codes for Arm
AP_JEP106_ARM = 0x23b

# AP classes
AP_CLASS_JTAG_AP = 0x0
AP_CLASS_COM_AP = 0x1 # SDC-600 (Chaucer)
AP_CLASS_MEM_AP = 0x8 # AHB-AP, APB-AP, AXI-AP

# MEM-AP type constants
AP_TYPE_AHB = 0x1
AP_TYPE_APB = 0x2
AP_TYPE_AXI = 0x4
AP_TYPE_AHB5 = 0x5
AP_TYPE_APB4 = 0x6
AP_TYPE_AXI5 = 0x7
AP_TYPE_AHB5_HPROT = 0x8

# AP flags.
AP_4K_WRAP = 0x1 # The AP has a 4 kB auto-increment modulus.
AP_ALL_TX_SZ = 0x2 # The AP is known to support 8-, 16-, and 32-bit transfers, *unless* Large Data is implemented.
AP_MSTRTYPE = 0x4 # The AP is known to support the MSTRTYPE field.

## Map from AP IDR fields to AccessPort subclass.
#
# The dict maps from a 4-tuple of (JEP106 code, AP class, variant, type) to 2-tuple (name, class, flags).
#
# Known AP IDRs:
# 0x24770011 AHB-AP with 0x1000 wrap and MSTRTYPE
#               Used on m4 & m3 - Documented in arm_cortexm4_processor_trm_100166_0001_00_en.pdf
#               and arm_cortexm3_processor_trm_100165_0201_00_en.pdf
# 0x34770001 AHB-AP Documented in DDI0314H_coresight_components_trm.pdf
# 0x44770001 AHB-AP Used on m1 - Documented in DDI0413D_cortexm1_r1p0_trm.pdf
# 0x04770031 AHB-AP Used on m0+? at least on KL25Z, KL46, LPC812
# 0x04770021 AHB-AP Used on m0? used on nrf51, lpc11u24
# 0x04770041 AHB-AP Used on m7, RT1050
# 0x64770001 AHB-AP Used on m7, documented in DDI0480G_coresight_soc_trm.pdf
# 0x74770001 AHB-AP Used on m0+ on KL28Z
# 0x84770001 AHB-AP Used on K32W042
# 0x14770005 AHB5-AP Used on M33. Note that M33 r0p0 incorrect fails to report this IDR.
# 0x04770025 AHB5-AP Used on M23.
# 0x54770002 APB-AP used on M33.
AP_TYPE_MAP = {
#   |JEP106        |Class              |Var|Type                    |Name      |Class
    (AP_JEP106_ARM, AP_CLASS_JTAG_AP,   0,  0):                     ("JTAG-AP", AccessPort, 0   ),
    (AP_JEP106_ARM, AP_CLASS_COM_AP,    0,  0):                     ("SDC-600", AccessPort, 0   ),
    (AP_JEP106_ARM, AP_CLASS_MEM_AP,    0,  AP_TYPE_AHB):           ("AHB-AP",  AHB_AP,     AP_ALL_TX_SZ ),
    (AP_JEP106_ARM, AP_CLASS_MEM_AP,    1,  AP_TYPE_AHB):           ("AHB-AP",  AHB_AP,     AP_ALL_TX_SZ|AP_4K_WRAP|AP_MSTRTYPE ),
    (AP_JEP106_ARM, AP_CLASS_MEM_AP,    2,  AP_TYPE_AHB):           ("AHB-AP",  AHB_AP,     AP_ALL_TX_SZ ),
    (AP_JEP106_ARM, AP_CLASS_MEM_AP,    3,  AP_TYPE_AHB):           ("AHB-AP",  AHB_AP,     AP_ALL_TX_SZ ),
    (AP_JEP106_ARM, AP_CLASS_MEM_AP,    4,  AP_TYPE_AHB):           ("AHB-AP",  AHB_AP,     AP_ALL_TX_SZ ),
    (AP_JEP106_ARM, AP_CLASS_MEM_AP,    0,  AP_TYPE_APB):           ("APB-AP",  MEM_AP,     0   ),
    (AP_JEP106_ARM, AP_CLASS_MEM_AP,    0,  AP_TYPE_AXI):           ("AXI-AP",  MEM_AP,     AP_ALL_TX_SZ ),
    (AP_JEP106_ARM, AP_CLASS_MEM_AP,    0,  AP_TYPE_AHB5):          ("AHB5-AP", AHB_AP,     AP_ALL_TX_SZ ),
    (AP_JEP106_ARM, AP_CLASS_MEM_AP,    1,  AP_TYPE_AHB5):          ("AHB5-AP", AHB_AP,     AP_ALL_TX_SZ ),
    (AP_JEP106_ARM, AP_CLASS_MEM_AP,    2,  AP_TYPE_AHB5):          ("AHB5-AP", AHB_AP,     AP_ALL_TX_SZ ),
    (AP_JEP106_ARM, AP_CLASS_MEM_AP,    0,  AP_TYPE_APB4):          ("APB4-AP", MEM_AP,     0   ),
    (AP_JEP106_ARM, AP_CLASS_MEM_AP,    0,  AP_TYPE_AXI5):          ("AXI5-AP", MEM_AP,     AP_ALL_TX_SZ ),
    (AP_JEP106_ARM, AP_CLASS_MEM_AP,    0,  AP_TYPE_AHB5_HPROT):    ("AHB5-AP", MEM_AP,     AP_ALL_TX_SZ ),
    }
