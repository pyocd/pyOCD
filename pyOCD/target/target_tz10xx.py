"""
TOSHIBA TZ10xx serias
"""
from .coresight_target import CoreSightTarget
from .memory_map import (FlashRegion, RamRegion, MemoryMap)
from time import sleep

class TZ10xx(CoreSightTarget):

    has_fpu = True
    memoryMap = MemoryMap(
        FlashRegion(    start=0,           length=0x00100000,   blocksize=0x100, isBootMemory=True),   #On package NOR Flash
        RamRegion(      start=0x10000000,  length=0x00040000),                                          #Code region
        RamRegion(      start=0x20000000,  length=0x00008000)                                           #Data region
        )

    def __init__(self, link):
        super(TZ10xx, self).__init__(link, self.memoryMap)

    def reset(self, software_reset=True):
        if software_reset == None:
            software_reset = True
        super(TZ10xx, self).reset(software_reset)
        if software_reset:
            sleep(0.1)
            self.__initializeDCDC()
            self.__initializeVoltageMode()
            self.__initializeClockSource()
            self.__initializeAndPowerOnPLL()
            self.__startUSB()
            self.__initializePU()
            self.__stopUSB()
            self.__initializeClockSourceMain()
            self.__initializePrescaler()
            self.__powerOnDomain()
            self.__initializeIOCell()
            self.__resetOnDomain()
            self.__powerOffDomain()
            self.__stopPrescaler()
            self.__initializeADPLL()
            self.__initializeRTC()
            self.__initializeMacro()
            self.__initializeMiscRegisters()

    #
    # Porting from TZ10xx initialize script.
    #
    def __initializeDCDC(self):
        # 1.
        self.writeMemory(0x400001C0, 0x00010000)        # CG_OFF_HARDMACRO

    def __initializeVoltageMode(self):
        # 2.
        stat = 1
        while stat != 0:
            stat = self.readMemory(0x40000700)          # MOVE_VOLTAGE_START
            stat &= 1
        self.writeMemory(0x40000730, 0x00000000)        # VOLTAGEMODE_SETTING
        self.writeMemory(0x40000704, 0x00000000)        # MOVE_POWER_VOLTAGE_MODE
        self.writeMemory(0x40000700, 0x00000001)        # MOVE_VOLTAGE_START
        stat = 1
        while stat != 0:
            stat = self.readMemory(0x40000700)          # MOVE_VOLTAGE_START
            stat &= 1

    def __initializeClockSource(self):
        # 3.
        self.writeMemory(0x40000404, 0x00000000)        # CSM_MAIN
        self.writeMemory(0x40000408, 0x00000000)        # CSM_CPUTRC
        self.writeMemory(0x4000040C, 0x00000000)        # CSM_CPUST
        self.writeMemory(0x40000414, 0x00000000)        # CSM_UART0
        self.writeMemory(0x40000418, 0x00000000)        # CSM_UART1
        self.writeMemory(0x4000041C, 0x00000000)        # CSM_UART2
        self.writeMemory(0x40000420, 0x00000000)        # CSM_ADCC12A
        self.writeMemory(0x40000424, 0x00000000)        # CSM_ADCC24A

    def __initializePrescaler(self):
        # 4.
        self.writeMemory(0x40000484, 0x00111111)        # PRESCAL_MAIN
        self.writeMemory(0x4000048C, 0x00000001)        # PRESCAL_CPUST
        self.writeMemory(0x40000494, 0x00000001)        # PRESCAL_UART0
        self.writeMemory(0x40000498, 0x00000001)        # PRESCAL_UART1
        self.writeMemory(0x4000049C, 0x00000001)        # PRESCAL_UART2
        self.writeMemory(0x400004A0, 0x00000001)        # PRESCAL_ADCC12A
        self.writeMemory(0x400004A4, 0x00000001)        # PRESCAL_ADCC24A

    def __initializeAndPowerOnPLL(self):
        # 5.
        # 5-1.
        stat = self.readMemory(0x40000500)              # CONFIG_OSC12M.OSC12M_EN
        if 0 == stat:   # OSC12M stopped
            # 5-2.
            self.writeMemory(0x40000500, 0x00000001)    # CONFIG_OSC12M
            sleep(0.01)
        # 5-3.
        stat = self.readMemory(0x40002444)              # PSW_PLL
        if 0 == stat:
            # 5-4.
            self.writeMemory(0x40002444, 0x00000001)    # PSW_PLL
            self.writeMemory(0x40002444, 0x00000003)    # PSW_PLL
        # 5-5.
        stat = self.readMemory(0x40002544)              # ISO_PLL
        if (3 == stat):
            # 5-6.
            self.writeMemory(0x40002544, 0x00000000)    # ISO_PLL
        # 5-7.
        self.writeMemory(0x40000508, 0x80000001)        # CONFIG_PLL_0
        self.writeMemory(0x4000050c, 0x00000093)        # CONFIG_PLL_1
        sleep(0.001)
        self.writeMemory(0x40000508, 0x00000000)        # CONFIG_PLL_0
        sleep(0.001)

    def __startUSB(self):
        # 6.
        self.writeMemory(0x40000410, 0x00000000)        # CSM_USBI
        # 7.
        self.writeMemory(0x40000490, 0x00000001)        # PRESCAL_USBI

    def __initializePU(self):
        # 8. clock and reset
        self.writeMemory(0x4000032C, 0x0000000d)        # SRST_ON_PU
        self.writeMemory(0x4000032C, 0x00000010)        # SRST_ON_PU
        self.writeMemory(0x40000000, 0x00000100)        # CG_ON_POWERDOMAIN

        # 9. isolation
        self.writeMemory(0x40002520, 0x00000003)        # ISO_PU

        # 10. turn off power-switches
        self.writeMemory(0x40002450, 0x00000000)        # PSW_IO_USB
        self.writeMemory(0x40002420, 0x00000000)        # PSW_PU
        self.writeMemory(0x40002454, 0x00000000)        # PSW_HARDMACRO

    def __stopUSB(self):
        # 11.
        self.writeMemory(0x40000490, 0x00000000)        # PRESCAL_USBI

    def __initializeClockSourceMain(self):
        # 12-0 check efuse
        seq  = self.readMemory(0x400005E0)              # EFUSE_BOOTSEQ
        seq &= 3
        if 0 == seq:    # 12-a
            val = self.readMemory(0x40000500)           # CONFIG_OSC_12M.OSC12M_EN
            if (0 == (val & 1)):
                # 12-a-2
                self.writeMemory(0x40000500, 0x00000001)    # OSC12M_EN
                sleep(0.01)
            # 12-a-3
            val = self.readMemory(0x40002444)           # PSW_PLL
            if 0 == (val & 3):
                # 12-a-4
                self.writeMemory(0x40002444, 0x00000001)    # PSW_PLL
                self.writeMemory(0x40002444, 0x00000003)    # PSW_PLL
            # 12-a-5
            val = self.readMemory(0x40002544)           # ISO_PLL
            if 3 == (val & 3):
                # 12-a-6
                self.writeMemory(0x40002544, 0x00000000)    # ISO_PLL
            # 12-a-7
            val = self.readMemory(0x40000508)           # CONFIG_PLL_0.PLL_BP
            if 1 == (val & 1):
                # 12-a-8
                self.writeMemory(0x40000508, 0x00000001)    # CONFIG_PLL_0
                sleep(0.001)
                self.writeMemory(0x40000508, 0x00000000)    # CONFIG_PLL_0
                sleep(0.001)
            # 12-a-9
            self.writeMemory(0x40000404, 0x00000002)    # CSM_MAIN
        elif 1 == seq:  # 12-b
            val = self.readMemory(0x40000500)           # OSC12M_EN
            if 0 == (val & 1):
                # 12-b-2
                self.writeMemory(0x40000500, 0x00000001)    # OSC12M_EN
                sleep(0.01)
            # 12-b-3
            self.writeMemory(0x40000404, 0x00000001)    # CSM_MAIN
            # 12-b-4
            val = self.readMemory(0x40000508)           # CONFIG_PLL_0.PLL_BP
            if 0 == (val & 1):
                # 12-b-5
                self.writeMemory(0x40000508, 0x00000001)    # CONFIG_PLL_0
            # 12-b-6
            val = self.readMemory(0x40002544)           # ISO_PLL
            if 0 == (val & 3):
              # 12-b-7
              self.writeMemory(0x40002544, 0x00000003)  # ISO_PLL
            # 12-b-8
            val = self.readMemory(0x40002444)           # PSW_PLL
            if 3 == (val & 3):
                # 12-b-9
                self.writeMemory(0x40002444, 0x00000000)    # PSW_PLL
        else:
            # 12-c-1
            self.writeMemory(0x40000404, 0x00000000)    # CSM_MAIN
            # 12-c-2
            val = self.readMemory(0x40000500)           # CONFIG_OSC_12M.OSC12M_EN
            if 0 != (val & 1):
                # 12-c-3
                self.writeMemory(0x40000500, 0x00000000)    # CONFIG_OSC_12M
                # 12-c-4
                val = self.readMemory(0x40000508)       # CONFIG_PLL_0.PLL_BP
                if 0 == (val & 1):
                    # 12-b-5
                    self.writeMemory(0x40000508, 0x00000001)    # CONFIG_PLL_0
                # 12-c-6
                val = self.readMemory(0x40002544)       # ISO_PLL
                if 0 == (val & 3):
                    # 12-c-7
                    self.writeMemory(0x40002544, 0x00000003)    # ISO_PLL
                # 12-c-8
                val = self.readMemory(0x40002444)       # PSW_PLL
                if 3 == (val & 3):
                    # 12-c-9
                    self.writeMemory(0x40002444, 0x00000000)    # PSW_PLL

    def __powerOnDomain(self):
        # 13-1
        self.writeMemory(0x40000714, 0x00000000)    # POWERDOMAIN_CTRL_MODE
        self.writeMemory(0x40000710, 0x00000e00)    # POWERDOMAIN_CTRL
        stat = 1
        while 0 != (stat & 0xffff3003):
            stat = self.readMemory(0x40000718)      # POWERDOMAIN_CTRL_STATUS
        # 13-2
        self.writeMemory(0x40000714, 0x00000000)    # POWERDOMAIN_CTRL_MODE
        self.writeMemory(0x40000710, 0x000000a4)    # POWERDOMAIN_CTRL
        stat = 1
        while 0 != (stat & 0xfffffc33):
            stat = self.readMemory(0x40000718)      # POWERDOMAIN_CTRL_STATUS
        # 13-3
        self.writeMemory(0x40000714, 0x00000000)    # POWERDOMAIN_CTRL_MODE
        self.writeMemory(0x40000710, 0x00000012)    # POWERDOMAIN_CTRL
        stat = 1
        while 0 != (stat & 0xffffff3f):
            stat = self.readMemory(0x40000718)      # POWERDOMAIN_CTRL_STATUS
        # 13-4
        self.writeMemory(0x40000714, 0x00000000)    # POWERDOMAIN_CTRL_MODE
        self.writeMemory(0x40000710, 0x00000008)    # POWERDOMAIN_CTRL
        stat = 1
        while 0 != stat:
            stat = self.readMemory(0x40000718)      # POWERDOMAIN_CTRL_STATUS

    def __initializeIOCell(self):
        # 14
        self.writeMemory(0x40002308, 0x00000000)    # CTRL_IO_AON_2
        self.writeMemory(0x4000230C, 0x00000000)    # CTRL_IO_AON_3
        # 15
        self.writeMemory(0x40002318, 0x00000000)    # CTRL_IO_AON_6
        self.writeMemory(0x40002314, 0x00000000)    # CTRL_IO_AON_5
        self.writeMemory(0x40002310, 0x00000001)    # CTRL_IO_AON_4

    def __resetOnDomain(self):
        # 16
        self.writeMemory(0x40000020, 0xfffffffe)    # SRST_ON_POWERDOMAIN
        # 17
        self.writeMemory(0x40000300, 0xfeffffff)    # SRST_ON_PM0
        self.writeMemory(0x40000304, 0xffffffff)    # SRST_ON_PM1
        self.writeMemory(0x40000308, 0xffffffff)    # SRST_ON_PM2
        # 18
        self.writeMemory(0x40000000, 0x00000f82)    # CG_ON_POWERDOMAIN
        # 19
        self.writeMemory(0x40000100, 0x00500000)    # CG_ON_PM_0
        self.writeMemory(0x40000104, 0xffffffff)    # CG_ON_PM_1
        self.writeMemory(0x40000108, 0xffffffff)    # CG_ON_PM_2
        # 20
        self.writeMemory(0x40001124, 0x00000004)    # CG_ON_PC_SCRT
        # 21
        self.writeMemory(0x40000004, 0x0000003c)    # CG_OFF_POWERDOMAIN
        # 22
        self.writeMemory(0x40000024, 0x00000020)    # SRST_OFF_POWERDOMAIN
        # 23
        self.writeMemory(0x40000180, 0x08800000)    # CG_OFF_PM_0
        # 24
        self.writeMemory(0x40000380, 0x09000000)    # SRST_OFF_PM_0

    def __powerOffDomain(self):
        # 25-1
        self.writeMemory(0x40000714, 0x00144004)    # POWERDOMAIN_CTRL_MODE
        self.writeMemory(0x40000710, 0x00000600)    # POWERDOMAIN_CTRL
        stat = 0
        while 0x00140000 != stat:
            stat = self.readMemory(0x40000718)      # POWERDOMAIN_CTRL_STATUS
        # 25-2
        self.writeMemory(0x40000714, 0x00144004)    # POWERDOMAIN_CTRL_MODE
        self.writeMemory(0x40000710, 0x00000082)    # POWERDOMAIN_CTRL
        stat = 0
        while 0x00144004 != stat:
            stat = self.readMemory(0x40000718)      # POWERDOMAIN_CTRL_STATUS

    def __stopPrescaler(self):
        # 26
        self.writeMemory(0x40000484, 0x00000011)    # PRESCAL_MAIN
        self.writeMemory(0x4000048C, 0x00000001)    # PRESCAL_CPUST
        self.writeMemory(0x40000494, 0x00000000)    # PRESCAL_UART0
        self.writeMemory(0x40000498, 0x00000000)    # PRESCAL_UART1
        self.writeMemory(0x4000049C, 0x00000000)    # PRESCAL_UART2
        self.writeMemory(0x400004A0, 0x00000000)    # PRESCAL_ADCC12A
        self.writeMemory(0x400004A4, 0x00000000)    # PRESCAL_ADCC24A

    def __initializeADPLL(self):
        # 27
        self.writeMemory(0x40000510, 0x00007008)    # CONFIG_ADPLL_0
        self.writeMemory(0x40000514, 0x00000000)    # CONFIG_ADPLL_1
        # 28
        self.writeMemory(0x40002548, 0x00000003)    # ISO_ADPLL
        # 29
        self.writeMemory(0x40002448, 0x00000000)    # PSW_ADPLL

    def __initializeRTC(self):
        # 30
        self.writeMemory(0x40000148, 0xffffffff)    # CG_ON_REFCLK
        # 31
        self.writeMemory(0x40002020, 0xffffffff)    # SRST_ON_PA
        sleep(0.001)
        # 32
        self.writeMemory(0x40002000, 0xffffffff)    # CG_ON_PA
        sleep(0.001)
        # 33
        self.writeMemory(0x40002080, 0x00000000)    # CSM_RTC
        # 34
        self.writeMemory(0x40002100, 0x00000000)    # CONFIG_OSC32K
        self.writeMemory(0x40002104, 0x00000000)    # CONFIG_SiOSC32K

    def __initializeMacro(self):
        # 35
        self.writeMemory(0x400005C0, 0x00000000)    # SELECT_EFUSE
        self.writeMemory(0x40000580, 0x00000000)    # OVERRIDE_EFUSE_OSC12M
        self.writeMemory(0x40002180, 0x00000000)    # OVERRIDE_EFUSE_OSC32K
        self.writeMemory(0x40002184, 0x00000000)    # OVERRIDE_EFUSE_SiOSC32K
        self.writeMemory(0x40002190, 0x00000000)    # OVERRIDE_EFUSE_BGR_0
        self.writeMemory(0x40002194, 0x00000000)    # OVERRIDE_EFUSE_BGR_1
        self.writeMemory(0x40000528, 0x00000000)    # CONFIG_DCDC_LVREG_1
        self.writeMemory(0x40002108, 0x00000011)    # CONFIG_SiOSC4M
        self.writeMemory(0x40002188, 0x00000000)    # OVERRIDE_EFUSE_SiOSC4M
        self.writeMemory(0x40002108, 0x00000001)    # CONFIG_SiOSC4M

    def __initializeMiscRegisters(self):
        # 36
        self.writeMemory(0x40000010, 0x00000000)    # DCG_POWERDOMAIN
        self.writeMemory(0x40000290, 0x00020002)    # CLKREQ_CONFIG_PE
        self.writeMemory(0x40000720, 0xffffffff)    # POWERDOMAIN_CTRL_MODE_FOR_WAIT
        self.writeMemory(0x40000724, 0x00a8abf8)    # POWERDOMAIN_CTRL_MODE_FOR_WRET
        self.writeMemory(0x40000728, 0x00a8aaa8)    # POWERDOMAIN_CTRL_MODE_FOR_RET
        self.writeMemory(0x40000740, 0x001e001e)    # WAITTIME_LDOF
        self.writeMemory(0x40000744, 0x000f000f)    # WAITTIME_PSW
        self.writeMemory(0x40000748, 0x00a01e1e)    # WAITTIME_DVSCTL
        self.writeMemory(0x40000780, 0x00000000)    # POWERMODE_SLEEP_CG_ON
        self.writeMemory(0x40000790, 0x00000000)    # POWERMODE_SLEEP_PRESCAL
        self.writeMemory(0x400020c0, 0x00000000)    # RTCLV_RSYNC_SETTING
        self.writeMemory(0x40002210, 0x00000000)    # BROWNOUTMODE
        self.writeMemory(0x40002700, 0x00000000)    # IRQ_SETTING_0
        self.writeMemory(0x40002704, 0x00000000)    # IRQ_SETTING_1
        self.writeMemory(0x40002708, 0xffffffff)    # IRQ_STATUS
        self.writeMemory(0x4000270C, 0x00000000)    # WAKEUP_EN
