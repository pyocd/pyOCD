# Copyright 2026 Ryan QIAN
# SPDX-License-Identifier: Apache-2.0

"""FTDI FT2232/FT232H/FT4232H JTAG debug probe using pyftdi MPSSE."""

from __future__ import annotations

import logging
from typing import ClassVar
from typing import Collection
from typing import List
from typing import Optional
from typing import Sequence
from typing import Set

from ..core import exceptions
from ..core.options import OptionInfo
from ..core.plugin import Plugin
from ..probe.debug_probe import DebugProbe
from ..probe.mpsse import MpsseCommandBuilder
from ..utility.concurrency import locked

LOG = logging.getLogger(__name__)
TRACE = LOG.getChild("trace")


# ---------------------------------------------------------------------------
# GPIO pin configuration
# ---------------------------------------------------------------------------

class FtdiGpioConfig:
    """FTDI JTAG GPIO pin configuration.

    Instead of raw bitmask, users specify signal-to-pin mappings (e.g. ntrst=9).
    Direction and initial state bitmasks are computed automatically:
      - direction: TCK/TDI/TMS/nTRST/nSRST = output (1), TDO = input (0)
      - initial:   TMS=HIGH, nTRST=HIGH (active-low deasserted), nSRST=HIGH

    Supports raw bitmask mode for migrating existing adapter GPIO layouts.
    When _raw_direction is set, direction/initial properties return raw values
    directly instead of computing from pin numbers.
    """
    __slots__ = ('tck', 'tdi', 'tdo', 'tms', 'ntrst', 'nsrst',
                 '_raw_direction', '_raw_initial')

    def __init__(
        self,
        tck: int = 0,
        tdi: int = 1,
        tdo: int = 2,
        tms: int = 3,
        ntrst: Optional[int] = None,
        nsrst: Optional[int] = None,
    ) -> None:
        self.tck = tck
        self.tdi = tdi
        self.tdo = tdo
        self.tms = tms
        self.ntrst = ntrst
        self.nsrst = nsrst
        self._raw_direction: Optional[int] = None
        self._raw_initial: Optional[int] = None

    @classmethod
    def from_raw(cls, direction: int, initial: int) -> FtdiGpioConfig:
        """Create config from raw direction/initial bitmasks."""
        cfg = cls()
        cfg._raw_direction = direction
        cfg._raw_initial = initial
        return cfg

    @property
    def direction(self) -> int:
        """GPIO direction bitmask: output=1, input=0."""
        if self._raw_direction is not None:
            return self._raw_direction
        bits = (1 << self.tck) | (1 << self.tdi) | (1 << self.tms)
        if self.ntrst is not None:
            bits |= (1 << self.ntrst)
        if self.nsrst is not None:
            bits |= (1 << self.nsrst)
        return bits

    @property
    def initial(self) -> int:
        """GPIO initial state: TMS=HIGH, nTRST=HIGH, nSRST=HIGH."""
        if self._raw_initial is not None:
            return self._raw_initial
        bits = (1 << self.tms)
        if self.ntrst is not None:
            bits |= (1 << self.ntrst)
        if self.nsrst is not None:
            bits |= (1 << self.nsrst)
        return bits

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FtdiGpioConfig):
            return NotImplemented
        return (self.direction == other.direction
                and self.initial == other.initial)

    def __repr__(self) -> str:
        if self._raw_direction is not None:
            return (f"FtdiGpioConfig.from_raw("
                    f"direction=0x{self._raw_direction:04X}, "
                    f"initial=0x{self._raw_initial or 0:04X})")
        parts = [f"tck={self.tck}", f"tdi={self.tdi}", f"tdo={self.tdo}",
                 f"tms={self.tms}"]
        if self.ntrst is not None:
            parts.append(f"ntrst={self.ntrst}")
        if self.nsrst is not None:
            parts.append(f"nsrst={self.nsrst}")
        return f"FtdiGpioConfig({', '.join(parts)})"


# Default config: standard JTAG pins, no optional signals (nTRST/nSRST).
# Board-level target files should set ftdi.pin.* options for board-specific adapters.
_FTDI_GPIO_DEFAULT = FtdiGpioConfig()


# ---------------------------------------------------------------------------
# FTDI debug probe
# ---------------------------------------------------------------------------

class FTDIProbe(DebugProbe):
    """FTDI-based JTAG debug probe using pyftdi and direct MPSSE commands."""

    CAPABILITIES: ClassVar[frozenset] = frozenset({
        DebugProbe.Capability.JTAG_SEQUENCE,
        DebugProbe.Capability.SWJ_SEQUENCE,
    })

    # pyftdi read_data_bytes(size, attempt) returns a short read after `attempt`
    # consecutive empty USB bulk reads. A MPSSE chunk that clocks many DR scans
    # (e.g. an autoexec abstract-command burst) keeps the probe busy generating
    # TCK cycles before the trailing read's TDO is available; a fixed small
    # attempt then yields zero bytes and the caller parses an empty buffer as
    # garbage TDO. Scale attempt with queued command bytes so the poll tolerates
    # the chunk's execution time. Floors and ceilings keep small reads cheap and
    # bound the worst-case wait if the probe truly stalls.
    READ_ATTEMPT_FLOOR: ClassVar[int] = 8
    READ_ATTEMPT_PER_CMD_BYTE: ClassVar[int] = 16
    READ_ATTEMPT_CEILING: ClassVar[int] = 512

    def __init__(self, url: str, serial_number: Optional[str] = None) -> None:
        super().__init__()
        self._url: str = url
        self._serial_number: Optional[str] = serial_number
        self._ftdi: Optional[object] = None
        self._is_open: bool = False
        self._protocol: Optional[DebugProbe.Protocol] = None
        self._frequency: float = 1.0E6

    # -- Properties --

    @property
    def vendor_name(self) -> str:
        return "FTDI"

    @property
    def product_name(self) -> str:
        return "FTDI JTAG Probe"

    @property
    def supported_wire_protocols(self) -> Collection[DebugProbe.Protocol]:
        return [DebugProbe.Protocol.DEFAULT, DebugProbe.Protocol.JTAG]

    @property
    def unique_id(self) -> str:
        if self._serial_number:
            return self._serial_number
        return self._url

    @property
    def wire_protocol(self) -> Optional[DebugProbe.Protocol]:
        return self._protocol

    @property
    def is_open(self) -> bool:
        return self._is_open

    @property
    def capabilities(self) -> Set[DebugProbe.Capability]:
        # RESET_ASSERT is not advertised because assert_reset() is currently
        # a no-op; advertising it would let a reset path run silently.
        return set(self.CAPABILITIES)

    @property
    def options(self) -> List[OptionInfo]:
        return [
            OptionInfo('ftdi.pin.tck', int, None,
                "FTDI GPIO pin number for TCK signal."),
            OptionInfo('ftdi.pin.tdi', int, None,
                "FTDI GPIO pin number for TDI signal."),
            OptionInfo('ftdi.pin.tdo', int, None,
                "FTDI GPIO pin number for TDO signal."),
            OptionInfo('ftdi.pin.tms', int, None,
                "FTDI GPIO pin number for TMS signal."),
            OptionInfo('ftdi.pin.ntrst', int, None,
                "FTDI GPIO pin number for nTRST signal (active-low)."),
            OptionInfo('ftdi.pin.nsrst', int, None,
                "FTDI GPIO pin number for nSRST signal (active-low)."),
            OptionInfo('ftdi.gpio_direction', int, None,
                "Raw GPIO direction bitmask (16-bit, 1=output, 0=input). "
                "Overrides all pin options. Use for migrating existing "
                "adapter GPIO layouts that already specify direction/"
                "initial bitmasks."),
            OptionInfo('ftdi.gpio_initial', int, None,
                "Raw GPIO initial output value (16-bit). "
                "Must be used together with ftdi.gpio_direction."),
        ]

    # -- Class methods --

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize a URL to the full pyftdi-compatible form.

        The aggregator splits --probe on ':' to extract probe type, so
        'ftdi://0x0403:0x6010/1' becomes '//0x0403:0x6010/1'. This method
        reconstructs the full URL.
        """
        if url.startswith("ftdi://"):
            return url
        if url.startswith("//"):
            return "ftdi:" + url
        return "ftdi://" + url

    @classmethod
    def get_all_connected_probes(
        cls,
        unique_id: Optional[str] = None,
        is_explicit: bool = False,
    ) -> Sequence[DebugProbe]:
        from pyftdi.ftdi import Ftdi
        devices = Ftdi.list_devices()
        probes: List[DebugProbe] = []
        for dev_desc, ifcount in devices:
            sn = dev_desc.sn
            if sn:
                url = f"ftdi://0x{dev_desc.vid:04x}:0x{dev_desc.pid:04x}/{sn}/1"
            else:
                url = f"ftdi://0x{dev_desc.vid:04x}:0x{dev_desc.pid:04x}/1"
            probes.append(cls(url, serial_number=sn))
        return probes

    @classmethod
    def get_probe_with_id(
        cls,
        unique_id: str,
        is_explicit: bool = False,
    ) -> Optional[DebugProbe]:
        # Try matching by serial number against connected devices
        from pyftdi.ftdi import Ftdi
        try:
            devices = Ftdi.list_devices()
        except Exception:
            devices = []
        for dev_desc, ifcount in devices:
            sn = dev_desc.sn
            if sn and sn == unique_id:
                url = f"ftdi://0x{dev_desc.vid:04x}:0x{dev_desc.pid:04x}/{sn}/1"
                return cls(url, serial_number=sn)
        # Fallback: treat unique_id as URL
        url = cls._normalize_url(unique_id)
        return cls(url)

    # -- Lifecycle --

    def _resolve_gpio_config(self) -> FtdiGpioConfig:
        """Resolve GPIO config from session options.

        Resolution priority (highest first): raw bitmask
        (ftdi.gpio_direction + ftdi.gpio_initial); then individual pin options
        (ftdi.pin.*); then board-level defaults set by the target class in its
        constructor; finally the built-in default
        (TCK=0, TDI=1, TDO=2, TMS=3, no nTRST).
        """
        # --- Tier 1: Raw bitmask (highest priority) ---
        if self.session:
            raw_dir = self.session.options.get('ftdi.gpio_direction')
            if raw_dir is not None:
                raw_init = self.session.options.get('ftdi.gpio_initial')
                config = FtdiGpioConfig.from_raw(raw_dir, raw_init or 0)
                LOG.info("FTDI GPIO config (raw bitmask): %s", config)
                return config

        # --- Tier 2: Individual pin options ---
        pin_names = ('tck', 'tdi', 'tdo', 'tms', 'ntrst', 'nsrst')
        pin_overrides: dict = {}
        if self.session:
            for name in pin_names:
                val = self.session.options.get(f'ftdi.pin.{name}')
                if val is not None:
                    pin_overrides[name] = val

        if pin_overrides:
            kwargs = {n: getattr(_FTDI_GPIO_DEFAULT, n) for n in pin_names}
            kwargs.update(pin_overrides)
            config = FtdiGpioConfig(**kwargs)
            LOG.info("FTDI GPIO config (pin overrides %s): %s",
                     pin_overrides, config)
            return config

        LOG.info("FTDI GPIO config (default): %s", _FTDI_GPIO_DEFAULT)
        return _FTDI_GPIO_DEFAULT

    def open(self) -> None:
        if self._is_open:
            return
        try:
            from pyftdi.ftdi import Ftdi
            self._ftdi = Ftdi()
        except Exception as exc:
            raise exceptions.ProbeError(str(exc)) from exc
        self._is_open = True

    def close(self) -> None:
        if not self._is_open:
            return
        if self._ftdi:
            try:
                self._ftdi.close()
            except Exception:
                pass
            self._ftdi = None
        self._is_open = False

    def connect(self, protocol: Optional[DebugProbe.Protocol] = None) -> None:
        if protocol in (None, DebugProbe.Protocol.DEFAULT, DebugProbe.Protocol.JTAG):
            pass
        else:
            raise ValueError(f"unsupported protocol: {protocol}")

        config = self._resolve_gpio_config()

        try:
            self._ftdi.open_mpsse_from_url(
                self._url,
                direction=config.direction,
                initial=config.initial,
                frequency=self._frequency,
            )
        except Exception as exc:
            raise exceptions.ProbeError(str(exc)) from exc
        self._protocol = DebugProbe.Protocol.JTAG

        # TAP reset to ensure known state after MPSSE initialization.
        # MPSSE open does not generate clock cycles, so TAP state is undefined.
        # 16 cycles TMS=1 reaches TEST_LOGIC_RESET from any TAP state,
        # then 1 cycle TMS=0 transitions to RUN_TEST_IDLE.
        self.swj_sequence(16, 0xFFFF)
        self.swj_sequence(1, 0x0)

    def disconnect(self) -> None:
        self._protocol = None

    # -- Clock & Reset --

    def set_clock(self, frequency: float) -> None:
        if frequency <= 0:
            raise ValueError("frequency must be positive")
        if self._ftdi and self._is_open and self._protocol:
            self._ftdi.set_frequency(frequency)
        else:
            self._frequency = frequency

    def reset(self) -> None:
        pass  # nTRST via GPIO if available

    def assert_reset(self, asserted: bool) -> None:
        pass  # nRESET via GPIO if available

    # -- JTAG Transport --

    def jtag_sequence(
        self,
        cycles: int,
        tms: int,
        read_tdo: bool,
        tdi: int,
    ) -> Optional[int]:
        result = self.jtag_sequence_batch([(cycles, bool(tms), read_tdo, tdi)])
        if result is None:
            return None
        value = int.from_bytes(result, byteorder='little')
        if cycles < 64:
            value &= (1 << cycles) - 1
        return value

    @locked
    def jtag_sequence_batch(
        self,
        sequences: Sequence[tuple],
    ) -> Optional[bytes]:
        if not sequences:
            return None
        TRACE.debug("jtag_sequence_batch: %d sequences", len(sequences))
        builder = MpsseCommandBuilder()
        for cycles, tms, read_tdo, tdi in sequences:
            builder.append_sequence(cycles, tms, read_tdo, tdi)

        chunks = builder.build()
        all_tdo = bytearray()

        try:
            for cmd_bytes, tdo_regions in chunks:
                self._ftdi.write_data(cmd_bytes)
                if tdo_regions:
                    # MPSSE returns 1 byte per read command regardless of bit count.
                    # Byte read: returns byte_count bytes.
                    # Bit read: returns 1 byte (MSB-aligned).
                    total_bytes = sum(
                        bc // 8 if bc % 8 == 0 else 1
                        for bc, _ in tdo_regions
                    )
                    attempt = min(self.READ_ATTEMPT_CEILING,
                                  max(self.READ_ATTEMPT_FLOOR,
                                      len(cmd_bytes) // self.READ_ATTEMPT_PER_CMD_BYTE))
                    response = self._ftdi.read_data_bytes(total_bytes, attempt)
                    if len(response) < total_bytes:
                        # Short read means the probe did not finish clocking the
                        # chunk within the attempt budget. Treat as a hard error
                        # so callers stop on corrupt TDO instead of consuming it.
                        raise exceptions.ProbeError(
                            f"FTDI short read: requested {total_bytes}, "
                            f"got {len(response)} (cmd_bytes={len(cmd_bytes)}, "
                            f"attempt={attempt})"
                        )
                    all_tdo.extend(
                        MpsseCommandBuilder.parse_tdo_response(response, tdo_regions)
                    )
        except Exception as exc:
            if "FtdiError" in type(exc).__name__:
                raise exceptions.ProbeError(str(exc)) from exc
            raise

        return bytes(all_tdo) if all_tdo else None

    def swj_sequence(self, length: int, bits: int) -> None:
        builder = MpsseCommandBuilder()
        builder.append_tms_sequence(length, bits)
        cmd_bytes = builder.build_single() + bytes([MpsseCommandBuilder.SEND_IMMEDIATE])
        try:
            self._ftdi.write_data(cmd_bytes)
        except Exception as exc:
            raise exceptions.ProbeError(str(exc)) from exc

    def jtag_configure(self, devices_irlen: Optional[list] = None) -> list:
        if devices_irlen is None:
            devices_irlen = [4]
        return list(devices_irlen)


class FTDIProbePlugin(Plugin):
    """Plugin for FTDI probe registration."""

    @property
    def name(self) -> str:
        return "ftdi"

    @property
    def description(self) -> str:
        return "FTDI FT2232/FT232H/FT4232H MPSSE JTAG debug probe"

    def should_load(self) -> bool:
        try:
            import pyftdi  # noqa: F401
            return True
        except ImportError:
            return False

    def load(self):
        return FTDIProbe
