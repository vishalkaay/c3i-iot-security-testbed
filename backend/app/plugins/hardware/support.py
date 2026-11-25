"""Hardware support layer: GPIO, serial, power control, baud detection.

Everything here degrades to a *no-op mock* on a non-Pi host (a laptop/office PC)
so the software can be developed and demonstrated without the physical rig -
but it never pretends a real action happened silently: the mock is reported.

Rig conventions (see docs/HARDWARE_SETUP.md):

* Power switches are optocouplers/relays wired in the DUT power path.
* **Optocoupler (BCM ``OCTOCOUPLER_POWER_PIN``, default 22): LOW = DUT powered.
* **Relay** (BCM ``RELAY_POWER_PIN``, default 6): HIGH = DUT powered.
* Both spellings ``octocoupler`` / ``optocoupler`` select the optocoupler; the
  legacy tools flipped the polarity for one of them, which silently *kept the
  DUT powered* during a supposed "power cycle". Polarity is now centralised in
  :func:`_power_level` so it can never disagree again.
* Boot-log capture opens the serial port **before** the power cycle (pattern
  from the original ``capture_uart_boot.py``) so early boot output is not lost.
"""

from __future__ import annotations

import base64
import contextlib
import glob
import hashlib
import json
import math
import os
import re
import socket
import stat
import subprocess
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from app.core.logging import get_logger
from app.plugins.tools import has_tool, run

log = get_logger("hardware.support")

# --------------------------------------------------------------------------- #
# GPIO
# --------------------------------------------------------------------------- #
class MockGPIO:
    """Deterministic mock used on non-Pi hosts. Records every operation."""

    BCM = "BCM"
    OUT = "OUT"
    IN = "IN"
    HIGH = 1
    LOW = 0

    def __init__(self) -> None:
        self.calls: list[str] = []

    def setwarnings(self, flag: bool) -> None:  # noqa: N802
        pass

    def setmode(self, mode) -> None:
        self.calls.append(f"setmode({mode})")

    def setup(self, channel, direction, *a, **k) -> None:
        self.calls.append(f"setup({channel},{direction})")

    def output(self, channel, state) -> None:
        self.calls.append(f"output({channel},{state})")

    def input(self, channel) -> int:
        return 0

    def cleanup(self, *a, **k) -> None:
        pass


def _real_gpio():
    try:
        import RPi.GPIO as GPIO  # type: ignore

        return GPIO, "RPi.GPIO"
    except Exception:  # noqa: BLE001,S110
        pass
    try:
        import lgpio  # type: ignore  # noqa: F401

        # lgpio present; RPi.GPIO shim via rpi-lgpio provides the same API.
        import RPi.GPIO as GPIO  # type: ignore

        return GPIO, "rpi-lgpio"
    except Exception:
        return MockGPIO(), "mock"


def get_gpio():
    gpio, backend = _real_gpio()
    if backend != "mock":
        gpio.setwarnings(False)
        gpio.setmode(gpio.BCM)
    return gpio, backend


# --------------------------------------------------------------------------- #
# Serial
# --------------------------------------------------------------------------- #
def resolve_serial_port() -> str:
    explicit = os.getenv("UART_PORT")
    if explicit:
        return explicit
    for pattern in ("/dev/ttyUSB*", "/dev/ttyACM*", "/dev/serial0", "/dev/ttyAMA0"):
        hits = sorted(glob.glob(pattern))
        if hits:
            return hits[0]
    return ""


def list_serial_ports() -> list[str]:
    """Real, usable serial ports (excludes the noisy /dev/ttyS10.. nodes)."""
    ports: list[str] = []
    for pattern in ("/dev/ttyUSB*", "/dev/ttyACM*", "/dev/serial0", "/dev/ttyAMA0",
                    "/dev/ttyS0", "/dev/ttyS1"):
        ports += sorted(glob.glob(pattern))
    return sorted(set(ports))


@dataclass
class BaudCandidate:
    baud: int
    score: float
    bytes_read: int
    sample: str = ""

    def to_dict(self) -> dict:
        return {"baud": self.baud, "score": round(self.score, 3),
                "bytes_read": self.bytes_read, "sample": self.sample[:200]}


BOOT_KEYWORDS = (
    "u-boot", "uboot", "linux version", "booting", "bootloader", "press any key",
    "starting kernel", "vmlinuz", "rootfs", "init", "login:", "buildroot",
    "openwrt", "kernel command line", "uncompressing linux", "decompressing",
)
DEFAULT_BAUDS = (9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600)


def _env_int(*names: str, default: int) -> int:
    for name in names:
        raw = os.getenv(name)
        if raw and raw.isdigit():
            return int(raw)
    return default


def score_output(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (0x0A, 0x0D, 0x09))
    ratio = printable / len(data)
    text = data.decode("latin-1", errors="ignore").lower()
    kw = sum(1 for k in BOOT_KEYWORDS if k in text)
    volume = min(1.0, len(data) / 512)
    return ratio * 0.5 + min(1.0, kw / 3) * 0.4 + volume * 0.1


def _glitch_pin_default() -> int:
    return _env_int("VOLTAGE_GLITCH_PIN", "GLITCH_PIN", default=20)


# --------------------------------------------------------------------------- #
# Serial reading
# --------------------------------------------------------------------------- #
@contextlib.contextmanager
def open_serial(port: str, baud: int) -> Iterator:
    """Open a serial port for the lifetime of a capture.

    Yields ``None`` when pyserial is missing or the port cannot be opened (the
    caller decides how to report that). Opening *once* and keeping the handle
    during a power cycle is what preserves the first bytes of boot output.
    """
    try:
        import serial  # type: ignore
    except Exception:
        log.warning("pyserial not importable; serial capture disabled")
        yield None
        return
    handle = None
    try:
        handle = serial.Serial(port, baud, timeout=0.3, write_timeout=1.0)
        yield handle
    except Exception as exc:  # noqa: BLE001
        log.warning("serial open failed on %s@%d: %s", port, baud, exc)
        yield None
    finally:
        if handle is not None:
            with contextlib.suppress(Exception):
                handle.close()


def _pump_serial(handle, deadline: float, cancel_cb: Callable[[], bool] | None = None,
                 progress_cb: Callable[[bytes], None] | None = None) -> bytes:
    buf = bytearray()
    while time.time() < deadline:
        if cancel_cb is not None and cancel_cb():
            break
        try:
            chunk = handle.read(4096)
        except Exception as exc:  # noqa: BLE001
            log.warning("serial read failed: %s", exc)
            break
        if chunk:
            buf.extend(chunk)
            if progress_cb is not None:
                progress_cb(bytes(chunk))
        else:
            time.sleep(0.02)
    return bytes(buf)


def read_serial_from(handle, seconds: float, *, cancel_cb: Callable[[], bool] | None = None,
                     progress_cb: Callable[[bytes], None] | None = None) -> bytes:
    """Read ``seconds`` worth of data from an *already open* handle."""
    if handle is None:
        return b""
    return _pump_serial(handle, time.time() + seconds, cancel_cb=cancel_cb,
                        progress_cb=progress_cb)


def read_for(port: str, baud: int, seconds: float, *,
             cancel_cb: Callable[[], bool] | None = None) -> bytes:
    """Open + read + close in one shot (kept for simple callers/tests)."""
    with open_serial(port, baud) as handle:
        if handle is None:
            return b""
        return _pump_serial(handle, time.time() + seconds, cancel_cb=cancel_cb)


def write_serial_to(handle, data: bytes) -> bool:
    if handle is None:
        return False
    try:
        handle.write(data)
        handle.flush()
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("serial write failed: %s", exc)
        return False


def write_bytes(port: str, baud: int, data: bytes) -> bool:
    with open_serial(port, baud) as handle:
        return write_serial_to(handle, data)


# --------------------------------------------------------------------------- #
# Power control (optocoupler / relay)
# --------------------------------------------------------------------------- #
_MODE_ALIASES = {
    "octocoupler": "optocoupler",
    "optocoupler": "optocoupler",
    "coupler": "optocoupler",
    "opto": "optocoupler",
    "relay": "relay",
}


def normalise_mode(mode: str | None) -> str:
    """Accept every historical spelling; the legacy tool compared the wrong one."""
    return _MODE_ALIASES.get((mode or "").strip().lower(), "optocoupler")


def _power_level(mode: str, state: str) -> int:
    """Single source of truth for DUT power polarity.

    state ``on``/``off`` refers to the *device under test*, not the GPIO line.
    Optocoupler: LOW = DUT powered. Relay: HIGH = DUT powered.
    """
    mode = normalise_mode(mode)
    on = state == "on"
    if mode == "optocoupler":
        return 0 if on else 1
    return 1 if on else 0


class PowerController:
    def __init__(self, mode: str = "optocoupler") -> None:
        self.gpio, self.backend = get_gpio()
        self.mode = normalise_mode(mode)
        relay_pin = _env_int("RELAY_POWER_PIN", default=6)
        opto_pin = _env_int("OPTOCOUPLER_POWER_PIN", "OCTOCOUPLER_POWER_PIN", "OCTO_POWER_PIN", default=22)
        self.relay_pin = relay_pin
        self.octo_pin = opto_pin
        self.pin = self.octo_pin if self.mode == "optocoupler" else self.relay_pin

    def _setup(self) -> None:
        self.gpio.setup(self.pin, self.gpio.OUT)

    def _write(self, state: str) -> None:
        """Drive GPIO so the DUT reaches the requested power ``state``."""
        self._setup()
        self.gpio.output(self.pin, _power_level(self.mode, state))

    def power_on(self) -> None:
        self._write("on")

    def power_off(self) -> None:
        self._write("off")

    def cycle(self, off_seconds: float = 1.0, on_seconds: float = 0.0) -> None:
        self.power_off()
        time.sleep(max(0.05, off_seconds))
        self.power_on()
        if on_seconds:
            time.sleep(on_seconds)

    def is_mock(self) -> bool:
        return self.backend == "mock"


# --------------------------------------------------------------------------- #
# SPI flash
# --------------------------------------------------------------------------- #
# Programmer strings validated against a whitelist - flashrom's -p argument is
# never concatenated from user input.
PROGRAMMERS = {
    "linux_spi": "linux_spi:dev=/dev/spidev0.0",
    "ch341a_spi": "ch341a_spi",
    "ft2232_spi": "ft2232_spi:port=A",
}


def spi_dump(out_path: str, *, chip: str | None = None, timeout: int = 600,
             programmer: str | None = None) -> dict:
    if not has_tool("flashrom"):
        return {"ok": False, "error": "flashrom not installed"}
    prog = PROGRAMMERS.get(programmer or "linux_spi")
    if prog is None:
        return {"ok": False, "error": f"unknown programmer {programmer!r}; "
                                      f"choose one of {sorted(PROGRAMMERS)}"}
    args = ["flashrom", "-p", prog, "-r", out_path]
    if chip:
        args += ["-c", chip]
    res = run(args, timeout=timeout)
    ok = res.returncode == 0 and Path(out_path).exists()
    return {"ok": ok, "programmer": prog, "output": (res.stdout + res.stderr)[-4000:],
            "path": out_path if ok else None}


def _flashrom_prog(programmer: str | None) -> str | None:
    return PROGRAMMERS.get(programmer or "linux_spi")


def _flashrom_text(res) -> str:
    return (res.stdout + res.stderr).strip()


def spi_identify(*, chip: str | None = None, programmer: str | None = None,
                 timeout: int = 45) -> dict:
    """Read-only SPI flash identity: JEDEC name, capacity, write protection.

    This is the safe first step before ``spi_dump``: it does not erase or write
    the chip, and it tells the operator whether the flash is write-protected.
    """
    if not has_tool("flashrom"):
        return {"ok": False, "error": "flashrom not installed"}
    prog = _flashrom_prog(programmer)
    if prog is None:
        return {"ok": False, "error": f"unknown programmer {programmer!r}; "
                                      f"choose one of {sorted(PROGRAMMERS)}"}
    base = ["flashrom", "-p", prog]
    if chip:
        base += ["-c", chip]

    name_res = run(base + ["--flash-name"], timeout=timeout)
    name_text = _flashrom_text(name_res)
    vendor = re.search(r'vendor="([^"]*)"', name_text)
    model = re.search(r'name="([^"]*)"', name_text)
    found = re.search(r'Found\s+(.+?)\s+flash chip\s+"([^"]+)"\s+\((\d+)\s*kB',
                      name_text, re.IGNORECASE)
    if name_res.returncode != 0:
        return {
            "ok": False, "programmer": prog, "requested_chip": chip,
            "error": "flashrom could not identify the chip (check wiring, voltage and "
                     "programmer selection)",
            "output": name_text[-4000:],
        }

    size_bytes = None
    size_res = run(base + ["--flash-size"], timeout=timeout)
    size_text = _flashrom_text(size_res)
    # flashrom --flash-size prints a bare decimal byte count on modern releases.
    size_matches = re.findall(r"^\s*(\d{3,})\s*$", size_text, re.MULTILINE)
    if size_matches:
        size_bytes = int(size_matches[-1])
    elif found:
        size_bytes = int(found.group(3)) * 1024

    wp_res = run(base + ["--wp-status"], timeout=timeout)
    wp_text = _flashrom_text(wp_res)
    mode_m = re.search(r"Protection mode:\s*(\w+)", wp_text, re.IGNORECASE)
    range_m = re.search(r"Protection range:\s*(start=0x[0-9a-fA-F]+)\s+"
                        r"(length=0x[0-9a-fA-F]+)", wp_text, re.IGNORECASE)
    write_protection = {
        "supported": wp_res.returncode == 0,
        "mode": (mode_m.group(1).lower() if mode_m else "unknown"),
        "range": (f"{range_m.group(1)} {range_m.group(2)}" if range_m else None),
        "output": wp_text[-1500:] if wp_text else None,
    }
    return {
        "ok": True,
        "programmer": prog,
        "requested_chip": chip,
        "vendor": vendor.group(1) if vendor else None,
        "chip": model.group(1) if model else (found.group(2) if found else None),
        "size_bytes": size_bytes,
        "size_human": (f"{size_bytes / 1024 / 1024:.1f} MiB"
                       if size_bytes and size_bytes >= 1024 * 1024
                       else f"{size_bytes / 1024:.1f} KiB" if size_bytes else None),
        "write_protection": write_protection,
        "output": name_text[-3000:],
    }


# --------------------------------------------------------------------------- #
# I2C bus reconnaissance (i2c-tools)
# --------------------------------------------------------------------------- #
I2C_ADDR_RE = re.compile(r"^[0-9a-fA-F]{2}$")


def i2c_scan(bus: int, *, timeout: int = 30) -> dict:
    """Scan an I2C bus with ``i2cdetect -y -r`` and return decoded addresses."""
    if not has_tool("i2cdetect"):
        return {"ok": False, "error": "i2cdetect not installed (i2c-tools)"}
    if not 0 <= int(bus) <= 255:
        return {"ok": False, "error": "I2C bus number must be 0-255"}
    res = run(["i2cdetect", "-y", "-r", str(int(bus))], timeout=timeout)
    text = _flashrom_text(res)
    devices: list[dict] = []
    for line in text.splitlines():
        m = re.match(r"^([0-9a-fA-F]{2}):\s+(.*)$", line)
        if not m:
            continue
        base = int(m.group(1), 16)
        for index, token in enumerate(m.group(2).split()):
            if token == "-" * 2:
                continue
            addr = base + index
            if token.upper() == "UU":
                devices.append({"address": f"0x{addr:02x}", "status": "in-use"})
            elif I2C_ADDR_RE.fullmatch(token):
                devices.append({"address": f"0x{addr:02x}", "status": "present"})
    # Deduplicate while preserving the bus order.
    seen: set[str] = set()
    unique = [d for d in devices if not (d["address"] in seen or seen.add(d["address"]))]
    return {
        "ok": res.returncode == 0,
        "bus": int(bus),
        "devices": unique,
        "count": len(unique),
        "raw": text[-6000:],
        "error": None if res.returncode == 0 else "i2cdetect failed (permissions/wiring?)",
    }


def i2c_dump(bus: int, address: int, *, timeout: int = 30) -> dict:
    """Read 256 bytes from an I2C address with ``i2cdump -y -r``.

    The dump is read-only, but i2cdump can confuse some devices: use it only on
    a target you own and start with a scan. ``responded`` is false when every
    byte is ``XX`` (no ACK / wrong address).
    """
    if not has_tool("i2cdump"):
        return {"ok": False, "error": "i2cdump not installed (i2c-tools)"}
    if not 0 <= int(bus) <= 255:
        return {"ok": False, "error": "I2C bus number must be 0-255"}
    if not 0x03 <= int(address) <= 0x77:
        return {"ok": False, "error": "I2C address must be 0x03-0x77"}
    res = run(["i2cdump", "-y", "-r", str(int(bus)), f"0x{int(address):02x}"],
              timeout=timeout)
    text = _flashrom_text(res)
    data_rows = [ln for ln in text.splitlines() if re.match(r"^[0-9a-fA-F]{2}:", ln)]
    responded = False
    for line in data_rows:
        m = re.match(r"^[0-9a-fA-F]{2}:\s*(.*)$", line)
        if not m:
            continue
        if any(re.fullmatch(r"[0-9a-fA-F]{2}", token) for token in m.group(1).split()):
            responded = True
            break
    return {
        "ok": res.returncode == 0,
        "bus": int(bus),
        "address": f"0x{int(address):02x}",
        "responded": responded,
        "raw": text[-12000:],
        "error": None if res.returncode == 0 else "i2cdump failed (permissions/wiring?)",
    }


# --------------------------------------------------------------------------- #
# Logic analyzer capture / protocol decode (sigrok-cli)
# --------------------------------------------------------------------------- #
LOGIC_PROTOCOLS = {"uart", "spi", "i2c"}
_CHANNEL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,16}$")
_CHANNELS_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*$")
_DRIVER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def logic_capture(*, driver: str, channels: str, protocol: str,
                  sample_rate: int, duration_s: float,
                  decoder_options: dict[str, str], timeout: int | None = None) -> dict:
    """Capture a passive logic-analyzer trace and decode one protocol.

    Uses ``sigrok-cli`` with argv-only invocation. Channel/decoder values are
    strictly validated so a colon cannot inject another decoder option.
    """
    if not has_tool("sigrok-cli"):
        return {"ok": False, "error": "sigrok-cli not installed"}
    if not _DRIVER_RE.fullmatch(driver or ""):
        return {"ok": False, "error": "invalid sigrok driver name"}
    if not _CHANNELS_RE.fullmatch(channels or ""):
        return {"ok": False, "error": "channels must be comma-separated names (e.g. D0,D1)"}
    protocol = (protocol or "").lower()
    if protocol not in LOGIC_PROTOCOLS:
        return {"ok": False, "error": f"protocol must be one of {sorted(LOGIC_PROTOCOLS)}"}
    if not 1_000 <= int(sample_rate) <= 100_000_000:
        return {"ok": False, "error": "sample_rate must be 1 kHz-100 MHz"}
    if not 0.2 <= float(duration_s) <= 60.0:
        return {"ok": False, "error": "duration must be 0.2-60 seconds"}

    clean_options: list[str] = []
    for key, value in (decoder_options or {}).items():
        if key not in {"baudrate", "rx", "tx", "scl", "sda", "clk", "mosi", "miso", "cs"}:
            return {"ok": False, "error": f"unsupported decoder option {key!r}"}
        if not _CHANNEL_RE.fullmatch(str(value)) and key != "baudrate":
            return {"ok": False, "error": f"invalid channel value for {key}"}
        clean_options.append(f"{key}={value}")
    decoder = f"{protocol}:" + ":".join(clean_options) if clean_options else protocol
    args = [
        "sigrok-cli", "-d", driver, "--channels", channels,
        "--config", f"samplerate={int(sample_rate)}",
        "--time", f"{float(duration_s):g}s",
        "-P", decoder, "-A", protocol,
    ]
    res = run(args, timeout=timeout or max(30, int(float(duration_s)) + 30))
    text = (res.stdout + res.stderr).strip()
    decoded_lines = [ln for ln in text.splitlines() if ln.strip()]
    return {
        "ok": res.returncode == 0,
        "driver": driver,
        "channels": channels,
        "protocol": protocol,
        "sample_rate": int(sample_rate),
        "duration_s": float(duration_s),
        "decoder": decoder,
        "argv": args,
        "line_count": len(decoded_lines),
        "decoded": text[-60_000:],
        "error": None if res.returncode == 0 else "sigrok-cli capture/decode failed",
    }


# --------------------------------------------------------------------------- #
# Lab inventory (USB debug probes, block devices, buses)
# --------------------------------------------------------------------------- #
USB_DEBUG_PROBES: dict[str, tuple[str, str]] = {
    "0403:6001": ("FTDI FT232R", "UART"),
    "0403:6010": ("FTDI FT2232H", "JTAG/SWD/SPI/UART (MPSSE)"),
    "0403:6011": ("FTDI FT4232H", "JTAG/SWD/SPI/UART (MPSSE)"),
    "0403:6014": ("FTDI FT232H", "JTAG/SWD/SPI/I2C (MPSSE)"),
    "1a86:5523": ("WCH CH341A", "SPI/I2C/UART"),
    "1a86:7523": ("WCH CH340", "UART"),
    "1a86:55d3": ("WCH CH347", "JTAG/SWD/SPI/I2C/UART"),
    "1d50:6018": ("Bus Pirate", "SPI/I2C/UART/JTAG"),
    "1d50:60e8": ("DirtyJTAG", "JTAG"),
    "2e8a:000c": ("Raspberry Pi Debug Probe", "SWD/UART"),
    "1366:0101": ("SEGGER J-Link", "JTAG/SWD"),
    "0483:3748": ("ST-LINK/V2", "SWD/JTAG"),
    "0483:374b": ("ST-LINK/V2-1", "SWD/JTAG"),
    "0d28:0204": ("DAPLink / CMSIS-DAP", "SWD/JTAG"),
}


def usb_debug_probes() -> list[dict]:
    """Identify common USB debug/programming probes attached to the host."""
    if not has_tool("lsusb"):
        return []
    res = run(["lsusb"], timeout=10)
    probes: list[dict] = []
    for line in res.lines():
        m = re.search(r"ID\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\s*(.*)", line)
        if not m:
            continue
        key = f"{m.group(1).lower()}:{m.group(2).lower()}"
        known = USB_DEBUG_PROBES.get(key)
        if not known:
            continue
        probes.append({
            "vid_pid": key,
            "name": known[0],
            "transports": known[1],
            "usb_description": m.group(3).strip(),
        })
    return probes


def storage_devices() -> list[dict]:
    """List block devices (read-only inventory; no imaging is performed)."""
    if not has_tool("lsblk"):
        return []
    res = run(["lsblk", "-J", "-o", "NAME,SIZE,TYPE,TRAN,MODEL,SERIAL,RO"], timeout=10)
    try:
        payload = json.loads(res.stdout)
    except (TypeError, ValueError):
        return []
    out: list[dict] = []

    def walk(items: list[dict]) -> None:
        for item in items:
            out.append({
                "name": item.get("name"),
                "size": item.get("size"),
                "type": item.get("type"),
                "transport": item.get("tran"),
                "model": (item.get("model") or "").strip() or None,
                "serial": (item.get("serial") or "").strip() or None,
                "read_only": item.get("ro") in (True, "1", 1),
            })
            walk(item.get("children") or [])

    walk(payload.get("blockdevices") or [])
    return out


def bus_nodes(prefix: str) -> list[str]:
    return sorted(glob.glob(prefix))


# --------------------------------------------------------------------------- #
# UART shell automation (login, bounded command execution, partition exfil)
# --------------------------------------------------------------------------- #
# Session markers wrap every command so the harvested stream can be separated
# from banner noise, login echoes and kernel messages that interleave on a
# serial console.
MARK_BEGIN = "C3I_B7F0"
MARK_END = "C3I_E243"

_PROMPT_RE = re.compile(r"(?:^|\n)[^\n#\$]{0,120}[#\$\]]\s*$")

MTD_ROW_RE = re.compile(
    r"^(mtd\d+):\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+\"([^\"]*)\"",
    re.M,
)


def serial_login(handle, username: str, password: str | None, *,
                 timeout_s: float = 30.0, cancel_cb: Callable[[], bool] | None = None) -> dict:
    """Drive a getty login on an established UART session.

    Returns ``{logged_in, transcript}`` — every stage is evidence, nothing is
    assumed. Blank passwords (common on cameras) are supported by passing an
    empty string; ``None`` skips the password stage entirely.
    """
    if any(ord(c) < 32 or ord(c) == 127 for c in username + (password or "")):
        raise ValueError("credentials cannot contain terminal control characters")
    transcript: list[str] = []

    def _collect(seconds: float, stop_at: tuple[str, ...]) -> str:
        buf = bytearray()
        deadline = time.time() + seconds
        while time.time() < deadline:
            if cancel_cb and cancel_cb():
                break
            buf += read_serial_from(handle, 0.2, cancel_cb=cancel_cb)
            text = buf.decode("latin-1", errors="replace")
            lowered = text.lower()
            if any(s in lowered for s in stop_at):
                break
        text = buf.decode("latin-1", errors="replace")
        transcript.append(text.replace(password, "[redacted]") if password else text)
        return text

    write_serial_to(handle, b"\n")
    text = _collect(min(timeout_s, 10.0), ("login:", "password:", "#", "$"))

    if "login:" in text.lower():
        write_serial_to(handle, username.encode() + b"\n")
        text = _collect(min(timeout_s, 15.0), ("password:", "#", "$", "incorrect"))
        if "incorrect" in text.lower():
            return {"logged_in": False, "transcript": "".join(transcript)}

    if "password:" in text.lower() and password is not None:
        write_serial_to(handle, password.encode() + b"\n")
        text = _collect(timeout_s, ("#", "$", "incorrect", "denied"))
        if "incorrect" in text.lower() or "denied" in text.lower():
            return {"logged_in": False, "transcript": "".join(transcript)}

    logged_in = bool(_PROMPT_RE.search(text)) and "incorrect" not in text.lower()
    return {"logged_in": logged_in, "transcript": "".join(transcript)}


def serial_command(handle, command: str, *, timeout_s: float = 60.0,
                   cancel_cb: Callable[[], bool] | None = None) -> str:
    """Execute one command on a live shell; returns output between markers.

    The caller is responsible for having a shell (login first where needed).
    Long-running commands (``cat /proc/mtd`` is instant; a stream is not) use
    the same bounded read loop as everything else and honour cooperative
    cancellation.
    """
    if any(ord(c) < 32 or ord(c) == 127 for c in command):
        raise ValueError("command must be a single line")
    # Drain pending console noise so it cannot confuse the marker window.
    read_serial_from(handle, 0.3, cancel_cb=cancel_cb)
    if not write_serial_to(handle, f"echo {MARK_BEGIN}; {command}; echo; echo {MARK_END}\n".encode()):
        raise RuntimeError("serial write failed")
    payload, ended, error = _read_frame(handle, timeout_s, 1024 * 1024, cancel_cb)
    if not ended:
        raise RuntimeError(error or "command timed out before the end marker")
    return payload.decode("latin-1", errors="replace").strip()


def _read_frame(handle, timeout_s, max_bytes, cancel_cb=None, progress_cb=None):
    """Consume exact marker lines; echoed command lines never delimit a frame."""
    deadline = time.monotonic() + timeout_s
    linebuf = bytearray()
    payload = bytearray()
    started = False
    error = "serial transfer timed out"
    while time.monotonic() < deadline:
        if cancel_cb and cancel_cb():
            error = "serial transfer cancelled"
            break
        linebuf.extend(read_serial_from(handle, 0.1, cancel_cb=cancel_cb))
        if len(linebuf) + len(payload) > max_bytes:
            error = "serial output exceeded the byte limit"
            break
        while b"\n" in linebuf:
            line, _, remaining = linebuf.partition(b"\n")
            linebuf = bytearray(remaining)
            line = line.rstrip(b"\r")
            if not started:
                if line == MARK_BEGIN.encode():
                    started = True
                continue
            if line == MARK_END.encode():
                return bytes(payload), True, None
            payload.extend(line + b"\n")
        if progress_cb:
            progress_cb(len(payload))
    write_serial_to(handle, b"\x03")  # stop the outstanding transfer, retain complete lines
    return bytes(payload), False, error


def parse_proc_mtd(text: str) -> list[dict]:
    """Parse ``/proc/mtd`` rows into [{dev, size, erasesize, name}]."""
    rows = []
    for m in MTD_ROW_RE.finditer(text):
        rows.append({
            "dev": f"/dev/{m.group(1)}",
            "size": int(m.group(2), 16),
            "erasesize": int(m.group(3), 16),
            "name": m.group(4),
        })
    return rows


def serial_dump_mtd(handle, device: str, size: int, *,
                    chunk: int = 65536, timeout_s: float = 1800.0,
                    cancel_cb: Callable[[], bool] | None = None,
                    progress_cb: Callable[[int, int], None] | None = None) -> dict:
    """Stream a partition out through base64 over the serial line.

    ``dd if=<device> | base64`` is wrapped in end markers; the base64 payload
    is decoded once the stream closes, so a cooperative cancel keeps the
    partial dump as evidence. Baud bounds throughput (~baud/10 * 0.75 B/s
    payload - show this estimate to the operator before starting).
    """
    if not re.fullmatch(r"/dev/(?:mtd(?:block)?\d+|mmcblk\d+(?:p\d+)?|sd[a-z](?:\d+)?)", device):
        raise ValueError("device must be an MTD, MMC or disk partition node")
    if not 0 < size <= 256 * 1024 * 1024 or not 512 <= chunk <= 1024 * 1024:
        raise ValueError("invalid dump size or chunk size")
    read_serial_from(handle, 0.3, cancel_cb=cancel_cb)
    sent = write_serial_to(
        handle,
        f"echo {MARK_BEGIN}; dd if={device} bs={chunk} 2>/dev/null | base64; "
        f"echo; echo {MARK_END}\n".encode(),
    )
    expected_b64 = max(1, (size + 2) // 3 * 4)
    if not sent:
        return {"ok": False, "payload": b"", "error": "serial write failed"}
    raw, got_end, error = _read_frame(
        handle, timeout_s, int(expected_b64 * 1.1) + 8192, cancel_cb,
        (lambda n: progress_cb(min(n * 3 // 4, size), size)) if progress_cb else None,
    )
    # Remove whitespace only. Dropping arbitrary text would silently turn kernel
    # log noise into apparently valid firmware bytes. Preserve '=' padding.
    raw = re.sub(rb"\s+", b"", raw)
    if not got_end:
        raw = raw[:len(raw) // 4 * 4]
    try:
        payload = base64.b64decode(raw, validate=True) if raw else b""
    except Exception as exc:  # corrupted stream (line noise, interleaved logs)
        return {"ok": False, "payload": b"",
                "error": f"base64 payload undecodable: {exc}", "partial": True}
    if not got_end:
        return {"ok": False, "payload": payload, "partial": True,
                "error": f"{error}: {len(payload)} of {size} bytes (partial retained)"}
    if len(payload) != size:
        return {"ok": False, "payload": payload, "size_mismatch": True, "partial": True,
                "error": f"read {len(payload)} bytes, /proc/mtd declared {size}"}
    return {"ok": True, "payload": payload, "device": device, "size": size}


_FS_PATH_RE = re.compile(r"/[A-Za-z0-9_./-]{0,200}")
_EXCLUDE_RE = re.compile(r"[A-Za-z0-9_*./-]{1,200}")


def serial_tar_archive(handle, paths: list[str], *, compression: str = "gzip",
                       exclude: list[str] | None = None,
                       max_bytes: int = 64 * 1024 * 1024, timeout_s: float = 1800.0,
                       cancel_cb: Callable[[], bool] | None = None,
                       progress_cb: Callable[[int], None] | None = None) -> dict:
    """Archive a *live, mounted* filesystem over the serial shell.

    ``tar cf - <paths> [| gzip] | base64`` wrapped in the standard marker frame.
    Unlike :func:`serial_dump_mtd` (block-level ``dd`` of a flash partition),
    this captures the *running* filesystem — overlay, tmpfs, unpacked squashfs
    and ramdisk included — which is how most live cameras and routers present
    their rootfs. The archive size is unknown in advance, so the ceiling is
    enforced by ``max_bytes`` rather than a declared partition size. Partial
    archives are retained for best-effort file recovery.
    """
    safe_paths: list[str] = []
    for p in paths:
        if not _FS_PATH_RE.fullmatch(p):
            raise ValueError(f"unsafe archive path: {p!r}")
        safe_paths.append(p)
    if not safe_paths:
        raise ValueError("no paths to archive")
    excl = ""
    for e in (exclude or []):
        if not _EXCLUDE_RE.fullmatch(e):
            raise ValueError(f"unsafe exclude pattern: {e!r}")
        excl += f" --exclude={e}"
    if compression not in ("gzip", "none"):
        raise ValueError("compression must be 'gzip' or 'none'")
    comp = "| gzip -c " if compression == "gzip" else ""
    read_serial_from(handle, 0.3, cancel_cb=cancel_cb)
    cmd = (f"echo {MARK_BEGIN}; tar cf - {' '.join(safe_paths)}{excl} 2>/dev/null "
           f"{comp}| base64; echo; echo {MARK_END}\n")
    if not write_serial_to(handle, cmd.encode()):
        return {"ok": False, "payload": b"", "error": "serial write failed"}
    cap_b64 = int(max_bytes * 4 / 3) + 8192
    raw, got_end, error = _read_frame(
        handle, timeout_s, cap_b64, cancel_cb,
        (lambda n: progress_cb(n * 3 // 4)) if progress_cb else None,
    )
    raw = re.sub(rb"\s+", b"", raw)
    if not got_end:
        raw = raw[:len(raw) // 4 * 4]
    try:
        payload = base64.b64decode(raw, validate=True) if raw else b""
    except Exception as exc:  # noqa: BLE001 - line noise / interleaved logs
        return {"ok": False, "payload": b"", "partial": True,
                "error": f"base64 payload undecodable: {exc}"}
    if not got_end:
        return {"ok": False, "payload": payload, "partial": True,
                "error": f"{error}: {len(payload)} bytes retained"}
    return {"ok": True, "payload": payload, "size": len(payload),
            "compression": compression, "paths": safe_paths}


def net_exfil_receive(out_path: str, *, port: int,
                      bind_host: str = "0.0.0.0",  # noqa: S104 - DUT dials in from its own IP
                      timeout_s: float = 600.0, max_bytes: int = 256 * 1024 * 1024,
                      cancel_cb: Callable[[], bool] | None = None,
                      trigger_cb: Callable[[], None] | None = None) -> dict:
    """Receive a stream the DUT pushes over TCP (``tar ... | nc <host> <port>``).

    Pure-Python TCP sink, so the *host* needs no netcat — only the device does.
    Binds and listens, calls ``trigger_cb`` once (typically to send the
    device-side command down the serial shell), then streams the connection to
    ``out_path`` until EOF or the byte cap. Far faster than UART base64 when the
    target has an IP. Returns ``{ok, bytes, sha256, error}``.
    """
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    total = 0
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((bind_host, port))
        srv.listen(1)
        srv.settimeout(1.0)
        if trigger_cb:
            trigger_cb()
        deadline = time.monotonic() + timeout_s
        conn = None
        while time.monotonic() < deadline:
            if cancel_cb and cancel_cb():
                return {"ok": False, "bytes": 0, "error": "cancelled before connect"}
            try:
                conn, _addr = srv.accept()
                break
            except TimeoutError:
                continue
        if conn is None:
            return {"ok": False, "bytes": 0, "error": "no connection from DUT before timeout"}
        conn.settimeout(5.0)
        h = hashlib.sha256()
        with conn, open(out_path, "wb") as fh:
            while time.monotonic() < deadline:
                if cancel_cb and cancel_cb():
                    return {"ok": False, "bytes": total, "sha256": h.hexdigest(),
                            "error": "cancelled mid-stream (partial retained)"}
                try:
                    chunk = conn.recv(65536)
                except TimeoutError:
                    continue
                if not chunk:  # clean EOF
                    return {"ok": True, "bytes": total, "sha256": h.hexdigest(), "error": None}
                total += len(chunk)
                if total > max_bytes:
                    fh.write(chunk)
                    return {"ok": False, "bytes": total, "sha256": h.hexdigest(),
                            "error": "exceeded byte cap (partial retained)"}
                fh.write(chunk)
                h.update(chunk)
        return {"ok": False, "bytes": total, "sha256": h.hexdigest(),
                "error": "timed out mid-stream (partial retained)"}
    finally:
        with contextlib.suppress(Exception):
            srv.close()


def is_block_device(path: str) -> bool:
    """True iff ``path`` is a block special file (overridable in tests)."""
    try:
        return stat.S_ISBLK(os.stat(path).st_mode)
    except OSError:
        return False


_WHOLE_DISK_RE = re.compile(r"(/dev/(?:sd[a-z]|mmcblk\d+|nvme\d+n\d+))")


def host_system_disks() -> set[str]:
    """Block devices backing the host's own /, /boot, swap — never image these."""
    disks: set[str] = set()
    with contextlib.suppress(Exception):
        for line in Path("/proc/mounts").read_text(errors="ignore").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] in ("/", "/boot", "/boot/efi") \
                    and parts[0].startswith("/dev/"):
                disks.add(parts[0])
                m = _WHOLE_DISK_RE.match(parts[0])
                if m:
                    disks.add(m.group(1))
    with contextlib.suppress(Exception):
        for line in Path("/proc/swaps").read_text(errors="ignore").splitlines()[1:]:
            dev = line.split()[0] if line.split() else ""
            if dev.startswith("/dev/"):
                disks.add(dev)
    return disks


def host_block_acquire(device: str, out_path: str, *, max_bytes: int = 0,
                       use_ddrescue: bool = False, timeout_s: int = 3600,
                       cancel_cb: Callable[[], bool] | None = None,
                       progress_cb: Callable[[int], None] | None = None) -> dict:
    """Read-only image of a block device attached to **this host**.

    For a device presented to the PC directly — USB mass-storage, an SD card in
    a reader, a UVC/CD gadget. The source is **never opened for writing and
    never mounted**; the host's own system disks are refused outright. Copies
    with ``dd`` (or ``ddrescue`` for flaky media) to ``out_path``, then hashes
    the result. ``max_bytes`` (rounded up to whole MiB) caps a partial image.
    """
    if not re.fullmatch(r"/dev/(?:sd[a-z]\d*|mmcblk\d+(?:p\d+)?)", device):
        raise ValueError("device must be /dev/sd* or /dev/mmcblk*")
    if not is_block_device(device):
        return {"ok": False, "bytes": 0, "error": f"{device} is not a block device"}
    forbidden = host_system_disks()
    if any(device == d or device.startswith(d) or d.startswith(device) for d in forbidden):
        return {"ok": False, "bytes": 0,
                "error": f"refusing to image host system disk {device} "
                         f"(backs {sorted(forbidden)})"}
    bs = 1024 * 1024
    if use_ddrescue:
        if not has_tool("ddrescue"):
            return {"ok": False, "bytes": 0, "error": "ddrescue not installed"}
        argv = ["ddrescue", "-n", "-f", device, out_path, out_path + ".mapfile"]
        if max_bytes and max_bytes > 0:
            argv[2:2] = ["-s", str(max_bytes)]
    else:
        argv = ["dd", f"if={device}", f"of={out_path}", f"bs={bs}", "conv=noerror,sync"]
        if max_bytes and max_bytes > 0:
            argv.append(f"count={math.ceil(max_bytes / bs)}")
    res = run(argv, timeout=timeout_s)
    if not Path(out_path).exists():
        return {"ok": False, "bytes": 0,
                "error": (res.stderr or "").strip()[:300] or f"{argv[0]} produced no file"}
    size = Path(out_path).stat().st_size
    h = hashlib.sha256()
    with open(out_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(bs), b""):
            h.update(chunk)
            if progress_cb:
                progress_cb(fh.tell())
    return {"ok": size > 0, "bytes": size, "sha256": h.hexdigest(), "device": device,
            "tool": argv[0], "stderr": (res.stderr or "").strip()[-500:]}


def _spawn_to_file(argv: list[str], out_path: str, *, timeout_s: int) -> dict:
    """Run ``argv`` capturing *binary* stdout to a file (tar/exec-out safe)."""
    with open(out_path, "wb") as fh:
        try:
            proc = subprocess.run(  # noqa: S603 - argv form, no shell
                argv, stdout=fh, stderr=subprocess.PIPE, timeout=timeout_s, check=False)
        except FileNotFoundError:
            return {"ok": False, "returncode": 127, "stderr": f"{argv[0]} not found"}
        except subprocess.TimeoutExpired:
            return {"ok": False, "returncode": 124, "stderr": f"timeout after {timeout_s}s"}
    return {"ok": proc.returncode == 0, "returncode": proc.returncode,
            "stderr": (proc.stderr or b"").decode("latin-1", "replace")[-500:]}


_ADB_SERIAL_RE = re.compile(r"[A-Za-z0-9:._-]{1,128}")


def adb_devices() -> list[dict]:
    """List attached Android devices as [{serial, state}] (empty if no adb)."""
    if not has_tool("adb"):
        return []
    res = run(["adb", "devices"], timeout=15)
    out: list[dict] = []
    for line in res.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] in ("device", "unauthorized", "recovery", "sideload"):
            out.append({"serial": parts[0], "state": parts[1]})
    return out


def adb_archive(serial: str | None, paths: list[str], out_path: str, *,
                timeout_s: int = 1800) -> dict:
    """Stream a tar of ``paths`` off an Android device via ``adb exec-out``.

    ``exec-out`` is binary-safe (no CRLF/base64 mangling). Returns
    ``{ok, bytes, sha256, returncode, stderr}``. Honest about an unauthorized
    or absent device rather than inventing success.
    """
    if not has_tool("adb"):
        return {"ok": False, "bytes": 0, "error": "adb not installed"}
    safe: list[str] = []
    for p in paths:
        if not _FS_PATH_RE.fullmatch(p):
            raise ValueError(f"unsafe path: {p!r}")
        safe.append(p)
    if not safe:
        raise ValueError("no paths to archive")
    base = ["adb"]
    if serial:
        if not _ADB_SERIAL_RE.fullmatch(serial):
            raise ValueError("invalid adb serial")
        base += ["-s", serial]
    argv = base + ["exec-out", "tar", "cf", "-", *safe]
    spawn = _spawn_to_file(argv, out_path, timeout_s=timeout_s)
    size = Path(out_path).stat().st_size if Path(out_path).exists() else 0
    h = hashlib.sha256()
    if size:
        with open(out_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    return {"ok": spawn["ok"] and size > 0, "bytes": size,
            "sha256": h.hexdigest() if size else None,
            "returncode": spawn["returncode"], "stderr": spawn["stderr"],
            "paths": safe, "error": None if (spawn["ok"] and size) else
            (spawn["stderr"] or "adb produced no data")}


# --------------------------------------------------------------------------- #
# Voltage glitch (bounded)
# --------------------------------------------------------------------------- #
@dataclass
class GlitchResult:
    pulses: int
    on_us: int
    off_us: int
    duration_s: float
    mock: bool
    log: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"pulses": self.pulses, "on_us": self.on_us, "off_us": self.off_us,
                "duration_s": self.duration_s, "mock": self.mock, "log": self.log[-2000:],
                **self.extra}


def run_glitch(
    *, pin: int | None = None, on_us: int, off_us: int, duration_s: float,
    max_pulses: int = 5000, progress_cb=None, cancel_cb: Callable[[], bool] | None = None,
) -> GlitchResult:
    """Drive a bounded voltage-glitch pulse train, then always restore power.

    ``on_us``/``off_us`` are clamped to safe bounds; total pulses are capped.
    Cancellation is checked once per pulse (cancels are prompt for microsecond
    pulse trains). Note: GPIO busy-waiting means the achieved pulse rate, not
    the nominal one, is what the evidence records.
    """
    pin = int(pin if pin is not None else _glitch_pin_default())
    on_us = max(50, min(500_000, int(on_us)))
    off_us = max(50, min(500_000, int(off_us)))
    duration_s = max(0.0, min(120.0, float(duration_s)))
    gpio, backend = get_gpio()
    gpio.setup(pin, gpio.OUT)
    start = time.monotonic()
    pulses = 0
    last_report = start
    log_lines: list[str] = []
    stop_reason = "duration_reached"
    try:
        while pulses < max_pulses:
            now = time.monotonic()
            if (now - start) >= duration_s:
                stop_reason = "duration_reached"
                break
            if cancel_cb is not None and cancel_cb():
                stop_reason = "cancelled_by_operator"
                break
            gpio.output(pin, gpio.LOW)
            _sleep_us(on_us)
            gpio.output(pin, gpio.HIGH)
            _sleep_us(off_us)
            pulses += 1
            now = time.monotonic()
            if progress_cb and (pulses % 25 == 0 or now - last_report > 0.5):
                progress_cb(pulses, now - start)
                last_report = now
        else:
            stop_reason = "pulse_cap_reached"
    finally:
        with contextlib.suppress(Exception):
            gpio.output(pin, gpio.HIGH)  # glitch line idle-high (optocoupler OFF)
    duration_actual = round(time.monotonic() - start, 3)
    rate = pulses / duration_actual if duration_actual > 0 else 0.0
    log_lines.append(
        f"pulses={pulses} on={on_us}us off={off_us}us pin={pin} backend={backend} "
        f"achieved_rate={rate:.0f}/s stop={stop_reason} "
        f"(GPIO busy-wait, not a precision pulse source)"
    )
    return GlitchResult(pulses=pulses, on_us=on_us, off_us=off_us,
                        duration_s=duration_actual,
                        mock=backend == "mock", log="\n".join(log_lines),
                        extra={"backend": backend, "pin": pin, "rate_hz": round(rate, 1),
                               "stop_reason": stop_reason})


def _sleep_us(micros: int) -> None:
    # Busy-wait for sub-millisecond precision (relay/octocoupler timing).
    target = time.perf_counter() + micros / 1_000_000
    while time.perf_counter() < target:
        pass
