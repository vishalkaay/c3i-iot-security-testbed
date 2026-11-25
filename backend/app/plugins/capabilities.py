"""Capability probing.

Modules declare the host capabilities they need (a CLI tool, a radio adapter,
the GPIO header, a serial port). The registry surfaces this to the UI so an
operator immediately sees *why* a module is unavailable on this host - rather
than watching it fail cryptically, as the legacy tools did.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Capability:
    id: str
    label: str
    kind: str  # tool | python | hardware | adapter | os | network
    check: Callable[[], bool]
    hint: str = ""
    install: str = ""  # copy-paste install command (Debian/Ubuntu/Kali), when applicable

    def available(self) -> bool:
        try:
            return bool(self.check())
        except Exception:
            return False

    def describe(self) -> dict:
        ok = self.available()
        return {
            "id": self.id,
            "label": self.label,
            "kind": self.kind,
            "available": ok,
            "hint": self.hint if not ok else "",
            "install": self.install if not ok else "",
        }


def _tool(name: str) -> Callable[[], bool]:
    return lambda: shutil.which(name) is not None


def _python(module: str) -> Callable[[], bool]:
    return lambda: importlib.util.find_spec(module) is not None


def _any_python(*modules: str) -> Callable[[], bool]:
    return lambda: any(importlib.util.find_spec(module) is not None for module in modules)


def _any_tool(*names: str) -> Callable[[], bool]:
    return lambda: any(shutil.which(n) for n in names)


def _all_tools(*names: str) -> Callable[[], bool]:
    return lambda: all(shutil.which(n) for n in names)


def _glob_any(*patterns: str) -> Callable[[], bool]:
    def check() -> bool:
        # ``Path.glob`` returns a generator even when it will yield no paths.
        # Testing that generator directly is always truthy and used to make
        # missing serial/SPI interfaces appear available. Consume one level.
        return any(any(Path("/").glob(pat.lstrip("/"))) for pat in patterns)

    return check


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _is_pi() -> bool:
    model = Path("/sys/firmware/devicetree/base/model")
    try:
        return model.exists() and "Raspberry Pi" in model.read_text(errors="ignore")
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Registry of well-known capabilities.
# --------------------------------------------------------------------------- #
CAPABILITIES: dict[str, Capability] = {}


def _register(cap: Capability) -> Capability:
    CAPABILITIES[cap.id] = cap
    return cap


CAP_LINUX = _register(Capability("os.linux", "Linux host", "os", _is_linux,
                                 "Bluetooth/Wi-Fi hardware modules require Linux."))
CAP_PI = _register(Capability("hw.raspberry_pi", "Raspberry Pi", "hardware", _is_pi,
                              "Physical-interface modules are designed for a Pi testbed."))
CAP_GPIO = _register(Capability("hw.gpio", "GPIO (libgpiod/lgpio)", "hardware",
                                _any_python("RPi.GPIO", "lgpio"),
                                "Install `rpi-lgpio` on the Pi to drive the testbed relays.",
                                 install="pip install rpi-lgpio"))
CAP_SERIAL = _register(Capability("hw.serial", "Serial port (/dev/ttyUSB*|ttyACM*|serial0)", "hardware",
                                  _glob_any("/dev/ttyUSB*", "/dev/ttyACM*", "/dev/serial0", "/dev/ttyAMA0"),
                                  "Connect a USB-TTL adapter or enable the Pi UART."))
CAP_SPI = _register(Capability("hw.spi", "SPI bus enabled", "hardware",
                               _glob_any("/dev/spidev*"),
                               "Enable SPI via raspi-config (used for flash dumping)."))
CAP_I2C = _register(Capability("hw.i2c", "I2C bus enabled", "hardware",
                               _glob_any("/dev/i2c-*"),
                               "Enable I2C via raspi-config and connect SDA/SCL with a common ground."))
CAP_I2C_TOOLS = _register(Capability("hw.i2c_tools", "i2c-tools (i2cdetect/i2cdump)", "tool",
                                     _all_tools("i2cdetect", "i2cdump"),
                                     "Install i2c-tools for bus scanning and EEPROM reads.",
                                 install="sudo apt install i2c-tools"))
CAP_SIGROK = _register(Capability("hw.logic_analyzer", "sigrok-cli installed", "tool",
                                  _tool("sigrok-cli"),
                                  "Install sigrok-cli; module execution still requires a compatible analyzer.",
                                 install="sudo apt install sigrok-cli sigrok-firmware-fx2lafw"))

CAP_BLUEZ = _register(Capability("bt.bluez", "BlueZ command-line tools", "tool",
                                 _any_tool("bluetoothctl", "btmgmt"),
                                 "Install bluez; an enabled adapter and running bluetoothd are checked at execution.",
                                 install="sudo apt install bluez bluez-tools"))
# The GATT code imports ``dbus`` (dbus-python) specifically; PyGObject alone
# does not satisfy it, so only ``dbus`` counts as available.
CAP_BT_DBUS = _register(Capability("bt.dbus", "BlueZ D-Bus bindings (dbus-python)", "python",
                                    _python("dbus"),
                                    "dbus-python is not importable by the backend's interpreter. "
                                    "Install it system-wide and create the venv with "
                                    "--system-site-packages, or `pip install dbus-python`.",
                                 install="sudo apt install python3-dbus  # Arch: pacman -S python-dbus"))
CAP_L2PING = _register(Capability("bt.l2ping", "l2ping", "tool", _tool("l2ping"),
                                  "Part of bluez-tools; needed for RTT/link probes.",
                                 install="sudo apt install bluez-tools"))
CAP_HCITOOL = _register(Capability("bt.hcitool", "hcitool", "tool", _tool("hcitool"),
                                   "Part of bluez; legacy HCI utilities.",
                                 install="sudo apt install bluez"))
CAP_TSHARK = _register(Capability("net.tshark", "tshark", "tool", _tool("tshark"),
                                  "Install tshark for packet capture/decoding.",
                                 install="sudo apt install tshark"))
CAP_TCPDUMP = _register(Capability("net.tcpdump", "tcpdump", "tool", _tool("tcpdump"),
                                   "Install tcpdump for capture.",
                                 install="sudo apt install tcpdump"))

CAP_NMAP = _register(Capability("net.nmap", "nmap", "tool", _tool("nmap"),
                                "Install nmap for service/OS discovery.",
                                 install="sudo apt install nmap"))
CAP_OPENSSL = _register(Capability("net.openssl", "openssl", "tool", _tool("openssl"),
                                   "Install openssl for TLS probing.",
                                 install="sudo apt install openssl"))
CAP_WIRELESS = _register(Capability("net.wireless_cli", "iw / iwconfig", "tool",
                                    _any_tool("iw", "iwconfig"),
                                    "Install `iw` for Wi-Fi interface management.",
                                 install="sudo apt install iw"))
CAP_AIRCRACK = _register(Capability("net.aircrack", "aircrack-ng suite", "tool",
                                    _any_tool("aircrack-ng", "airmon-ng"),
                                    "Install aircrack-ng for monitor-mode work.",
                                 install="sudo apt install aircrack-ng"))
CAP_MQTT = _register(Capability("net.mosquitto_cli", "mosquitto client", "tool",
                                _any_tool("mosquitto_pub", "mosquitto_sub"),
                                "Install mosquitto-clients for MQTT auditing.",
                                 install="sudo apt install mosquitto-clients"))
CAP_BINWALK = _register(Capability("fw.binwalk", "binwalk", "tool", _tool("binwalk"),
                                    "Install binwalk for firmware carving.",
                                 install="sudo apt install binwalk"))
CAP_FLASHROM = _register(Capability("fw.flashrom", "flashrom", "tool", _tool("flashrom"),
                                     "Install flashrom for SPI flash access.",
                                 install="sudo apt install flashrom"))
CAP_STRINGS = _register(Capability("fw.strings", "strings (binutils)", "tool", _tool("strings"),
                                   "Install binutils.",
                                 install="sudo apt install binutils"))
CAP_OBJDUMP = _register(Capability("fw.objdump", "objdump/readelf", "tool",
                                    _any_tool("objdump", "readelf"),
                                    "Install binutils.",
                                 install="sudo apt install binutils"))

# --- Acquisition: fast network exfil, host block imaging, Android ----------- #
CAP_NETCAT = _register(Capability("net.netcat", "netcat (nc/ncat)", "tool",
                                   _any_tool("ncat", "nc", "netcat"),
                                   "Needed only for network-based firmware exfil "
                                   "(tar | nc) in rootfs_archive; UART transport needs nothing.",
                                 install="sudo apt install netcat-openbsd"))
CAP_LSBLK = _register(Capability("host.block_tools", "Host block tools (lsblk/dd)", "tool",
                                  _all_tools("lsblk", "dd"),
                                  "Needed to image a device attached to this PC "
                                  "(USB mass-storage / SD reader) with host_block_acquire.",
                                 install="sudo apt install util-linux coreutils"))
CAP_DDRESCUE = _register(Capability("host.ddrescue", "gddrescue (ddrescue)", "tool",
                                    _tool("ddrescue"),
                                    "Optional: resilient imaging of flaky media in host_block_acquire.",
                                 install="sudo apt install gddrescue"))
CAP_ADB = _register(Capability("android.adb", "Android Debug Bridge (adb)", "tool",
                               _tool("adb"),
                               "Needed for adb_acquire on Android-based devices; "
                               "USB debugging must be enabled and the host authorized on the device.",
                                 install="sudo apt install adb"))


def resolve(ids: list[str]) -> list[Capability]:
    return [CAPABILITIES[i] for i in ids if i in CAPABILITIES]


def missing(ids: list[str]) -> list[Capability]:
    return [c for c in resolve(ids) if not c.available()]


def describe_all(ids: list[str]) -> list[dict]:
    return [c.describe() for c in resolve(ids)]
