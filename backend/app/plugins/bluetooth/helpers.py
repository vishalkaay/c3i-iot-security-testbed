"""BlueZ interaction helpers (Linux).

Real capabilities, honestly reported:

* discovery via ``bluetoothctl`` (classic + LE),
* device attribute parsing (class, icon, UUIDs, pairing flags, RSSI, TxPower),
* Device Information Service reads via the BlueZ D-Bus GATT API (preferred),
  with ``gatttool`` as a fallback,
* link RTT / packet-delivery statistics via ``l2ping``,
* a heuristic OS-family/version inference from the SDP + class fingerprints.

Every function degrades gracefully and says *why* when something is unavailable
instead of returning fabricated data (a recurring sin in the legacy tool).
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field

from app.plugins.tools import CapabilityUnavailable, CommandResult, has_tool, run

DEVICE_RE = re.compile(r"Device\s+([0-9A-Fa-f:]{17})\s*(.*)")
RSSI_RE = re.compile(r"RSSI:\s*(?:0x[0-9a-fA-F]+\s*\()?\s*(-?\d+)")
INFO_KEY_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 ]*):\s*(.*)$")

DIS_UUIDS = {
    "00002a29-0000-1000-8000-00805f9b34fb": "manufacturer_name",
    "00002a24-0000-1000-8000-00805f9b34fb": "model_number",
    "00002a25-0000-1000-8000-00805f9b34fb": "serial_number",
    "00002a26-0000-1000-8000-00805f9b34fb": "firmware_revision",
    "00002a27-0000-1000-8000-00805f9b34fb": "hardware_revision",
    "00002a28-0000-1000-8000-00805f9b34fb": "software_revision",
    "00002a50-0000-1000-8000-00805f9b34fb": "pnp_id",
}

# CoD major service/device classes -> coarse device category.
COD_MAJOR = {
    0x00: "misc", 0x01: "computer", 0x02: "phone", 0x03: "lan-ap",
    0x04: "audio-video", 0x05: "peripheral", 0x06: "imaging", 0x07: "wearable",
    0x08: "toy", 0x09: "health",
}

# OUI prefixes -> likely vendor family (kept small; the full OUI DB is optional).
OUI_VENDOR = {
    "00:1A:7D": "Apple", "3C:2E:F9": "Apple", "A4:C3:61": "Apple", "F0:99:BF": "Apple",
    "5C:F3:70": "Samsung", "34:14:5F": "Samsung", "E8:50:8B": "Samsung",
    "64:A2:F9": "OnePlus", "94:65:2D": "OnePlus",
    "28:6C:07": "Xiaomi", "7C:1D:D9": "Xiaomi",
    "00:1B:DC": "Intel", "00:1E:64": "Intel",
    "9C:AE:D3": "Bose", "00:0C:8A": "Bose",
    "00:1B:66": "Sennheiser", "00:18:09": "Jabra",
    "00:02:5B": "Nordic", "C4:BE:84": "Nordic", "F4:CE:36": "Nordic",
    "00:12:6F": "ESPRESSIF", "24:0A:C4": "ESPRESSIF", "A4:CF:12": "ESPRESSIF",
}

# Bluetooth SIG company identifiers (subset) seen in LE advertising data and in
# `bluetoothctl`'s ManufacturerData output. These are *assigned* IDs, far more
# reliable than OUI prefixes (modern LE devices randomise their MAC).
COMPANY_IDS = {
    "0x004c": "Apple", "0x0006": "Microsoft", "0x00e0": "Google",
    "0x0075": "Samsung", "0x012d": "Sony", "0x009e": "Bose",
    "0x0057": "Harman International (JBL)", "0x011b": "Logitech",
    "0x0087": "Garmin", "0x0157": "Anhui Huami (Amazfit)", "0x0188": "Sonos",
}

# Company ID -> plausible host OS family (heuristic, clearly labelled as such).
COMPANY_OS = {
    "Apple": "Apple (iOS/macOS family)",
    "Microsoft": "Windows device",
    "Google": "Android (Google Fast Pair ecosystem)",
}

# Device-name fingerprints. Windows default hostnames (DESKTOP-XXXX / LAPTOP-XXXX
# from OOBE) and Apple naming are near-authoritative; vendor model names are low
# confidence and labelled as such.
_NAME_OS = [
    (re.compile(r"\bmacbook\b|\bimac\b|\bairpods?\b|\biphone\b|\bipad\b", re.I),
     "Apple (iOS/macOS)", "medium",
     "device name is Apple's product naming"),
    (re.compile(r"^(desktop|laptop)-[a-z0-9]+$", re.I),
     "Windows", "high",
     "name is a Windows setup default hostname (DESKTOP-*/LAPTOP-*)"),
    (re.compile(r"\bgalaxy\b|^sm-[a-z0-9]|buds\d?", re.I),
     "Android (Samsung)", "medium",
     "device name is Samsung's naming convention"),
    (re.compile(r"\b(redmi|poco|xiaomi)\b|\bmi band\b", re.I),
     "Android (Xiaomi)", "medium",
     "device name is Xiaomi's naming convention"),
    (re.compile(r"\bsurface\b", re.I),
     "Windows (Microsoft Surface)", "medium",
     "device name is a Microsoft Surface product"),
    (re.compile(r"\b(victus|omen|thinkpad|ideapad|legion|vivobook|zenbook|pavilion)\b", re.I),
     "Windows/Linux PC", "low",
     "device name is a PC vendor model name"),
]

_HEX_HEX = re.compile(r"^[0-9a-fA-F ]+\.{0,3}$")


def _company_name(raw_key: str) -> str | None:
    """Map a ManufacturerData key to a SIG company name.

    bluetoothctl prints the 16-bit company identifier in little-endian display
    order for LE advertising (Apple airs 0x004C but it renders as ``0x4c00``),
    so both orderings are checked before giving up.
    """
    try:
        key = int(raw_key, 16) & 0xFFFF
    except ValueError:
        return None
    for candidate in (key, ((key & 0xFF) << 8) | (key >> 8)):
        name = COMPANY_IDS.get(f"0x{candidate:04x}")
        if name:
            return name
    return None


@dataclass
class BtDevice:
    address: str
    name: str = ""
    rssi: int | None = None
    device_class: str | None = None
    icon: str | None = None
    paired: bool = False
    trusted: bool = False
    connected: bool = False
    uuids: list[str] = field(default_factory=list)
    modalias: str | None = None
    manufacturer: str | None = None
    tx_power: int | None = None
    appearance: str | None = None
    manufacturer_data: dict[str, str] = field(default_factory=dict)  # SIG key -> "0x… (hex bytes)"
    service_data: dict[str, str] = field(default_factory=dict)
    address_type: str | None = None  # public | random (D-Bus discovery only)

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "name": self.name,
            "rssi": self.rssi,
            "device_class": self.device_class,
            "icon": self.icon,
            "paired": self.paired,
            "trusted": self.trusted,
            "connected": self.connected,
            "uuids": self.uuids,
            "modalias": self.modalias,
            "manufacturer": self.manufacturer,
            "tx_power": self.tx_power,
            "appearance": self.appearance,
            "manufacturer_data": self.manufacturer_data or None,
            "service_data": self.service_data or None,
            "address_type": self.address_type,
        }


def _vendor(address: str) -> str | None:
    return OUI_VENDOR.get(address.upper()[:8])


def list_adapters() -> list[dict]:
    if not has_tool("bluetoothctl"):
        return []
    res = run(["bluetoothctl", "list"], timeout=15)
    adapters = []
    for line in res.lines():
        m = re.match(r"Controller\s+([0-9A-Fa-f:]{17})\s*(.*)", line)
        if m:
            adapters.append({"address": m.group(1), "name": m.group(2).strip()})
    return adapters


_MFD_KEY_RE = re.compile(r"ManufacturerData(?:\.Key)?\s*:\s*(?:[Kk]ey\s*)?0x([0-9a-fA-F]+)")
_SVC_KEY_RE = re.compile(r"ServiceData(?:\.Key)?\s*:\s*(?:[Kk]ey\s*)?0x([0-9a-fA-F]+)")
_TXPOWER_RE = re.compile(r"TxPower:\s*0x[0-9a-fA-F]+\s*\(\s*(-?\d+)\s*\)")
_APPEARANCE_RE = re.compile(r"Appearance:\s*0x([0-9a-fA-F]+)")
_DEVICE_PREFIX_RE = re.compile(r"Device\s+([0-9A-Fa-f:]{17})")


def _feed_attr_lines(devices: dict[str, BtDevice], ansi_free_lines: list[str]) -> None:
    """Fold bluetoothctl attribute updates into the seen device objects.

    Handles both the single-line form (``[CHG] Device MAC UUIDs: …``) and the
    multi-line hex-dump form (``ManufacturerData.Key:`` / ``ManufacturerData.Value:``
    followed by raw hex lines). Unknown devices mentioned in attribute lines are
    registered so no fingerprint is lost.
    """
    pending: dict | None = None  # {"target": dict, "key": str, "buf": str}
    current: BtDevice | None = None  # device the latest line belonged to
    for raw in ansi_free_lines:
        line = raw.strip()
        if not line or line.startswith(("SetDiscovery", "Discovery started", "Discovery stopped")):
            continue
        line = re.sub(r"^\[(NEW|CHG|DEL)\]\s*", "", line)

        # Hex-dump rows of a pending ManufacturerData/ServiceData.Value block:
        # e.g. "02 24 02 00 … .$.............." — BlueZ appends an ASCII guest
        # column after the bytes, so only the LEADING hex-pair run is consumed.
        if pending is not None:
            hrow = re.match(r"^([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})+)", line)
            if hrow:
                hex_part = re.sub(r"[^0-9a-fA-F]", "", hrow.group(1))
                buf = (pending["buf"] + hex_part)[:256]
                pending["buf"] = buf
                pending["target"][pending["key"]] = _summarise_adv_bytes(pending["key"], buf)
                continue

        dm = _DEVICE_PREFIX_RE.search(line)
        rest = line[dm.end():].strip() if dm else line
        if dm:
            # Attribute lines that follow a bare "Device MAC (public)" header
            # (the `bluetoothctl info` shape) continue to belong to it.
            current = devices.setdefault(
                dm.group(1).upper(), BtDevice(address=dm.group(1).upper())
            )
        target = current

        vm = _MFD_KEY_RE.search(rest)
        if vm:
            key = vm.group(1).lower().rjust(4, "0")
            pending = {"target": target.manufacturer_data if target else {},
                       "key": key, "buf": ""}
            if target is not None:
                target.manufacturer_data.setdefault(key, "")
            continue
        sm = _SVC_KEY_RE.search(rest)
        if sm:
            key = sm.group(1).lower().rjust(4, "0")
            pending = {"target": target.service_data if target else {},
                       "key": key, "buf": ""}
            if target is not None:
                target.service_data.setdefault(key, "")
            continue
        if re.match(r"(ManufacturerData|ServiceData)\.Value\s*:", rest):
            if pending is not None:
                pending["buf"] = ""
            continue

        pending = None  # a non-advertising key ends the hex-stream context

        if target is None:
            continue
        if rest.startswith(("UUID",)):
            um = re.search(r"\(([0-9a-fA-F-]{36})\)", rest)
            name = rest.split(":", 1)[1].strip().split("(")[0].strip() if ":" in rest else ""
            target.uuids.append(um.group(1) if um else (name or rest))
            continue
        kv = INFO_KEY_RE.match(rest)
        if not kv:
            continue
        key, val = kv.group(1).strip(), kv.group(2).strip()
        if key in ("Name", "Alias"):
            # BlueZ uses the dashed address as the alias of a nameless device.
            if not _is_placeholder_name(val, target.address) and (key == "Name" or not target.name):
                target.name = val
        elif key == "Class":
            target.device_class = val
        elif key == "Icon":
            target.icon = val
        elif key in ("Paired", "Trusted", "Connected", "Blocked", "Bonded"):
            yes = val.lower() == "yes"
            if key == "Paired":
                target.paired = yes
            elif key == "Trusted":
                target.trusted = yes
            elif key == "Connected":
                target.connected = yes
        elif key == "Modalias":
            target.modalias = val
        elif key == "RSSI":
            rm = RSSI_RE.search(rest)
            if rm:
                with contextlib.suppress(ValueError):
                    target.rssi = int(rm.group(1))
        else:
            tm = _TXPOWER_RE.search(rest)
            if tm:
                target.tx_power = int(tm.group(1))
                continue
            am = _APPEARANCE_RE.search(rest)
            if am:
                target.appearance = f"0x{am.group(1).lower()}"


def _summarise_adv_bytes(key: str, hexbytes: str) -> str:
    vendor = _company_name(key)
    short = (hexbytes[:32] + "…") if len(hexbytes) > 32 else hexbytes
    name = vendor or "unmapped company"
    return f"{name} ({key}): {short}"


_ATTR_REST_RE = re.compile(r"^[A-Za-z][A-Za-z0-9. ]*:(\s|$)")


def _is_placeholder_name(name: str, address: str) -> bool:
    """BlueZ prints the address with dashes when a device has no name."""
    return name.replace("-", ":").upper() == address.upper()


def parse_scan_output(lines: list[str]) -> list[BtDevice]:
    """Turn raw ``bluetoothctl scan on`` output into devices.

    Only ``[NEW] Device <MAC> <name>`` lines carry a name; ``[CHG]`` lines are
    attribute updates (``RSSI:``, ``Name:``, ``ManufacturerData.Key:`` ...) and
    are folded in by ``_feed_attr_lines``. Two legacy defects are fixed here:
    attribute text was stored as the device name, and BlueZ's dashed-address
    placeholder made every anonymous device look "named" (so the unnamed-device
    finding never fired).
    """
    devices: dict[str, BtDevice] = {}
    ansi_free: list[str] = []
    for line in lines:
        clean = re.sub(r"\x1b\[[0-9;]*m", "", line)
        ansi_free.append(clean)
        m = re.search(r"\[(NEW|CHG|DEL)\]\s+Device\s+([0-9A-Fa-f:]{17})\s*(.*)", clean)
        if not m:
            continue
        tag, addr, rest = m.group(1), m.group(2).upper(), m.group(3).strip()
        if tag == "DEL":
            continue
        dev = devices.setdefault(addr, BtDevice(address=addr))
        if (tag == "NEW" and rest and not _ATTR_REST_RE.match(rest)
                and not _is_placeholder_name(rest, addr)):
            dev.name = dev.name or rest

    _feed_attr_lines(devices, ansi_free)

    for dev in devices.values():
        if dev.name and _is_placeholder_name(dev.name, dev.address):
            dev.name = ""
        dev.manufacturer = _vendor(dev.address)
        if not dev.manufacturer:
            for key in dev.manufacturer_data:
                dev.manufacturer = _company_name(key)
                if dev.manufacturer:
                    break
    return sorted(devices.values(), key=lambda d: (d.rssi is None, -(d.rssi or -999)))


def adapter_status() -> dict:
    """Is there a powered controller? Lets modules fail loudly instead of
    reporting an empty (false-negative) scan."""
    if not has_tool("bluetoothctl"):
        return {"present": False, "powered": False, "reason": "bluetoothctl not installed"}
    res = run(["bluetoothctl", "show"], timeout=15)
    out = res.stdout + res.stderr
    if "No default controller" in out or "Controller" not in out:
        return {"present": False, "powered": False,
                "reason": "no Bluetooth controller (plug in an adapter; check `rfkill list` "
                          "and `systemctl status bluetooth`)"}
    powered = bool(re.search(r"Powered:\s*yes", out))
    return {"present": True, "powered": powered,
            "reason": "" if powered else "controller is powered off (`bluetoothctl power on`)"}


def _scan_dbus(duration: int) -> list[BtDevice] | None:
    """Discover via the BlueZ D-Bus API and read each device's real properties.

    Preferred over parsing ``bluetoothctl`` output, which only prints property
    *changes* (a device whose RSSI did not change during the window had none)
    and replays BlueZ's stale device cache as ``[NEW]``. Here a device counts
    only if BlueZ holds a live RSSI for it, i.e. it was heard in this window.
    Returns ``None`` when D-Bus is unusable so the caller can fall back.
    """
    try:
        import dbus  # type: ignore
    except Exception:
        return None
    import time as _t
    try:
        bus = dbus.SystemBus()
        om = dbus.Interface(bus.get_object("org.bluez", "/"),
                            "org.freedesktop.DBus.ObjectManager")
        adapter_path = next(
            (str(path) for path, ifaces in om.GetManagedObjects().items()
             if "org.bluez.Adapter1" in ifaces
             and bool(ifaces["org.bluez.Adapter1"].get("Powered", False))), None)
        if not adapter_path:
            return None
        adapter = dbus.Interface(bus.get_object("org.bluez", adapter_path), "org.bluez.Adapter1")
        adapter.StartDiscovery()
    except Exception:  # noqa: BLE001
        return None
    try:
        _t.sleep(duration)
        objects = om.GetManagedObjects()
    except Exception:  # noqa: BLE001
        return None
    finally:
        with contextlib.suppress(Exception):
            adapter.StopDiscovery()

    devices: list[BtDevice] = []
    for path, ifaces in objects.items():
        d = ifaces.get("org.bluez.Device1")
        if not d or not str(path).startswith(adapter_path) or "RSSI" not in d:
            continue
        address = str(d.get("Address", "")).upper()
        dev = BtDevice(address=address)
        name = str(d.get("Name", "") or "")
        dev.name = "" if _is_placeholder_name(name, address) else name
        dev.rssi = int(d["RSSI"])
        if "TxPower" in d:
            dev.tx_power = int(d["TxPower"])
        dev.icon = str(d["Icon"]) if "Icon" in d else None
        if "Class" in d:
            cod = int(d["Class"])
            dev.device_class = f"0x{cod:08x}"
            dev.uuids.append(f"cod-major:{COD_MAJOR.get((cod >> 8) & 0x1F, hex((cod >> 8) & 0x1F))}")
        if "Appearance" in d:
            dev.appearance = f"0x{int(d['Appearance']):04x}"
        dev.paired = bool(d.get("Paired", False))
        dev.trusted = bool(d.get("Trusted", False))
        dev.connected = bool(d.get("Connected", False))
        dev.address_type = str(d.get("AddressType", "")) or None
        dev.modalias = str(d["Modalias"]) if "Modalias" in d else None
        dev.uuids = [str(u).lower() for u in d.get("UUIDs", [])] + dev.uuids
        for key, val in dict(d.get("ManufacturerData", {})).items():
            k = f"{int(key):04x}"
            dev.manufacturer_data[k] = _summarise_adv_bytes(k, bytes(bytearray(val)).hex()[:256])
        for key, val in dict(d.get("ServiceData", {})).items():
            k = _uuid16(str(key))
            dev.service_data[k] = bytes(bytearray(val)).hex()[:64]
        dev.manufacturer = _vendor(address) or next(
            (n for n in map(_company_name, dev.manufacturer_data) if n), None)
        devices.append(dev)
    return sorted(devices, key=lambda x: -(x.rssi or -999))


def scan(duration: int = 10) -> list[BtDevice]:
    """Discover classic + LE devices. ``duration`` is clamped to 5-60s."""
    duration = max(5, min(60, int(duration)))
    if not has_tool("bluetoothctl"):
        raise CapabilityUnavailable("bluetoothctl is not installed; Bluetooth discovery cannot run.")
    status = adapter_status()
    if not (status["present"] and status["powered"]):
        raise CapabilityUnavailable(f"Bluetooth discovery cannot run: {status['reason']}.")
    found = _scan_dbus(duration)
    if found is not None:
        return found
    # Fallback: `--timeout` makes bluetoothctl exit on its own.
    res = run(["bluetoothctl", "--timeout", str(duration), "scan", "on"],
              timeout=duration + 15)
    return parse_scan_output(res.lines())


def device_info(address: str) -> BtDevice:
    dev = BtDevice(address=address.upper(), manufacturer=_vendor(address))
    if not has_tool("bluetoothctl"):
        return dev
    res = run(["bluetoothctl", "info", address], timeout=25)
    # Strip bluetoothctl's prompt decorations and fold every attribute line
    # (including multi-line ManufacturerData hex dumps) into the device object.
    lines = []
    for line in res.lines():
        clean = re.sub(r"\x1b\[[0-9;]*m", "", line)
        # device_info runs inside an interactive bluetoothctl session, so each
        # answer line is prefixed with the "[bluetooth]# " prompt.
        clean = re.sub(r"^\[[^\]]*\]\s*", "", clean)
        if clean.strip():
            lines.append(clean)
    _feed_attr_lines({address.upper(): dev}, lines)

    if dev.device_class and dev.device_class.startswith("0x"):
        # Class prints as "0x002e410c (3031308)" — parse the hex token only
        # (the previous int(cls, 16) on the whole string always failed, so the
        # major-device-class hint silently never fired).
        cm = re.match(r"0x([0-9A-Fa-f]+)", dev.device_class)
        if cm:
            try:
                cod = int(cm.group(1), 16)
                major = (cod >> 8) & 0x1F
                dev.uuids.append(f"cod-major:{COD_MAJOR.get(major, hex(major))}")
            except ValueError:
                pass
    return dev


# --------------------------------------------------------------------------- #
# Device Information Service (firmware / model / versions)
# --------------------------------------------------------------------------- #
def read_dis_dbuss(address: str) -> dict:
    """Read DIS characteristics via the BlueZ D-Bus GATT API. Returns {} on failure."""
    try:
        import dbus  # type: ignore
    except Exception:
        return {"_error": "python-dbus not available"}
    try:
        bus = dbus.SystemBus()
        om = dbus.Interface(bus.get_object("org.bluez", "/"),
                            "org.freedesktop.DBus.ObjectManager")
        objects = om.GetManagedObjects()
    except Exception as exc:  # noqa: BLE001
        return {"_error": f"D-Bus unavailable: {exc}"}

    dev_path = None
    for path, ifaces in objects.items():
        d = ifaces.get("org.bluez.Device1")
        if d and str(d.get("Address", "")).upper() == address.upper():
            dev_path = path
            break
    if not dev_path:
        return {"_error": "device not known to BlueZ (scan first)"}

    try:
        dev = dbus.Interface(bus.get_object("org.bluez", dev_path), "org.bluez.Device1")
        if not dev.Get("org.bluez.Device1", "Connected"):
            dev.Connect()
    except Exception as exc:  # noqa: BLE001
        return {"_error": f"connect failed: {exc}"}

    result: dict[str, str] = {}
    try:
        objects = om.GetManagedObjects()
        for path, ifaces in objects.items():
            ch = ifaces.get("org.bluez.GattCharacteristic1")
            if not ch or not path.startswith(dev_path):
                continue
            uuid = str(ch.get("UUID", "")).lower()
            field_name = DIS_UUIDS.get(uuid)
            if not field_name:
                continue
            try:
                char = dbus.Interface(
                    bus.get_object("org.bluez", path), "org.bluez.GattCharacteristic1"
                )
                data = bytes(bytearray(char.ReadValue({})))
                result[field_name] = data.decode("utf-8", errors="replace").strip("\x00 ")
            except Exception:  # noqa: BLE001,S112
                continue
    finally:
        with contextlib.suppress(Exception):
            dev.Disconnect()
    return result


def read_dis_gatttool(address: str) -> dict:
    """Fallback DIS read using gatttool (older BlueZ stacks)."""
    if not has_tool("gatttool"):
        return {"_error": "gatttool not available"}
    result: dict[str, str] = {}
    for uuid, name in DIS_UUIDS.items():
        short = uuid[4:8]
        res = run(["gatttool", "-b", address, "--char-read", "-u", short], timeout=15)
        m = re.search(r"Characteristic value/descriptor:\s*([0-9a-fA-F ]+)", res.stdout)
        if m:
            try:
                result[name] = bytes.fromhex(m.group(1).replace(" ", "")).decode(
                    "utf-8", errors="replace"
                ).strip("\x00 ")
            except ValueError:
                continue
    return result or {"_error": "no DIS characteristics readable"}


def read_device_information(address: str) -> dict:
    for reader in (read_dis_dbuss, read_dis_gatttool):
        data = reader(address)
        if data and "_error" not in data:
            data["_source"] = reader.__name__
            return data
    return {"_error": "Device Information Service not readable (D-Bus and gatttool both failed)"}


# --------------------------------------------------------------------------- #
# Link RTT / packet delivery and coarse RSSI ranging
# --------------------------------------------------------------------------- #
# RSSI is a *coarse* ranging signal. A single sample is affected by antenna
# orientation, body shadowing, multipath, and the device's actual transmit
# power. The log-distance model below is deliberately exposed with an
# uncertainty interval and a confidence label rather than pretending that a
# Bluetooth RTT or one RSSI reading is a tape measure. For precise ranging use
# UWB, time-of-flight, or a calibrated multi-anchor RSSI survey.
DEFAULT_REFERENCE_RSSI_DBM = -59.0  # typical BLE RSSI at 1 m (not TxPower!)
DEFAULT_PATH_LOSS_EXPONENT = 2.5     # indoor, 2.4 GHz; free space is 2.0


def estimate_distance(
    rssi_dbm: int | float | None,
    *,
    reference_rssi_dbm: float | None = None,
    path_loss_exponent: float = DEFAULT_PATH_LOSS_EXPONENT,
    reference_source: str = "assumed_typical_-59_dbm_at_1m",
) -> dict:
    """Estimate range from one RSSI sample using a log-distance model.

    ``d = 10 ** ((RSSI_ref - RSSI) / (10 * n))`` where ``RSSI_ref`` is the
    measured RSSI at 1 m and ``n`` is the path-loss exponent. The returned
    interval varies ``n`` by ±0.5 to show model sensitivity; it is *not* a
    statistical confidence interval. Returns ``available: False`` when no
    usable RSSI is available.
    """
    caveat = (
        "RSSI ranging is approximate: orientation, body/antenna shadowing, "
        "multipath and transmit-power differences can cause 2-3x error. "
        "Calibrate RSSI at 1 m in the target environment; use UWB/ToF for "
        "precise ranging. RTT is not used for distance because Bluetooth "
        "baseband processing dominates the round-trip time."
    )
    if rssi_dbm is None:
        return {
            "available": False,
            "estimated_m": None,
            "range_m": None,
            "method": "rssi_log_distance",
            "confidence": "unavailable",
            "caveat": "No RSSI reading was available from BlueZ; supply a measured "
                      "RSSI or run a discovery/profile pass first. " + caveat,
        }
    try:
        rssi = float(rssi_dbm)
    except (TypeError, ValueError):
        return {"available": False, "estimated_m": None, "range_m": None,
                "method": "rssi_log_distance", "confidence": "unavailable",
                "caveat": "RSSI was not numeric. " + caveat}
    # RSSI 0 / positive values are BlueZ sentinels, not usable measurements.
    if rssi >= 0 or rssi < -127:
        return {
            "available": False, "estimated_m": None, "range_m": None,
            "method": "rssi_log_distance", "confidence": "unavailable",
            "rssi_dbm": round(rssi, 1),
            "caveat": "BlueZ returned an invalid/unknown RSSI sentinel. " + caveat,
        }

    ref = float(reference_rssi_dbm if reference_rssi_dbm is not None
                else DEFAULT_REFERENCE_RSSI_DBM)
    n = max(1.2, min(5.0, float(path_loss_exponent)))
    d = 10 ** ((ref - rssi) / (10 * n))
    # Higher n attenuates faster -> shorter estimate; lower n -> longer.
    n_near = max(1.2, n - 0.5)
    n_far = min(5.0, n + 0.5)
    d_near = 10 ** ((ref - rssi) / (10 * n_far))
    d_far = 10 ** ((ref - rssi) / (10 * n_near))
    return {
        "available": True,
        "estimated_m": round(d, 2),
        "range_m": [round(min(d_near, d_far), 2), round(max(d_near, d_far), 2)],
        "rssi_dbm": round(rssi, 1),
        "reference_rssi_dbm": ref,
        "reference_source": reference_source,
        "path_loss_exponent": n,
        "method": "rssi_log_distance",
        "confidence": "medium" if reference_source.startswith("operator_calibrated") else "low",
        "caveat": caveat,
    }


@dataclass
class RttStats:
    sent: int
    received: int
    loss_pct: float
    min_ms: float | None
    avg_ms: float | None
    max_ms: float | None
    distance_m: float | None
    distance: dict = field(default_factory=dict)
    raw: str = ""

    def to_dict(self) -> dict:
        return {
            "sent": self.sent, "received": self.received, "loss_pct": round(self.loss_pct, 1),
            "min_ms": self.min_ms, "avg_ms": self.avg_ms, "max_ms": self.max_ms,
            "estimated_distance_m": self.distance_m,
            "distance_estimate": self.distance,
        }


def l2ping(
    address: str,
    count: int = 10,
    size: int = 44,
    *,
    rssi_dbm: int | None = None,
    reference_rssi_dbm: float | None = None,
    path_loss_exponent: float = DEFAULT_PATH_LOSS_EXPONENT,
) -> RttStats | str:
    if not has_tool("l2ping"):
        return "l2ping not installed (bluez-tools)"
    count = max(1, min(100, int(count)))
    size = max(1, min(65535, int(size)))
    res: CommandResult = run(
        ["l2ping", "-c", str(count), "-s", str(size), address], timeout=count * 3 + 20
    )
    out = res.stdout + res.stderr
    times = [float(t) for t in re.findall(r"time\s+([0-9.]+)\s*ms", out, re.IGNORECASE)]
    sent_m = re.search(r"Sent\s+(\d+)\s+bytes", out)
    recv_m = re.search(r"(\d+)\s+received", out)
    sent = int(sent_m.group(1)) if sent_m else count
    received = int(recv_m.group(1)) if recv_m else len(times)
    loss = 100.0 * (1 - received / sent) if sent else 100.0
    avg = sum(times) / len(times) if times else None

    # Pull RSSI from BlueZ when the caller did not provide a measured sample.
    # TxPower is deliberately *not* used as the 1 m reference: BlueZ's TxPower
    # is the radio's transmit level, not a calibrated RSSI-at-1m value.
    if rssi_dbm is None:
        dev = device_info(address)
        rssi_dbm = dev.rssi
    reference_source = ("operator_calibrated" if reference_rssi_dbm is not None
                        else "assumed_typical_-59_dbm_at_1m")
    distance = estimate_distance(
        rssi_dbm,
        reference_rssi_dbm=reference_rssi_dbm,
        path_loss_exponent=path_loss_exponent,
        reference_source=reference_source,
    )
    return RttStats(
        sent=sent, received=received, loss_pct=loss,
        min_ms=min(times) if times else None,
        avg_ms=round(avg, 2) if avg else None,
        max_ms=max(times) if times else None,
        distance_m=distance.get("estimated_m"),
        distance=distance, raw=out[-4000:],
    )


# --------------------------------------------------------------------------- #
# Heuristic OS / firmware inference
# --------------------------------------------------------------------------- #
@dataclass
class OsInference:
    os_family: str
    os_version: str | None
    confidence: str  # low | medium | high
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "os_family": self.os_family, "os_version_estimate": self.os_version,
            "confidence": self.confidence, "reasons": self.reasons,
        }


def infer_os(dev: BtDevice, dis: dict | None = None) -> OsInference:
    """Heuristic OS/vendor-family inference from every fingerprint available.

    Reasons always state the *basis* of each conclusion and the confidence is
    capped by how authoritative the source is: SIG company IDs in advertising
    data and Windows OOBE hostnames are strong claims, icon/class guesses are
    weak ones. No version number is ever fabricated - without a DIS read the
    estimate stays ``None``.
    """
    candidates: list[tuple[str, str, str, str]] = []  # (family, confidence, basis, detail)

    # 1) LE advertising company IDs - assigned by the SIG, most reliable.
    for key, _summary in (dev.manufacturer_data or {}).items():
        company = _company_name(key)
        if company:
            fam = COMPANY_OS.get(company)
            if fam:
                candidates.append((
                    fam, "high",
                    "advertising company ID", f"{company} ({key})",
                ))

    # 2) Device-name fingerprints.
    for pattern, family, conf, why in _NAME_OS:
        if dev.name and pattern.search(dev.name):
            candidates.append((family, conf, "device name", why))

    # 3) MAC OUI (weakest identity signal: LE devices randomise their MAC).
    vendor = dev.manufacturer or _vendor(dev.address)
    if vendor:
        fam = COMPANY_OS.get(vendor)
        if fam:
            candidates.append((fam, "low", "MAC OUI prefix", f"maps to {vendor}"))

    # 4) Class of device / icon.
    icon = (dev.icon or "").lower()
    cod_major = next(
        (u.split(":", 1)[1] for u in dev.uuids if u.startswith("cod-major:")),
        None,
    )
    if cod_major == "computer" or icon == "computer":
        basis = "class of device = computer" if cod_major == "computer" else "icon = computer"
        candidates.append(("Windows/Linux/macOS", "low", basis, "OS not disclosed"))
    elif icon == "phone" or cod_major == "phone":
        basis = "class of device = phone" if cod_major == "phone" else "icon = phone"
        candidates.append(("Android/other mobile", "low", basis, "OS not disclosed"))
    elif icon in ("audio-headset", "audio-headphones", "audio-card", "audio-speakers"):
        candidates.append(("RTOS (audio stack)", "low", f"icon = {icon}",
                           "embedded audio firmware"))
    elif icon in ("input-keyboard", "input-mouse", "input-gaming"):
        candidates.append(("RTOS (HID peripheral)", "low", f"icon = {icon}",
                           "embedded HID firmware"))
    elif cod_major == "wearable":
        candidates.append(("RTOS (wearable)", "low", "class of device = wearable",
                           "embedded wearable firmware"))

    # 5) Device Information Service read - the only real *version* source.
    version = None
    if dis and "_error" not in dis:
        version = dis.get("firmware_revision") or dis.get("software_revision")
        if version:
            candidates.append(("vendor-specific", "high", "DIS firmware revision",
                               f"reports '{version}'"))

    if not candidates:
        return OsInference(os_family="Unknown/embedded", os_version=version,
                           confidence="low",
                           reasons=["no recognisable fingerprint in discovery data"])

    rank = {"high": 2, "medium": 1, "low": 0}
    best = max(candidates, key=lambda c: rank[c[1]])
    reasons = [
        f"[{conf}] {basis}" + (f": {detail}" if detail else "")
        for _fam, conf, basis, detail in candidates
    ]
    return OsInference(os_family=best[0], os_version=version,
                       confidence=best[1], reasons=reasons)


# --------------------------------------------------------------------------- #
# Full GATT enumeration + access classification (industry BLE pentest core)
# --------------------------------------------------------------------------- #
# A BLE attribute is reachable at one of several security levels. BlueZ exposes
# this per characteristic as a "Flags" list; the plain ``read``/``write``/
# ``write-without-response`` flags mean the attribute is accessible WITHOUT
# encryption or authentication ("OPEN"), whereas the ``encrypt-*``/``secure-*``/
# ``authenticated-signed-writes`` flags require a bonded/encrypted link
# ("PROTECTED"). An OPEN writable characteristic on an actuator, lock or config
# service is a classic real-world BLE finding.
_OPEN_READ_FLAGS = {"read"}
_PROT_READ_FLAGS = {"encrypt-read", "encrypt-authenticated-read", "secure-read"}
_OPEN_WRITE_FLAGS = {"write", "write-without-response"}
_PROT_WRITE_FLAGS = {"encrypt-write", "encrypt-authenticated-write", "secure-write",
                     "authenticated-signed-writes"}
_NOTIFY_FLAGS = {"notify", "indicate"}

# A compact label map for the well-known SIG 16-bit UUIDs so the enumeration is
# readable without a full database. Unknown UUIDs are reported verbatim.
GATT_LABELS = {
    "1800": "Generic Access", "1801": "Generic Attribute", "180a": "Device Information",
    "180f": "Battery Service", "1805": "Current Time", "1812": "HID",
    "feaa": "Eddystone", "fd6f": "Exposure Notification", "110b": "A2DP Audio Sink",
    "2a00": "Device Name", "2a01": "Appearance", "2a19": "Battery Level",
    "2a29": "Manufacturer Name", "2a24": "Model Number", "2a26": "Firmware Revision",
    "2a25": "Serial Number", "2a27": "Hardware Revision", "2a28": "Software Revision",
    "2a4d": "HID Report", "2a4a": "HID Information", "2902": "CCC Descriptor",
}


def _uuid16(uuid: str) -> str:
    """Return the 16-bit short form of a 128-bit SIG base UUID, else the full UUID."""
    u = (uuid or "").lower()
    if len(u) == 36 and u.endswith("-0000-1000-8000-00805f9b34fb"):
        return u[4:8]
    return u


def gatt_label(uuid: str) -> str:
    short = _uuid16(uuid)
    return GATT_LABELS.get(short, "")


def _classify_flags(flags: list[str]) -> dict:
    fset = {str(f).lower() for f in (flags or [])}
    readable = bool(fset & (_OPEN_READ_FLAGS | _PROT_READ_FLAGS))
    writable = bool(fset & (_OPEN_WRITE_FLAGS | _PROT_WRITE_FLAGS))
    return {
        "flags": sorted(fset),
        "readable": readable,
        "writable": writable,
        "notify": bool(fset & _NOTIFY_FLAGS),
        # OPEN = reachable with no encryption/authentication.
        "open_read": bool(fset & _OPEN_READ_FLAGS) and not (fset & _PROT_READ_FLAGS),
        "open_write": bool(fset & _OPEN_WRITE_FLAGS) and not (fset & _PROT_WRITE_FLAGS),
        "protected": bool(fset & (_PROT_READ_FLAGS | _PROT_WRITE_FLAGS)),
    }


_AUTH_ERROR_HINTS = ("notauthorized", "notpermitted", "authentication", "authorization",
                     "encryption", "insufficient")


def classify_read_failure(exc: Exception) -> dict:
    """Interpret a failed GATT read.

    BlueZ only reports a remote characteristic's *properties* (read, write...),
    never its server-side permission, so a characteristic that requires an
    encrypted link still shows a plain ``read`` flag. The read attempt is the
    real evidence: a security error means PROTECTED, anything else is merely
    "unverified" (timeout, disconnect).
    """
    name = getattr(exc, "get_dbus_name", lambda: "")() or type(exc).__name__
    text = f"{name} {exc}".lower()
    protected = any(h in text for h in _AUTH_ERROR_HINTS)
    return {"read_error": name.rsplit(".", 1)[-1][:60], "rejected_for_security": protected}


def enumerate_gatt(address: str, *, read_values: bool = True,
                   max_read_bytes: int = 64, settle_tries: int = 10) -> dict:
    """Walk the device's entire GATT database over the BlueZ D-Bus API.

    Returns every service, characteristic (with access classification) and
    descriptor, plus bounded authorized reads of OPEN-readable characteristics.
    This is enumeration of an exposed attribute table — not an auth bypass:
    the device chose to expose anything reported here without encryption.
    """
    try:
        import dbus  # type: ignore
    except Exception:
        return {"_error": "python-dbus not available (install python3-dbus)"}
    import time as _t
    try:
        bus = dbus.SystemBus()
        om = dbus.Interface(bus.get_object("org.bluez", "/"),
                            "org.freedesktop.DBus.ObjectManager")
        objects = om.GetManagedObjects()
    except Exception as exc:  # noqa: BLE001
        return {"_error": f"D-Bus unavailable: {exc}"}

    dev_path = None
    for path, ifaces in objects.items():
        d = ifaces.get("org.bluez.Device1")
        if d and str(d.get("Address", "")).upper() == address.upper():
            dev_path = path
            break
    if not dev_path:
        return {"_error": "device not known to BlueZ (scan first)"}

    try:
        dev = dbus.Interface(bus.get_object("org.bluez", dev_path), "org.bluez.Device1")
        props = dbus.Interface(bus.get_object("org.bluez", dev_path),
                               "org.freedesktop.DBus.Properties")
        if not props.Get("org.bluez.Device1", "Connected"):
            dev.Connect()
        # GATT objects only populate once services are resolved.
        for _ in range(max(1, settle_tries)):
            if bool(props.Get("org.bluez.Device1", "ServicesResolved")):
                break
            _t.sleep(0.5)
    except Exception as exc:  # noqa: BLE001
        return {"_error": f"connect failed: {exc}"}

    services: list[dict] = []
    characteristics: list[dict] = []
    open_reads: list[dict] = []
    open_writes: list[dict] = []
    try:
        objects = om.GetManagedObjects()
        svc_uuid_by_path = {}
        for path, ifaces in objects.items():
            s = ifaces.get("org.bluez.GattService1")
            if s and path.startswith(dev_path):
                uuid = str(s.get("UUID", "")).lower()
                svc_uuid_by_path[path] = uuid
                services.append({"path": path, "uuid": uuid, "label": gatt_label(uuid),
                                 "primary": bool(s.get("Primary", False))})
        for path, ifaces in objects.items():
            ch = ifaces.get("org.bluez.GattCharacteristic1")
            if not ch or not path.startswith(dev_path):
                continue
            uuid = str(ch.get("UUID", "")).lower()
            svc_path = str(ch.get("Service", ""))
            access = _classify_flags([str(f) for f in ch.get("Flags", [])])
            entry = {"uuid": uuid, "label": gatt_label(uuid),
                     "service_uuid": svc_uuid_by_path.get(svc_path, ""), **access}
            if read_values and access["open_read"]:
                try:
                    char = dbus.Interface(bus.get_object("org.bluez", path),
                                          "org.bluez.GattCharacteristic1")
                    data = bytes(bytearray(char.ReadValue({})))[:max_read_bytes]
                    entry["value_hex"] = data.hex()
                    text = data.decode("utf-8", errors="replace").strip("\x00")
                    if text.isprintable():
                        entry["value_text"] = text
                    entry["read_verified"] = True
                except Exception as exc:  # noqa: BLE001
                    failure = classify_read_failure(exc)
                    entry["read_error"] = failure["read_error"]
                    if failure["rejected_for_security"]:
                        # Declared readable, but the device refused an
                        # unencrypted/unauthenticated read: not OPEN.
                        entry["open_read"] = False
                        entry["protected"] = True
                        access = {**access, "open_read": False}
                        entry["access_note"] = ("read rejected on an unpaired link - requires "
                                                "encryption/authentication")
            if access["open_write"]:
                entry["access_note"] = entry.get("access_note") or (
                    "write property declared; no write was attempted, so the device's "
                    "server-side permission check is unverified")
            characteristics.append(entry)
            if access["open_read"]:
                open_reads.append(entry)
            if access["open_write"]:
                open_writes.append(entry)
    finally:
        with contextlib.suppress(Exception):
            dev.Disconnect()

    return {
        "address": address.upper(),
        "services": services,
        "characteristics": characteristics,
        "stats": {
            "services": len(services),
            "characteristics": len(characteristics),
            "open_readable": len(open_reads),
            "open_writable": len(open_writes),
            "protected": sum(1 for c in characteristics if c.get("protected")),
            "reads_verified": sum(1 for c in characteristics if c.get("read_verified")),
        },
        "open_reads": open_reads,
        "open_writes": open_writes,
    }


def read_security_posture(address: str) -> dict:
    """Observable LE security posture: address privacy + pairing/bonding state.

    Draws on bluetoothctl properties and, where available, BlueZ D-Bus
    (AddressType/Bonded/ServicesResolved). It reports only what is observable
    without actively driving a pairing handshake, and never fabricates an SMP
    method it did not witness.
    """
    dev = device_info(address)
    svc_uuids = [u for u in dev.uuids if not u.startswith("cod-major:")]
    out = {
        "address": address.upper(), "name": dev.name or None,
        "paired": dev.paired, "trusted": dev.trusted, "connected": dev.connected,
        "address_type": None, "bonded": None, "services_resolved": None,
        "advertised_services": len(svc_uuids),
    }
    try:
        import dbus  # type: ignore
        bus = dbus.SystemBus()
        om = dbus.Interface(bus.get_object("org.bluez", "/"),
                            "org.freedesktop.DBus.ObjectManager")
        for _path, ifaces in om.GetManagedObjects().items():
            d = ifaces.get("org.bluez.Device1")
            if d and str(d.get("Address", "")).upper() == address.upper():
                out["address_type"] = str(d.get("AddressType", "")) or None
                if "Bonded" in d:
                    out["bonded"] = bool(d.get("Bonded"))
                if "ServicesResolved" in d:
                    out["services_resolved"] = bool(d.get("ServicesResolved"))
                break
    except Exception as exc:  # noqa: BLE001
        out["_dbus_error"] = str(exc)[:160]

    # Privacy classification (honest about BlueZ's limits).
    at = out["address_type"]
    if at == "public":
        out["privacy"] = "trackable"  # fixed public address, no MAC randomisation
    elif at == "random":
        out["privacy"] = "random (possibly resolvable/private — not distinguishable via BlueZ)"
    else:
        out["privacy"] = "unknown"
    return out
