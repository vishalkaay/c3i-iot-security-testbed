"""Wi-Fi / IP-network helpers: nmap parsing, TLS probing, wireless survey."""

from __future__ import annotations

import contextlib
import os
import re
import socket
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from app.plugins.tools import CapabilityUnavailable, has_tool, run


# --------------------------------------------------------------------------- #
# nmap
# --------------------------------------------------------------------------- #
@dataclass
class Service:
    port: int
    protocol: str
    state: str
    name: str = ""
    product: str = ""
    version: str = ""
    extra: str = ""

    def to_dict(self) -> dict:
        banner = " ".join(x for x in (self.product, self.version) if x).strip()
        return {"port": self.port, "protocol": self.protocol, "state": self.state,
                "service": self.name, "product": self.product, "version": self.version,
                "banner": banner, "extra": self.extra}


@dataclass
class HostResult:
    address: str
    hostnames: list[str] = field(default_factory=list)
    os_matches: list[dict] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)


def nmap_scan(target: str, *, ports: str | None = None, version: bool = True,
              os_detect: bool = False, timeout: int = 900) -> HostResult:
    argv = ["nmap", "-oX", "-", "-T4"]
    if version:
        # Bounded version detection: the default intensity spends minutes on
        # services that never answer a probe (common on embedded targets).
        # Anything nmap leaves "unknown" is classified by identify_service().
        argv += ["-sV", "--version-intensity", "2"]
    argv.append("-sT")  # connect scan: no root required
    if os_detect and os.geteuid() == 0:
        argv.append("-O")
    if ports:
        argv += ["-p", ports]
    argv.append(target)
    res = run(argv, timeout=timeout)
    return parse_nmap_xml(res.stdout, target)


def parse_nmap_xml(xml: str, fallback_addr: str) -> HostResult:
    host = HostResult(address=fallback_addr)
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return host
    for h in root.findall("host"):
        addr_el = h.find("address")
        if addr_el is not None:
            host.address = addr_el.get("addr", fallback_addr)
        for hn in h.findall("hostnames/hostname"):
            name = hn.get("name")
            if name:
                host.hostnames.append(name)
        for om in h.findall("os/osmatch"):
            host.os_matches.append({"name": om.get("name"), "accuracy": om.get("accuracy")})
        for port in h.findall("ports/port"):
            state_el = port.find("state")
            svc = port.find("service")
            host.services.append(
                Service(
                    port=int(port.get("portid", "0")),
                    protocol=port.get("protocol", "tcp"),
                    state=state_el.get("state", "unknown") if state_el is not None else "unknown",
                    name=svc.get("name", "") if svc is not None else "",
                    product=svc.get("product", "") if svc is not None else "",
                    version=svc.get("version", "") if svc is not None else "",
                    extra=svc.get("extrainfo", "") if svc is not None else "",
                )
            )
    host.services.sort(key=lambda s: s.port)
    return host


def ping_sweep(subnet: str, timeout: int = 120) -> list[str]:
    """Host discovery via nmap -sn (no root needed for connect-adjacent discovery)."""
    if not has_tool("nmap"):
        raise CapabilityUnavailable("nmap is not installed; host discovery cannot run.")
    res = run(["nmap", "-sn", "-oG", "-", subnet], timeout=timeout)
    hosts = []
    for line in res.lines():
        if line.startswith("Host:") and "Status: Up" in line:
            hosts.append(line.split()[1])
    return hosts


# --------------------------------------------------------------------------- #
# TLS probing
# --------------------------------------------------------------------------- #
# Labels must match the ones emitted by tls_probe() below. (A previous
# "tls1_1" spelling meant TLS 1.1 was never reported as weak.)
WEAK_PROTOCOLS = {"ssl2", "ssl3", "tls1", "tls1.1"}


def tls_probe(host: str, port: int, *, timeout: int = 15) -> dict:
    """Probe supported TLS versions and the negotiated cipher via openssl.

    openSSL prints ``Cipher is (NONE)`` even when the handshake fails with a
    graceful close - counting that as "supported" produced the legacy
    "this server supports SSLv3 with cipher (NONE)" false positives. Here a
    probe only counts as supported when a real cipher was negotiated.
    """
    if not has_tool("openssl"):
        return {"error": "openssl not installed"}
    supported, rejected = [], []
    for flag, label in (("-ssl2", "ssl2"), ("-ssl3", "ssl3"), ("-tls1", "tls1"),
                        ("-tls1_1", "tls1.1"), ("-tls1_2", "tls1.2"), ("-tls1_3", "tls1.3")):
        res = run(["openssl", "s_client", flag, "-connect", f"{host}:{port}",
                   "-servername", host], timeout=timeout, input_text="Q\n")
        out = res.stdout + res.stderr
        cipher_m = re.search(r"Cipher\s+is\s+(\S+)", out)
        cipher = cipher_m.group(1) if cipher_m else None
        failed = (
            "handshake failure" in out.lower()
            or "no protocols available" in out.lower()
            or "unsupported protocol" in out.lower()
            or "wrong version number" in out.lower()
            or "alert protocol version" in out.lower()
            or cipher in (None, "(NONE)", "0000")
            or res.returncode != 0
        )
        if failed:
            rejected.append(label)
        else:
            supported.append({"version": label, "cipher": cipher})
    weak = [s for s in supported if s["version"] in WEAK_PROTOCOLS]
    return {"supported": supported, "rejected": rejected, "weak_protocols": weak,
            "certificate": _tls_cert(host, port, timeout)}


def _tls_cert(host: str, port: int, timeout: int) -> dict:
    """Fetch the leaf certificate and decode subject/issuer/validity/key size.

    ``s_client`` alone never prints the validity window, so the PEM is piped
    through ``openssl x509`` (expiry was previously always empty).
    """
    res = run(["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host],
              timeout=timeout, input_text="Q\n")
    text = res.stdout
    subject = re.search(r"subject=(.*)", text)
    issuer = re.search(r"issuer=(.*)", text)
    bits = re.search(r"Server public key is (\d+) bit", text)
    cert = {
        "subject": subject.group(1).strip() if subject else None,
        "issuer": issuer.group(1).strip() if issuer else None,
        "validity": {},
        "key_bits": int(bits.group(1)) if bits else None,
        "signature_algorithm": None,
        "expired": None,
        "days_remaining": None,
        "self_signed": bool(subject and issuer
                            and subject.group(1).strip() == issuer.group(1).strip()),
    }
    pem = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
    if not pem:
        return cert
    dec = run(["openssl", "x509", "-noout", "-dates", "-text"], timeout=timeout,
              input_text=pem.group(0) + "\n")
    nb = re.search(r"notBefore=(.*)", dec.stdout)
    na = re.search(r"notAfter=(.*)", dec.stdout)
    sig = re.search(r"Signature Algorithm:\s*(\S+)", dec.stdout)
    if nb:
        cert["validity"]["Not Before"] = nb.group(1).strip()
    if na:
        cert["validity"]["Not After"] = na.group(1).strip()
        try:
            from datetime import UTC, datetime
            end = datetime.strptime(na.group(1).strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
            days = (end - datetime.now(UTC)).days
            cert["days_remaining"] = days
            cert["expired"] = days < 0
        except ValueError:
            pass
    if sig:
        cert["signature_algorithm"] = sig.group(1)
    return cert


# --------------------------------------------------------------------------- #
# Lightweight service identification (fallback when nmap says "unknown")
# --------------------------------------------------------------------------- #
_MQTT_CONNECT = (b"\x10\x13\x00\x04MQTT\x04\x02\x00\x1e\x00\x07c3iscan")


def _recv_some(sock: socket.socket, limit: int = 512) -> bytes:
    try:
        return sock.recv(limit)
    except (TimeoutError, OSError):
        return b""


def _classify_banner(data: bytes) -> str | None:
    low = data.lower()
    if data.startswith(b"SSH-"):
        return "ssh"
    if data.startswith(b"220") and (b"ftp" in low or b"ftpd" in low):
        return "ftp"
    if data.startswith(b"220") and (b"smtp" in low or b"esmtp" in low):
        return "smtp"
    if data[:1] == b"\xff" or b"login:" in low or b"busybox" in low:
        return "telnet"
    if data.startswith(b"HTTP/"):
        return "http"
    if data.startswith(b"RTSP/"):
        return "rtsp"
    return None


def identify_service(host: str, port: int, timeout: float = 2.0) -> dict:
    """Classify one open TCP port with a few benign protocol greetings.

    Embedded services on non-standard ports are routinely left "unknown" by
    nmap, which hid Telnet/MQTT/HTTP exposure from the findings. Order: passive
    banner, TLS hello, HTTP GET, MQTT CONNECT. Returns ``{}`` when unsure -
    never a guess from the port number alone.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = _recv_some(sock)
            name = _classify_banner(banner)
            if banner and not name:
                # Greeting and login prompt often arrive in separate segments.
                sock.settimeout(0.7)
                banner += _recv_some(sock)
                name = _classify_banner(banner)
            if name:
                return {"service": name, "banner": banner[:120].decode("latin-1").strip(),
                        "method": "banner"}
    except OSError:
        return {}
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw, \
                ctx.wrap_socket(raw, server_hostname=None) as tls:
            return {"service": "https" if _http_speaks(tls, host) else "ssl",
                    "banner": tls.version() or "", "method": "tls-handshake"}
    except (OSError, ValueError):
        pass
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if _http_speaks(sock, host):
                return {"service": "http", "banner": "", "method": "http-get"}
    except OSError:
        pass
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_MQTT_CONNECT)
            ack = _recv_some(sock, 4)
            if len(ack) == 4 and ack[0] == 0x20 and ack[1] == 0x02:
                return {"service": "mqtt", "banner": f"CONNACK rc={ack[3]}",
                        "method": "mqtt-connect"}
    except OSError:
        pass
    return {}


def _http_speaks(sock, host: str) -> bool:
    try:
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        return sock.recv(16).startswith(b"HTTP/")
    except (TimeoutError, OSError):
        return False


# --------------------------------------------------------------------------- #
# Native MQTT anonymous-access probe (no mosquitto client needed)
# --------------------------------------------------------------------------- #
def mqtt_anonymous_probe(host: str, port: int, seconds: int = 5, timeout: float = 5.0) -> dict:
    """CONNECT without credentials, SUBSCRIBE to ``#`` and list observed topics.

    Read-only: nothing is published. ``connack`` is the broker's return code
    (0 accepted, 4 bad credentials, 5 not authorised).
    """
    out: dict = {"reachable": False, "connack": None, "anonymous": False, "topics": []}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        out["error"] = str(exc)
        return out
    with sock:
        sock.settimeout(timeout)
        try:
            sock.sendall(_MQTT_CONNECT)
            ack = _recv_some(sock, 4)
            if len(ack) < 4 or ack[0] != 0x20:
                out["error"] = "no MQTT CONNACK (not an MQTT 3.1.1 broker?)"
                return out
            out["reachable"] = True
            out["connack"] = ack[3]
            if ack[3] != 0:
                return out
            out["anonymous"] = True
            sock.sendall(b"\x82\x06\x00\x01\x00\x01#\x00")  # SUBSCRIBE "#" QoS0
            deadline = time.monotonic() + max(1, seconds)
            buf = b""
            topics: list[str] = []
            sock.settimeout(0.5)
            while time.monotonic() < deadline and len(topics) < 200:
                chunk = _recv_some(sock, 4096)
                if chunk:
                    buf += chunk
                buf = _mqtt_drain(buf, topics)
            out["topics"] = list(dict.fromkeys(topics))
            with contextlib.suppress(OSError):
                sock.sendall(b"\xe0\x00")  # DISCONNECT
        except OSError as exc:
            out["error"] = str(exc)
    return out


def _mqtt_drain(buf: bytes, topics: list[str]) -> bytes:
    """Consume complete MQTT packets from ``buf``; collect PUBLISH topic names."""
    while len(buf) >= 2:
        length, mult, idx = 0, 1, 1
        while True:
            if idx >= len(buf):
                return buf
            byte = buf[idx]
            length += (byte & 0x7F) * mult
            idx += 1
            if not byte & 0x80:
                break
            mult *= 128
            if idx > 4:
                return b""
        if len(buf) < idx + length:
            return buf
        body = buf[idx:idx + length]
        if buf[0] >> 4 == 3 and len(body) >= 2:
            tlen = int.from_bytes(body[:2], "big")
            topics.append(body[2:2 + tlen].decode("utf-8", errors="replace"))
        buf = buf[idx + length:]
    return buf


# --------------------------------------------------------------------------- #
# Wireless survey (access points / encryption)
# --------------------------------------------------------------------------- #
@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    channel: int | None = None
    signal_dbm: int | None = None
    encryption: str = "unknown"
    wps: bool = False
    frequency_mhz: int | None = None
    auth: list[str] = field(default_factory=list)      # PSK, SAE, 802.1X, OWE ...
    ciphers: list[str] = field(default_factory=list)   # CCMP, TKIP, GCMP ...
    pmf: str = "unknown"                               # required | capable | disabled | unknown
    hidden: bool = False

    def to_dict(self) -> dict:
        return {"ssid": self.ssid, "bssid": self.bssid, "channel": self.channel,
                "frequency_mhz": self.frequency_mhz,
                "signal_dbm": self.signal_dbm, "encryption": self.encryption,
                "auth": self.auth, "ciphers": self.ciphers, "pmf": self.pmf,
                "wps": self.wps, "hidden": self.hidden}


def _freq_to_channel(freq: int) -> int | None:
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return None


def parse_iw_scan(text: str) -> list[AccessPoint]:
    """Parse ``iw dev <if> scan`` output into access points with real security
    attributes: WPA generation, AKM suites, pairwise ciphers, PMF (802.11w)
    and WPS. Encryption is derived from the RSN/WPA elements and the Privacy
    capability bit - never assumed."""
    aps: list[AccessPoint] = []
    cur: AccessPoint | None = None
    state: dict = {}
    section = ""

    def finish() -> None:
        if cur is None:
            return
        rsn, wpa, privacy = state.get("rsn"), state.get("wpa"), state.get("privacy")
        auth = set(cur.auth)
        if rsn:
            if "SAE" in auth and "PSK" in auth:
                cur.encryption = "WPA2/WPA3-transition"
            elif "SAE" in auth:
                cur.encryption = "WPA3-SAE"
            elif "OWE" in auth:
                cur.encryption = "OWE (enhanced open)"
            elif any(a.startswith("IEEE 802.1X") or a == "802.1X" for a in auth):
                cur.encryption = "WPA2/3-Enterprise"
            else:
                cur.encryption = "WPA/WPA2-mixed" if wpa else "WPA2-PSK"
        elif wpa:
            cur.encryption = "WPA (legacy)"
        elif privacy:
            cur.encryption = "WEP"
        else:
            cur.encryption = "open"
        if rsn and cur.pmf == "unknown":
            cur.pmf = "disabled"
        cur.auth = sorted(auth)
        cur.ciphers = sorted(set(cur.ciphers))
        aps.append(cur)

    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"BSS ([0-9A-Fa-f:]{17})", s)
        if m:
            finish()
            cur = AccessPoint(ssid="<hidden>", bssid=m.group(1).upper(), hidden=True)
            state, section = {}, ""
            continue
        if cur is None:
            continue
        if s.startswith("SSID:"):
            name = s.split(":", 1)[1].strip()
            if name and not re.fullmatch(r"(\\x00)+", name):
                cur.ssid, cur.hidden = name, False
        elif s.startswith("freq:"):
            fm = re.search(r"(\d+)", s)
            if fm:
                cur.frequency_mhz = int(fm.group(1))
                if cur.channel is None:
                    cur.channel = _freq_to_channel(cur.frequency_mhz)
        elif s.startswith("signal:"):
            sm = re.search(r"(-?\d+(?:\.\d+)?)", s)
            if sm:
                cur.signal_dbm = int(float(sm.group(1)))
        elif s.startswith("DS Parameter set: channel") or s.startswith(("primary channel:",
                                                                        "* primary channel:")):
            cm = re.search(r"channel:?\s+(\d+)", s)
            if cm:
                cur.channel = int(cm.group(1))
        elif s.startswith("capability:"):
            state["privacy"] = "Privacy" in s
        elif s.startswith("RSN:"):
            state["rsn"], section = True, "rsn"
        elif s.startswith("WPA:"):
            state["wpa"], section = True, "wpa"
        elif s.startswith("WPS:"):
            cur.wps, section = True, "wps"
        elif s.startswith("* Authentication suites:") and section in ("rsn", "wpa"):
            cur.auth += s.split(":", 1)[1].split()
        elif s.startswith("* Pairwise ciphers:") and section in ("rsn", "wpa"):
            cur.ciphers += s.split(":", 1)[1].split()
        elif s.startswith("* Capabilities:") and section == "rsn":
            if "MFP-required" in s:
                cur.pmf = "required"
            elif "MFP-capable" in s:
                cur.pmf = "capable"
            else:
                cur.pmf = "disabled"
        elif re.match(r"[A-Za-z][\w /.-]*:", s) and not s.startswith("*"):
            section = ""
    finish()
    # "IEEE 802.1X" is split in two tokens by iw; normalise.
    for ap in aps:
        if "IEEE" in ap.auth:
            ap.auth = sorted({a for a in ap.auth if a not in ("IEEE", "802.1X")} | {"802.1X"})
            if ap.encryption in ("WPA2-PSK", "WPA/WPA2-mixed") and "PSK" not in ap.auth:
                ap.encryption = "WPA2/3-Enterprise"
    return aps


def wireless_survey(interface: str) -> tuple[list[AccessPoint], dict]:
    """Survey nearby APs. Returns ``(aps, meta)``.

    An active scan needs CAP_NET_ADMIN. Without it the kernel's cached scan
    table (``scan dump``) is used and the result is labelled as such; if
    neither works the module fails loudly - an unprivileged scan used to be
    reported as a clean "0 APs" site, which is a false negative.
    """
    if not has_tool("iw"):
        raise CapabilityUnavailable("iw is not installed; wireless survey cannot run.")
    res = run(["iw", "dev", interface, "scan"], timeout=60)
    meta = {"source": "active scan", "complete": True, "note": ""}
    text = res.stdout
    if res.returncode != 0:
        err = (res.stderr or "").strip()[:200]
        dump = run(["iw", "dev", interface, "scan", "dump"], timeout=30)
        if dump.returncode != 0 or "BSS " not in dump.stdout:
            raise CapabilityUnavailable(
                f"Wireless scan on {interface} failed ({err or 'no output'}). Run the backend "
                "with CAP_NET_ADMIN (root, or `setcap cap_net_admin,cap_net_raw+ep` on iw) "
                "and check the interface is up and not rfkill-blocked."
            )
        text = dump.stdout
        meta = {"source": "cached scan table (iw scan dump)", "complete": False,
                "note": f"Active scan refused ({err}); showing only BSSes the kernel already "
                        "knew about. This is NOT a full site survey - grant CAP_NET_ADMIN."}
    return parse_iw_scan(text), meta


def interfaces() -> list[dict]:
    if not has_tool("iw"):
        return []
    res = run(["iw", "dev"], timeout=15)
    out: list[dict] = []
    cur: dict = {}
    for line in res.stdout.splitlines():
        s = line.strip()
        m = re.match(r"Interface\s+(\S+)", s)
        if m:
            if cur.get("name"):
                out.append(cur)
            cur = {"name": m.group(1)}
        elif s.startswith("type "):
            cur["type"] = s.split(None, 1)[1]
        elif s.startswith("addr "):
            cur["address"] = s.split(None, 1)[1]
        elif s.startswith("channel "):
            cur["channel"] = s.split(None, 1)[1]
    if cur.get("name"):
        out.append(cur)
    return out


# --------------------------------------------------------------------------- #
# Default-credential probes (used by the ACTIVE module)
# --------------------------------------------------------------------------- #
def http_basic_probe(host: str, port: int, user: str, password: str, timeout: int = 8) -> dict:
    """Single HTTP Basic auth attempt, with a credential-free baseline.

    ``ok: True`` asserts the device *required* auth (baseline 401/403) and then
    accepted the given credential - a public 200 page without credentials is
    not a "default credentials accepted" match.
    """
    import base64

    import httpx

    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=False) as client:  # noqa: S501
            baseline = client.get(f"http://{host}:{port}/")
            resp = client.get(
                f"http://{host}:{port}/", headers={"Authorization": f"Basic {token}"}
            )
        baseline_status = baseline.status_code
        status = resp.status_code
        auth_required = baseline_status in (401, 403)
        accepted = auth_required and status < 400
        return {
            "ok": accepted,
            "status": status,
            "baseline_status": baseline_status,
            "auth_required": auth_required,
            "server": resp.headers.get("server", ""),
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


COMMON_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("root", "root"), ("root", "admin"), ("admin", ""), ("user", "user"),
    ("support", "support"), ("admin", "admin123"), ("guest", "guest"),
]
