# Security Tools & Libraries

This page lists **every external security tool and library** the testbed uses,
what it does, which module calls it, and the licence. This matters commercially:
clients ask "what are you running against my device?", and the answer should be
exact.

> **Licensing note for commercial sale.** The proprietary code in this repository
> never *links* against these tools — it invokes them as separate OS processes
> (fork/exec) and parses their output. GPL-family tools are therefore used as
> independent programs, which is the conventional arrangement for scanners like
> this. If you redistribute the tools *bundled* with the product, review each
> licence (column 5). Where a permissive alternative exists it is marked
> *alternative*.

## 1. Network / Wi-Fi domain

| Tool | Role | Used by | Invocation | Licence |
|---|---|---|---|---|
| **nmap** | Port/service/version discovery, host sweep, OS detection | `wifi.portscan`, `wifi.discovery`, `wifi.os_fingerprint` | `nmap -sT -sV -oX -` | NPSL (GPL-derived) |
| **ping** | TTL probe → coarse OS guess | `wifi.os_fingerprint` | `ping -c 2` | iputils (GPL) |
| **openssl** | TLS version/cipher enumeration + certificate inspection | `wifi.tls_audit` | `openssl s_client -tls1_2 …` | Apache-2.0 |
| **iw** | Wireless survey (APs, encryption, WPS) | `wifi.wireless_survey` | `iw dev <if> scan` | GPL-2.0 |
| **tcpdump** | Packet capture to PCAP | `wifi.traffic_capture` | `tcpdump -i <if> -w …` | BSD-3 |
| **tshark** (Wireshark) | Packet decoding / field extraction | `wifi.traffic_capture`, `bluetooth.capture_audit` | `tshark -T fields -e data.data` | GPL-2.0 |
| **mosquitto_pub/sub** | MQTT broker exposure (anonymous subscribe) | `wifi.mqtt_audit` | `mosquitto_sub -t '#'` | EPL-2.0 / BSD |
| **aircrack-ng** (`airmon-ng`, `aireplay-ng`) | Bounded de-authentication validation (gated) | `wifi.deauth_test` | `aireplay-ng --deauth N` | GPL-2.0 |
| **httpx** (Python) | HTTP Basic auth probing for default credentials | `wifi.default_credentials` | in-process | BSD-3 |

## 2. Bluetooth / BLE domain

| Tool | Role | Used by | Invocation | Licence |
|---|---|---|---|---|
| **BlueZ `bluetoothctl`** | Classic + LE discovery, device attributes (class, paired, UUIDs) | `bluetooth.scan`, `bluetooth.profile` | `bluetoothctl --timeout N scan on` | GPL-2.0 |
| **BlueZ D-Bus API** | GATT Device Information Service read (firmware/model) | `bluetooth.gatt_firmware` | `python-dbus` → `org.bluez.GattCharacteristic1.ReadValue` | GPL-2.0 (BlueZ) / MIT (dbus-python) |
| **`gatttool`** | DIS read fallback for older BlueZ | `bluetooth.gatt_firmware` | `gatttool --char-read -u 2a26` | GPL-2.0 |
| **`btmgmt`** | Local adapter public-address change (impersonation test, gated) | `bluetooth.mac_spoof` | `btmgmt public-addr …` | GPL-2.0 |
| **`l2ping`** | L2CAP echo → RTT, packet loss, bounded link stress (gated); RSSI for coarse distance comes from BlueZ, not RTT | `bluetooth.link_rtt`, `bluetooth.link_stress` | `l2ping -c N -s B` | GPL-2.0 (bluez-tools) |
| **tshark** | Capture-based encrypted-vs-plaintext verification | `bluetooth.capture_audit` | `tshark … -e data.data` | GPL-2.0 |

## 3. Hardware testbed domain (Raspberry Pi rig)

| Tool | Role | Used by | Invocation | Licence |
|---|---|---|---|---|
| **pyserial** | UART read/write (baud detection, boot log, console, shell commands, partition dump) | `hardware.detect_baud`, `capture_bootlog`, `uart_console`, `serial_exec`, `filesystem_dump` | in-process | BSD-3 |
| **rpi-lgpio / libgpiod** | GPIO for relay, optocoupler, and glitch pulse train | `hardware.power_control`, `voltage_glitch` | in-process | LGPL-3 / LGPL-2.1 |
| **flashrom** | Read-only SPI identity/capacity/write-protection state; SPI flash read-out | `hardware.spi_identify`, `hardware.spi_dump` | `flashrom -p <programmer> --flash-name/--flash-size/--wp-status/-r` | GPL-2.0 |
| **i2c-tools** (`i2cdetect`, `i2cdump`) | I2C bus inventory and bounded address dump | `hardware.i2c_scan` | `i2cdetect -y -r <bus>`, `i2cdump -y -r <bus> <addr>` | GPL-2.0 |
| **sigrok-cli** | Passive logic capture + UART/SPI/I2C protocol decode | `hardware.logic_capture` | `sigrok-cli -d <driver> --channels … -P uart:…` | GPL-3.0 |
| **usbutils / util-linux** | Debug-probe and block-device inventory (no writes) | `hardware.hardware_info` | `lsusb`, `lsblk -J` | GPL-2.0 / GPL-2.0 |
| *(built-in)* | Baud scorer, boot-log rule engine, bounded glitch loop, boot-chain string audit | hardware/firmware modules | in-repo Python | proprietary |

## 4. Firmware static-analysis domain

| Tool | Role | Used by | Invocation | Licence |
|---|---|---|---|---|
| **binwalk** | Signature scanning + filesystem carving | `firmware.analyse`, `firmware.extract` | `binwalk -e --directory …` | MIT |
| **strings** (binutils) | Printable-string harvest from images | `firmware.secrets`, `firmware.sbom` | `strings -n 5` | GPL-3 |
| **readelf/objdump** | Binary inspection (capability probe) | firmware helpers | `objdump`/`readelf` | GPL-3 |
| *(built-in)* | ShannonEntropy profiler, secret regex rules, component/SBOM matcher, default-credential candidate detector, secure-boot/debug-lock string audit | `firmware.entropy`, `secrets`, `sbom`, `boot_chain` | in-repo Python | proprietary |

## 5. Vulnerability intelligence

| Source | Role | Licence/terms |
|---|---|---|
| **NVD 2.0 API** (`services.nvd.nist.gov`) | Canonical CVE records, CVSS, CPE | US Gov public domain; rate-limited (5/30 s, 50 with API key) |
| **OSV.dev API** | Ecosystem advisories / patch info | Apache-2.0 (API: open) |
| **EPSS** (`api.first.org`) | Exploit Prediction Scoring (probability + percentile) | Free, attribution requested |
| *(built-in)* | SQLite FTS5 offline cache + severity/risk scoring | proprietary |

## 6. Platform libraries (backend)

| Library | Role | Licence |
|---|---|---|
| **FastAPI** | HTTP API framework | MIT |
| **Uvicorn** | ASGI server | BSD-3 |
| **SQLAlchemy 2** | ORM / database | MIT |
| **Pydantic v2** | Validation + auto-generated UI schemas | MIT |
| **PyJWT** | JWT access tokens | MIT |
| **httpx** | Async HTTP client (NVD/OSV/EPSS, probes) | BSD-3 |
| **ReportLab** | PDF report generation | BSD-3 |
| *(stdlib)* | PBKDF2-HMAC-SHA256 password hashing, HMAC RoE signing | PSF |

## 7. Console (web)

| Library | Role | Licence |
|---|---|---|
| **React 18** | UI | MIT |
| **Vite** | Build tooling | MIT |
| **TypeScript** | Type safety | Apache-2.0 |
| **Tailwind CSS** | Styling | MIT |
| **TanStack Query** | Data fetching/caching | MIT |
| **lucide-react** | Icons | ISC |

## 8. Optional

| Tool | Role | Licence |
|---|---|---|
| **Ollama** + a model (e.g. `qwen2.5:3b`) | Local AI assistant (optional) | MIT |
| **ChromaDB** | Vector store for the assistant | Apache-2.0 |

## 9. What the testbed does **not** do

Deliberately excluded, because they are unreliable, non-reproducible, or create
legal exposure that a client-facing product should not carry:

- Unbounded DoS / RF jamming.
- Mass credential brute-forcing (only small, bounded, in-scope default-credential checks).
- Any exploit that permanently modifies or bricks the target without explicit written consent.

Bounded, reversible equivalents are provided behind the Rules-of-Engagement gate
instead (see `docs/SECURITY_AND_ETHICS.md`).
