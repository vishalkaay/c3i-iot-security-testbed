# Module Reference

36 modules across four domains. **Safety**: P = passive, A = active (RoE),
I = invasive (RoE + host switch).

## Bluetooth (`bluetooth`)

| Module | Safety | Capability | What it does |
|---|---|---|---|
| `scan` | P | bluez | Discover classic + LE devices over BlueZ D-Bus (live RSSI, address type, manufacturer data; CLI fallback); fails loudly if no powered adapter; flags strong unnamed devices; adds manufacturer/class OS hints. |
| `profile` | P | bluez | SDP/class + manufacturer-data evidence; infers OS family/version with confidence; flags pairing hygiene. |
| `gatt_firmware` | P | bluez D-Bus | Reads Device Information Service; maps firmware/model to CVEs. |
| `gatt_enum` | P | bluez D-Bus | Walks the full GATT table; reads declared-readable values (bounded). A read rejected for security is classified PROTECTED; declared writes are reported as unverified (no write is performed). |
| `le_security` | P | bluez | Address privacy (public vs random), pairing/bonding state, services exposed while unpaired. |
| `link_rtt` | P | l2ping | L2CAP echo RTT + packet delivery; coarse RSSI log-distance range with a plausible interval and explicit caveat (RTT itself is not used for distance); link-quality findings. |
| `capture_audit` | P | tshark | Encrypted-vs-plaintext verdict + version hints + CVE mapping from a capture. |
| `cve_lookup` | P | — | Map OS/firmware tokens to CVEs (offline-first). |
| `link_stress` | **I** | l2ping | Bounded (≤1000 pkt) L2CAP echo load; verdict `resilient` / `degraded` / `not_tested` (no reply is never reported as degradation); always stops. |
| `mac_spoof` | **I** | bluez | Change local adapter address, then restore; tests impersonation resistance. |

## Wi-Fi / IP (`wifi`)

| Module | Safety | Capability | What it does |
|---|---|---|---|
| `discovery` | P | nmap | Host sweep to inventory the device mesh. |
| `portscan` | P | nmap | Bounded service/version scan; ports nmap leaves `unknown` are classified by benign banner/TLS/HTTP/MQTT probes; flags dangerous services; version→CVE mapping. |
| `os_fingerprint` | P | nmap | TTL heuristic + optional nmap `-O`. |
| `tls_audit` | P | openssl | Enumerates TLS versions/ciphers; flags TLS ≤1.1, self-signed, expired, <2048-bit and MD5/SHA-1-signed certificates. |
| `wireless_survey` | P | iw (CAP_NET_ADMIN) | Nearby APs with WPA generation, AKM (PSK/SAE/802.1X/OWE), ciphers, 802.11w/PMF and WPS; flags open, WEP, TKIP/WPA1, PMF-off, WPS. Without privilege it uses the cached scan table and marks the result INCOMPLETE. |
| `mqtt_audit` | P | — | Built-in read-only MQTT 3.1.1 probe: anonymous CONNECT + wildcard subscribe, reports CONNACK code and sampled topics. |
| `traffic_capture` | P | tcpdump+tshark | Captures N seconds, verifies encryption, mines version hints + CVEs. |
| `default_credentials` | **A** | — | Bounded default-credential test on an HTTP UI. |
| `deauth_test` | **I** | iw/aircrack | ≤20 deauth frames; detects missing 802.11w; always restores the interface. |

## Hardware testbed (`hardware`)

| Module | Safety | Capability | What it does |
|---|---|---|---|
| `hardware_info` | P | — | Rig diagnostics: GPIO backend, serial ports, readiness. |
| `detect_baud` | **A** | serial+GPIO | Auto-discovers the UART baud rate by scoring boot output. |
| `capture_bootlog` | **A** | serial | Power-cycles the DUT, captures + analyses the boot log, maps CVEs. |
| `uart_console` | **A** | serial | Detects console/login/bootloader; optional safe U-Boot breakout. |
| `serial_exec` | **A** | serial | Execute a bounded command on an existing shell or log in with supplied credentials. |
| `filesystem_dump` | **A** | serial | Enumerate /proc/mtd and recover a selected partition over base64/UART; preserve incomplete evidence. |
| `power_control` | **A** | GPIO | Manual relay/optocoupler on/off/cycle. |
| `spi_identify` | **A** | flashrom | Read-only JEDEC identity, capacity and status-register write-protection state before dumping. |
| `i2c_scan` | **A** | i2c-tools | Scan an I2C bus or read 256 bytes from one address; flags EEPROM/SPD candidates. |
| `logic_capture` | **A** | sigrok-cli | Passive bounded capture + UART/SPI/I2C decode from a USB logic analyzer; saves the decoded transcript. |
| `spi_dump` | **I** | flashrom | Reads via Pi linux_spi, CH341A or FT2232; hands the image to the firmware domain. |
| `voltage_glitch` | **I** | GPIO | Bounded glitch pulse train (≤5000 pulses, ≤60 s); always restores power. |

## Firmware (`firmware`)

| Module | Safety | What it does |
|---|---|---|
| `analyse` | P | End-to-end: binwalk/carve signatures, entropy, secrets, components, defaults, CVEs. |
| `extract` | P | binwalk or built-in bounded gzip/CPIO/tar/ZIP carving; downloadable extracted-files ZIP. SquashFS unpacking requires unsquashfs. |
| `entropy` | P | Per-block entropy (encryption/compression detection). |
| `secrets` | P | Private keys, cloud keys, password assignments, shadow hashes. |
| `sbom` | P | Component inventory + CVE mapping. |
| `boot_chain` | P | Static secure-boot evidence: signed FIT/AVB/dm-verity, root-of-trust/fuse, anti-rollback, debug locks; reports gaps without claiming hardware proof. |
| `bootlog` | P | Analyse boot-log text/upload with the UART engine. |

## Capabilities legend

`os.linux`, `hw.raspberry_pi`, `hw.gpio`, `hw.serial`, `hw.spi`, `hw.i2c`,
`hw.i2c_tools`, `hw.logic_analyzer`, `bt.bluez`, `bt.dbus`, `bt.l2ping`,
`bt.hcitool`, `net.tshark`, `net.tcpdump`, `net.nmap`, `net.openssl`,
`net.wireless_cli`, `net.aircrack`, `net.mosquitto_cli`, `fw.binwalk`,
`fw.flashrom`, `fw.strings`, `fw.objdump`.

The console shows, per module, which of these are present on the host and what
to install if not (`GET /api/v1/plugins`).
