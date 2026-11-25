# Methodology

The testbed operationalises the C3i Hub / IIITA research programme and extends
it into one tool. Three reference works frame the design:

1. **Automated Hardware Auditing Testbed for UART and SPI based IoT Devices**
   (IOTSMS 2023, C3i Hub — the source of the Raspberry Pi + voltage-glitcher
   rig).
2. **A comprehensive Bluetooth security audit framework for IoT devices**
   (Computers & Security 164, 2026 — device profiling, OS/firmware
   identification, encryption verification, CVE mapping, penetration tests).
3. **IoT device security audit tools: a layered architecture approach**
   (Int. J. Information Security 24, 2025 — the seven-layer threat model and
   the argument that no single existing tool covers the stack).

## 1. Unified seven-layer threat model

The Wi-Fi testbed slides and the layered-architecture paper define the layers we
audit. Each layer maps to concrete modules in this testbed.

| Layer | Threat examples | Testbed modules |
|---|---|---|
| **Application** | brute-force, injection, reverse shells | `wifi.default_credentials`, `firmware.secrets` |
| **Session** | protocol downgrade, unauthenticated MQTT/CoAP | `wifi.tls_audit`, `wifi.mqtt_audit` |
| **Network** | mesh attacks, MAC tracking, injection | `wifi.discovery`, `wifi.portscan`, `wifi.traffic_capture` |
| **OS** | privilege escalation, OS fingerprinting | `wifi.os_fingerprint`, `bluetooth.profile` |
| **Firmware** | hard-coded creds, unsigned boot, OTA injection, known CVEs | `firmware.analyse`, `firmware.boot_chain`, `bluetooth.gatt_firmware`, `hardware.capture_bootlog` |
| **Memory** | cleartext dumps, buffer overflows | `hardware.spi_identify`, `hardware.spi_dump`, `hardware.filesystem_dump`, `firmware.entropy` |
| **Physical/Interface** | UART/JTAG/I2C access, bootloader breakout, glitching | `hardware.uart_console`, `hardware.i2c_scan`, `hardware.logic_capture`, `hardware.detect_baud`, `hardware.voltage_glitch` |

## 2. Hardware phase (the physical rig)

Follows the paper's flow:

1. **Identify interfaces** (manual): examine the PCB for UART (4-pin) and SPI
   (8-pin/SOIC8) pads.
2. **Interface**: connect the Pi's UART (BCM14/15) and an SPI flash clip.
3. **Power-based attacks**: drive the relay/optocoupler to cycle power and to
   inject glitches.
4. **Recon**: `detect_baud` → `capture_bootlog` / `uart_console`; identify SPI
   flash read-only (`spi_identify`), scan I2C (`i2c_scan`) or passively decode a
   bus (`logic_capture`).
5. **Extract**: `filesystem_dump` over UART or `spi_dump` after identity checks.
6. **Analyse**: boot-log rules + CVE mapping; firmware entropy/secrets/SBOM and
   the `boot_chain` secure-boot/debug-lock audit.

The baud detector brute-forces candidate rates and scores captured output by
printable ratio, volume, and the presence of boot keywords (`U-Boot`,
`Linux version`, `Starting kernel`, …) — the same principle as the paper's
module, made deterministic and bounded.

## 3. Bluetooth phase

Mirrors and extends the Bluetooth audit framework:

| Framework capability | Module |
|---|---|
| Device profiling / behavioural analysis | `bluetooth.scan` |
| OS type & version identification | `bluetooth.profile` |
| Firmware identification (GATT DIS + fallback) | `bluetooth.gatt_firmware` |
| Encrypted-communication verification | `bluetooth.capture_audit` |
| CVE mapping | `bluetooth.cve_lookup`, `gatt_firmware` |
| Distance / link quality | `bluetooth.link_rtt` (RTT for quality; RSSI log-distance for a coarse range with uncertainty) |
| Penetration testing (resilience) | `bluetooth.link_stress`, `bluetooth.mac_spoof` (gated) |

Firmware identification uses the **Device Information Service** (0x2A24–0x2A29,
0x2A50) over the BlueZ D-Bus GATT API, with `gatttool` as a fallback — the
"dual-mode" approach the paper describes.

## 4. Wi-Fi / IP phase

Covers the network/session/OS layers, and — importantly — closes the gaps the
legacy tool left open:

- The legacy "firmware extraction over Wi-Fi" was string-mining a pcap. Here,
  `wifi.traffic_capture` explicitly does **traffic capture + encryption
  verification + version-hint extraction**, and any real firmware image is
  pushed through the `firmware` domain.
- The legacy deauth implementation was stubbed. Here it is a real, **bounded**
  (≤20 frames), reversible test behind the RoE gate.

## 5. Static firmware phase

`binwalk` signatures → entropy profile → `strings` harvest → secret rules
(private keys, cloud keys, password assignments, shadow hashes) → component
inventory (BusyBox, OpenSSL, dropbear, lighttpd, …) → CVE mapping via NVD/OSV,
enriched with EPSS.

## 6. Risk scoring

Per-finding severity is normalised from CVSS (critical ≥ 9.0, high ≥ 7.0,
medium ≥ 4.0, low > 0). Engagement risk is a diminishing-returns roll-up of
weighted severities, capped at 100, so many low findings never mask one critical.

## 7. Evidence & reproducibility

Every physical or intrusive action records its parameters (baud, pulse widths,
frame counts, target, scope) and a content-hashed artefact, so a finding can be
reproduced and defended in a client report.
