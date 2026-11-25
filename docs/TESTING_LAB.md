# Test the platform: files, a local network target, and a camera

## 1. Test firmware supplied in this repository

Open **Firmware analysis**, upload `lab/fixtures/c3i-camera-lab.bin`, and run
**Full analysis**. This is a reproducible 4 MiB calibration image with a valid
uImage header, gzip/newc CPIO rootfs, a tar archive, dummy secrets, component
banners and a known high-entropy region. It is synthetic, not bootable camera
firmware and not an image to flash onto a device.

Expected results:
- component candidates: BusyBox 1.31.0, OpenSSL 1.0.2u, Dropbear 2019.78,
  dnsmasq 2.80, U-Boot 2020.01;
- secret-rule hits: password, API key, shadow hash;
- embedded gzip at offset 64, CPIO at 4096, tar at 262144;
- **Carve / extract** produces a downloadable `extracted_files.zip` with
  files such as `etc/camera.conf`, `etc/os-release`, `etc/versions`.

`lab/fixtures/manifest.json` contains the exact offsets and SHA-256 hashes of
the images and every rootfs file. Verify contents/hashes, not just a success banner.
The component names are test strings, not installed vulnerable executables.
CVE matches are candidates and depend on the cache/network; a version string
alone does not prove exploitability.

Also run:
- `clean-control.bin`: no intentional secret/component hits;
- `truncated-stream.bin`: a gzip signature may appear, but extraction must
  report the truncated stream rather than silently accept it;
- `camera-rootfs.tar`: test standalone archive recovery.

Regenerate from the repository root:

```bash
python3 lab/make_firmware.py
```

For a real production-image benchmark, obtain a **sysupgrade image from the
official OpenWrt download site** for a specific device and verify its published
SHA-256 before uploading it. This kit does not include a third-party vendor
image. Real SquashFS unpacking needs `unsquashfs` (`squashfs-tools` on Debian/
Ubuntu). UBI/UBIFS, encrypted updates, and proprietary containers need their
format-specific tooling; signature detection is not equivalent to unpacking.

## 2. Simulate an IoT camera's network services (IP-service simulator)

Run on the **same machine as the backend**:

```bash
python3 lab/network_simulator.py
```

This starts real TCP services on loopback:

| Port | Service | Deliberate lab weakness |
|---|---|---|
| 18080 | HTTP management UI | `admin:admin` HTTP Basic authentication |
| 18443 | HTTPS management UI | Self-signed TLS certificate |
| 18021 | FTP | Banner + accepts `USER` / `PASS` |
| 18022 | SSH | OpenSSH-style version banner |
| 18023 | Telnet | Login prompt and BusyBox shell banner |
| 18883 | MQTT 3.1.1 broker | Anonymous subscribe; sends a sample telemetry message |

No Wi-Fi adapter or Raspberry Pi is needed. Keep this terminal running.
Create an engagement named `Local camera lab` and authorize target `127.0.0.1`.
In **Module runner**, select **Wi-Fi / IP Network Audit** and try:

| Module | Parameters | Expected observation |
|---|---|---|
| `discovery` | `subnet=127.0.0.1/32` | Local host reachable |
| `portscan` | `host=127.0.0.1`, `ports=18021-18023,18080,18443,18883` | FTP, SSH, Telnet, HTTP, TLS and MQTT services; nmap needed |
| `tls_audit` | `host=127.0.0.1`, `port=18443` | TLS versions/certificate; self-signed lab certificate |
| `default_credentials` | `host=127.0.0.1`, `port=18080`, `usernames=[admin]`, `passwords=[admin]` | Baseline 401, authenticated 200; default-credential finding |
| `mqtt_audit` | `host=127.0.0.1`, `port=18883`, `seconds=3` | Anonymous subscription and `camera/telemetry` topic (built-in probe, no extra tool) |

`portscan` should report four exposure findings here (FTP, Telnet, HTTP, MQTT):
nmap labels the non-standard ports `unknown`, and the module's own probes
classify them. The banner services are
protocol-shaped test targets for fingerprinting, not full FTP/SSH/Telnet servers.

Open **Findings**, inspect the evidence and remediation, then **Evidence &
reports** to export. Ctrl+C stops the simulator. `--no-tls` skips the HTTPS
listener; `--no-services` skips the FTP/SSH/Telnet/MQTT ports. Nothing in this
simulator modifies a real device.

This is **IP-service simulation**, not a radio/access-point simulator. It cannot
validate `wireless_survey`, monitor-mode capture, channel switching or deauth.
For those, use your own isolated AP and a Linux-supported Wi-Fi adapter. An
advanced no-RF alternative is a Linux VM with `mac80211_hwsim` and `hostapd`;
the backend and virtual interfaces must live in that same VM. `sudo lab/wifi_hwsim_lab.sh up` builds it (a weak WPA/WPA2+WPS AP, an open AP and
a spare scanner radio) and `down` removes it; the manual recipe is in
[WIFI_HWSIM_LAB.md](WIFI_HWSIM_LAB.md). OS fingerprinting on loopback
identifies the host OS, not a simulated camera OS.

## 3. What hardware is needed?

| Task | Minimum equipment | Direct laptop? | Raspberry Pi? |
|---|---|---|---|
| Firmware file analysis | Firmware file + Linux host | Yes | Optional |
| IP/TLS/HTTP assessment | Network connection + owned target/AP | Yes | Optional |
| Bluetooth discovery/profile | BlueZ-supported BT adapter + target | Yes | Built-in/USB adapter |
| Wireless survey/capture | Compatible Wi-Fi adapter; monitor mode for raw capture | Yes | USB adapter preferred for capture |
| UART console / partition dump | Voltage-compatible USB–TTL adapter, leads, multimeter, target supply | **Yes** | USB adapter or Pi UART |
| SPI NOR identity/read | Supported programmer, matching clip/probes, correct voltage/level adapter | CH341A/FT2232 | `linux_spi` via spidev |
| I2C scan/EEPROM dump | USB I2C adapter or Pi I2C header, pull-ups, `i2c-tools` | USB adapter | **Yes** |
| Logic capture/decode | $10–$30 USB logic analyzer supported by sigrok + `sigrok-cli` | **Yes** | Yes (USB) |
| Automated power cycling | Pi, suitable driver/relay, external supply | Backend must run on controller | Yes |
| Precise voltage fault injection | Dedicated glitch hardware + scope, characterized power path | Specialist setup | Pi GPIO timing is not precision glitch equipment |

Good starter kit: Linux laptop, CP2102/FT232 USB–TTL adapter with verified
3.3 V logic, multimeter, jumper/probe leads, own camera/router, and its original
power supply. Add a Pi only when GPIO automation is needed.

### Direct connection

```text
Laptop running backend ─ USB ─ USB–TTL adapter
                                  TX  ─── camera RX
                                  RX  ─── camera TX
                                  GND ─── camera GND
                                  VCC     disconnected
Camera ─ original/external regulated supply
```

Identify the pads and measure logic voltage before connecting. UART can be
1.8 V or 3.3 V; TTL UART is not RS-232. A supply-voltage jumper does not always
change an adapter's signal voltage. Connect with power off, then power the
camera normally. Use `/dev/serial/by-id/...` where possible, or `/dev/ttyUSB0`.
Only one process can use a UART at a time; close other serial terminals first.

### Raspberry Pi as the bench controller

```text
Laptop browser ─ Ethernet/Wi-Fi ─ Raspberry Pi running backend
                                      ├ USB–TTL or GPIO UART ─ camera
                                      ├ SPI programmer/spidev ─ flash
                                      └ GPIO driver ─ power relay
```

Open `http://<pi-address>:8080` on the laptop. Hardware attaches to the
**backend host**, not the browser host. There is no automatic remote GPIO
agent on a Pi when the backend still runs on the laptop.

Pi UART: physical pin 8 / BCM14 TX → DUT RX; pin 10 / BCM15 RX ← DUT TX;
ground → DUT ground. Disable the Pi serial login console and enable its UART.
Pi GPIO is 3.3 V and not 5 V tolerant. Leave DUT VCC off the Pi header.
See [HARDWARE_SETUP.md](HARDWARE_SETUP.md) for the full pin map.

## 4. Board-level recon (SPI / I2C / logic)

These are the practical additions for a real bench. Start read-only, keep the
probe ground connected, and never connect a powered target's flash while the
target is on.

### 4.1 SPI flash identity (before any dump)

Run **Hardware workbench → Board-level recon → SPI flash identity** (or
`hardware.spi_identify`) with the programmer selected:

- `linux_spi` on a Pi with the flash on the SPI header;
- `ch341a_spi` or `ft2232_spi` from a laptop with a voltage-compatible clip.

It reads `--flash-name`, `--flash-size` and `--wp-status` only. Confirm the
reported vendor/chip matches the package marking and check the write-protection
mode. A disabled status register is a real finding, but secure boot may still
prevent modified firmware from running. Only then use `spi_dump`.

### 4.2 I2C scan and EEPROM-style dump

Install `i2c-tools`, connect SDA/SCL/GND (3.3 V logic, common ground), then run
`hardware.i2c_scan` with `action=scan`, `bus=1`. If an EEPROM/SPD candidate at
`0x50`–`0x57` appears, switch to `action=dump`, `address=80` (the UI accepts the
decimal form; the module reports `0x50`). The dump is 256 bytes and read-only,
but some devices dislike repeated reads: use only on your target.

### 4.3 Logic-analyzer capture

A low-cost FX2-based analyzer plus `sigrok-cli` is enough for 3.3 V UART, SPI
and I2C. Wire the analyzer's ground to the target ground and clip the channels
to the signals **without driving them**. In `hardware.logic_capture`:

- `driver=fx2lafw` for many $10 analyzers (use `sigrok-cli --scan` to confirm);
- `channels=D0,D1,...` for the connected channels;
- `protocol=uart`, `baudrate=115200`, `rx=D0` (add `tx` for the other direction);
- or `protocol=spi` with `clk/mosi/miso/cs`, or `protocol=i2c` with `scl/sda`;
- `sample_rate` at least 10× the signal rate (1 MHz is a good UART default);
- `duration_s` short (2–5 s) for the first capture.

The decoded transcript is saved as evidence. No frames usually means a channel
mapping, ground, voltage or baud-rate problem, not "no traffic".

## 5. Camera extraction workflow

UART connection alone does not provide a filesystem. You need an accessible
Linux shell (already open or with known credentials), readable partition nodes,
and `dd` and `base64` on the camera. A bootloader-only prompt, locked login,
encrypted flash, or NAND requiring ECC/OOB handling needs a different acquisition
method. This flow does not bypass secure boot or unlock a camera.

1. Export `UART_PORT=/dev/ttyUSB0` in the shell that starts the backend (or set
   it in the service environment). For `serial_exec` and `filesystem_dump`, the
   `port` field can also select it explicitly.
2. Add that **exact serial path** to an engagement's authorized targets and sign
   the RoE. `serial_exec` and `filesystem_dump` are active modules.
3. Use `detect_baud` without automatic power cycles for a USB-only setup, or
   use the known baud (often 115200). Inspect `uart_console` output.
4. In `serial_exec`, use known credentials if needed and a diagnostic command
   such as `cat /proc/mtd`. This is a real shell command, not a terminal emulator.
5. Run `filesystem_dump` with `list_only=true` to inspect the partition map.
6. Choose an unambiguous partition name, e.g. `rootfs`, set `list_only=false`,
   and allow enough time. For eMMC nodes not in `/proc/mtd`, supply `device`
   and the independently known `expected_size` in bytes.
7. Download the `.bin`, then use **Firmware analysis → Carve / extract**.
   Download `extracted_files.zip` and inspect recovered files. For deeper
   string analysis of compressed data, submit the recovered file separately.

### 5.1 Complete acquisition (not just one partition)

- **Every partition at once:** run `filesystem_dump` with `all_partitions=true`.
  It streams each `/proc/mtd` partition to its own image and returns a manifest
  (name, size, SHA-256, ok/partial). This is the complete block-level dump.
- **Running device with NAND/UBI/overlay:** a block `dd` of a NAND `mtdblock`
  is not meaningful. Use `rootfs_archive` to `tar` the *mounted* filesystem
  (overlay and tmpfs included) — `transport=serial` (base64 over UART) or, if
  the camera has an IP, `transport=netcat` with `host_ip` set, which is far
  faster (the camera pushes `tar | nc` to the testbed host's built-in listener).
- **Storage attached to the PC directly:** if the camera exposes USB
  mass-storage, or you move its SD/eMMC into a reader, run `host_block_acquire`
  — pick the `/dev/sd*`/`/dev/mmcblk*` node (`list_only=true` first), retype it
  into `confirm`, and it images the device **read-only** (it refuses the host's
  own system disks and never mounts the target).
- **Android-based device:** with USB debugging on, `adb_acquire` tars `/system`,
  `/vendor`, etc. off the device.

See the full **method matrix** (which method for which wiring/state, plus the
exact device-side commands and limits) in
[HARDWARE_SETUP.md §7](HARDWARE_SETUP.md#7-complete-filesystem-acquisition--method-matrix).

Base64 over 115200 baud carries at most about **8.4 KiB/s** after encoding
and line overhead: a 16 MiB partition takes roughly **33 minutes or longer**.
Choose a sufficient `timeout_s` (up to 7200). Partial, corrupt, and size-mismatched
transfers are reported as incomplete. The saved SHA-256 identifies the local
artefact; verify it against a device-side checksum for acquisition integrity.

These paths are fixture-tested. Actual camera models, UART adapters, SPI chip
voltages, and Pi GPIO must still be validated on your bench.

## 6. Bluetooth distance reading

The Bluetooth `link_rtt` result now includes a **coarse distance estimate** in
the UI card labelled *Estimated distance*. It is computed from the device's
current RSSI (read from BlueZ) using a log-distance path-loss model; the RTT
itself is not used for distance because Bluetooth baseband scheduling dominates
it.

- Default 1 m reference: **−59 dBm** (a typical BLE value, not the advertised
  `TxPower`).
- Default path-loss exponent: **2.5** indoor (2.0 free space, ~3.0 obstructed).
- The card shows the point estimate, a plausible range from varying `n` by
  ±0.5, the RSSI, the reference and the confidence.
- A single sample is inherently noisy. For a better result, measure RSSI at
  1 m in the same environment and pass it as `reference_rssi_dbm`; the
  confidence becomes `medium` (never `high`).
- If BlueZ does not expose RSSI, the card says **No RSSI estimate** instead of
  inventing a number. Use `scan`/`profile` first or supply `rssi_dbm`.
- For precise ranging use UWB/time-of-flight or a calibrated multi-anchor
  survey. Bluetooth RSSI is not a tape measure.

## 6a. Bluetooth targets and host setup

There is no loopback Bluetooth simulator: BlueZ cannot be scanner and target on
one controller. Use a second device you own as the target:

- **Phone:** nRF Connect -> *Configure GATT server* + *Advertiser* gives a BLE
  peripheral with characteristics you define (make one writable without
  encryption to see the `gatt_enum` open-write finding).
- **ESP32 dev board:** flash [`lab/esp32_ble_target`](../lab/esp32_ble_target/README.md),
  a deliberately weak "smart lock" with one open-write, one leaky open-read and
  one encryption-protected characteristic, plus the expected result per module.

Flow: `scan` -> note the address -> `profile`, `le_security`, `gatt_enum`,
`gatt_firmware`. Parsing logic is covered offline by
`tests/test_radio_hardening.py` and `tests/test_bluetooth_fingerprints.py`.

The GATT modules import `dbus` (dbus-python). The venv must be able to see it:
create it with `python -m venv --system-site-packages .venv` after installing
the distro package (`python-dbus` on Arch, `python3-dbus` on Debian), or
`pip install dbus-python`. `python -m app.cli doctor` shows `bt.dbus`.

## 7. Developer verification

```bash
cd backend
../.venv/bin/python -m pytest -q
```

The suite uses fake serial devices, archive fixtures, and loopback HTTP/TCP targets.
It must not power-cycle the real rig or transmit test frames during regression runs.

The acquisition paths added for complete filesystem extraction are covered by
`tests/test_acquisition.py`, entirely offline:

- **dump-all** — a multi-partition emulated `/proc/mtd` console; asserts one
  image per partition and a manifest with matching sizes/hashes.
- **rootfs_archive** — an emulated shell that answers `tar … | base64`; the test
  gunzips the recovered payload and lists the tar members.
- **netcat exfil** — a real loopback socket pushes bytes to the built-in
  receiver; asserts byte-exact capture and SHA-256.
- **host_block_acquire** — a monkeypatched `dd` images a temp file; asserts the
  hash, and that a host **system disk is refused** and a non-block node rejected.
- **adb** — a stubbed `adb` validates tar capture, the no-device path, and
  `adb devices` parsing.
