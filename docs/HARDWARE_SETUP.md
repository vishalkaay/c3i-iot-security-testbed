# Hardware Testbed Setup (Raspberry Pi 5)

Derived from the C3i Hub IOTSMS-2023 testbed. Wire **with the DUT powered off**.

For direct laptop/USB operation, the camera UART workflow, and a minimal shopping
list, see [TESTING_LAB.md](TESTING_LAB.md). A Pi is optional for USB serial/SPI
and firmware/IP testing; it provides GPIO-based bench automation.

## 1. Bill of materials

| Item | Purpose |
|---|---|
| Raspberry Pi 5 (4/8 GB) | controller + web UI |
| microSD / NVMe | OS + data |
| 2-channel relay board (or 8-channel) | power ON/OFF switching |
| Optocoupler module (fast switch) | glitch / fast power cycling |
| LM317 + LM7805/LM7812 regulators, or bench PSU | supply target voltage |
| USB-TTL adapter (CP2102/FT232/CH340) | UART (alternative to Pi UART) |
| SPI flash clip (SOIC8) | firmware extraction |
| USB logic analyzer (FX2/Saleae-compatible) | passive UART/SPI/I2C decode with `sigrok-cli` |
| USB I2C adapter or Pi I2C header | bus scan / EEPROM dump with `i2c-tools` |
| Jumper wires, common GND | interconnect |

> Power the DUT from
> the regulated/bench supply through the relay/optocoupler — **never** from the
> Pi header when the DUT has LEDs, radios, or motors.

## 2. Pin map (BCM numbering, 3.3 V logic — not 5 V tolerant)

| Signal | BCM | Physical pin | Connects to |
|---|---|---|---|
| UART TX | 14 | 8 | DUT RX |
| UART RX | 15 | 10 | DUT TX |
| GND | — | 6/9/14/25/… | DUT GND (**must be common**) |
| Relay power | 6 | 31 | relay IN1 |
| Optocoupler power | 22 | 15 | optocoupler IN |
| Glitch channel | 26 | 37 | channel select |
| Glitch trigger | 20 | 38 | fast pulse trigger |
| SPI MOSI | 10 | 19 | flash pin 5 (DI) |
| SPI MISO | 9 | 21 | flash pin 2 (DO) |
| SPI SCLK | 11 | 23 | flash pin 6 (CLK) |
| SPI CE0 | 8 | 24 | flash pin 1 (/CS) |
| 3V3 | — | 1/17 | flash pin 8 (VCC)* |
| GND | — | 25 | flash pin 4 (GND) |

\* Prefer an external 3.3 V supply for the flash to avoid brown-out.

Pin overrides are process environment variables (`RELAY_POWER_PIN`,
`OPTOCOUPLER_POWER_PIN` — the legacy spelling `OCTOCOUPLER_POWER_PIN` is still
accepted as an alias — `CHANNEL_PIN`, `VOLTAGE_GLITCH_PIN`). Export them in
the backend shell or configure the service environment. The same applies to
`UART_PORT`.

## 3. Provisioning

```bash
sudo bash deploy/provision-pi.sh
sudo reboot
bash deploy/install.sh
cd backend && ../.venv/bin/python -m app.cli doctor
```

The doctor should report `hw.raspberry_pi`, `hw.gpio`, `hw.serial`, `hw.spi` as
available. On a laptop they report the mock backend — the software still runs.

## 4. EEPROM / flash safety (read the paper's warnings)

- Flash chips may have **read protection** or a **watchdog** that reboots the
  SoC on illegal access.
- If the flash shares a rail with other chips, do not power it from the Pi.
- Use `flashrom -p linux_spi:dev=/dev/spidev0.0` (the `spi_dump` module does
  this). Wrong chip selection can brick the target and the rig.
- Off-Pi, choose the `ch341a_spi` or `ft2232_spi` programmer in `spi_dump`.
  Verify the programmer's I/O voltage and use a level adapter where needed.
- **Never** connect a powered DUT's flash while the DUT is on.
- Start with `spi_identify` (read-only). Confirm the package marking, voltage and
  write-protection state before `spi_dump`.
- For I2C, verify pull-ups and common ground; `i2cdetect`/`i2cdump` can confuse
  some devices, so use a target you own and begin with `action=scan`.
- A logic analyzer is **listen-only**: connect its ground, clip the channels, and
  never drive the target's bus. Keep the sample rate at least 10× the signal.

## 5. First-run workflow

1. `hardware_info` → confirm rig readiness, attached debug probes, storage,
   I2C/SPI buses and whether `sigrok-cli` is available.
2. `detect_baud` → find the console rate (e.g. 115200).
3. `capture_bootlog` → power-cycle + capture + analyse.
4. `uart_console` → check for a bootloader/login; attempt breakout if allowed.
5. `serial_exec` → run a bounded diagnostic on an existing shell (or log in with
   known credentials). `filesystem_dump` → enumerate `/proc/mtd`, then recover
   one partition — or set **`all_partitions=true`** to stream *every* partition
   (complete block-level acquisition with a per-partition manifest). For a
   *running* device, `rootfs_archive` tars the live mounted filesystem instead
   (see the matrix in §7).
6. Feed each recovered image to **Firmware analysis → Carve / extract**, then run
   `boot_chain` to triage secure-boot/debug-lock evidence.
7. `spi_identify` → confirm the chip and write protection; then `spi_dump` →
   feed the image to the `firmware` domain.
8. `i2c_scan` → inventory the bus; optionally `action=dump` an EEPROM candidate.
9. `logic_capture` → decode a UART/SPI/I2C trace passively when a console is not
   reachable.
10. `voltage_glitch` (gated) → bounded fault injection; correlate with state.

## 6. Cameras / phones / earbuds (as you mentioned)

- **Phones / earbuds**: use as real-world Bluetooth targets (`bluetooth.scan`,
  `profile`, `gatt_firmware`, `link_rtt`). Earbuds are ideal for
  `capture_audit` (A2DP traffic) and `link_stress`.
- **Cameras**: the UART acquisition path is implemented: `uart_console` →
  `serial_exec` → `filesystem_dump` → **Firmware analysis → Carve / extract**.
  It requires a reachable Linux shell and known credentials; it does not bypass
  secure boot or a locked login. See [TESTING_LAB.md](TESTING_LAB.md) for the
  full workflow, timing, and integrity limits. Photograph boards before/after
  probing for your assessment record.

## 7. Complete filesystem acquisition — method matrix

"Extract the whole filesystem" has several correct answers depending on how the
device is wired and whether it is running. Pick by connection and state, not by
habit. Every method writes a SHA-256-identified image to evidence and hands off
to the **Firmware** domain for carving.

| Situation | Module | What it does | Speed / notes |
|---|---|---|---|
| Live device, UART root shell, NOR flash | `filesystem_dump` `all_partitions=true` | `dd` every `/proc/mtd` partition → one image each + manifest | ~8 KB/s at 115200 baud; block-exact, verifies declared size |
| Live device, UART shell, **NAND/UBI/overlay** | `rootfs_archive` (transport=serial) | `tar` the *mounted* rootfs (overlay/tmpfs/unpacked squashfs) | block `dd` of a NAND mtdblock is meaningless; tar the live FS instead |
| Live device **with an IP** + UART shell | `rootfs_archive` (transport=netcat) | DUT runs `tar … \| nc <host> <port>`; host receives | 100×+ faster than UART; needs `nc` on the DUT, host listens (pure-Python) |
| Device storage on the PC (USB mass-storage / SD/eMMC in a reader) | `host_block_acquire` | read-only `dd`/`ddrescue` of `/dev/sd*` or `/dev/mmcblk*` | full USB speed; **refuses the host's own system disks**; never mounts |
| Android-based camera/IoT, USB debugging on | `adb_acquire` | `adb exec-out tar` of `/system`, `/vendor`, … | binary-safe; honest about unauthorized/absent device |
| Bare SPI-NOR chip (chip-off or clip) | `spi_identify` → `spi_dump` | `flashrom` reads the chip directly | invasive, gated; confirm chip + voltage first |

Device-side commands the tool issues (so you can reproduce by hand):

```sh
# all_partitions (per partition, wrapped in session markers):
dd if=/dev/mtd0 bs=65536 2>/dev/null | base64
# rootfs_archive over UART:
tar cf - /etc /bin /sbin /usr /lib /www /var 2>/dev/null | gzip -c | base64
# rootfs_archive over netcat (DUT pushes to the testbed host):
tar cf - / --exclude=/proc --exclude=/sys --exclude=/dev 2>/dev/null | gzip -c | nc <host> 4444
```

**Limits (be honest in the report):** none of these bypass a locked bootloader,
secure boot or an unknown login — they acquire what an existing shell or an
exposed storage interface already gives. `host_block_acquire` images only what
the host enumerates as a block device (a device in *vendor* USB mode shows no
disk). Chip-off NAND readers and JTAG/SWD are out of scope (no software path).
