# Hardware & BLE research notes

This page records the public research and practitioner material that shaped the
latest hardware-lab additions, what was implemented, and what was deliberately
left out. It is a design note, not a claim that any cited author endorses this
tool.

The guiding rule is the same as the rest of the testbed: **use the smallest
observation that answers the question, keep the evidence, and never turn a
string match or one RSSI sample into a certainty.**

## 1. What was added

| Addition | Why it is useful | Where it lives |
|---|---|---|
| Coarse BLE/Classic distance estimate | Operators repeatedly ask "how far away is it?" A calibrated RSSI log-distance model with an explicit range and confidence is honest; a single RTT-derived number is not. | `bluetooth.link_rtt` (RSSI from BlueZ or operator-supplied), `web/src/components/ResultView.tsx` |
| SPI flash identity + write-protection read | Before dumping, confirm the chip, capacity and whether block protection is active. This is read-only and catches wrong-clip/voltage mistakes early. | `hardware.spi_identify` |
| I2C bus scan / bounded dump | EEPROMs, SPD, sensors and debug/control devices are common on IoT boards. A scan is a fast board-inventory step; a dump preserves the bytes for review. | `hardware.i2c_scan` |
| Logic-analyzer capture + protocol decode | A low-cost USB logic analyzer plus `sigrok-cli` can recover UART/SPI/I2C traffic without soldering a UART header. Passive capture complements active console access. | `hardware.logic_capture` |
| USB debug-probe and storage inventory | Shows which adapters (FTDI, CH341A, J-Link, ST-LINK, CMSIS-DAP, Pi Debug Probe) and block devices are attached to the backend host, so the operator knows what the rig can actually do. | `hardware_info`, `/api/v1/system/hardware`, Hardware page |
| Static secure-boot / debug-lock audit | Hardware-rooted security is more than a flash dump: check for signed FIT/AVB/dm-verity, fuse/OTP/root-of-trust references, anti-rollback counters and debug-port locks. Gaps are labelled as *not evidenced*, not as proof. | `firmware.boot_chain`, included in `firmware.analyse` |

## 2. Sources and how they influenced the design

### Firmware extraction and board-level access

- **Vasile, Oswald & Chothia, "Breaking All the Things: A Systematic Survey of
  Firmware Extraction Techniques for IoT Devices"** (CARDIS 2018/2019).
  The survey's useful lesson for a product is not a single magic technique; it is
  that acquisition paths are device-specific and evidence must record which path
  was used. This informed the read-only SPI identity step, explicit programmer
  selection, partial-dump preservation, and the separation between *acquisition*
  and *analysis*.
- **Giese & Noubir, "Amazon Echo Dot or the Reverberating Secrets of IoT
  Devices"** (WiSec 2021). Their eMMC/chip-off work shows why direct storage
  access matters when UART is locked. We added read-only storage inventory and
  kept the existing UART filesystem dump; we did not automate chip-off or
  destructive eMMC removal.
- **OWASP Internet of Things Project** and **NIST IR 8259** provide the
  device-capability/security-baseline framing used by the boot-chain audit:
  debug interfaces, secure boot, update integrity, and rollback protection are
  baseline questions, not exotic extras.

### Logic analysis and hardware tooling

- **sigrok / PulseView documentation** (`sigrok-cli`): the CLI's
  `--driver`, `--channels`, `--config samplerate=…`, `--time`, `-P` and `-A`
  options are the basis for `hardware.logic_capture`. The module validates
  driver/channel/decoder values and uses argv-only execution, so a colon in a
  channel name cannot inject a second decoder option.
- **ChipWhisperer documentation**: the existing bounded voltage-glitch module is
  the safe, low-cost cousin of a real fault-injection lab. We did not add
  side-channel capture because it requires a characterized target, a scope or
  ChipWhisperer-class hardware, and a much larger safety envelope.
- Practitioner hardware-hacking tool lists (CH341A/FT2232 programmers, SOIC-8
  clips, USB-TTL adapters, $10–$30 logic analyzers) informed the inventory and
  the "read-only first" workflow. The tool reports what is attached instead of
  assuming a particular probe.

### Bluetooth distance and privacy

- **Rajput, "Accurate On-Body Distance Estimation using BLE RSSI and IMU Sensor
  Fusion"** (Virginia Tech, 2025) is a useful reminder that raw RSSI alone is
  unstable; sensor fusion and calibration are what produce centimetre-level
  results. We therefore expose a **range**, a **path-loss exponent**, and a
  **low/medium confidence** label, and explicitly say that RTT is not a distance
  measurement. The operator can supply a measured 1 m reference to move from
  "assumed" to "operator-calibrated".
- **BLE tracker-detection research and practitioner talks** (for example the
  PDX Scholar work on suspicious-tracker detection and public BLE-tracking
  demonstrations such as `https://www.youtube.com/watch?v=LH_3NEYE-jc`) motivate
  the existing strong-signal/unnamed-device heuristic. We did not add an
  identity-tracking or IRK-cracking capability; the testbed stays on the
  defensive/assessment side.
- **CACM, "Defeating Bluetooth Trackers"** and the OWASP/NIST privacy guidance
  reinforce the same point: BLE addresses and RSSI are not proof of identity or
  intent. Findings are labelled as observations, not attributions.

## 3. Why the distance number is deliberately fuzzy

The model is:

```
d = 10 ** ((RSSI_at_1m - RSSI) / (10 * n))
```

- `RSSI_at_1m` defaults to **−59 dBm**, a typical BLE value, not the device's
  advertised `TxPower`. BlueZ `TxPower` is the radio's transmit level; treating
  it as a calibrated 1 m RSSI would produce a confidently wrong answer.
- `n` defaults to **2.5** for indoor 2.4 GHz (2.0 is free space, ~3.0 is
  obstructed). The UI shows the assumed value and accepts an operator override.
- The returned interval varies `n` by ±0.5. It is a **model-sensitivity range**,
  not a statistical confidence interval.
- Body shadowing, antenna orientation, multipath, and transmitter power changes
  can easily produce 2–3× error. For precise ranging use UWB/time-of-flight or a
  calibrated multi-anchor survey.
- RTT from `l2ping` is reported separately for link quality. Bluetooth baseband
  scheduling and retransmissions dominate it, so it is not converted into a
  distance.

If BlueZ has no RSSI, the module says **range unavailable** rather than inventing
a number. If the operator supplies a measured 1 m reference, confidence is
raised to `medium`; it is never `high` from a single sample.

## 4. Deliberately not implemented

- **Automatic JTAG/SWD chain scan.** OpenOCD adapter/target files are Tcl
  programs; accepting an arbitrary config path would turn a web parameter into
  code execution. We inventory debug probes and document the manual OpenOCD
  workflow instead. A future allow-listed, admin-installed config directory
  could add this safely.
- **Chip-off / eMMC destructive extraction.** The tool inventories storage and
  preserves dumps; it does not instruct an operator to desolder a BGA package.
- **Side-channel analysis / glitch parameter search.** The bounded glitch module
  is an execution aid, not a ChipWhisperer replacement.
- **RF jamming, unbounded deauth, or mass credential brute force.** These remain
  excluded for safety and legal reasons.
- **BLE identity tracking / IRK recovery.** Out of scope; the platform is for
  authorized device assessment, not tracking people.

## 5. References

- Vasile, S., Oswald, D., Chothia, T. *Breaking All the Things: A Systematic
  Survey of Firmware Extraction Techniques for IoT Devices.* CARDIS 2018/2019.
- Giese, D., Noubir, G. *Amazon Echo Dot or the Reverberating Secrets of IoT
  Devices.* WiSec 2021.
- Rajput, A. *Accurate On-Body Distance Estimation using BLE RSSI and IMU Sensor
  Fusion.* Virginia Tech, 2025.
  https://vtechworks.lib.vt.edu/items/c02c4502-18c5-4cf9-96b5-86f873354b86
- sigrok project. *sigrok-cli manual / wiki.* https://sigrok.org/wiki/Sigrok-cli
- ChipWhisperer documentation. https://chipwhisperer.readthedocs.io/
- OWASP Internet of Things Project. https://owasp.org/www-project-internet-of-things/
- NIST IR 8259, *Foundational Cybersecurity Activities for IoT Device
  Manufacturers.* https://csrc.nist.gov/pubs/ir/8259/final
- CACM. *Defeating Bluetooth Trackers.*
  https://cacm.acm.org/news/defeating-bluetooth-trackers/
- BLE tracking demonstration (practitioner video):
  https://www.youtube.com/watch?v=LH_3NEYE-jc

These references are for design context. Always verify a technique against the
specific device, its authorization scope, and current tool documentation.
