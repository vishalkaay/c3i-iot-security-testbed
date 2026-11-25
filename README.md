# C3i Hub — IoT Security Testbed

**A unified, industry-grade IoT security auditing platform for Bluetooth, Wi-Fi,
and hardware/firmware domains.**

Built for the [C3i Hub, IIT Kanpur](https://c3ihub.org) — developed under the
*Development of Security Audit Framework for secure IoT network* project
(NM-ICPS, DST, Government of India).

---

## What this is

One platform that fuses three previously separate tools — a Bluetooth GUI, a
Wi-Fi scanner, and a Raspberry-Pi hardware auditing rig — into a single,
coherent, client-ready product:

- 🔵 **Bluetooth / BLE** — discovery, SDP profiling, OS/version inference, GATT
  firmware identification, coarse RSSI distance estimate with uncertainty,
  encrypted-traffic verification, CVE mapping.
- 📶 **Wi-Fi / IP** — host discovery, service & OS fingerprinting, TLS posture,
  wireless reconnaissance, MQTT exposure, capture analysis.
- 🔧 **Hardware testbed** — UART baud discovery, boot-log capture, bootloader
  console detection, SPI identity/dump, I2C scan/dump, logic-analyzer decode,
  and bounded voltage fault injection (Raspberry Pi 5 or USB adapters).
- 🧩 **Firmware** — signature carving, entropy, hard-coded secrets, component
  SBOM, secure-boot/debug-lock audit, and CVE mapping.

Unlike the tools it replaces, every finding comes from a real probe of the
authorized target — lab fixtures and the loopback simulator are clearly labelled
synthetic, and the platform never fabricates a finding to make a demo look
successful. Every intrusive action is **cryptographically gated** behind a signed
Rules of Engagement, and every result is **auditable** and exportable as HTML /
PDF / JSON / SARIF.

## Why it's different

| | Legacy tools | This testbed |
|---|---|---|
| Architecture | three unrelated codebases | one plugin-driven FastAPI platform |
| Safety | a hard-coded root password, wide-open endpoints | RBAC, JWT/API keys, RoE signature over scope |
| Command execution | `shell=True` string interpolation (injection) | argv-only, validated inputs |
| Firmware "extraction" | string-mined a pcap | binwalk/carve, entropy, secrets, and SBOM pipeline |
| Wi-Fi deauth | stubbed out | real, bounded (≤20 frames), reversible |
| Failure handling | fake success or crash | capabilities probed; honest "unavailable" |
| Output | ad-hoc screen scraping | reports + SARIF + audit trail |

## Quickstart

```bash
git clone <repo> c3i-iot && cd c3i-iot
bash deploy/install.sh                 # venv, deps, .env, web build, DB seed
source .venv/bin/activate
cd backend && uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Open **http://localhost:8080** → log in (credentials in `.env`) → change the
password → create an engagement → run a module.

Dev mode (hot reload):

```bash
make api     # backend on :8080
make web     # console on :5173 (proxies to :8080)
```

Verify the host and dependencies:

```bash
cd backend && ../.venv/bin/python -m app.cli doctor
```

## The safety gate in one picture

```
create engagement ──► sign Rules of Engagement (admin only)
                          │  signature = HMAC(secret,
                          │      engagement | signer | scope | expiry)
                          ▼
        run passive module ─────► allowed (auditor+)
        run active/invasive ────► host switch ✔
                                  engagement authorized ✔
                                  RoE unexpired ✔
                                  signature matches scope ✔
                                  target ∈ scope ✔   ──► run; else 403
```

Widen the scope without re-signing and the launch is refused
(`roe_tampered`). This is enforced in code and covered by tests.

## Security tools used

Every external tool the testbed invokes — with its exact role, the module that
calls it, and its licence — is documented in **[`docs/TOOLS.md`](docs/TOOLS.md)**.
Summary of the scanning engine:

| Domain | Tools |
|---|---|
| **Bluetooth / BLE** | BlueZ `bluetoothctl`, BlueZ D-Bus GATT API, `gatttool`, `btmgmt`, `l2ping`, `tshark` |
| **Wi-Fi / IP** | `nmap`, `ping`, `openssl`, `iw`, `tcpdump`, `tshark`, `mosquitto_sub`, `aircrack-ng` (gated), `httpx` |
| **Hardware rig** | `pyserial`, `rpi-lgpio`/`libgpiod`, `flashrom`, `i2c-tools`, `sigrok-cli`, `lsusb`, `lsblk` |
| **Firmware** | `binwalk`, `strings` (binutils), `readelf`/`objdump` |
| **Vuln intel** | NVD 2.0, OSV.dev, EPSS (with an offline SQLite cache) |

Tools are always invoked as **separate processes with argv arrays** (never
`shell=True`), and input is validated before use. If a tool is missing, the
module reports `capability unavailable` with an install hint instead of failing
silently. Licensing rationale is in `docs/TOOLS.md`.

## How to use it

The console is organised around one linear workflow:

```
① Engagements → ② Firmware analysis / Hardware / Module runner → ③ Findings → ④ Evidence & reports
```

| Page | What you do there |
|---|---|
| **Overview** | Assessment posture, host readiness, recent runs, and domain shortcuts. |
| **Engagements** | Create an assessment; **sign the Rules of Engagement** to enable gated tests. |
| **Firmware analysis** | Upload a firmware image / boot log / capture, run static analysis, and download evidence. |
| **Hardware workbench** | Rig status, USB vs Pi wiring, pin map, and one-click UART/SPI/I2C/logic/glitch actions. |
| **Module runner** | Run any of the 36 modules with a generated parameter form, live status, structured results, and downloadable evidence. |
| **Findings** | Filter by severity/domain; expand for evidence and remediation. |
| **Evidence & reports** | Download captured artefacts (boot logs, PCAPs, firmware dumps) and generated reports. |
| **Domains & modules** | Full module catalogue + which host capabilities are present. |

**Analysing a file (no hardware required):** *Firmware analysis* → upload a
`.bin` → run `Full analysis` → read secrets/components → download the artefact.

**Connecting hardware:** *Hardware workbench* → follow the wiring steps → run
`Detect baud rate` → `Capture boot log`. For a camera shell, continue with
`serial_exec` → `filesystem_dump` → `Firmware analysis → Carve / extract`.

## Safety notice

> This tool can disrupt the devices it tests. **Only use active and invasive
> modules on hardware you own or are authorized in writing to test.** See
> [`docs/SECURITY_AND_ETHICS.md`](docs/SECURITY_AND_ETHICS.md). Invasive modules
> ship **disabled** and require a signed, in-scope Rules of Engagement.

## Repository layout

```
iot/
├── backend/app/
│   ├── core/        config · database · security · authorization(RoE) · events
│   ├── models/      User · Engagement · Asset · Job · Finding · Evidence · Report
│   ├── plugins/     bluetooth/ · wifi/ · hardware/ · firmware/  (+ base, registry, tools)
│   ├── services/    vuln(NVD/OSV/EPSS) · traffic · bootlog · risk · reporting
│   ├── jobs/        runner (thread pool + event streaming + domain locks)
│   ├── api/v1/      auth · engagements · plugins · jobs · findings · reports · system · ws
│   ├── main.py      app wiring + static console serving
│   └── cli.py       serve · seed · demo · doctor · sync-cve
├── web/             React + Vite + TS + Tailwind console
├── deploy/          install.sh · provision-pi.sh · systemd unit
├── docs/            architecture, methodology, modules, deployment, hardware, ethics, roadmap
├── Dockerfile · docker-compose.yml · Makefile · pyproject.toml
├── lab/             reproducible firmware fixtures + loopback camera simulator
└── backend/tests/   offline regression suite (gate, runner, engines, API)
```

## Running the tests

```bash
cd backend && ../.venv/bin/python -m pytest -q
```

Covers the authorization gate (including tamper detection and per-action target
derivation), power-polarity conventions, cancellation terminal states, per-job
WebSocket status events, finding persistence, path containment, uploads,
password change, CVE-cache sync, and the analysis engines.

## Try it without a hardware rig

- Upload [`lab/fixtures/c3i-camera-lab.bin`](lab/fixtures/c3i-camera-lab.bin) in
  **Firmware analysis**. This is a synthetic calibration image, with expected
  offsets and hashes in `lab/fixtures/manifest.json`.
- Run `python3 lab/network_simulator.py` to start a loopback **IP-service** camera target with
  HTTP/TLS, FTP, SSH, Telnet, and an anonymous MQTT broker. Select **Wi-Fi / IP**
  in the module runner and test `127.0.0.1`.
- Use **Ctrl+K** to search pages/modules. The workspace supports narrow screens
  and reduced-motion preferences.
- Follow [`docs/TESTING_LAB.md`](docs/TESTING_LAB.md) for expected results,
  hardware requirements, direct USB vs Pi connections, and camera extraction.

## Configuration reference (env)

All settings are `C3I_`-prefixed env vars (or `.env`). Relative paths are
resolved against the **repository root**, not the current working directory, so
starting uvicorn from `backend/` or from the repo root yields the same database
and data directory (this killed a legacy trap where two different databases
existed depending on launch directory).

| Variable | Default | Meaning |
|---|---|---|
| `C3I_ENV` | `development` | `production` enforces strong secret + no dev auth |
| `C3I_DATA_DIR` | `data/` | SQLite + uploads + evidence + firmware dirs (repo-root anchored) |
| `C3I_SECRET_KEY` | dev placeholder | **must** be ≥32 chars in production |
| `C3I_DEV_NO_AUTH` | `false` | disables auth (dev only; forbidden in production) |
| `C3I_ENABLE_INVASIVE` | `false` | host-level arming switch for invasive modules |
| `C3I_MAX_UPLOAD_MB` | `512` | upload size cap (`413` beyond) |
| `C3I_CVE_ONLINE` | `true` | allow NVD/OSV/EPSS lookups (air-gap: `false`) |

## Hardware rig conventions ( Raspberry Pi 5 )

Power polarity is centralised in the backend (`plugins/hardware/support.py`) and
surfaced in `/api/v1/system/hardware` (`power_polarity`):

| Actuator | BCM pin | DUT powered | DUT unpowered |
|---|---|---|---|
| Optocoupler (incl. the legacy `octocoupler` spelling) | 22 | GPIO **LOW** | GPIO **HIGH** |
| Relay | 6 | GPIO **HIGH** | GPIO **LOW** |

Boot-log capture opens the serial port **before** the power cycle and keeps one
handle for the whole capture (so early bootloader output is never lost).
Voltage-glitch runs report the *achieved* pulse rate (`stop_reason` /
`rate_hz` in the result) because GPIO busy-waiting is not a precision pulse
source. Cooperative cancellation (`ctx.cancelled()`) is honoured by serial
reads, glitch trains and scan loops; a cancelled job ends in state
**`cancelled`** (never `succeeded`) and retains the evidence collected so far.

⚠️ Serial/radio/GPIO behaviour (UART baud discovery, boot-log capture, SPI
flash read, optocoupler/relay switching, deauth frames, Bluetooth radios) can
only be fully validated on the physical rig — the test suite exercises the
logic layer with mock GPIO and fixtures, not copper.

## Documentation

| Doc | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | components, request lifecycle, plugin framework, extending |
| [`docs/TOOLS.md`](docs/TOOLS.md) | **every external security tool, role, module, and licence** |
| [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) | mapping to the C3i Hub / IIITA research and the seven-layer threat model |
| [`docs/MODULES.md`](docs/MODULES.md) | full module reference (36 modules) |
| [`docs/TESTING_LAB.md`](docs/TESTING_LAB.md) | test images, network simulator, hardware shopping list, UART camera workflow |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | laptop vs office PC vs Pi, dependencies, operations |
| [`docs/HARDWARE_SETUP.md`](docs/HARDWARE_SETUP.md) | pin map, wiring, flash safety, first run |
| [`docs/WIFI_HWSIM_LAB.md`](docs/WIFI_HWSIM_LAB.md) | no-RF Wi-Fi lab (mac80211_hwsim + hostapd) for survey/capture/deauth |
| [`docs/HARDWARE_RESEARCH.md`](docs/HARDWARE_RESEARCH.md) | research/YouTube sources behind the hardware and BLE-distance additions, and what is intentionally not implemented |
| [`docs/SECURITY_AND_ETHICS.md`](docs/SECURITY_AND_ETHICS.md) | authorization, blast-radius controls, data protection |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | compliance modes, emulation, JTAG, ML, Zigbee, side-channel |

## License

Proprietary — © C3i Hub, IIT Kanpur. See [`LICENSE`](LICENSE).
