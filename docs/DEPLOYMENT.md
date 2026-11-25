# Deployment & Operations

This document answers the practical questions: *where do I build, what do I
transfer, and what must be installed on the office PC / Raspberry Pi?*

## 1. Should I build here and move it to the office PC?

**Yes — build here, move via Git.** The codebase is fully portable. What is
*not* portable, and must be created fresh on the target, is:

- the Python virtual environment (`.venv`) — machine/OS specific,
- `node_modules/` — rebuild with `npm install`,
- `data/` (databases, evidence, reports) — intentionally gitignored,
- `.env` — never commit it; regenerate with a fresh `SECRET_KEY`.

```bash
# on the laptop
git init && git add . && git commit -m "C3i IoT testbed v2"
git remote add origin <your-repo>
git push -u origin main

# on the office PC
git clone <your-repo> c3i-iot && cd c3i-iot
bash deploy/install.sh
```

`deploy/install.sh` creates the venv, installs dependencies, generates a `.env`
with a fresh secret, builds the console, and seeds the database.

## 2. Deployment modes

| Mode | Best for | Command |
|---|---|---|
| **Dev** | laptop, UI work | `make api` and `make web` (two terminals) |
| **Native (single service)** | office PC / Pi | `deploy/install.sh` then `uvicorn app.main:app` (serves the built console at `/`) |
| **Docker** | office server | `docker compose up --build -d` |
| **Pi rig** | hardware testbed | `sudo bash deploy/provision-pi.sh` then `deploy/install.sh` |
| **systemd** | always-on appliance | copy `deploy/c3i-iot.service` to `/etc/systemd/system/` |

## 3. Operating-system support

| Host | Bluetooth | Wi-Fi radio | GPIO/SPI/UART rig | Firmware analysis |
|---|---|---|---|---|
| **Linux (recommended)** | full (BlueZ) | full | full on Pi | full |
| Windows | no (BlueZ is Linux-only) | partial | no | partial |
| macOS | partial | partial | no | partial |

The testbed is designed for **Linux**. Bluetooth and the physical rig are
Linux-only by nature; the firmware/analysis modules and the console run
anywhere Python does. `app.cli doctor` tells you exactly what is available on
the current host.

## 4. Dependencies

### Required (all hosts)
- **Python ≥ 3.11**
- Python packages (installed automatically): FastAPI, Uvicorn, SQLAlchemy,
  Pydantic v2, PyJWT, httpx, Jinja2, ReportLab (PDF).
- **Node ≥ 18** — only to build the web console.

### Per-module external tools (install what you need)
| Domain | Debian/Ubuntu package(s) |
|---|---|
| Bluetooth | `bluez bluez-tools python3-dbus` |
| Wi-Fi / network | `nmap tcpdump tshark openssl iw wireless-tools` |
| Wireless testing | `aircrack-ng` |
| MQTT | `mosquitto-clients` |
| Firmware | `binwalk binutils file` |
| SPI flash | `flashrom` |
| I2C buses | `i2c-tools` (`i2cdetect`, `i2cdump`) |
| Logic analyzer | `sigrok-cli` plus the driver for your analyzer (`sigrok-firmware-fx2lafw` for many $10 FX2 units) |
| Probe/storage inventory | `usbutils` (`lsusb`), `util-linux` (`lsblk`) |
| Hardware (Pi) | `rpi-lgpio gpiod` (enabled via `pip install -e ".[hardware]"`) |

### Optional
- **Ollama** + a model (`qwen2.5:3b`) for the AI assistant (set
  `C3I_ASSISTANT_ENABLED=true`).
- An **NVD API key** (`C3I_NVD_API_KEY`) to raise the CVE lookup rate limit
  from 5 to 50 requests / 30 s.

### Hardware (Pi rig)
Raspberry Pi 5, an 8-channel or 2-channel relay board, an optocoupler for fast
power switching, an SPI flash clip (SOIC8), a USB-TTL adapter (or the Pi's
UART), and regulated supplies for the DUT. See `HARDWARE_SETUP.md`.

## 5. Configuration

All configuration is environment-driven (`.env`). The security-relevant knobs:

```ini
C3I_SECRET_KEY=<48-byte random>     # MUST be unique per deployment
C3I_ADMIN_PASSWORD=<strong>         # change on first login
C3I_ENABLE_INVASIVE=false           # master switch for active/invasive modules
C3I_CVE_ONLINE=true                 # allow outbound NVD/OSV/EPSS calls
C3I_ALLOWED_ORIGINS=http://localhost:5173,http://localhost:8080
```

Run `python -m app.cli doctor` to print capability + CVE-cache status, and
`python -m app.cli sync-cve` to warm the offline CVE cache before going
air-gapped.

## 6. Day-2 operations

- **Backups**: back up `data/` (SQLite DB + evidence + reports).
- **Air-gapped use**: set `C3I_CVE_ONLINE=false` and pre-run `sync-cve` on a
  connected host, then copy `data/cve/cve.db`.
- **Updates**: `git pull && deploy/install.sh` (idempotent).
- **Logs**: `journalctl -u c3i-iot -f` under systemd.
- **Scaling**: point `C3I_DATABASE_URL` at PostgreSQL for multi-analyst use.

## 7. Verification checklist after install

1. `cd backend && ../.venv/bin/python -m app.cli doctor` → confirm capabilities.
2. Open `http://<host>:8080`, log in, change the admin password.
3. Create an engagement; run a **passive** module (e.g. `firmware.entropy`).
4. Sign a Rules of Engagement; confirm an **in-scope** invasive module launches
   and an **out-of-scope** one is refused.
5. Generate an HTML report and open it.
