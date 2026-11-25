# Roadmap — What to Build Next

Prioritised by client value and feasibility **at your level** (existing Pi rig,
UART/SPI, cameras, phones, earbuds, BT/Wi-Fi tools). This is where the biggest
commercial and research upside is.

## Now (high value, low effort — 1–2 weeks each)

1. **Compliance report modes** — generate the report against **ETSI EN 303 645**,
   **OWASP IoT Top 10**, and the **EU Cyber Resilience Act** checklist. Clients
   buy *evidence of compliance*, not raw CVEs; mapping existing findings to these
   frameworks is mostly a taxonomy layer over `services/reporting.py`.
2. **Journal/paper-ready metrics** — export per-engagement statistics (findings
   per layer, time-to-finding, module coverage) for publication and client decks.
3. **Camera-assisted PCB documentation** — a `hardware.capture_board` module that
   grabs a labelled photo, stores it as hashed evidence, and (with OCR) extracts
   silkscreen text / SoC markings to seed component CVE lookup.
4. **Audit-drift / regression reporting** — diff two runs of the same asset and
   report *new* / *fixed* / *changed* findings (the legacy Wi-Fi drift controller
   was a good idea; make it first-class and domain-agnostic).
5. **SBOM + VEX export** — emit CycloneDX/SPDX from the firmware `sbom` module so
   clients can push findings into their supply-chain tooling.

## Next (medium effort — 3–6 weeks each)

6. **Firmware emulation** — integrate **FirmAE / EMBA** to actually *run* the
   extracted image and perform dynamic web/console testing (unionfs, QEMU). This
   is the single biggest capability jump over the legacy tools.
7. **JTAG/SWD module** — the hardware paper explicitly calls for modular
   extension beyond UART. Debug-probe inventory is already in `hardware_info`;
   the remaining step is an **allow-listed** OpenOCD config directory (adapter
   and target files are Tcl programs, so arbitrary paths must never be accepted)
   plus IDCODE scan, SWD/JTAG enumeration and debug-port lock detection.
8. **ML fingerprinting, productised** — lift the `OS/pr` RandomForest pipeline
   (OS / firmware / version classifiers + clock-skew) into a versioned model
   served by the API, replacing the duplicated `final_test` stubs. Persist and
   version models; expose confidence and "masking" detection.
9. **Traffic anomaly detection** — an unsupervised model over captured flows
   (IoT-23/UNSW-IoTraffic are already in your repo) to flag C2 / beaconing.
10. **Glitch campaign orchestration** — parameter-sweep the voltage glitcher
    (on/off/delay), auto-capture the console after each attempt, and detect
    success (bootloader prompt / different boot path) automatically. This turns
    manual fault-injection into a repeatable experiment.
11. **Zigbee / Thread / Matter** — add 802.15.4 capture (nRF52840 dongle or
    Sonoff/Zigbee sniffer) as a fifth domain; the plugin framework already
    supports it.

## Later (larger bets)

12. **Side-channel (power/EM) capture** — ChipWhisperer integration for
    trace capture + simple leakage analysis; strong research output.
13. **Threat-intel enrichment** — CISA KEV + vendor advisories + EPSS trends;
    surface "actively exploited" flag prominently in the UI.
14. **Multi-tenant / SSO** — PostgreSQL + OIDC for an on-prem appliance that
    several analysts and clients share, with per-client data isolation.
15. **RAG assistant** — local Ollama + ChromaDB (the legacy tool had this) to
    answer *"what should I try next on this device, and why?"* over the
    engagement's findings.
16. **Topology graph** — live d3/react-flow network graph of discovered assets
    (legacy had `network-graph`), colour-coded by risk.

## Deliberately deferred

- **Unbounded DoS / jamming / mass credential brute-force.** These have poor
  reproducibility and legal exposure; the testbed keeps bounded, reversible
  equivalents behind the RoE gate instead.
- **Fake/simulated findings.** Every module returns real tool output or an
  honest "unavailable" — no theatre.

## Positioning (why this sells)

Compared with the legacy tools and the surveyed state of the art, this testbed
uniquely combines: **hardware fault injection + firmware static analysis +
Bluetooth audit + Wi-Fi audit in one platform**, with **cryptographically
enforced authorization**, **auditable evidence**, and **compliance-ready
reporting**. That combination is the sellable story for C3i Hub clients.
