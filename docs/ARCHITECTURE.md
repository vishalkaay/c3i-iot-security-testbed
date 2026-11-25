# Architecture

## 1. Design goals

The legacy codebase was three unrelated tools (a Node/React Bluetooth GUI, a
Node/React Wi-Fi scanner, a Flask hardware tool) that shared nothing, duplicated
logic, embedded a root password, and passed user input straight into shells.

This rewrite unifies them into **one product** with a small number of
deliberate, enforced properties:

| Goal | How it is achieved |
|---|---|
| **One control plane** | A single FastAPI service owns assets, jobs, findings, evidence, and reports for all three domains. |
| **Extensibility** | A plugin/module registry. A new capability is a decorated method that declares its parameters, intrusiveness, and host prerequisites. |
| **Safety by construction** | A cryptographic Rules-of-Engagement gate in front of every non-passive module. |
| **Deploy anywhere** | Passive analysis runs on a laptop; the physical rig runs on a Raspberry Pi 5; containers cover the API. Capabilities are probed, never assumed. |
| **Auditability** | Every security-relevant action is written to an audit log; evidence is content-hashed (SHA-256). |
| **Client-ready output** | HTML/PDF/JSON reports plus SARIF for CI/pipeline ingestion. |

## 2. Component map

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Web console (React + Vite + TS + Tailwind)                              │
│   Dashboard · Engagements · Testbed Runner · Findings · Domains          │
│   ── REST (/api/v1) ── WebSocket (/ws/jobs/{id}) ──                      │
└───────────────▲──────────────────────────────────────────────────────────┘
                │
┌───────────────┴──────────────────────────────────────────────────────────┐
│  FastAPI application (backend/app)                                       │
│                                                                          │
│  api/v1 ─── deps.py (auth, RBAC)                                         │
│     │                                                                    │
│  core/  config · database · security · authorization(RoE) · events       │
│     │                                                                    │
│  jobs/runner ── thread pool ──► plugin modules ──► subprocess/tools      │
│     │                                   │                                │
│  services/  vuln(NVD/OSV/EPSS) · traffic · bootlog · risk · reporting    │
│     │                                                                    │
│  plugins/  bluetooth · wifi · hardware · firmware                        │
│     │            │            │           │                              │
│  models/  User · Engagement · Asset · Job · Finding · Evidence · Report  │
│                                                                          │
│  SQLite (PostgreSQL-swappable)                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## 3. Request lifecycle (a module run)

1. **Auth** — the request carries a JWT (or `X-API-Key`). `deps.current_user`
   resolves the principal and its role.
2. **Role check** — passive modules need `auditor`; active/invasive need
   `operator`.
3. **Authorization gate** — `core.authorization.assert_authorized` verifies the
   host switch, engagement state, RoE acceptance/expiry, the **HMAC signature
   over the scope**, and that the target is inside that scope.
4. **Job row** — persisted as `queued`; the params carry the normalised target.
5. **Execution** — `jobs.runner` runs the module in a worker thread, building a
   `PluginContext` that streams logs/progress into `JobLog` and over the event
   bus.
6. **Persistence** — the module returns a `ModuleResult`; the runner upserts
   assets, de-duplicates findings by fingerprint, stores evidence (hashed), and
   finalises the job.
7. **Live stream** — the browser subscribed to `/ws/jobs/{id}` receives log and
   status events as they happen.

## 4. The authorization gate (why it is a real control)

Most "are you sure?" dialogs are cosmetic. Here, authorization is a signature
over the *scope*:

```
signature = HMAC-SHA256(secret,
    engagement_id | signed_by | sorted(scope) | expires_at)
```

- Only an **admin** can sign.
- The signature is recomputed on every non-passive launch. If anyone edits
  `authorized_targets` in the database without re-signing, verification fails
  and the launch is refused (`roe_tampered`).
- The target must match the scope by exact value, glob (`AA:BB:CC:*`), or CIDR
  membership (`192.168.1.0/24`).

This is verified by `tests/test_authorization.py` and the API test
`test_engagement_lifecycle_and_gate`.

## 5. Intrusiveness model

Every module declares one of:

| Level | Meaning | Examples | Gate |
|---|---|---|---|
| `passive` | Read-only observation | BLE scan, nmap, TLS probe, entropy, secret scan | none |
| `active` | Sends probes / authenticates / power-cycles | default-cred test, UART baud detection, boot-log capture | RoE required |
| `invasive` | May disrupt, degrade, or fault the device | bounded deauth, L2CAP stress, SPI dump, voltage glitch | RoE required + host switch |

## 6. Extending the testbed

Add a module in ~15 lines:

```python
class MyPlugin(BasePlugin):
    name, domain, title = "myplugin", "custom", "My Domain"

    @module(
        name="check_x",
        title="Check X",
        safety=Safety.PASSIVE,
        params_model=MyParams,          # a pydantic model -> auto UI form
        capabilities=[CAP_STRINGS],
        tags=["custom"],
    )
    def check_x(self, ctx: PluginContext, params: MyParams) -> ModuleResult:
        ctx.progress(50, "working")
        return ModuleResult(
            data={"ok": True},
            findings=[FindingDraft(title="...", category="...", severity="low")],
            summary="done",
        )
```

Register it in `plugins/registry.load_plugins()`; the console picks up the new
module, its parameter form, its safety badge, and its capability requirements
automatically.

## 7. Storage & evidence

- SQLite by default at `data/c3i_iot.db` (set `C3I_DATABASE_URL` for Postgres).
- Evidence (pcaps, boot logs, SPI dumps, firmware reports, glitch logs) is
  written under `data/evidence/<job_id>/` and recorded with size + SHA-256.
- Reports are written under `data/reports/<engagement_id>/`.

## 8. Failure philosophy

The legacy tools either faked success or blew up. Here:

- Missing tool/hardware ⇒ a **capability** is `available: false`; the UI explains
  *what to install*; the module degrades to a clear message.
- No physical rig ⇒ GPIO uses a **mock backend that says so** (never silent).
- Network down ⇒ the CVE engine returns cached results and marks them partial.
