# Security, Safety & Ethics

This testbed can disrupt the devices it tests. That is the point of an auditing
tool — and it is why the following controls are built into the product rather
than left to documentation.

## 1. Authorized use only

> **You may only run active or invasive modules against hardware you own, or for
> which you hold written authorization from the owner.** Using this tool against
> third-party devices without authorization may be a criminal offence and a
> contract breach.

The licensed operator is responsible for obtaining authorization. The software
enforces the *mechanical* part of that obligation:

## 2. The Rules-of-Engagement gate

1. **Host switch** — `C3I_ENABLE_INVASIVE=false` by default. Nothing intrusive
   runs until an administrator enables it on the host.
2. **Per-engagement authorization** — only an `admin` can sign an RoE, naming
   the authorizer, a reference, the target scope, and an expiry.
3. **Cryptographic scope binding** — the signature is an HMAC over
   `engagement_id | signed_by | scope | expiry`. Editing the scope without
   re-signing invalidates the authorization (`roe_tampered`).
4. **Target scope check** — each invasive launch is refused unless the target
   matches the signed scope (exact / glob / CIDR).
5. **Expiry** — authorization lapses automatically.

## 3. Intrusiveness & blast-radius controls

| Control | Where |
|---|---|
| Hard packet/frame/pulse caps | `link_stress` (≤1000), `deauth_test` (≤20), `voltage_glitch` (≤5000 pulses, ≤60 s) |
| Always-restore semantics | interface monitor mode is torn down; adapter MAC restored; power restored in `finally` |
| Dry-by-default | GPIO uses a **mock backend** and says so off-Pi |
| Evidence | every intrusive action records its parameters, content-hashed |

## 4. Authentication & access control

- JWT access tokens (HS256) with a configurable TTL; API keys (SHA-256) for
  automation — both revocable.
- RBAC: `viewer < auditor < operator < admin`.
  - `viewer` read-only; `auditor` may run **passive** modules; `operator` may
    run active/invasive (subject to RoE); `admin` may sign RoE and manage users.
- CORS is restricted to `C3I_ALLOWED_ORIGINS`.
- Every security-relevant action is written to `audit_logs` (actor, action,
  engagement, outcome).

## 5. Secrets handling

- Passwords use PBKDF2-HMAC-SHA256 (240 000 iterations, per-user salt).
- The `firmware.secrets` and boot-log modules **mask** discovered secret values
  in findings (first/last four characters) so reports can be shared safely.
- No credentials are hard-coded. The legacy tool's embedded root password is
  gone by design.

## 6. Data protection

- Evidence contains potentially sensitive material (boot logs, credentials,
  network captures). Store `data/` on encrypted media and share reports only
  with the commissioning party. Reports carry a confidentiality footer.
- Do not commit `.env`, `data/`, or evidence to version control (`.gitignore`
  enforces this).

## 7. Ethical guidance for clients

When selling an assessment:
- Issue a written scope + RoE before any testing.
- Prefer the least intrusive module that answers the question.
- Schedule invasive tests in a maintenance window with a rollback plan.
- Return findings with remediation, not just exploit proof.
