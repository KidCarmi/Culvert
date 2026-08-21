# Traffic-Log Destination Privacy — Operator Runbook (PR3 Option B)

How to **enable**, **rotate**, and **operate** Culvert's traffic-log
destination-privacy posture — the global, opt-in toggle that pseudonymizes
the destination host/URI recorded in traffic logs.

This is the operator-facing companion to
[`docs/adr/0011-decryption-observability.md`](../adr/0011-decryption-observability.md)
§4 and the design record
[`roadmap/PR3-privacy-posture-v2-DECISION.md`](../../roadmap/PR3-privacy-posture-v2-DECISION.md).
It documents the shipped admin surface; those documents explain the threat
model and the sink-by-sink inventory behind it.

> **TL;DR**
>
> - **Opt-in, off by default.** Plaintext host/URI logging is unchanged until
>   an operator turns it on.
> - Toggle it in the admin UI (**Privacy** panel) or via
>   `PUT /api/decryption/redaction`. Takes effect immediately — **no restart**.
> - It is a **per-node** setting: it is **not** synced CP→DP, exported, or
>   restored by config-version rollback. Enable it on every node where you
>   want the posture.
> - **Key rotation has no UI button yet.** It is only reachable via
>   `PUT /api/decryption/redaction` with `{"rotate_key": true}` — see [§4](#4-rotating-the-pseudonym-key).
> - Rotating (or losing) the key **permanently breaks correlation** with
>   records pseudonymized under the old key. There is no way to recover the
>   old mapping.

---

## Contents

1. [What this protects (and what it does not)](#1-what-this-protects-and-what-it-does-not)
2. [Concepts: pseudonym key, chokepoint, fail-closed](#2-concepts-pseudonym-key-chokepoint-fail-closed)
3. [Enabling the posture](#3-enabling-the-posture)
4. [Rotating the pseudonym key](#4-rotating-the-pseudonym-key)
5. [Verifying via `GET /api/decryption/redaction`](#5-verifying-via-get-apidecryptionredaction)
6. [Cluster behavior (CP/DP)](#6-cluster-behavior-cpdp)
7. [Limitations](#7-limitations)
8. [Audit events](#8-audit-events)
9. [Troubleshooting](#9-troubleshooting)
10. [Quick reference](#10-quick-reference)

---

## 1. What this protects (and what it does not)

When enabled, every traffic-log record's destination is replaced with a
stable pseudonym token (`h_`+12 hex characters) instead of the plaintext
host/URI, **everywhere that record is written**:

- the in-memory request feed (dashboard)
- the JSONL log file and the queryable history store
- the syslog/SIEM export
- the request-feed drill-down
- the nested decryption-observability fields `dec.host` / `dec.sni`
  (ADR-0011)
- the in-memory `top_hosts` ranking

This is a **logging/observability privacy control**, not a traffic-decision
control: it never changes policy evaluation, routing, or what is
inspected/blocked — only what destination value is *recorded*. Turning it on
or off is **not retroactive**: only records written after the change use the
new posture; already-persisted entries keep whatever they were written with.

**Out of scope for this posture:** identity fields (`auth_*`), request
method/status/bytes, rule/profile identifiers, and certificate metadata are
unaffected — only the destination (host/URI/SNI) is pseudonymized.

---

## 2. Concepts: pseudonym key, chokepoint, fail-closed

- **Pseudonym key.** A node-local, randomly generated 32-byte key. The token
  is `"h_" + hex(HMAC-SHA256(key, normalized_host))[:12]` — a **keyed** HMAC,
  not a bare hash, so the mapping cannot be reversed by dictionary/rainbow
  lookup, while staying stable enough that a SOC can still correlate
  repeated visits to the same destination.
- **Single chokepoint.** Redaction happens once, at the `persistLogEntry`
  point that every sink reads from — there is no separate code path per sink
  that could drift out of sync or leak plaintext to one sink and not
  another.
- **Fail-closed.** If the posture is **on** but no valid key is available
  (e.g. a corrupt/truncated key was hand-edited into `admin_settings.json`),
  the destination is recorded as the constant sentinel string `redacted` —
  **never** plaintext, and never a weak/predictable token.

---

## 3. Enabling the posture

**Admin UI:** Policy/Decryption area → **Privacy** panel → *"Pseudonymize
destination in traffic logs"* checkbox. Requires the `admin` role. Takes
effect immediately.

**API:**

```bash
# Enable (admin session required)
curl -sS -X PUT https://<host>:<ui-port>/api/decryption/redaction \
  -H 'Content-Type: application/json' \
  --cookie "$SESSION_COOKIE" \
  -d '{"redact_hosts": true}'
```

On first enable, Culvert mints a fresh 32-byte pseudonym key **before**
persisting the toggle, so there is never a window where the posture is on
but no key exists. The toggle and the key are written to
`admin_settings.json` (`0600`) in one save; if that write fails, both the
toggle and any newly-minted key are rolled back and the previous state
stays in effect.

Disable the same way with `{"redact_hosts": false}` — this does **not**
delete the key (so re-enabling later reuses the same key and correlation is
preserved across an off/on cycle).

---

## 4. Rotating the pseudonym key

Rotation mints a **brand-new** random key, so every future token changes.
**There is currently no button for this in the admin UI** — it is only
reachable via the API:

```bash
curl -sS -X PUT https://<host>:<ui-port>/api/decryption/redaction \
  -H 'Content-Type: application/json' \
  --cookie "$SESSION_COOKIE" \
  -d '{"rotate_key": true}'
```

Notes:

- `rotate_key` is **orthogonal** to the on/off posture: sending
  `{"rotate_key": true}` preserves whatever the posture currently is (on
  stays on, off stays off). You do not need to also pass `redact_hosts`, and
  a client should not assume its absence means "turn it off."
- Rotation is **irrecoverable**: tokens produced before rotation can never
  again be correlated with tokens produced after it. There is no dual-key
  grace window. Plan rotations around when you are willing to lose
  cross-time correlation (e.g. after closing an investigation).
- Rotate when you suspect the key material has been exposed (e.g. a
  `admin_settings.json` backup leaked to an unintended party), on a
  routine compliance cadence, or before decommissioning a node whose
  historical tokens should no longer be linkable to future ones.

---

## 5. Verifying via `GET /api/decryption/redaction`

Available to `viewer` role and above:

```bash
curl -sS https://<host>:<ui-port>/api/decryption/redaction --cookie "$SESSION_COOKIE"
```

```json
{
  "redact_hosts": true,
  "scope": "traffic_destination",
  "scope_fields": ["host", "uri", "dec.host", "dec.sni", "top_hosts"],
  "key_provisioned": true,
  "note": "..."
}
```

- `key_provisioned` reports whether the node holds a usable 32-byte key —
  **the key value itself is never returned** by this or any other API,
  export, or support-bundle surface.
- `key_provisioned: false` while `redact_hosts: true` means the node is
  currently emitting the fail-closed `redacted` sentinel for every
  destination — treat this as a `fail`-severity condition and fix it (see
  [§9](#9-troubleshooting)).

---

## 6. Cluster behavior (CP/DP)

The posture and its key are declared `AdminDurable`-only in the
config-surface registry (`config_surfaces.go`) — deliberately **excluded**
from:

- **Export/import** (`apiConfigExport`/`apiConfigImport`)
- **Config-version rollback** (`configversion.go`)
- **CP→DP `ConfigSnapshot` sync**

This is a **per-appliance privacy choice**, not fleet policy: enabling it on
the Control Plane does **not** enable it on any Data Plane node, and
rolling back to an earlier config version will **not** change it either
way. To apply the posture fleet-wide, enable it on each node
individually (UI or API, per node). Fleet-wide pseudonym-key sync (so every
node produces the *same* token for the same destination) is a deferred
follow-up — today each node's key, and therefore its tokens, are unique to
that node.

---

## 7. Limitations

- **Host-filtered log search stops matching plaintext.** The request-feed
  `?filter=` search matches the *stored* value. While the posture is on,
  that means searching for a plaintext hostname will not find matching
  records — search by the token instead (visible on already-pseudonymized
  rows), or correlate via another field (rule, identity, time range).
- **No GUI control for key rotation** (see [§4](#4-rotating-the-pseudonym-key)) —
  API only, admin role required.
- **Not retroactive.** Toggling the posture, or rotating the key, only
  affects records written from that point forward.
- **Node-local only** — see [§6](#6-cluster-behavior-cpdp).
- **A residual path-echo case.** `redactDestinationURI` scrubs the
  destination host from the request path in both its exact logged form and
  its port-stripped form, but an IPv6-literal destination echoed in the path
  in a *differently bracketed* form than the authority is not guaranteed to
  be scrubbed. This is a contrived case (the client would have to echo its
  own destination in the path) and the authority itself is always
  tokenized; see `traffic_redaction.go` for the exact boundary.

---

## 8. Audit events

| Action | Meaning | Object (state) |
|--------|---------|-----------------|
| `decryption.redaction` | The on/off posture changed. | `enabled` or `disabled` |
| `decryption.redaction.key-rotated` | The pseudonym key was rotated. | current posture (`enabled`/`disabled`) |

Neither event ever carries the key value. Find them in the audit log (UI
**Audit** panel, the audit JSONL file, or any configured syslog/SIEM sink)
by filtering on the `decryption.redaction*` action prefix.

---

## 9. Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| Traffic logs show the literal string `redacted` for every destination. | Posture is on but `key_provisioned` is `false` (fail-closed sentinel). | `PUT` with `{"redact_hosts": true}` again to re-provision a key, or check `admin_settings.json` was not hand-edited/truncated. |
| A DP node still logs plaintext destinations after enabling the posture on the CP. | The posture is node-local (§6) — CP enablement never propagates. | Enable it directly on that DP node via its own admin UI/API. |
| Searching the request feed for a known hostname returns nothing while the posture is on. | Expected — see [§7](#7-limitations); search matches the stored token, not plaintext. | Search by the token, or disable the posture temporarily if you need plaintext search (new records only). |
| Old and new records for the same destination no longer share a token. | The key was rotated (§4) or the node's `admin_settings.json` was restored from an unrelated node/backup. | Expected and irreversible — rotation intentionally breaks correlation. |

---

## 10. Quick reference

**Enable / disable** (admin, hot-applies, no restart)

```
PUT /api/decryption/redaction   {"redact_hosts": true|false}
```

**Rotate key** (admin, API-only — no UI button)

```
PUT /api/decryption/redaction   {"rotate_key": true}
```

**Check status** (viewer)

```
GET /api/decryption/redaction
  redact_hosts     — on/off
  key_provisioned  — false ⇒ fail-closed sentinel is being emitted
  scope_fields     — exactly which fields are pseudonymized
```

**Scope:** host, uri, `dec.host`, `dec.sni`, `top_hosts` — **not** synced
CP→DP, exported, or rollback-restored (per-node only).

**Audit actions:** `decryption.redaction`, `decryption.redaction.key-rotated`

---

*See also:*
[`docs/adr/0011-decryption-observability.md`](../adr/0011-decryption-observability.md)
§4 (design + serialization contract),
[`roadmap/PR3-privacy-posture-v2-DECISION.md`](../../roadmap/PR3-privacy-posture-v2-DECISION.md)
(the A-vs-B decision + full sink inventory),
[`docs/operator/decryption-auto-exclusions.md`](decryption-auto-exclusions.md)
(a separate, unrelated decryption-profile privacy/coverage control).
