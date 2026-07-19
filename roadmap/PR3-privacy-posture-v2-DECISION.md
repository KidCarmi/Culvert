# PR3 — Decryption / Traffic-Log Privacy Posture v2 — DECISION

**Status:** DECIDED → **Option B SHIPPED** (node-local key). PR #868 shipped the B0
honesty fix; the follow-up ships B1 (chokepoint redaction) + B2 (node-local keyed-HMAC
key), fail-closed. **B3 (fleet-wide CP→DP key sync) is deferred** to a multi-node
follow-up — the node-local key is the default (a stable per-node pseudonym). See
`traffic_redaction.go`.

**As-shipped key posture (reconciles the "encrypted under KEK" aspiration below):** the
`TrafficPseudonymKey` is persisted **plaintext inside the 0600 `admin_settings.json`**,
byte-consistent with the established `MetricsToken` / `SessionHMAC` secret posture — NOT
KEK-encrypted. This is the accepted secret-at-rest layer for this appliance (the threat
model protects against the SIEM/log-reader/DBA without file access, not an attacker with
`admin_settings.json` read). A key ≠ 32 bytes on load is ignored (fail-closed). Rotation
is an admin action (`PUT {"rotate_key":true}`); disable keeps the key so re-enable
correlates. The **top-hosts ranking is redacted too** (it is a viewer-facing sink). The
`§4/§5` references to "encrypted at rest under the KEK" describe the original aspiration,
not the shipped code.
**Author role:** Observability & Privacy Architect
**Base:** `origin/main` @ e5b7a8b7 (PR1 #855 permissive-retirement + PR2 #860 security-generation fencing merged)
**Wave:** Adaptive-decryption production-hardening, PR3

---

## Executive summary (for the product owner)

Culvert ships a "redact host/SNI" decryption privacy toggle whose contract is **misleading**: it hashes `dec.host`/`dec.sni` inside the nested decryption block, but the **same log record still carries the destination in plaintext** in top-level `Entry.Host` and `Entry.URI`, and those plaintext fields are streamed to **syslog/SIEM, the JSONL log, the queryable history store, and the dashboard drill-down API** untouched. Worse, the hash it does apply is an **unsalted, unkeyed SHA-256 truncated to 12 hex chars — trivially reversed for any common hostname with a precomputed dictionary**. For the regulated/healthcare buyers this hardening wave targets, a toggle that provides *false* privacy assurance is a compliance trap, not a feature.

**Verdict: RECOMMEND OPTION B** — a global, opt-in (default-off) destination-privacy posture that pseudonymizes host + URI **consistently across every sink** using a **keyed HMAC**, with Option A's honesty fix folded in as B's first, immediately-shippable step. The single most important enabling fact: **every sink fans out from one chokepoint (`persistLogEntry`, store.go:1231)**, and the two hard pieces — a keyed-HMAC tokenizer and a fleet-consistent synced secret — **already exist in the tree** (`internal/redaction.maskString`, and the `SessionHMAC` CP→DP sync). B is therefore both the only option that satisfies the stated regulated requirement and far more tractable than its scope suggests.

---

## 1. Sink inventory — where a destination can leak

Every persistent/streamed request or tunnel record is built and fanned out by **one function**:

> `persistLogEntry(ip, method, host, status, …, uri, auth AuthLogFields)` — **store.go:1231–1255**
> Builds `LogEntry{Host: host, URI: uri, …, Dec: auth.Dec}` then calls
> `logAdd(entry)` (store.go:1250) **and** `globalSyslog.WriteRequest(entry)` (store.go:1252–1253).

`logAdd = reqlog.Add` (store.go:177) itself fans out to three places (reqlog.go:153–185): the in-memory ring, the JSONL writer, and the queryable-history hook (`SetHistory → globalLogStore.Add`, store.go:189). Both the tunnel-close path (`recordTunnelCloseGatedDec → persistTunnelCloseDec`, store.go:1206/1171) and the decrypt-failure path (`recordDecryptFailureEntry`, decryption_metrics.go:248) terminate here. **This single chokepoint is the load-bearing fact of the whole decision.**

The record type is `logstore.Entry` (logstore.go:60–102). The destination lives in **three** places on it:
- `Entry.Host` (logstore.go:66) — top-level, always plaintext
- `Entry.URI` (logstore.go:67) — top-level, `host+path`, plaintext, populated when the matched rule sets `LogFullURI`
- `Entry.Dec.Host` / `Entry.Dec.SNI` (logstore.go:125–126) — nested, the *only* fields the current toggle touches

| # | Sink | File:line (evidence) | Destination field(s) carried | Redacted by the current toggle? |
|---|------|----------------------|------------------------------|--------------------------------|
| 1 | In-memory request/traffic feed (ring) | reqlog.go:153–163; store.go:1250 | `Entry.Host`, `Entry.URI` (+ `dec.host/sni`) | **NO** (top-level plaintext) |
| 2 | Persistent history (JSONL, rotating) | reqlog.go:166–179 | `Entry.Host`, `Entry.URI` | **NO** |
| 3 | Queryable history store (Badger, on-disk, survives restart) | logstore.go:378 via hook store.go:189 | `Entry.Host`, `Entry.URI` | **NO** |
| 4 | JSONL export / `GET /api/logs` (+ `source=file`/`store`) | ui_config.go:206–259 | returns raw `LogEntry` incl. `Host`,`URI`,`dec` | **NO** |
| 5 | SSE stream `GET /api/events` | events.go:162; DashboardPayload events.go:32–45 | **aggregate only** (counts + `TopCountries`); no per-session host | N/A — per-session host never on SSE. *But* aggregate hostname ranking leaks via `/api/stats` top-hosts (store.go topHosts) |
| 6 | syslog / SIEM forwarding | store.go:1252–1253 → syslog.go:212–218 (`json.Marshal(entry)`) | **whole Entry** → `Host`,`URI`,`dec` to SIEM | **NO** (plaintext host+URI shipped off-box) |
| 7 | Support bundles / diagnostics | support_collectors_reused.go:281–318 | `Host`,`URI` tagged `redact:"sensitive"` | **N/A to this toggle** — masked by a *separate, stronger* salted-HMAC scheme (see §2) |
| 8 | Nested decryption block `dec.*` | decryption_observability.go:110–111 → redactHost | `dec.host`, `dec.sni` | **YES** — but weak hash (see §2) |
| 9 | Top-level `Entry.Host` | logstore.go:66; set plaintext at store.go:1238 & decryption_metrics.go:248 | destination host | **NO** |
| 10 | `Entry.URI` (can it leak host even when `dec.host` is hashed?) | logstore.go:67 | `host+path` — **contains the host verbatim** | **NO — and it defeats the hash**: a record with `dec.host="h_ab12…"` still shows `uri:"https://patient-portal.example.com/…"` |
| 11 | Dashboard drill-down / raw-entry APIs | ui_config.go:206 (`apiLogs`), `apiLogsServeStore` | raw `LogEntry` | **NO** |

**Net finding:** the toggle redacts exactly **1 of the 3 destination fields, on 1 of ~10 sinks**. Sinks 1–4, 6, 9–11 emit the plaintext destination regardless of the toggle. The claim "host/SNI is redacted" is false whenever the same record is read from the feed, the JSONL, the history store, the SIEM, or the drill-down — i.e. essentially always.

---

## 2. Characterizing the current hash

`redactHost` — **decryption_observability.go:424–430**:

```go
func redactHost(v string, redact bool) string {
    if !redact || v == "" { return v }
    sum := sha256.Sum256([]byte(v))
    return "h_" + hex.EncodeToString(sum[:])[:12]
}
```

- **Algorithm:** SHA-256 over the raw host/SNI bytes.
- **Truncation:** first **12 hex chars = 48 bits** of digest, `"h_"` prefix.
- **Salted / keyed:** **Neither.** No salt, no key, no per-node/per-tenant material. `SHA256("www.example.com")` is a global constant.
- **Where computed:** at projection time in `toBlock(redact)` (decryption_observability.go:101,110–111), gated by the node-local `decRedactHosts()` atomic (decryption_redaction.go:24).
- **Applied to:** `dec.host` and `dec.sni` only.

**Dictionary-recovery weakness (quantified).** Because the transform is a pure unsalted hash, it is a **rainbow-table lookup, not a redaction**. An attacker (or a SIEM operator who should not see PHI destinations) precomputes `"h_"+SHA256(host)[:12]` for a hostname wordlist and matches by equality:
- The Tranco/Alexa top-1M list is ~1M entries; hashing it is milliseconds and a ~30 MB table. Any enterprise destination in that list is recovered instantly.
- 48-bit truncation gives an expected accidental-collision count over a 1M dictionary of ≈ 1e6 / 2^48 ≈ **3.5×10⁻⁹** — i.e. a matched prefix is a *confident* recovery, not an ambiguous one.
- No salt/key ⇒ **one table works across every node, every tenant, and forever**; nothing rotates or diverges.
- It also **correlates trivially** with sink #10: the plaintext `Entry.URI` in the very same record hands the attacker the pre-image for free, so even the dictionary is unnecessary in practice.

Conclusion: the current scheme is a **pseudonym with no confidentiality** for any host that is common, guessable, or present elsewhere in the record.

**Contrast — the primitive the tree already has the right way.** Support bundles mask sensitive strings via `internal/redaction.maskString` (redactor.go:296–305):

```go
h := hmac.New(sha256.New, r.salt)   // per-bundle random salt (redactor.go:94–97)
return "mask_" + hex.EncodeToString(h.Sum(nil))[:12]
```

This is a **keyed HMAC-SHA256, 12-hex token** — dictionary-*resistant* (an attacker without the salt cannot precompute). Its salt is per-bundle (correlate within a bundle, not across), which is right for bundles but wrong for fleet-wide traffic-log correlation. **The keyed-HMAC building block Option B needs is therefore already written, reviewed, and shipping.**

---

## 3. The A-vs-B decision (council analysis)

**Option A — Decryption-metadata-only redaction (honest scope-correction).** Rename the setting to say what it does (affects only `dec.host`/`dec.sni`), document it, and make the UI warn that the ordinary request-log host/URI remain plaintext.

**Option B — Full traffic-log destination privacy.** An opt-in, default-off global posture that pseudonymizes the destination **consistently across all sinks** — top-level `Host`, `URI`, and `dec.*` — using a **keyed HMAC** (stable, correlatable, not dictionary-recoverable).

| Axis | Option A | Option B |
|------|----------|----------|
| **Operational usability** | Zero migration cost, ships in a day. But delivers **no privacy capability** — the regulated admin still has no way to keep destinations out of the SIEM. | Real capability. Cost: operators who *enable* it see pseudonyms in the feed/logs; must be default-off so the mainstream operator is unaffected. |
| **SOC correlation** | N/A (nothing changes for SOC). | **Preserved** with keyed HMAC: the same host → same token across all records/nodes/time, so analysts still pivot/group/alert on the pseudonym. (The unsalted hash *also* correlates, but is reversible; the per-bundle salt does *not* correlate — HMAC-with-a-shared-key is the sweet spot.) |
| **Healthcare / regulated (HIPAA/PII)** | **Fails the requirement and is arguably worse than nothing** — a toggle labelled "redact" that ships PHI destinations to the SIEM creates false assurance and audit risk. | **Meets the requirement**: destination absent in plaintext from every persisted/streamed sink; pseudonym not dictionary-recoverable. This is the entire reason the axis exists. |
| **Migration & back-compat** | None. | On-disk history/JSONL written *before* enabling stay plaintext (documented; redaction is forward-only, matching the auto-exclude tunable precedent). Dashboards keep working (they render whatever token is stored). No schema change — `Host`/`URI` stay strings. |
| **Key management** | None. | Needs a dedicated pseudonym key. **Reuse existing at-rest mechanisms** — the CA-passphrase-derived PBKDF2 key (logstore.go:192 `EncKey`) / KEK envelope already protect the history store and admin secrets; store the pseudonym key the same way (0600, encrypted at rest, never in export/rollback/API/support-bundle — the exact posture `SessionHMAC`/`MetricsToken` already have). |
| **Fleet consistency** | N/A. | For cross-node correlation the key **must be byte-identical fleet-wide ⇒ must sync CP→DP**. Precedent exists: `SessionHMAC` is carried in `ConfigSnapshot` and zeroed for non-enrolled pullers (controlplane_server.go:116–125). This is a **secret-sync + redaction-parity hazard** (see §5) and is the single biggest risk. |
| **Incident response** | N/A. | Break-glass de-pseudonymization is **impossible by design** with a one-way HMAC (that is the point) — IR correlates on the token, and un-masking requires either a side keyed-lookup table (extra secret store) or leaving IR to correlate on the stable token + `IP`/`identity`. Recommend: **no reverse map** (keep it one-way); document that IR pivots on the pseudonym. |

**Why not stop at A.** A is *necessary* — we must not ship a false claim — but A alone concedes the product has no destination-privacy capability, in a wave whose stated target is healthcare/regulated. That is a gap, not a resolution.

**Why B is tractable (the decisive engineering facts).**
1. **One chokepoint.** `persistLogEntry` (store.go:1231) is the sole builder/fan-out for the ring, JSONL, history store, and syslog. Redacting `host`+`uri`+`dec` *there*, before the fan-out, gives all four sinks a **byte-identical contract for free** — this is a single-function change, not a per-sink retrofit. Read-side APIs (`apiLogs`, drill-down) then read already-redacted storage automatically.
2. **The primitive exists.** `internal/redaction` already implements keyed HMAC-SHA256→12-hex; B swaps the per-bundle salt for a fleet-stable key.
3. **The secret-sync precedent exists.** `SessionHMAC` already demonstrates a fleet-consistent secret synced CP→DP and redacted from non-enrolled pullers — the exact plumbing B's key needs.
4. **Opt-in/default-off defuses the mainstream/SOC objection.** Forward proxies (and PAN-OS, which Culvert mirrors) log plaintext destinations by default because the destination *is* the security signal; B changes nothing for that user because it is off by default. Only the regulated deployment turns it on.

---

## 4. Implementation plan (Option B)

**Phase B0 — honesty first (ship immediately, inside B).** Do Option A's correction as the first commit so no misleading claim exists during rollout: reword the `/api/decryption/redaction` setting + the SPA panel to state its *current* scope, and add the UI warning. This is throwaway-safe and de-risks the interim.

**Phase B1 — the redaction chokepoint.**
- New file `traffic_redaction.go` (main): `redactDestination(host string) string` and `redactURI(uri string) string`, both keyed HMAC over the host (URI redaction must **hash the host component and preserve/trim the path per policy**, so it cannot leak the host — see the URI-leak test below). Reuse `internal/redaction`'s HMAC construction or lift it to a shared helper so bundles and traffic logs share one implementation.
- **Single application point:** in `persistLogEntry` (store.go:1231), when the posture is on, replace `Host: host` / `URI: uri` with the redacted forms, and redact `auth.Dec.Host/SNI` via the **same** function (retire the separate `redactHost` weak hash — decryption_observability.go:424 — or repoint it at the keyed helper so `dec.*` and top-level share one contract).
- Because `apiLogs`/drill-down/export read from the ring/store/JSONL, they need **no change** — they inherit the contract. Verify no other builder writes `LogEntry.Host` bypassing `persistLogEntry` (grep shows only store.go:1238 and the decrypt-failure path, both routed here).

**Phase B2 — key management.** Provision a dedicated `TrafficPseudonymKey` (32 random bytes): generated on first enable, persisted encrypted-at-rest under the existing KEK/CA-passphrase mechanism (mirror logstore `EncKey`), 0600, and given the `SessionHMAC`/`MetricsToken` non-export posture (off export/import, off rollback, redacted from `GetConfig` for non-enrolled nodes, never logged/audited/in support bundles).

**Phase B3 — fleet consistency.** Add the key to `ConfigSnapshot` **only** when fleet correlation is desired, with the CP→DP redaction-parity guard (§5). Default: node-local key (no sync) unless the operator opts into fleet correlation, because a synced secret is a strictly larger blast radius.

**Guaranteeing one identical contract across sinks:** a **single** `redactDestination`/`redactURI` pair, called **only** inside `persistLogEntry`, is the mechanism — not per-sink redaction. Enforced by a cross-sink test (below) that drives one request and asserts the ring, JSONL, store, and a syslog capture all show the identical token and zero plaintext.

**Hot-path allocation budget.** `persistLogEntry` is off the latency-critical decision (it runs at request/tunnel close, and the projection comment at store.go:1205 already notes this), but it is still per-request. Budget: **≤ 2 short-lived allocations** per redacted record (one HMAC state via `sync.Pool`, one 12-byte hex string per field). The keyed hash is ~microseconds; the existing benchgate lane must gain a `persistLogEntry`-with-redaction benchmark asserting no regression beyond the accepted budget, and the CONNECT decision hot path must remain untouched (redaction stays at close, never at decision).

**Test map (required):**
- *Sink inventory test* — enumerate every sink that can carry a destination; fail if a new sink appears un-routed through the redactor (mirrors the `uiRoutes`/`configSurfaces` anti-drift walls).
- *Cross-sink identical-contract test* — one request → ring, JSONL, store, syslog capture all carry the **same** token for a host.
- *No-plaintext-in-full-mode test* — with the posture on, assert the raw host string appears in **none** of `Entry.Host`, `Entry.URI`, `dec.host`, `dec.sni` across all sinks.
- *Correlation-stability test* — same host across two records/two nodes → same token (with a shared key).
- *Different-keys→different-pseudonyms test* — two keys → different tokens for the same host (proves keying).
- *No-secret-key-leak test* — key never appears in `/api/logs`, `/api/config` export, rollback snapshot, `GetConfig` for a non-enrolled node, or a support bundle.
- *Rotation test* — rotating the key changes tokens going forward; historical tokens keep their old value (documented correlation break).
- *URI-can't-leak-host test* — a redacted `Entry.URI` must not contain the plaintext host substring.
- *Search/filter-under-redaction test* — `GET /api/logs?host=…` hashes the query term with the active key and matches redacted storage (exact match works; document that substring/glob filtering degrades).
- *Bounded-cardinality test* — tokens are fixed-length (12 hex), so top-hosts/label cardinality is unchanged.
- *No-alloc-regression benchmark* — `persistLogEntry` stays within the allocation budget.

---

## 5. Key-management & fleet-consistency risk flags (Option B)

1. **Where the key lives.** Reuse the existing at-rest envelope — the CA-passphrase/PBKDF2 key that already encrypts the history store (logstore.go:178–208) and the KEK path — rather than inventing a new secret store. Same 0600 + encrypted-at-rest posture as `MetricsToken`/`SessionHMAC`.
2. **CP→DP sync is required for correlation, and it is a secret-sync hazard.** A stable *cross-node* pseudonym is only possible if every node holds the identical key, so the key must ride `ConfigSnapshot` like `SessionHMAC`. That inherits `SessionHMAC`'s redaction obligation: it **must** be zeroed in the non-enrolled `GetConfig` block (controlplane_server.go:116–125) and walled by `config_surfaces_test.go`. **Redaction-parity failure mode:** if the posture is on but the key fails to reach a DP (sync gap, rollback, un-upgraded node), that DP either (a) has no key and silently logs **plaintext**, or (b) has a *different* key and produces tokens that don't correlate — a regulated customer would get a silent PHI leak on one node. Mitigation: **fail-closed** — a node with the posture on but no valid pseudonym key must refuse to emit the destination at all (drop to a constant `"redacted"` sentinel), never fall back to plaintext.
3. **Rotation breaks historical correlation.** Rotating the key means post-rotation tokens differ from pre-rotation tokens for the same host, so time-series correlation across the rotation boundary breaks. This is inherent to one-way keyed pseudonyms. Surface it explicitly: an audit event + a dashboard banner on rotation ("destination pseudonyms rotated at <ts>; correlation across this boundary is not possible"), and keep rotation a deliberate, rare, admin-only action.
4. **No reverse map (deliberate).** Do not build a de-pseudonymization table — it would become the single most sensitive artifact in the system and re-introduce the leak. IR correlates on the stable token plus `IP`/`identity`; document this as the break-glass posture.

---

## Verdict

**RECOMMEND OPTION B** (opt-in, default-off, keyed HMAC, applied at the single `persistLogEntry` chokepoint, with Option A's honesty fix as its first step).

**Single most important reason:** every sink already fans out from one function (`persistLogEntry`, store.go:1231) and the keyed-HMAC primitive + fleet-secret-sync precedent already exist in the tree — so a truthful, non-dictionary-recoverable, still-correlatable destination-privacy posture is genuinely achievable and is the only option that satisfies the regulated requirement this wave targets, whereas Option A ships a privacy toggle that provides no privacy.

**If B: key-management approach** — a dedicated 32-byte `TrafficPseudonymKey`, encrypted at rest under the existing CA-passphrase/KEK envelope, with the `SessionHMAC` non-export + CP→DP-with-redaction posture. **Biggest risk** — redaction-parity across the fleet: a node that has the posture on but is missing/rolled-back the synced key must **fail closed to a constant sentinel, never to plaintext**, or a regulated customer silently leaks PHI destinations on that node.
