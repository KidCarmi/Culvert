# Adaptive Decryption Exclusion — Auto-Learn + Fail-Open (plan)

Status: PLAN (pre-implementation). Authority for the "auto-exclusion cache /
fail-open" work item deferred out of the Decryption Profile program (#688).

## 1. Problem & goal

A TLS-terminating SWG cannot inspect every origin. Two failure classes break an
inspected (`SSLAction=Inspect`) CONNECT tunnel today with a hard `502`/close and
**no self-healing**:

1. **Origin cert-verify failure** — the origin presents a chain Culvert cannot
   verify (private PKI we don't trust, an origin that requires a client
   certificate, an expired/mismatched leaf). Strip path: `proxy_tunnel.go:579`;
   native path: `handshakeUpstreamALPN` (`proxy_tunnel_h2.go:228`).
2. **Client cert-pinning rejection** — the client (a pinned mobile app, a
   Google/Apple native client) refuses our forged leaf and aborts its own
   handshake. Strip path: `proxy_tunnel.go:661`; native path:
   `proxy_tunnel_h2.go:177`.

Both are *"this host is incompatible with inspection"* signals. A commercial SWG
(PAN-OS) handles this with a **local decryption-exclusion cache**: on a
decryption failure it records the server for ~12h and **future sessions to that
server bypass decryption automatically** (fail-open), so a pinned app or private
origin keeps working after the first stumble instead of staying broken until an
operator hand-adds a bypass pattern.

Culvert has the **manual** half already (`internal/sslbypass` — operator-authored
bypass patterns). This work adds the **adaptive** half: learn the exclusion from
the failure, apply it to subsequent sessions, expire it, and make every part of
it visible and operator-controllable.

**Goal:** an opt-in, per-profile *fail-open* action that (a) records a broken
host into a bounded TTL auto-exclusion cache, (b) where the session hasn't yet
committed to the client, transparently rescues the *current* session via bypass,
and (c) causes subsequent CONNECTs to that host to bypass inspection until the
entry expires — all observable (metrics + audit + a read-only UI list) and
manually clearable.

## 2. Non-goals / explicit scope boundaries

- **Not** a global auto-bypass. Only rules whose decryption profile opts into
  `fail-open` populate the cache. Fail-closed stays the default and today's
  behavior is byte-identical when nothing opts in.
- **Not** persisted across restart. PAN-OS's local exclusion cache is volatile;
  we match that. In-memory only ⇒ it stays OFF every config surface
  (export/import, rollback, CP→DP snapshot) — no `config_surfaces.go` row, no
  parity-test entanglement. A restart re-learns cheaply. (Reviewer question:
  should the cache sync CP→DP? Default answer: **no** for v1 — each DP learns its
  own origins; documented.)
- **Not** re-opening `permissive` cert-verification or `OnUnsupported`
  enforcement (both still deferred). This feature's trigger set is
  cert-verify-failure + client-pinning-rejection, which is *distinct* from
  `OnUnsupported` (TLS version/cipher below floor). See §7 for the consolidation
  question we want reviewers to rule on.
- **Not** a live rescue on the native-ALPN path or the client-pinning path —
  those are **learn-only** (next session self-heals). Only the strip path
  rescues the live session (§4.3). This asymmetry is inherent to where the `200`
  is sent relative to each handshake, and is documented, not hidden.

## 3. The two mechanisms

### 3.1 Auto-exclusion cache — `internal/autoexclude`

A new pure engine (mirrors `sslbypass`/`decryptprofile` decomposition):

- `Cache` struct: `map[host]entry` under `sync.RWMutex`; `entry{reason, learnedAt, expiresAt}`.
- `Record(host, reason)` — insert/refresh with `ttl` from now; bounded at
  `maxEntries` (default 4096) with an amortized decay/prune pass (mirror the
  `topHosts` cap pattern — host is attacker-influenced, so the map must not grow
  unbounded).
- `Contains(host) (reason, bool)` — hot-path read; lazily treats an expired entry
  as absent (no background sweeper needed on the read path).
- `List() []Entry` — snapshot for the API (drops expired).
- `Remove(host) bool`, `Clear() int` — manual operator control.
- `Prune() int` — periodic background eviction (wired to an existing ticker
  loop; keeps `List()`/gauge honest without relying on read traffic).
- `Len() int` — gauge source.
- TTL is a construction param (default `12h`, matching PAN-OS); host is
  normalized via `hostutil.NormalizeHost` so cache keys match the matcher/policy
  key space exactly.

Package `main` keeps the singleton `autoExclude`, the resolver hooks, the API
handlers, and the UI — same shim pattern as every other engine.

### 3.2 Fail-open action — a decryption-profile field

Add to `decryptprofile.Profile`:

```go
// OnInspectError posture when an inspected tunnel fails to establish
// (origin cert cannot be verified, or the client rejects the forged leaf):
// "" inherit (fail-close, today's behavior) | "fail-close" (502/drop) |
// "fail-open" (record the host in the auto-exclusion cache; bypass the current
// session where it has not yet committed to the client, and bypass subsequent
// sessions to the host until the entry expires).
OnInspectError string `json:"onInspectError,omitempty"`
```

- Validation: `validOnInspectError = {"", "fail-close", "fail-open"}` in
  `Validate` (enforced on Add/Update/ReplaceAll — closes the import/snapshot
  bypass, same as every other enum).
- Resolver `resolveFailOpen(match) bool` in `decryptprofile_resolve.go`:
  `true` iff the matched rule's profile sets `OnInspectError=="fail-open"`.
  Fail-safe at eval: a dangling profile ref ⇒ `false` ⇒ fail-closed (a bad
  reference can NEVER newly-disable inspection — consistent with the existing
  fail-safe-at-eval invariant).

Because it's a profile field it **automatically rides** the `decryption_profiles`
config surface (already `WireWipeCapable`, in snapshot/rollback/export/import). No
new surface row; the parity tests just need the new field exercised in the
existing round-trip fixtures.

## 4. Hot-path wiring

### 4.1 `resolveSSLAction` — consult the cache (the self-heal read)

```go
func resolveSSLAction(match, host, clientIP) (SSLAction, bool) {
    // ... existing rule + smart-bypass logic → sslAction ...
    if sslAction == SSLInspect {
        if reason, ok := autoExclude.Contains(host); ok {
            sslAction = SSLBypass
            autoExcludeHitCounter.Add(1)
            logger.Printf("SSL_AUTOEXCLUDE_BYPASS %s -> %q (reason=%s)", clientIP, sanitizeLog(host), reason)
        }
    }
    return sslAction, tlsSkipVerify
}
```

- Consulted **globally** for any Inspect decision (mirrors PAN-OS: once a server
  is in the local cache, all sessions to it are excluded). Population is still
  gated to fail-open rules (§4.2), so a deployment with zero fail-open profiles
  has an always-empty cache and unchanged behavior.
- Ordering: cache check runs **after** the explicit `sslBypass.Matches` override
  (an operator pattern and a learned entry both land on bypass; order is moot but
  keep the explicit-operator log line first).

### 4.2 Learning — record on qualifying failure (gated on fail-open)

At each of the four failure sites, when `resolveFailOpen(match)`:

- `recordAutoExclude(host, reason)` → `autoExclude.Record` + counter
  `culvert_decrypt_autoexclude_total{reason}` + **one audit event**
  (`decryption.autoexclude.learn`, object=host) so the security-relevant act of
  auto-disabling inspection for a host is in the audit ring, not just a log line.
- Reasons (bounded label set): `origin_cert` (upstream verify/handshake fail),
  `client_pinned` (client rejected forged leaf).

Sites:
- `handleTunnelInspect` upstream handshake fail (`:579`) → `origin_cert` + live
  rescue (§4.3).
- `handleTunnelInspect` client handshake fail (`:661`) → `client_pinned`
  (learn-only; 200 already sent).
- `handshakeUpstreamALPN` fail (native, `:228`, surfaced at `:164`) →
  `origin_cert` (learn-only; 200 already sent).
- `handleInspectNativeALPN` client handshake fail (`:177`) → `client_pinned`
  (learn-only).

### 4.3 Live rescue — strip path only

In `handleTunnelInspect`, the upstream handshake at `:579` happens **before** the
`200`/hijack. On failure with fail-open, instead of `502` we:

1. Close the failed `upstreamTLS` (its TLS state is dead) and **re-dial** a fresh
   plain-TCP `rawUpstream` to the same `targetHost` (SSRF-guarded, same
   `ssrfControl` dialer). Re-dial rather than reuse because `tls.Client` wrapping
   consumed the original conn.
2. Delegate to a bypass relay: hijack, send `200`, splice client ↔ new upstream
   (the client does its own TLS directly to the origin — transparent). This is
   exactly `handleTunnelBypass`'s body; extract the post-dial half into a shared
   `relayBypassRawDial(w, r, rawUpstream, match, id, "autoexclude")` helper and
   call it from both the normal bypass path and here. Record a `TUNNEL_CLOSED`
   entry tagged `autoexclude` for the disposition column.
3. All other failure sites are learn-only: they `recordAutoExclude` then fall
   through to today's teardown. The next CONNECT to the host hits §4.1 and
   bypasses cleanly with no failed handshake.

**Client-pinning note:** the strip path's client handshake (`:661`) is *after*
the `200`, so it is learn-only too. Only the origin-cert failure at `:579` is
early enough to rescue live. This is the honest boundary; the doc states it.

## 5. Admin API + UI (GUI parity)

**Profile field:** `OnInspectError` dropdown in the existing decryption-profile
editor (`fail-close` default / `fail-open`). No new panel.

**Auto-exclusion cache surface** — new read-mostly panel + endpoints:

- `GET  /api/decryption-exclusions` (viewer) — list learned entries
  (host, reason, learned_at, expires_at, ttl_remaining_secs).
- `DELETE /api/decryption-exclusions?host=<h>` (operator) — evict one.
- `DELETE /api/decryption-exclusions` (operator) — clear all (audit
  `decryption.autoexclude.clear`).
- uiRoutes rows (method-aware: GET viewer, DELETE operator); D0/C1 route-count
  bumps.
- SPA: nav-item `decexclusions`, a `#view-decexclusions` table (host / reason /
  learned / expires / [evict]) + a "Clear all" button, `viewMeta`, switchView
  dispatch, `data-click` handlers, `escHtml`. Honest positioning copy: this is a
  **compatibility/availability** control (learned decryption exceptions), and each
  entry means "inspection is currently OFF for this host" — surfaced in warn
  color with the expiry.

The cache is a runtime observability surface (like the live request feed), so it
is intentionally **not** on export/import/rollback. The panel says so.

## 6. Metrics

- `culvert_decrypt_autoexclude_total{reason}` — learn events (counter,
  cardinality-capped reason set: `origin_cert`, `client_pinned`, `_other_`).
- `culvert_decrypt_autoexclude_hit_total` — sessions bypassed due to a cache hit
  (counter).
- `culvert_decrypt_autoexclude_active` — current cache size (gauge, scrape-time
  `autoExclude.Len()`), so an operator can alert on "inspection coverage eroding".

Mirror `decProfMintlsRejects.writePrometheus` for the labeled counter (inline
`strings.ReplaceAll` sanitize so CodeQL sees the guard).

## 7. Open questions for the reviewer panel

1. **Consolidate with `OnUnsupported`?** Both are `fail-close`/`fail-open`.
   `OnUnsupported` (deferred) = TLS version/cipher below floor; `OnInspectError`
   (this work) = cert-verify + pinning. Keep distinct (different triggers,
   clearer audit reasons) or fold into one `onDecryptFailure` knob? Recommend
   **keep distinct** but wire `OnUnsupported=fail-open` to the SAME learn+rescue
   plumbing if cheap — TBD by reviewers.
2. **Cache poisoning risk.** An attacker who can force a decryption failure for a
   host (present an unverifiable cert; drive a client that pins) could push that
   host into the exclusion cache → inspection off for everyone for the TTL →
   exfil channel. Mitigations proposed: opt-in only, bounded+TTL, audit on every
   learn, visible+clearable, and a per-host learn only from a *genuine* TLS-layer
   failure (not arbitrary 5xx). Is that sufficient, or do we need (a) a shorter
   default TTL, (b) a confirm-count (N failures before excluding), or (c)
   scoping the exclusion to the client population that triggered it? Reviewer
   call.
3. **CP→DP:** learn locally per DP (recommended) vs. sync exclusions from CP?
4. **Live rescue on native path** worth a re-dial+relay, or leave learn-only?
   Recommend learn-only for v1 (self-heals in one retry).
5. **Voice-of-customer:** does auto-fail-open actually help the real cases
   (pinned mobile apps, corporate SaaS with private PKI, Google clients), or do
   customers expect the *first* session to also succeed (i.e. is learn-only a
   support-ticket generator)?

## 8. Slices (one PR)

- **S1 — engine + field:** `internal/autoexclude` (+ tests), `OnInspectError`
  field + validation, resolvers (`resolveFailOpen`, `recordAutoExclude`),
  singleton + startup wiring (TTL flag/const), background `Prune` on an existing
  ticker.
- **S2 — hot path:** `resolveSSLAction` cache consult, four learn sites, strip
  live rescue via `relayBypassRawDial`, metrics + audit. Byte-identical when no
  profile opts in (regression-pinned).
- **S3 — API + UI:** endpoints, uiRoutes, D0/C1 bumps, SPA panel + profile-editor
  dropdown, honest positioning.
- **S4 — parity + docs + gate:** config-surface test exercises `OnInspectError`
  in the decryption_profiles round-trip; Prometheus exposition; operator doc
  `docs/operator/decryption-auto-exclusions.md`; determinism + full `-race`;
  4-reviewer code gate (PAN-OS architect, config/security, config-arch,
  voice-of-customer).

## 9. Invariants preserved

- Fail-closed default; opt-in only; byte-identical when unused.
- Fail-safe at eval (dangling profile ⇒ fail-closed, never newly-disables).
- One enforcement path (`resolveSSLAction` is the sole SSL-action decision; the
  cache is an input to it, not a second path).
- Bounded, attacker-aware cache (TTL + cap + decay, mirroring `topHosts`).
- GUI parity (every knob has an API + panel); audit on every inspection-disabling
  act; observable via metrics.

---

# v2 — reviewer consolidation (4-seat panel)

Four independent reviewers pressure-tested the v1 plan: a PAN-OS SWG architect,
a config/security architect, a config-arch/codebase-fit engineer, and a
voice-of-customer/field-CISO. Their findings converge on a **reframe of the
trigger set** plus a set of hard guardrails. This section is authoritative where
it differs from §1–§9 above.

## V2-1 — Trigger set REFRAMED (PAN-OS M1/M2, Security M1)

The v1 premise ("learn on origin cert-verify failure") was backwards. A real SWG
does NOT auto-exclude on an untrusted/expired/name-mismatch origin cert — that is
a **Block** decision, and auto-bypassing it is precisely the poisoning/exfil
vector (an on-path attacker presents a bad cert → earns a TTL-long uninspected
channel). Reclassify the inspect-handshake failure into learnable vs not:

| Reason | Trigger | Learn? | Live rescue |
|---|---|---|---|
| `unsupported` | TLS version/cipher/protocol incompatibility (the canonical PAN-OS trigger) | YES | strip path |
| `client_cert_required` | origin sent `CertificateRequest`; we cannot present a client cert (server-observed, non-spoofable) | YES | strip path |
| `client_pinned` | client rejected our forged leaf with a cert alert (`bad_certificate`/`unknown_ca`/`certificate_*`) | YES, **guarded** (confirm-count, shorter TTL) | none (post-`200` in BOTH paths — inherent) |
| `origin_cert_verify` | untrusted issuer / expired / hostname mismatch | **NO** — stays a `502` (today's behavior) | — |
| `other` | EOF / RST / network / unrecognized | **NO** — fail-closed default | — |

A new `classifyInspectFailure(err)` maps the handshake error to one of these.
**It defaults to no-learn:** only a positive match on `unsupported` /
`client_cert_required` (origin leg) or a client cert-alert (client leg) learns;
every unrecognized error keeps today's `502`. Misclassification therefore can
only ever fail *closed* (inspect/block), never wrongly bypass. Classification is
`errors.As` on `*tls.CertificateVerificationError` + `x509.UnknownAuthorityError`/
`CertificateInvalidError`/`HostnameError` for the do-NOT-learn `origin_cert_verify`
bucket, and substring matching on the known TLS alert descriptions for the
learnable buckets (brittleness is safe because the default is no-learn).

This reframe also **resolves the private-PKI "root-cause masking" concern** (VoC
Scenario B): an untrusted corporate-CA origin now stays a hard `502`, surfacing
"add this CA and keep inspecting" instead of silently going dark.

`unsupported` folds the previously-deferred `OnUnsupported=fail-open` into the
SAME plumbing (PAN-OS M2): ONE operator knob (`OnInspectError=fail-open`), with
distinct audit/metric *reasons*. `OnUnsupported` stays a documented, superseded
no-op for fail-open purposes.

## V2-2 — Confirm-count over DISTINCT client IPs (Security M1, VoC #1, PAN-OS M4)

A host does not enter the active cache on the first failure. The engine holds a
**pending observation** per `(host, reason)` accumulating the set of *distinct
client IPs* that hit a qualifying failure within a rolling `window` (default
10m). Only when `len(distinctIPs) >= confirmN` (default **2**) is the host
promoted to an active exclusion. This single mechanism does the heavy lifting:

- A single malicious/insider endpoint cannot self-poison (one IP never reaches
  the threshold) — closes the `client_pinned` forge vector.
- A genuine fleet-wide pinned app trips failures from many devices and crosses
  the threshold almost immediately — the flagship UX still self-heals fast.
- A transient single-origin blip (one client, one moment) does not disable
  inspection for 12h (VoC edge-case 5.1).

Promotion (`Observe` → `promoted=true`) is the security-relevant event that fires
the audit + alert + metric. `client_pinned` entries get a **shorter TTL**
(`pinnedTTL`, default 1h) than the server-observed reasons (`ttl`, default 12h)
because the client signal is the spoofable class (PAN-OS N4/M4, Security S1).

## V2-3 — Cache READ gated on fail-open (Security M2, PAN-OS M3/N3, config-arch S4)

`resolveSSLAction` consults the cache **only when `resolveFailOpen(match)`** for
the session's matched rule — NOT globally. Consequences:

- A **fail-close rule never consults the cache** ⇒ hosts covered only by
  fail-close rules can never be auto-bypassed. **This is the never-exclude /
  force-inspect control** (Security M3, PAN-OS N1/M3): keep the IdP/SSO, banking,
  software-update, DLP-critical origins on fail-close rules and they are
  un-poisonable by design — no separate list needed for v1.
- Kills the cross-policy downgrade leak (a fail-open rule's learned entry cannot
  silently bypass a *different* inspect-mandatory rule for the same host).
- Makes "byte-identical when unused" airtight: with zero fail-open profiles the
  cache is never read AND (per V2-2 gating) never written.

Deliberately more conservative than PAN-OS's per-firewall global cache;
documented as such. `sslBypass.Matches` (explicit operator bypass) still wins
first; precedence is **manual ssl-bypass > auto-exclusion (fail-open rules only)
> policy inspect**.

## V2-4 — SSRF inline on the live-rescue re-dial (Security M4)

The strip-path rescue re-dials the origin and raw-relays. There is **no new
TOCTOU** (the re-dial re-resolves DNS and `ssrfControl` rejects a private result
at connect time exactly as the first dial does), but the re-dial MUST reproduce
`isPrivateHost(targetHost)` + the `ssrfControl` dialer **inline at the call site**
(CodeQL visibility + CLAUDE.md convention), not via a helper that hides the guard.
A test asserts the rescue path dials through `ssrfControl` (rejects a
private-IP-rebinding origin). `relayBypassRawDial` must be unreachable with a
dialer lacking `Control: ssrfControl`.

## V2-5 — Host-only normalization on BOTH read and write (Security M5, config-arch M6)

The engine normalizes with `hostutil.NormalizeHost` **inside** `Record`/`Observe`
AND `Contains` (do not trust call sites; `resolveSSLAction` passes raw `host`),
and keys on **host-only** (port stripped — the matcher/`sslBypass` space is
host-only; keying `host:443` lets a port-varying attacker evade the operator's
mental model / the fail-close scoping). Pinned by a test that `EXAMPLE.com.` and
`example.com` collide.

## V2-6 — Observability upgraded from pull to push (VoC #2/#3/#5, PAN-OS N6)

- **Alert on learn:** promotion fires `fireAlert("decryption_autoexclude", …)` so
  the inspection-went-dark event reaches syslog/SIEM, not just the 500-entry
  audit ring. This is what makes the feature acceptable to regulated buyers
  instead of disqualifying (VoC Scenarios B/C).
- **Audit on learn + evict + clear** (all three), actor = triggering client IP
  (sanitized) on learn so a poisoning source is traceable (Security S2).
- **Blast-radius fields** in the list/API: per-entry **hit count** (how much
  traffic rode the bypass) + `learned_at` / `expires_at` / `ttl_remaining_secs`,
  so the security team can triage benign-vs-exfil. Per-*hit* audit is
  deliberately omitted (would flood); metric + per-entry counter suffice.
- **Provable OFF state:** `/api/decryption-exclusions` reports config
  (`confirm_n`, `ttl`, `pinned_ttl`, active/pending counts) so an operator can
  show an auditor the feature's posture; a deployment with no fail-open profile
  shows an empty, inert cache.

## V2-7 — Engine mechanics (config-arch S1/S2/S3)

- **No dedicated Prune goroutine.** Follow the `topHosts` precedent: `List()` and
  `Len()` filter expired at call time (the gauge is scrape-time), and the bounded
  eviction (expired-first, then oldest `learnedAt`) runs **amortized inside
  `Observe`**. Eliminates the ticker, its shutdown wiring, and the test-start
  hazard. Eviction direction is safe (evicting = re-enabling inspection =
  fail-closed), so a distinct-host flood only restores inspection.
- **Injected clock:** `now func() time.Time` (defaults to `time.Now`) so
  expiry/window tests never `time.Sleep` (determinism gate re-runs `-shuffle`).
- **Placement:** a distinct pure engine `internal/autoexclude` (NOT folded into
  `sslbypass`, which is persisted + config-synced, nor `decryptprofile`, which is
  validated persistent storage — wrong lifecycles). Package `main` keeps the
  `autoExclude` singleton + resolvers + API + UI (ADR-0002 shim pattern).

## V2-8 — Config-surface / parity seams that have NO reflection guard (config-arch M1/M2)

The `DecryptionProfile` inner struct is hand-enumerated in two places that no
reflection test forces to update:

- `configversion.go:680 sameDecryptionProfile` — **add `x.OnInspectError ==
  y.OnInspectError`** or a rollback that changes only this field reports "no
  change" and the dry-run lies.
- `config_surfaces_test.go` fixtures — set `OnInspectError` to a non-default in
  the seed/diff states (`:199`, `:315/316`, `:431`, `:457`) so the round-trip and
  diff paths actually exercise the field surviving `ReplaceAll`/`copyOut`.

`Validate` (add `validOnInspectError`) covers all three write paths
(Add/Update/ReplaceAll) — no import/snapshot bypass. `copyOut` needs no change
(`OnInspectError` is a value `string`). No new `config_surfaces.go` row (the
registry binds the top-level slice; the cache is a separate global off all
surfaces). All confirmed clean by the config-arch review.

## V2-9 — API RBAC/metadata correctness (config-arch M4/M5)

One `uiRoutes` path `/api/decryption-exclusions` with TWO `Methods` rows
(GET→viewer, DELETE→operator), NOT `MethodAny`. The handler branches on method
with a **per-branch `requireRole`** (viewer on GET, operator on DELETE) or it
trips C1.5 AST parity / fires C4 role-divergence. **Both** DELETE variants
(single-host `?host=` evict AND clear-all) must emit an `auditEvent` or C2c logs
`audit_missing`. D0 canonical route count is **+1 path** (both methods share it).

## V2-10 — Global-singleton test discipline (config-arch M3 — the PR3d fence class)

`autoExclude` is the same global-mutable-state hazard that caused the PR3d
determinism-gate failure. Mandatory:

- `swapAutoExclude(t)` helper (mirrors `swapDecProfileStore`, decryptprofile_api_test.go:14):
  stash + install a fresh empty cache + `t.Cleanup` restore. Every test touching
  `Observe`/`resolveSSLAction` uses it.
- A regression pin that `resolveSSLAction` with an empty cache is **byte-identical
  to today** (empty-map `Contains` → false → dead block).
- Learn emits an audit event into the 500-entry ring → tests assert on entry
  **content** (unique discriminator: a TEST-NET client IP + action + baseline
  `TS`), never `len(auditGet())` deltas.

## V2-11 — Explicit v1 scope vs deferrals

**In v1 (this PR):** the reframed trigger set + classifier; confirm-count
(distinct IPs); fail-open-gated read; strip-path live rescue (unsupported +
client_cert_required) with inline SSRF; client_pinned learn-only (guarded);
`OnInspectError` field + validation + resolver; `internal/autoexclude` engine
(injected clock, amortized prune, hit-count, host-only normalize); API + UI panel
+ profile dropdown; alert + audit + metrics (`learn_total{reason}`, `hit_total`,
`active` gauge, `pending` gauge); parity (V2-8/9/10); operator doc.

**Deferred to v1.1 (documented, with rationale):**
- **Predefined curated pinned-app list** (Apple/Dropbox/Windows-Update/… as a
  versioned content feed) for *first-session* success on KNOWN pinned apps
  (PAN-OS N1). v1 documents the precedence and recommends operators add known
  pinned apps to the manual `ssl-bypass` list for first-contact success.
- **Native-path live rescue** (re-dial+relay for the H2 path) — v1 is learn-only
  there and documents the strip-vs-native fail-open asymmetry (PAN-OS N2, VoC #6).
- **`learn-review` third posture** (record+alert, bypass only after operator
  approval) — the enum is designed to admit it later (VoC #7).
- **Weekly compliance digest**, **adaptive TTL**, **broad-profile UI guardrail /
  admin-role gate on enabling fail-open** (VoC #4/#8/#9) — v1 surfaces a UI
  warning when fail-open is enabled; the rest is v1.1.

## V2-12 — The honest customer-facing framing (VoC)

This is a **compatibility/availability** control that is *also* a security
decision, so the product must never make it quietly. First-contact with a
never-seen pinned host still fails (inherent — you cannot rescue a client that
refuses your cert without prior knowledge; PAN-OS solves this only via its
predefined list, deferred here). The doc states plainly: expect one failed
connection per newly-incompatible host per TTL window; use the manual bypass +
(future) predefined list for guaranteed first-session success; and every host the
proxy stops inspecting is alerted, audited, listed with its blast radius, and
clearable.

---

# v3 — post-merge-review blocker resolution (PR #693)

A follow-up security review of the implemented PR raised six merge-blockers. All
are resolved on the branch; this section is authoritative where it differs above.

- **B1 — Scoped key (policy isolation).** Exclusions are keyed by
  `(scopeID, host)` where `scopeID` is the matched decryption profile's identity
  (`resolveDecryptionProfile(match).ID`), NOT host-only. `Observe`/`Contains`/
  `Remove` all take the scope; `resolveSSLAction` consults within the session's
  profile scope only. A host learned under profile A can never bypass profile B's
  rule. §4.1's "consulted globally" is SUPERSEDED — consumption is scoped, which
  also subsumes the cross-policy-leak concern. Scope + per-scope rule blast-radius
  surfaced in the API (`scope_rule_counts`), metric label (`{reason,scope}`), UI
  (Profile + Rules columns), and audit (object = `scope/host`). Pinned by
  `TestScopeIsolation` + `TestResolveSSLAction_CrossScopeContamination`.

- **B2 — Tightened classifier.** An origin controls its own TLS alerts, so the
  learnable origin set drops the generic/origin-emitted strings (`handshake
  failure`, broad `unsupported`, `no application protocol`). It keeps only the
  specific `certificate_required` alert and the LOCAL Go param-mismatch strings
  (`no supported versions satisfy`, `server selected unsupported protocol
  version`, `no cipher suite supported by both`). Unknown/ambiguous/wrapped/
  cert-verify → fail-close. Negative tests cover generic alerts, wrapped errors,
  transport failures, and origin-controlled rejection.

- **B3 — Restricted live rescue.** `classifyOriginInspectFailure` returns a third
  `rescue` bool; only `client_cert_required` sets it. `maybeFailOpenOrigin`
  returns that bool, so ONLY client-cert-required live-rescues the triggering
  strip-path session; `unsupported_params` is learn-only. The §2/§4.3 "the strip
  path rescues on any server signal" is narrowed. Residual downgrade risk (origin
  controls the alert) documented in the operator guide, bounded by the per-profile
  opt-in + scope.

- **B4 — Distinct-client evidence.** The confirm-count counts distinct
  client-evidence tokens: authenticated `ProxyIdentity.Identity` (trustworthy,
  not a client header) when present, else the client IP — IPv6 collapsed to /64
  (single-host churn), IPv4 RAW (a /24 over-collapses NAT fleets). The engine
  treats the token opaquely; `clientEvidence` (main) owns the policy. NAT/DHCP
  limitation documented.

- **B5 — Config-schema / rollback.** `OnInspectError` is acknowledged as an
  additive PERSISTED profile field (a schema change, no new top-level surface).
  `TestOnInspectError_SchemaRoundTripAndDowngrade` proves forward round-trip AND
  that an older binary ignores the unknown key and degrades to fail-close.

- **B6 — Risk + rollout.** PR reclassified 🔴 High security. Operator guide gains
  a staged-rollout section (narrow profile first → watch panel + gauge + SIEM →
  expand; critical hosts stay fail-close). Independent security/SWG/Go reviewers
  re-run against the diff with focused cross-scope + ambiguous-TLS regression
  tests.
