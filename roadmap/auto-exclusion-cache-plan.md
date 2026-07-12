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
