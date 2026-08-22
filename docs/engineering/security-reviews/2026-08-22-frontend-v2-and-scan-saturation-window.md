# Security Regression Review — Frontend V2 (FE-1A…FE-4), Scan-Saturation Chaos (CHAOS-52), Connection-Limiter Sharding

- **Date:** 2026-08-22
- **Reviewer role:** Security Regression Engineer (standing charter, `docs/engineering/ENGINEERING-CONSTITUTION.md`)
- **Baseline:** `7df2677` (tip of the 2026-08-21 review)
- **Tip under review:** `fdad525`
- **Window:** PRs #1187–#1194 — 198 files, ~43k insertions. Dominated by
  #1194 (the new React admin frontend + the ADR-FE-002 Monitor query contract)
  and the CHAOS-52 body-scan saturation work; #1187/#1188/#1190/#1191/#1192/#1193
  are the chaos, ADR-renumber (ADR-0025 → ADR-0027 for the LDAP IdP), and
  compose-hardening slices.

## Verdict

**One security regression found and fixed.** It is an information-disclosure
regression on an unauthenticated surface, introduced by an otherwise correct
and welcome hardening change (warning an operator that the admin login page is
being served in cleartext).

Everything else in this window is either byte-faithful to the baseline or
**strictly tighter**. Two changes close real pre-existing security defects; see
"What got safer".

| ID | Finding | Severity | Class | Status |
|----|---------|----------|-------|--------|
| SEC-TLSFB-1 | The raw self-sign error string is published on two **unauthenticated** endpoints (`/api/setup/status`, `/api/auth/status`), where it can carry an operator-configured SAN or the appliance's own host name | **Low** | CWE-209 (Generation of Error Message Containing Sensitive Information) · CWE-200 · OWASP A01 (Broken Access Control) | Fixed + pinned |

---

## SEC-TLSFB-1 — Unauthenticated disclosure of the TLS self-sign error

**Files:** `ui.go` (`uiTLSFallbackReason`), `ui_auth.go` (`jsonOKAuthStatus`,
`apiSetupStatus`)
**Introduced by:** PR #1189, the admin-UI cleartext-warning slice.

### What changed

`startUI` now records why self-signed TLS generation failed and the product
surfaces it, so an operator no longer learns "the admin panel is plaintext"
only by noticing a missing padlock:

```go
uiTLSFallbackActive = true
uiTLSFallbackReason = err.Error()      // ui.go
```

The **flag** is exposed on three endpoints. Two of them —
`/api/setup/status` and `/api/auth/status` — are on the unauthenticated
allowlist (`isPublicUIAuthPath`), deliberately and correctly: a browser about
to submit the initial admin password, or a password on the login overlay, must
be able to render the warning *before* a session exists. That part of the
design is right and is preserved.

The **cause** was shipped alongside it on both of those public endpoints.

### Why that is a regression

`uiTLSFallbackReason` is a raw `error` string from `uitls.SelfSigned`, and the
errors that path can produce are not content-free. Go's x509 encoder embeds the
offending value in its own error text — `x509: "<name>" cannot be encoded as an
IA5String` — and `uitls.collectSANs` feeds that encoder three operator/host
inputs: `--ui-san` / `ui_sans` entries, `CULVERT_PUBLIC_IP`, and
**`os.Hostname()`**. So the reachable worst case is an internal host name or an
operator-configured internal SAN returned verbatim to any unauthenticated
client that can reach the admin port.

That also breaks a rule this repository already applies everywhere else. The
readiness rows adopted it explicitly, for exactly this reason:

> FIXED detail because the endpoint is unauthenticated (same rule as the
> ca/clamav rows) — `appendFrontendV2ReadinessCheck`, `ca_health.go`,
> `cluster_ca_health.go`

`/ready` carries a fixed sentence; the cause goes to the log and to the
authenticated `/api/diagnostics`. The new field simply had not been held to the
convention its neighbours already follow.

### Attack scenario

1. Culvert boots with a `--ui-san`/`CULVERT_PUBLIC_IP` value (or a host name)
   that the x509 encoder rejects, so self-signing fails and the admin UI falls
   back to plain HTTP.
2. An unauthenticated attacker who can reach the admin port — the same
   reachability that already lets them see the login page — requests
   `GET /api/setup/status`.
3. The response carries `ui_tls_fallback_reason`, disclosing the internal name.

**Preconditions:** network reach to the admin port; a self-sign failure whose
error embeds an input value.
**Exploitability:** trivial once the precondition holds (one unauthenticated
GET). Reaching the precondition needs a specific misconfiguration, which is
what keeps this Low rather than Medium.
**Likelihood:** low — most self-sign failures are content-free crypto errors.
**Impact:** internal-topology disclosure that aids targeting; no authentication
or authorization bypass, no integrity impact.
**Affected assets:** appliance host name, operator-configured SAN values.
**Regression risk of the fix:** none — the fix removes a value from a response
and adds nothing to any decision path.

### Fix

`preAuthTLSFallbackReason()` returns the empty string unconditionally, and both
public endpoints use it. The full cause remains on
`GET /api/settings/network` (viewer+, not on the public allowlist), next to
`ui_sans`, where its audience is already authenticated.

Three deliberate details:

- **The boolean stays pre-authentication.** The warning is the whole point of
  the original change; removing it to "fix" the disclosure would be a much
  worse outcome than the disclosure. Pinned in both directions.
- **The key is emitted, not omitted.** Both frontends decode this response with
  a strict runtime decoder (`readString` in `frontend/src/api/decode.ts` throws
  on `undefined`), so dropping the key would fail-close the v2 boot machine.
  Emitting `""` keeps both decoders and both banners correct — the v2
  `TLSFallbackWarning` already omits its "Server detail" clause on an empty
  cause, and the legacy banner's reason `<span>` simply stays empty.
- **The pre-auth banners now say where the cause lives** (fixed static markup,
  no server data), so the operator is not left guessing.

### Files

- `ui_auth.go` — `preAuthTLSFallbackReason()`; `jsonOKAuthStatus`, `apiSetupStatus`
- `static/index.html` — fixed pointer text on the setup and login banners
- `api/openapi/openapi.yaml` (+ regenerated `openapi.json`) — the two pre-auth
  schemas now document the field as always empty and say why
- `ui_tls_fallback_preauth_test.go` — new

### Required tests (all present, all verified failing against the pre-fix tree)

| Test | Class |
|------|-------|
| `TestSECTLSFB1_SetupStatusNeverLeaksTheCause` | negative — public endpoint, cause absent from the body |
| `TestSECTLSFB1_AuthStatusNeverLeaksTheCause` | negative — all three `/api/auth/status` branches |
| `TestSECTLSFB1_FlagStillReachesPreAuthWhenClear` | positive — the warning channel is not silently disabled |
| `TestSECTLSFB1_PreAuthReasonIsUnconditional` | malformed/boundary — empty, CRLF-injection-shaped, 64 KiB |
| `TestSECTLSFB1_AuthenticatedCauseStillAvailable` | authorization — viewer+ still gets the diagnostic |
| `TestSECTLSFB1_UnauthenticatedCallerIsRefusedTheAuthenticatedSurface` | authorization — boundary of both allowlists |

Verification: with `preAuthTLSFallbackReason` reverted to return the real
value, 3 of the 6 fail (7 subtests); restored, all pass. Full suite green
(`go test ./...`).

---

## What got safer in this window

Two changes close real pre-existing defects and are worth recording as the
security wins of the window.

**The ClamAV queue-full fail-OPEN inversion (`internal/clamav`, `internal/secscan`).**
The queue wait used to expire on its own private 5 s constant and return an
ordinary error, which the orchestrator classifies as an engine fault and
handles **fail-open** — so five concurrent large downloads against a perfectly
healthy daemon admitted content **unscanned**, while the orchestrator's own
10 s deadline, the limit that is supposed to decide this, fails **closed**. An
inner deadline was inverting an outer one's posture. `ScanContext` now charges
the queue wait to the caller's context, so exceeding the budget lands on the
fail-closed path, and `ErrQueueFull` keeps saturation distinguishable from a
daemon fault. Verified: with the orchestrator (which always carries a
deadline), `acquireSlot` can only return `ErrQueueFull` once `ctx` is done, so
`scanBodyInner`'s `ctx.Err()` gate turns it into a block. The legacy
deadline-free `Scan()` entry point retains the old fail-open behavior — see
Residual Risk.

**Abandoned scans could publish a CLEAN verdict.** A scan whose caller had
already returned the fail-closed timeout verdict kept running and wrote its
result to the hash cache, silently converting a refusal into a cached admission
for the rest of the TTL — whether an object was blocked or served came down to
a race. `publishVerdict` now discards a late *clean* verdict (counted as
`culvert_scan_late_discarded_total`) while still admitting a late *block*
(tighten-only). The paired `cacheTimeoutCooldown` fix is the same rule in the
other direction: the fail-closed placeholder no longer overwrites a confirmed,
named threat entry, and it now expires in 30 s instead of inheriting the 1 h
content TTL — a few seconds of scanner slowness used to block that object
node-wide for an hour after the fault cleared.

## Reviewed and found sound (no change required)

- **Embedded frontend serving (`ui_frontend_v2.go`).** Asset lookup is exact
  match against a validated set — no path cleaning, no fallback, no directory
  listing — so traversal is structurally unreachable; `manifest.json` and
  sourcemaps are outside the served namespace. The manifest is treated as
  hostile input (absolute/traversal/encoded/scheme/non-canonical/out-of-
  namespace rejection, allowlisted extensions, content-hash contract required
  before `immutable` caching is granted, duplicate-JSON-key pre-scan with an
  explicit frame stack rather than recursion). The route-scoped CSP is strict
  and nonce-free (`script-src 'self'`, `object-src 'none'`, `base-uri 'none'`,
  `frame-ancestors 'none'`), and the global `securityMiddleware` still supplies
  `nosniff`/`X-Frame-Options` underneath it. Default-off, GET/HEAD-only,
  disabled ⇒ the same 404 an unregistered path yields. The `/assets/` namespace
  does not collide with anything the legacy shell serves (`static/` contains no
  `assets/`, and `static/index.html` references none). Validation failure
  degrades the preview UI to 503 and is report-only on `/ready` — it cannot
  eject a serving proxy.
- **v2 client (`frontend/src`).** No `dangerouslySetInnerHTML`, no `innerHTML`,
  no `eval`/`new Function`, no `document.write`, no `target="_blank"`. The only
  client-side persistence is `localStorage['culvert-theme']`; no token, session,
  or identity material is stored. Committed `dist` is embedded, and the drift +
  tamper + determinism gates run inside a digest-pinned Node container as a
  required PR gate, so the artifact cannot diverge from its source unnoticed.
- **Monitor keyset cursor (`ui_logs_cursor.go`, `internal/logstore`).** The
  cursor is opaque but unauthenticated-unforgeable is *not* claimed and is not
  needed: `/api/logs` is viewer-gated, so a forger is already authorized to
  read the data, and the decode is bounded (256 B cap before base64), version-
  checked, fingerprint-bound to the query, and validated against the request's
  own time window — a forged cursor can only reposition pagination inside a
  window the caller may already read. No datastore internals are exposed. The
  legacy offset path is untouched.
- **Sharded connection limiter (`internal/connlimit`).** Every operation for a
  given IP routes through the one `shard(ip)` function, so the cap stays
  per-IP, never per-shard; the TOCTOU guard, the `cur == ctr` entry-identity
  check on the reject path, and the unconditional-accounting contract that
  closes the #503 fail-closed/fail-open pair are each transposed per shard
  unchanged. The seed is per-process and random, so shard placement is not
  externally steerable. The only behavioural difference is `ActiveIPs()`
  becoming a sum of per-shard snapshots — a diagnostic gauge, off the request
  path.
- **Category-store fingerprint memo (`internal/urlcat`).** The revision-keyed,
  lazily-computed memo that resolves SEC-UCAT-1 from the previous review.
  Freshness is exact in the direction that matters: `rev` advances inside the
  writer's critical section and is monotonic, publication is serialized by
  `fpMu`, and every observable interleaving either hits a memo valid for
  content the reader can see or misses and recomputes. A stale fingerprint
  cannot be published.
- **Compose `cli` service.** `command: ["-h"]` replaces `command: []`. An
  accidental `--profile cli up -d` previously fell through `main.go`'s one-shot
  dispatch into a full second proxy + admin UI against the same `proxy-data`
  volume the running service owns. Strictly safer.
- **ADR-0025 → ADR-0027 renumbering** across `auth_*`, `diagnostics*`,
  `store.go`, `proxy*.go`, `config_surfaces.go`: comments only, verified with
  no accompanying logic change.
- **`trailerRescrubBody`** (identity-ingress hardening): the embedded
  `io.ReadCloser` became a named field with an explicit `Close`, so no copy
  fast path (`io.WriterTo`) can ever be promoted and drain the body past the
  rescrub. Structural, not incidental.

## Residual risk

1. **`clamav.Client.Scan` (deadline-free) still fails open on queue-full.**
   `acquireSlot` gives a caller with no deadline `clamQueueWaitFallback` (5 s)
   and returns `ErrQueueFull`, which `recordClamFailure` counts as saturation
   and which then leaves `scanBodyInner` on the clean path with `clamDark` set
   — content is admitted unscanned, uncached. This is the **pre-existing**
   posture and is unchanged by this window; the production orchestrator always
   carries a deadline and is now fail-closed. Recorded rather than changed:
   flipping the deadline-free path to fail-closed is a posture decision for the
   owner, not a regression fix.
2. **The Monitor cursor is unauthenticated-forgeable by an authorized reader.**
   By design (stateless, no server-side session). The window/fingerprint
   binding confines it to data the caller may already read. If `/api/logs` ever
   grows per-identity row filtering, the cursor must become MAC-bound to the
   caller — it is not today.
3. **`ui_tls_fallback_reason` remains available to any viewer** on
   `/api/settings/network`. That is the intended audience (it sits beside
   `ui_sans`, which is the same class of data), but it does mean the cause is
   not admin-only.
4. **`frontendV2ValidateShellBinding` parses the shell with regexes**, not an
   HTML parser. Sound as long as the shell stays machine-generated by the
   pinned Vite toolchain, which the FE-1A bundle gate enforces. A hand-edited
   or differently-bundled `index.html` is outside the proof.
