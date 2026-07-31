# Security Regression Review — M7 telemetry consent + Stage-1 auth snapshot + scan fail-closed + sslbypass precompute (window 2eef667 → 67ab218)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-07-26
> **Baseline:** `2eef667` — end of the previous review's window
> (PR #915, `docs/security-reviews/` report for the M6 secure-upload / CP-DP delta-sync window; still open/unmerged)
> **Head:** `67ab218` (`origin/main`)
> **Scope reviewed:** every code-bearing change in the window — 13 first-parent merges
> (PRs #911, #913, #914, #917–#922, #924, #934–#936), 73 files, +7,210 / −80 —
> reviewed as four parallel domain deep passes (Stage-1 auth-outcome snapshot;
> SSL-bypass matcher normalization; content-scan fail-closed batch; the new M7
> telemetry consent/config surface) plus orchestrator direct review of every
> remaining diff (install passphrase floor, empty-admin-password fix, OTLP
> push-health, snapshot-apply health, catalog User-Agent, HA log sanitization,
> SPA additions, route metadata). Docs-only merges (#917 terminology, #919 MCP
> design docs) were read for intent but not treated as attack surface.

---

## Executive Summary

**No CRITICAL, HIGH, or MEDIUM security regressions were found.** The window is a net
security improvement, and the three changes with the highest regression potential
were each verified to preserve their security contract exactly:

- The **Stage-1 auth-outcome snapshot** perf change (PR #936) is provably equivalent
  to the old resolver — no cached snapshot exists (the live COW slice is read per
  request), every mutation path publishes atomically, an empty snapshot fails closed
  to the auth gate, and the equivalence matrix is pinned by tests re-run here under
  `-race`.
- The **SSL-bypass matcher precompute** (PR #918) is byte-equivalent at the merged
  end state — proven with a differential harness over 27 patterns × 40 adversarial
  hosts (zero divergences). One *intermediate* commit briefly widened regex matching
  for trailing-dot hosts; the follow-up in the same PR restored exact parity before
  merge (recorded below so nobody cherry-picks the middle commit).
- The **scan fail-closed batch** (PR #935) does what it claims: a plain-HTTP scan
  read error now 502s before any byte reaches the client, partial-scan verdicts no
  longer poison the hash cache, and the async ClamAV-error alert cannot affect the
  verdict.

The window's one genuinely new attack surface — the **M7 telemetry consent/config
API** (PRs #911/#920–#922) — is admin-only end to end, keeps its bearer credential
off every config surface (export/import, rollback, CP→DP, admin_settings), reads its
file through a single-descriptor `O_NOFOLLOW|O_NONBLOCK` open, and has **zero egress
in this build** (verified by grep and pinned by no-egress tests). The remaining
merges (empty-admin-password fix, install passphrase floor, catalog User-Agent, OTLP
push-health, snapshot-apply health, HA log sanitization) are neutral or
security-positive.

**Four LOW findings** (two in-window convention/robustness nits, one deferred-by-design
SSRF precondition that MUST be honored by M7 Slice 3, one pre-existing bypass quirk
surfaced by the differential) and a set of INFO notes are recorded below. None
changes a trust decision, none fails open, none blocks release.

**Verification:** `go build` clean at `67ab218`; targeted suites green at HEAD
(`internal/secscan`, `internal/sslbypass`, `internal/hostutil`, package-main
SetUIUser/scan/auth-resolve suites incl. the snapshot-equivalence matrix under
`-race`, benchgate allocation contracts; `-count=1`).

---

## Findings

### Stage-1 auth-outcome snapshot resolution (PR #936 — b2a4d38)

**No regressions; no findings above Info.** The perf change replaces
`resolveAuthOutcomeFrom(policyStore.List(), ctx)` with
`resolveAuthOutcomeSnapshot(policyStore.evaluationSnapshot(), ctx)`
(`authpolicy.go:411-412`). Verified:

- **No stale-snapshot window.** The "snapshot" is not cached — it is the live
  `ps.rules` slice header read under `RLock` per request (`policy.go:1047-1058`).
  Every mutation path (API add/update/delete/reorder, config import replace+merge,
  version rollback, CP→DP `ReplaceAll`, SIGHUP `Load`, draft promote) publishes a
  **new** slice under the write lock — copy-on-write with `sortLocked` cloning every
  rule before publication — so the next request sees the new revision. Residual
  staleness is one in-flight scan on the old header (microseconds), identical to the
  old `List()`-copy behavior.
- **Fail-closed on nil/empty.** An empty snapshot yields `OutcomeDefault` — "run the
  auth gate" (407 challenge), never allow (`authpolicy.go:500`). Every per-rule
  predicate fails closed on wrong type / nil spec / unknown outcome / unparseable
  client IP (`matchSubjectAddr`: `clientAddr == nil → false`). The
  `defaultAuthOutcome` Exempt/Default switch is not in the snapshot at all — read
  live per request (`proxy.go:175`) with fail-closed normalization, untouched.
- **No torn reads.** Published rule definitions are immutable (reorder mutates
  `.Priority` only on shallow clones before publishing); the returned
  `AuthDecision.Rule` is deep-copied (`copyPolicyRuleForMatch`, incl.
  `Auth.ProviderRefs` consumed by the SSO branch), pinned by
  `TestResolveAuthOutcomeSnapshot_ReturnsDetachedRule`.
- **Semantic equivalence** verified predicate-by-predicate (membership, priority
  order incl. ties, FQDN precomputed-vs-pure — `MatchFQDN(p,h) ≡
  MatchFQDNNorm(NormalizeHost(p), NormalizeHost(h))` with a correctness fallback when
  `normFQDN==""` — CIDR hoisted-parse, schedule/expiry/protocol/method/kill-switch),
  pinned by `TestResolveAuthOutcome_SnapshotEquivalentToPure` (18 contexts × 8 rule
  shapes, kill switch both states) and the benchgate allocation contract. Equivalence
  suite re-run locally under `-race`: green.
- Info-only: stale doc-comment references to the removed
  `resolveAuthOutcomeFromExcluding` stopgap (`authpolicy.go:422-441`); the policy
  simulator deliberately stays on the pure resolver, guarded by the equivalence test.

### SSL-bypass matcher precompute (PR #918 — 574576d, 95b6843, 771df6a)

**No regressions — the merged end state is byte-equivalent to the baseline matcher.**
The bypass list decides which CONNECT hosts skip MITM inspection, so this was
reviewed as a potential decryption-bypass widening. Verified analytically and by a
differential harness (baseline `Matches` reimplemented verbatim, 27 patterns × 40
adversarial hosts — case, 1–3 trailing dots, IDN/punycode, suffix-confusion
`evil-example.com` / `example.com.evil`, IP literals, embedded wildcards/ports, `*`,
empty, plus 5 regex patterns): **zero divergences in either direction**.

- The load-bearing subtlety: the new conditional second normalization pass, gated on
  a trailing dot (`internal/sslbypass/sslbypass.go:193-196`), exactly reproduces the
  old unconditional double-normalization — `NormalizeHost` is non-idempotent only
  when its output ends in `.` (empty trailing DNS label), including the IDNA-failure
  fallback path. Regexes keep the single-pass host, as at baseline.
- **No cache staleness:** every mutation path (API, config import, rollback, startup
  slice, CP→DP snapshot apply) goes through `Set`/`Add`/`Load`, which recompile and
  recompute `norm` under the write lock; only raw strings are persisted.
- **Intra-window note (matters only for cherry-picks):** 574576d alone was a
  narrowing (security-positive, operator-intent-breaking), and 95b6843 alone
  introduced a real if exotic **regex widening** (`~^example\.com$` matched
  `example.com..`) — fixed by 771df6a before merge. The deployed delta is net-zero;
  do not ship the middle commit without the third.
- Contract pinned by `TestMatcher_NormalizedPatternMatches`,
  `TestMatcher_TrailingDotHostMatches`, `TestMatcher_EmptyFastPath`,
  `TestPolicySecurity_*`, and benchgate `TestBenchGate_SSLBypassMatchesAllocs`
  (2 allocs/op flat) — all green locally.

Pre-existing quirks surfaced by the differential (identical old and new — NOT
regressions, recorded as hardening candidates):

- **F4 — LOW · pre-existing — empty glob pattern is a near-universal bypass for
  pathological hosts.** Pattern `""` matches any host whose double-normalized form
  still ends in `.` (e.g. `anything.example...`). The API handler skips empties
  (`ui_policy.go:2104-2106`) but `Set` via config import / cluster snapshot /
  rollback performs no such filtering. Recommend filtering empties in
  `sslbypass.Set`/`compilePattern` itself (fail-closed at the engine, not the
  handler). Preconditions: an empty string reaching the persisted list AND a client
  sending ≥3 trailing dots — low likelihood, but the fix is one guard.
- **INFO · pre-existing:** pattern `*.` normalizes to `*` and matches every host —
  an admin typo away from a universal inspection bypass; bare-domain globs include
  all subdomains by design (Palo Alto semantics).

### Scan pipeline (PR #935 — fe3d22a, 3697b42, 5a515c9)

**No regressions.** The CHAOS-17 read-error fix is genuine fail-closed hardening: a
plain-HTTP response-scan read error now writes a 502 **before any body bytes reach the
client** (`proxy_http.go:182-190` returning into `handleHTTP`'s early-return at
`proxy_http.go:112-114`), pinned by `TestScanHTTPResponseBody_ReadErrorFailsClosed`
(covers chunked via `ContentLength: -1`). The CHAOS-10 cache fix closes a real
poisoning window: a ClamAV error sets `clamDark` and the clean-verdict `hashcache.Set`
is gated on `!clamDark` (`internal/secscan/secscan.go:527-557`), so partial scans can
no longer cache "clean"; infected verdicts (complete by definition) still cache. The
async alert change cannot affect the verdict — the counter increments synchronously
and the goroutine carries no verdict state; firing synchronously inside `ScanBody`'s
10s fail-closed timeout could actually have converted a fail-open clam error into a
spurious timeout-block, so async is the right direction.

- **F1 — LOW · CWE-117 — unsanitized `readErr` in the new fail-closed log line.**
  `proxy_http.go:187` logs the origin-derived read error with `%v`; chunked/trailer
  parse errors can embed origin-controlled bytes incl. `\r`. Log-forgery only; the
  identical lax pattern pre-exists at `proxy_tunnel.go:1214` and `proxy_http.go:120`.
  Fix: `%q` + inline `strings.ReplaceAll` per convention, all three sites.
- **F2 — LOW · CWE-770/availability — alert-dedup bust on non-stable ClamAV error strings.**
  `internal/secscan/secscan.go:509-515` — timeouts embed ephemeral local ports, so a
  clam outage under load defeats the `event+Detail` dedup key and each request runs a
  full `Dispatch` (synchronous disk write when the semaphore is full). Normalize
  `Detail` before dispatch. Not attacker-triggerable while clamd is healthy.
- **Residual (pre-existing, now partially visible):** a clam **backend** error remains
  fail-open for the triggering request in every configuration (falls through to YARA,
  then forwards) — now counted (`culvert_clam_scan_errors_total`), alerted
  (`scan_clam_error`), and never cached, but there is still no fail-closed-on-clam-error
  toggle. Also pre-existing and untouched: a chunked response larger than `MaxBytes`
  (default 5 MiB) streams its unscanned tail **silently** (no `scan_skipped` fires —
  the counter is gated on a non-negative Content-Length), on both the plain and
  inspect paths. The most exploitable residual in this area; recommend counting it.

### M7 telemetry consent/config surface (PRs #911, #920, #921, #922 — new surface)

**No Critical/High/Medium.** The follow-up commits closed the real issues (TOCTOU,
origin echo, port range, persisted-credential laundering, privacy classification).
Verified safe with cites:

- **RBAC:** exactly two new routes, three method policies, all `RoleAdmin` in both
  metadata (`ui_routes_meta.go:790-798`) and handler-level `requireRole`
  (`support_telemetry_preview.go:36`, `support_telemetry_config.go:471,533`);
  PUT audits via `auditEventDiff` on success only.
- **Secret containment:** bearer credential in a 0600 file (descriptor-bound fchmod
  self-heal + `AtomicWrite`), field named `Credential` (G117-safe), never echoed —
  GET returns `credential_set bool` only; a hand-edited `user:secret@host` origin is
  re-validated and **omitted** from every read surface. Greps confirm the credential
  is on **no** `configSurfaces` row: off export/import, rollback, `admin_settings.json`,
  and CP→DP `ConfigSnapshot`; not in the telemetry sample; not swept into support
  bundles.
- **TOCTOU (Copilot alerts #255/#256):** single-descriptor `O_NOFOLLOW|O_NONBLOCK`
  open; fstat/fchmod/size-cap/bounded-read all bind to that descriptor; FIFO-block
  DoS closed; write path is `CreateTemp(O_EXCL)`+fsync+rename. Malformed/oversized/
  unsafe all fail closed to disabled.
- **Zero egress verified:** no `http.Client`/`Dial` in any new file, no consumer of
  `telemetryEnabled()`, startup validation is inert, pinned by
  `support_telemetry_noegress_test.go`.
- **kin-openapi GHSA-r277-6w6q-xmqw (PR #921/118eef5):** `go.mod` at v0.144.0 (fixed).
  The vulnerable `openapi3filter.ValidationHandler` fail-open path was **never linked
  into the shipped binary** (offline `cmd/apibundle` + test gates only) — hygiene
  upgrade, not a runtime exposure either way.

New-surface residuals (carry forward, not current vulns):

- **F3 — LOW · CWE-918 (deferred precondition) — DNS-resolving origins are not SSRF-checked.**
  `validateTelemetryEndpoint` (`support_telemetry_config.go:393-428`) refuses only
  literal private IPs; `https://127.0.0.1.nip.io` persists fine. Harmless in this
  build (zero egress), but **Slice 3's sender MUST use the connect-time
  `ssrf.Control` dialer** — record it as a hard precondition in the M7 plan.
- **INFO:** intermediate-directory symlink residual (final-component `O_NOFOLLOW`
  only — same accepted posture as every `dataDir` state file); Windows builds degrade
  `O_NOFOLLOW` to 0 (documented, Linux appliance); `MkdirAll` never tightens a
  pre-existing loose `support/` dir; C1 control chars pass credential validation
  (no injection possible — Go header writer treats them as obs-text); 405 answered
  before role check (authenticated users only, consistent with siblings);
  `saveConfigVersion` deliberately absent (consent must not be resurrectable by
  config rollback — registered-pattern exception mirroring `uploadConfig`).

### Orchestrator-reviewed remainder (PRs #913, #914 non-scan parts, #924, #934, #936-adjacent observability)

All neutral or security-positive; no findings above INFO:

- **`SetUIUser` empty-password fix (acf1add, PR #913):** closes a silent-failure bug
  where creating a new admin user with an omitted password returned `{"ok":true}` +
  an audit entry while persisting nothing. Now errors (`store.go:695-699`), with a
  regression test. Security-positive (CWE-393 wrong-status class).
- **Install passphrase floor (c4a3db1, PR #934):** operator-entered at-rest
  passphrases must now be ≥12 chars (`scripts/install.sh:1551ff`) — strengthens the
  PBKDF2→AES-256-GCM key protecting the CA key and logs. Security-positive.
- **Catalog User-Agent (e4d8f39, PR #924):** adds a static UA header to catalog
  fetches. Set before the `decorate` hook, no header injection surface (constant
  string). Neutral.
- **OTLP push-health (f583267):** new `Health()` diagnostics exposed only on the
  admin-gated `GET /api/otlp` (auth header **value** still never returned); the
  `lastError` string could embed the admin-configured endpoint URL — admin-only
  surface, acceptable. SPA renders it through `escHtml`. Neutral.
- **Snapshot-apply health (`configsnapshot_apply_health.go`):** pure observability
  atomics marked at existing rejection points in `controlplane_client.go`; deliberately
  excludes the epoch fence (leadership signal, not content validity) — no gating
  behavior changed. The optimistic default (healthy until first failure) matches the
  established `dpControlPlanePollFailing` posture. Neutral.
- **HA leader-log sanitization (7fe8aa8):** replaces inline CR/LF stripping with the
  canonical `sanitizeLog`. Security-positive.
- **SPA additions:** every server-derived value in the new OTLP-health and telemetry
  panels flows through `escHtml`; status colors come from a fixed map. No DOM-XSS.
- **`healthcheck.go` refactor:** `caExpiryDaysRemaining()` extraction is behavior-
  preserving (single source of truth for the CA notAfter read). Neutral.

---

## Prior Findings Status

All findings from the two still-open prior review PRs remain **OPEN** — verified by
empty diff over their underlying files in this window:

- **#915 M1 (MEDIUM, CWE-789)** — TAC-gateway-controlled `chunk_size` unbounded
  allocation → process crash-loop (`internal/supportupload/upload.go`,
  `support_upload_wire.go`): untouched.
- **#915 M2 (MEDIUM, CWE-770)** — unbounded pre-auth exfil-throttle map keyed on
  peer IP, IPv6 not collapsed (`controlplane_server.go:188-218`): untouched.
- **#915 L1–L4** and the 2026-07-19 (#878) findings: all underlying files
  (`.github/workflows/` governance pair, bootstrap verifier, delta blocklist cap,
  upload drain write-back) untouched this window.

The two #915 MEDIUMs are now two windows old; both fixes are pure narrowing and
should be scheduled.

---

## Recommended Follow-ups (none blocking)

1. **F1:** sanitize `readErr` at `proxy_http.go:187` (and the two pre-existing
   siblings `proxy_tunnel.go:1214`, `proxy_http.go:120`) — `%q` + inline
   `strings.ReplaceAll` per the CWE-117 convention. Tests: a malformed-chunked
   origin fixture asserting the log line contains no raw CR.
2. **F2:** normalize the ClamAV error `Detail` (strip addresses/ports) before
   `Dispatch` so outage storms dedup. Tests: two timeouts with different ephemeral
   ports → one delivered alert.
3. **F3:** record in the M7 plan that Slice 3's sender MUST dial through the
   connect-time `ssrf.Control` guard (not a pre-flight resolve). Tests: sender
   refuses an origin resolving to RFC1918/loopback at dial time.
4. **F4:** filter empty patterns in `sslbypass` engine `Set`/`compilePattern`
   (fail-closed at the engine, covering import/snapshot/rollback callers). Tests:
   `Set([""])` yields no compiled pattern; `Matches("host...")` false.
5. **Pre-existing visibility gap:** count/alert the chunked >`MaxBytes` unscanned
   tail (currently silent on both plain and inspect paths); consider a
   fail-closed-on-clam-error toggle for high-assurance deployments.
6. **Prior #915 M1/M2** (chunk_size allocation, pre-auth throttle map) are two
   windows old — schedule the narrowing fixes.

## Residual Risk

Accepted residuals, unchanged by this window: ClamAV **backend** errors remain
fail-open for the triggering request (now counted + alerted, never cached); the
chunked over-cap unscanned tail streams silently; telemetry origin DNS-resolution
SSRF is deferred to Slice 3's dial-time guard (zero egress today); intermediate-
directory symlinks on `dataDir` state files are out of threat model (local writer
can edit the files directly); Windows builds degrade `O_NOFOLLOW` (documented,
Linux appliance). No new trust decision, secret surface, or fail-open path was
introduced in this window.
