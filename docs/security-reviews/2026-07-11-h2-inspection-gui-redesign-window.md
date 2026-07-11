# Security Regression Review — native HTTP/2 inspection + GUI redesign + release re-sign (window 8e88a40 → 7c64699)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-07-11
> **Baseline:** `origin/main` @ `8e88a40` (end of the previous review's window,
> `docs/security-reviews/2026-07-10-release-platform-m0m1-window.md`)
> **Head:** `origin/main` @ `7c64699`
> **Scope reviewed:** every code-bearing change merged in the window — 157 files,
> +12,973 / −8,510 (93 Go files, +5,272 / −6,998) — across 26 first-parent merges
> (PRs #640–#670): the native **HTTP/2 SSL-inspection** program (PR0–PR3c: the
> protocol-neutral `inspectExchange` seam, ClientHello ALPN peek + `StripALPN`
> resolver, per-stream inactivity watchdog, H2 frame/header caps, trailer
> filtering, block responder), the **admin GUI redesign** (M1/M2/M3: design
> tokens, air-gapped vendored assets, policy editor, decision-trace), the
> **release-platform M1-4** weekly no-bump catalog re-sign + 180-day freshness
> (SEC-F1/F2/F4/F7), the **HA fencing** Stop/latch fixes, the **fresh-install /
> maintenance-agent** hardening (sudoers colon-escape, `O_NOFOLLOW` read guards,
> fail-closed bundle trust), the **legacy Docker updater removal** (attack-surface
> reduction), the `SaveUIUsersFile` lost-write race fix, the admin login-lockout
> list/unlock endpoint, and the `diskUsage` platform-split.
> Review executed as five parallel deep-review passes (H2 inspection ×2 — an
> independent second data-path pass; auth/policy/UI; installer/maint-agent;
> release/HA/CI) plus independent orchestrator spot-checks of the H2 pipeline
> unification, the ALPN parser, the block-responder refactor, and the lockout
> RBAC. All findings below were verified against the working tree at `7c64699`.

---

## Executive summary

**One genuine security regression found and FIXED in this review (F1, Medium):**
a new HTTP/2-only response-integrity defect where an origin stream abort *during
scan buffering* surfaced to the client as a clean, empty, cacheable `200 OK`
instead of a stream failure. The fix, tests, and proof are in this same change.

Everything else in the window is security-clean or a net security improvement.
Notably: the shared `runInspectExchange` pipeline gives H1 and H2 a single
enforcement path (scrub → hop-by-hop strip → file-block → scan → deliver), so H2
inherits H1's protections structurally; the CSP was *tightened* (dropped
`https://cdn.jsdelivr.net` now that Chart.js is vendored locally); the legacy
Docker updater (a privileged `TriggerUpdate` RPC + sidecar) was removed; the
release re-sign strengthened the appliance replay ratchet (SEC-F4) and tag-creation
restriction (SEC-F7); and the installer/maint-agent privilege-boundary changes are
availability fixes and new fail-closed defense-in-depth.

No CRITICAL or HIGH regressions. One Medium (fixed here). The remaining items are
LOW/informational hardening or pre-existing accepted-risk deferrals, tracked below.

---

## F1 — [Medium, FIXED here] HTTP/2 scan-buffer read error surfaced as a clean empty 200

**CWE:** CWE-393 (Return of Wrong Status Code) / CWE-444-adjacent (response
integrity on an inspecting intermediary). **OWASP:** A04 Insecure Design /
A05 Security Misconfiguration. **Severity:** Medium. **Regression risk:** the
defect was introduced *in this window* by the native-H2 path (PR3b); the H1 path
never had it.

### Attack scenario / failure

On an SSL-inspected HTTP/2 tunnel, when a response has a buffering-eligible
content-type (e.g. `text/plain` with DPI enabled, or any type with ClamAV/YARA
body-scan on), the proxy reads the whole body into the scan buffer *before*
delivering anything to the client (`scanInspectBody`, `proxy_tunnel.go`). If the
origin resets or truncates the stream mid-buffer (`io.ReadAll` returns a non-EOF
error), the pre-fix code returned a bare `true` from `scanInspectBody`, which
`runInspectExchange` mapped to `exBlocked` — the *same* outcome as a real policy
block. But no block page had been written.

- On **H1** (`runH1InspectLoop`) `exBlocked` does `break relayLoop`, tearing the
  tunnel down — the client observes a connection error. Correct / fail-closed.
- On **H2** (`handleH2StreamOutcome`) the `exBlocked` case does nothing (it assumes
  the responder already wrote the 403). With nothing written, the handler returns
  and `http2.Server` emits `:status 200` + `END_STREAM` — **a clean, empty,
  successful 200**.

An on-path attacker (or a malicious/compromised origin) who can reset origin
streams can therefore convert a failed fetch into a syntactically-successful empty
`200` on the H2 path. For a shared/downstream cache fetching e.g. a JS or CSS
asset through the gateway, this is a response-integrity / cache-poisoning vector
(empty body served as a valid `200`), and it breaks the gateway's fail-closed
contract (a fetch that did not complete must not look like it did).

The PR3c watchdog panic (`ctx.Err() != nil && out.kind != exDelivered` →
`http.ErrAbortHandler`) covered only the *cancel/stall* case; a plain origin read
error does not cancel the stream context, so this path fell straight through.

### Preconditions / exploitability / likelihood

- SSL inspection with **native H2** enabled on the matching rule (`StripALPN=false`
  — opt-in, not the default; a pre-feature rule strips ALPN and uses the safe H1
  path).
- A buffering-eligible content-type (DPI/ClamAV/YARA on).
- Attacker can induce an origin-side stream reset mid-response (on-path, a hostile
  origin, or an origin under load returning `INTERNAL_ERROR`).

Exploitability: moderate (requires native-H2 inspection to be enabled and a way to
reset origin streams). Likelihood: low-to-moderate — but the *integrity* impact of
a silent success is high enough to rate the finding Medium.

### Fix (in this change)

`scanInspectBody` now returns a typed `scanBodyOutcome` (`scanClean` /
`scanBlocked` / `scanReadError`) instead of a bare `bool`, so a read failure is
distinguishable from a policy block. `runInspectExchange` maps `scanReadError` to
`exDeliverError`:

- **H1**: `exDeliverError` is already in the tunnel-teardown case — behavior is
  byte-identical to before (was `exBlocked` → teardown, now `exDeliverError` →
  teardown). No H1 change.
- **H2**: `exDeliverError` triggers `panic(http.ErrAbortHandler)` → `RST_STREAM`.
  The client now observes a stream error instead of a clean empty 200. Fixed.

This reuses an outcome kind both transports already handle correctly, so the fix
cannot silently fall through a switch (the risk of adding a brand-new kind).

### Required tests (added here)

- `TestRunInspectExchange_ScanReadErrorFailsClosed` (`inspect_exchange_test.go`) —
  seam-level: an origin body that yields bytes then `io.ErrUnexpectedEOF` must
  produce `exDeliverError` (not `exBlocked`/`exDelivered`); the block responder is
  NOT invoked; deliver does NOT run; the body is closed (no fd leak).
- `TestMITM_NativeH2_ScanBufferReadErrorFailsClosed` (`inspect_h2_e2e_test.go`) —
  wire-level: DPI on + `text/plain` origin that flushes a chunk then
  `panic(http.ErrAbortHandler)` mid-buffer; the client must NOT receive a clean
  empty `200`. Distinct from the existing delivery-truncation test (headers
  committed first → 502) and the stall test (watchdog *cancel*, not a read error).

Both were confirmed to FAIL against the reverted fix (the e2e test observed the
literal "clean empty 200") and PASS with it, under `-race`.

---

## Verified sound (no regression) — by area

### Native HTTP/2 inspection

- **One enforcement path.** `h2InspectStream` builds an `inspectExchange` and runs
  the identical `runInspectExchange` the H1 loop uses, so request-side
  `scrubForwardedHeaders` (X-User-Identity / private XFF stripped) and
  `removeHopHeaders`, file-block, magic/polyglot, CDR, DPI, ClamAV/YARA, and
  response-side hop-by-hop stripping all apply to H2 byte-for-byte
  (`proxy_tunnel.go:834`). H2 additionally filters hop-by-hop *trailer* names in
  `h2DeliverResponse`. The `runH1InspectLoop` extraction was confirmed
  order-identical to the pre-window inline loop.
- **ALPN peek is fail-closed and desync-free.** `parseClientHelloALPN`
  (`inspect_h2_alpn.go`) is fully bounds-checked (forward-only cursor, every vector
  length validated), linear (no quadratic/regex DoS), fuzzed, and read-only (peeks
  the buffered ClientHello; `tls.Server` re-reads identical bytes). Any
  malformed/fragmented/oversized ClientHello falls back to `["http/1.1"]` — the
  *fully-inspected* path. Dispatch keys on the actual negotiated protocol on both
  legs, not the peek. ALPN stripping can only downgrade *toward* more inspection,
  never away from it — no downgrade-to-bypass.
- **`resolveStripALPN` is presence-aware** (`proxy.go`): `nil`/pre-feature → strip
  (unchanged); no silent upgrade of existing deployments to native H2.
- **DoS caps (client-facing):** `MaxConcurrentStreams=32`, `MaxReadFrameSize`/
  `MaxHeaderBytes`=1 MiB, `WriteByteTimeout`, `IdleTimeout`; x/net v0.57.0
  (past the Rapid-Reset/CONTINUATION floors). Per-stream inactivity watchdog
  re-arms on progress in either direction and fails closed to RST_STREAM.
- **TLS / cert handling:** upstream inspect leg verifies via
  `upstreamInspectTLSConfig` (RootCAs, SNI, TLS 1.2 floor); `InsecureSkipVerify`
  only under the admin-configured, logged per-rule `tlsSkipVerify`. Forged leaf via
  `certMgr.GetCert`, TLS 1.2 floor. Per-tunnel `NewClientConn` (no pooled transport,
  no cross-identity coalescing); `:authority` cannot redirect off the pinned conn
  (no SSRF).
- **Block-responder refactor** (`inspect_block.go`, `scanner.go`,
  `security_scan.go`, `cdr_proxy.go`): the raw-conn 403 writers now route through
  the protocol-neutral `blockResponder`. The H1 responder is byte-identical
  (`Connection: close`, locked by characterization tests); the H2 responder omits
  connection-specific headers (RFC 9113 §8.2.2). H1 still breaks the relay loop on
  block (block-then-close preserved — no response smuggling).

### Auth / policy / admin UI / GUI redesign

- **RBAC / route parity intact.** New `/api/auth/lockouts` gates both GET and POST
  with `requireRole(RoleAdmin)`; `uiRoutes` metadata declares GET=admin,
  POST=admin+Mutating+AuditExpected — handler and metadata agree (no C1.5
  divergence). POST audits via `auditEvent`. 11 `/api/update/*` routes removed
  cleanly; canonical D0/C1 counts updated consistently (145+1−11=135).
- **CSP tightened.** `ui_middleware.go` dropped `https://cdn.jsdelivr.net` from
  `script-src`; Chart.js is now vendored (`static/chart.umd.js`, genuine v4.4.0, no
  `eval`/`new Function` in app code) and loaded same-origin with the per-request
  nonce. No `unsafe-inline`/`unsafe-eval`.
- **SPA XSS:** consistent `escHtml()` on attacker-controllable proxy data (traffic
  feed, blocklist, toasts); shared dialogs use `textContent`; event delegation
  replaces inline `on*=` handlers; no `javascript:` hrefs. `escHtml` omitting
  single-quote escaping is non-exploitable (no single-quoted attribute interpolates
  data).
- **`SaveUIUsersFile` race fix** correct: `saveUIUsersMu` held across the whole
  snapshot+write closes a real lost-update TOCTOU (two concurrent saves' `rename()`s
  were unordered). Pinned by `TestSaveUIUsersFile_ConcurrentSavesDoNotLoseUsers`.
- **Login-lockout list/unlock:** enforcement logic unchanged; `Snapshot()` is
  read-only; username + source-IP telemetry is admin-gated; unlock delegates to
  the existing `ResetUser` and is audited.

### Release re-sign / HA / CI

- **Catalog re-sign (M1-4)** preserves every trust invariant: verify-before-read
  (SEC-F1 — `LoadVerifiedCatalog` against baked root + pinned identity before any
  field is read), version binding, immutability (same `catalog_version`/
  `created_at`, byte-identical manifests, only `generated_at`/`expires_at` +180d),
  latest-tag assert (SEC-F2a), monotonic live binding (SEC-F2b), and the new
  `(HighestVersion, HighestGeneratedAt)` appliance replay ratchet (SEC-F4) that
  closes a same-version replay window. All mutation-proven by
  `release_resign_gate_test.go` / `release_workflow_invariants_test.go`.
- **Pinned Sigstore identity NOT widened:** `officialSigstoreIssuer` /
  `officialSigstoreSANRegex` unchanged (exact repo + `ci.yml` + tag anchor);
  `release_identity.env` byte-equal, SSOT-walled, now also pinned against
  `scripts/install.sh`.
- **`resign-catalog.yml`** is least-privilege (`actions:write` + `contents:read`
  only, signs nothing), schedule/dispatch-only, semver-validated inputs, no
  untrusted `${{ github.event.* }}` in `run:`.
- **SEC-F7** v-tag creation restriction (`deploy/terraform/github.tf`) is
  fail-closed (only repo admins bypass; auto-tag pushes as `RELEASE_TAG_PAT`).
- **HA fencing** (`ha.go`/`ha_lease.go`): the `stopping` latch only refuses new
  loop spawns during shutdown — it does not gate `IsLeader`/`WriteAllowed`/
  `selfFence`, so no demoted node can believe it is leader (no split-brain). `Stop`
  joining goroutines closes a straggler-config-write race. "Cancelled sync is not
  leader failure" declines to manufacture a promotion for a shutting-down node —
  the fail-closed direction.
- **Dependency bumps** (sigstore-go 1.2.2, badger 4.9.4, golang-x group, harden-runner
  2.20.0) are routine security-maintenance upgrades; no trust-policy/API change in
  our usage.

### Installer / maintenance-agent / host-ops (privilege boundary)

- **Sudoers colon-escape** (`5c8704b`) and `{{json\ .Image}}` space-escape are
  tightening/availability fixes, not broadening. `proxy_repo` renders as a fixed
  literal (no wildcard); the pinned digest is exactly 64 lowercase hex; the retag
  destination is the fixed literal `culvert/proxy:pinned`; runner-side
  `validatePinnedDigestRef` rejects any non-conforming ref. A compromised
  `culvert-maint` cannot influence the repo or retag destination.
- **`O_NOFOLLOW` read guards** (`nofollow_unix.go`/`_windows.go`) close the final-
  component TOCTOU on the two read paths (`catalogReadBounded`, `list_backups`);
  both are `Lstat` + `ModeSymlink` + `O_RDONLY|O_NOFOLLOW`. No write path uses it —
  no write-TOCTOU exposure.
- **Install trust anchor** is fail-closed: the host-root bundle installer runs only
  on a real source checkout, a cosign-verified pinned image (`verify_pinned_image_
  signature` against the in-script pinned identity, `--timeout=60s`), or an explicit
  break-glass env; every `CULVERT_MAINT_SKIP_VERIFY=1` invocation was traced to an
  already-trusted source. The `.dockerignore`/`deploy_bundle_contract_test.go` wall
  keeps `cmd/` out of the deploy bundle, so a malicious image cannot spoof the
  source-checkout branch. The 0700-home ancestor-traversability check fails closed
  (agent skipped, proxy unaffected).
- **`diskUsage` platform-split** (`diskusage_unix.go`/`_windows.go`): the Unix impl
  is byte-identical to the pre-split code; Windows is equivalent semantics. No
  disk-guard fail-behavior change.
- **Legacy updater removal:** `TriggerUpdate` gRPC RPC, updater sidecar, self-update,
  `/api/update/*` routes, and the updater compose image are deleted — a net
  attack-surface reduction. No dangling nil-route registrations.

---

## Residual / accepted-risk items (not regressions — tracked)

1. **L1 — upstream H2 `http2.Transport{}` uncapped (LOW).** The client-facing
   `http2.Server` is explicitly capped, but the upstream leg
   (`proxy_tunnel_h2.go:278`) leaves `MaxHeaderListSize` at the x/net ~10 MiB
   default vs the 1 MiB client-side cap — a header-size asymmetry a malicious origin
   could exploit (×32 streams), bounded by the per-stream watchdog and per-IP
   connlimit. Recommended one-line hardening: set `MaxHeaderListSize`/
   `MaxReadFrameSize`/`ReadIdleTimeout` on the upstream Transport to match the
   server side. Deferred (LOW, not a regression — new-surface hardening).

2. **RF7 global scan-memory budget not shipped (accepted, plan-gated).** Worst case
   per malicious H2 connection is 32 streams × (scan buffer + decompression output +
   CDR copy). This is a ×32 amplification of H1's per-conn exposure, opt-in per rule,
   and classed as a *default-enable blocker* in the H2 plan — keep it so. The
   operator doc understates the ceiling (omits the decompression multiplier);
   recommend folding that math into `docs/operator/http2-inspection.md`.

3. **`:authority`/Host ≠ CONNECT host not re-validated (parity, not regression).**
   The H1 inspect path has the identical property; no SSRF (round-trip pinned to the
   CONNECT upstream ClientConn); single-SAN forged leaves prevent coalescing.
   Documented as a deferred 421/defense-in-depth item.

4. **Request trailers unscrubbed (shared H1+H2, LOW).** `scrubForwardedHeaders`
   touches `req.Header`, not `req.Trailer`; a trailered `X-User-Identity` would
   forward. Pre-existing on the H1 chunked path; recommend extending the scrub to
   trailers as follow-up.

5. **`stripAlpn` GUI-parity gap (INFO).** No control in `static/index.html` for the
   new per-rule `StripALPN` field (CLAUDE.md GUI-parity rule). Rule-level DP sync/
   export/rollback ride `PolicyRule` automatically (omitempty; old DPs fail-safe to
   strip). Tracked as a UI follow-up.

6. **Installer `reject_unsafe` fnmatch metachars (pre-existing, out of threat
   model).** `proxy_repo` (root-owned, install-time) is not scrubbed for sudoers
   fnmatch metacharacters (`* ? [ ]`). The `culvert-maint` account cannot alter it.
   Recommend defense-in-depth: reject `* ? [ ] \ ,` for sudoers-literal-destined
   values. Follow-up, not a blocker.

---

## Files changed by this review

- `proxy_tunnel.go` — `scanInspectBody` returns a typed `scanBodyOutcome`;
  `runInspectExchange` maps `scanReadError` → `exDeliverError` (F1 fix).
- `inspect_exchange_test.go` — `TestRunInspectExchange_ScanReadErrorFailsClosed`.
- `inspect_h2_e2e_test.go` — `TestMITM_NativeH2_ScanBufferReadErrorFailsClosed`.
- `docs/security-reviews/2026-07-11-h2-inspection-gui-redesign-window.md` — this ledger.

## Residual risk

Low. The one genuine regression (F1) is fixed with fail-closed semantics reusing an
outcome kind both transports already handle, and is guarded by a seam test and a
wire-level e2e test both proven to catch the defect. The remaining items are
LOW/informational hardening or plan-gated deferrals with compensating controls; none
opens an authentication, authorization, policy, TLS, or trust bypass.
