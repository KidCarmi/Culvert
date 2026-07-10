# Security Regression Review — release-platform M0/M1 program + core-fix batch (window 328c883 → 8e88a40)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-07-10
> **Baseline:** `origin/main` @ `328c883` (end of the previous review's window,
> `docs/security-reviews/2026-07-09-policy-priority-enrollment-cidr-window.md`)
> **Head:** `origin/main` @ `8e88a40`
> **Scope reviewed:** every code-bearing change merged in the window — 108 files,
> +9,967 / −312 (64 Go files, +6,121 / −240) — spanning 27 first-parent merges (PRs #567–#639):
> the entire release-platform **M0** (R2 stage→verify→promote publisher, dual-publish verify
> workflow, egress allow-lists, IaC guardrails skeleton, legacy GitHub-tags fallback gate) and
> **M1** (production HTTP catalog-refresh loop with built-in default origin, detection/alerting
> with latched release-catalog alerts) programs; the auth-policy kill-switch fail-open fix
> (#626); the connlimit Release-symmetry fix (#625) + SOCKS5 per-IP budget (CHAOS-02); the
> reqlog fixed circular buffer (#620); the threat-feed domain-allowlist consolidation (#623);
> upstream circuit-breaker UI surfacing (#606); OCSP fail-closed observability (#581); four
> chaos-window fixes (#622: CP version-floor persistence, root-CA failure visibility, SOCKS5
> conn-limit, OCSP indeterminate TTL); the policy hot-path precompute; the installer
> `allow_peers = []` patch fix (#621); and the Go 1.25.12 / govulncheck bump (#624).
> Review executed as three parallel deep-review passes (release-platform runtime; core
> proxy/policy/auth + internal packages; CI workflows + Terraform) plus independent
> orchestrator spot-checks of the five riskiest diffs. All findings below were verified
> against the working tree at `8e88a40` before being recorded.

---

## Executive Summary

**No CRITICAL or HIGH security regressions were found.** The window is a large net security
improvement: the legacy unauthenticated GitHub API call is now OFF by default on the update
path (fail-safe: a typo or unset stays off, proven by a dial-spy test); the Exempt kill switch
no longer **fails open** on no-backend deployments (scoped `CredentialRequired` rules challenge
again — a genuine auth-enforcement regression fixed, not introduced); the connection limiter is
now symmetric across runtime enable/disable (closing both an admit-past-cap fail-open and the
#503 fail-closed wedge) and SOCKS5 tunnels finally consume the same per-IP budget as
HTTP/CONNECT; catalog cache validators are committed only after a fully successful
verify+swap+reload (a malicious origin can no longer 304 its way into perpetual false success);
and seed/refresh error strings are redacted host-only before reaching logs, API, audit, and
alerts (covering presigned-credential URL paths).

**Two MEDIUM findings** are recorded, both on the CI/IaC supply-chain surface, both residual
hardening gaps rather than broken trust boundaries (in-binary signature verification + the
monotonic rollback floor remain the real trust boundary and are intact): the R2 publisher's
egress allow-list still permits generic exfiltration channels (`*.r2.cloudflarestorage.com`
matches **any** Cloudflare tenant), and the Terraform provider lock file is gitignored, so the
IaC that manages the release trust guardrails runs hash-unpinned providers at exactly the
moment admin-scope tokens are in the environment.

**Six LOW findings** follow, the most notable being new in this window: the unauthenticated
`/ready` endpoint on the proxy port now discloses the CA bundle filesystem path, the raw load
error, and — most actionably for an insider — the fact that SSL inspection (scanning/DLP/CDR)
is currently disabled. The remaining LOWs: the stale-catalog watchdog is never re-evaluated in
fetch-disabled/permissive deployments; the policy store's in-place mutators still race the
lock-free `Evaluate` scan (pre-existing, but now carrying more in-place state); and three
publisher-workflow hardening gaps (bracket-form secrets blind spot, glob-based asset selection,
stage-guard ETag TOCTOU).

The five riskiest diffs were independently double-checked by the orchestrator in addition to
the parallel passes and found semantics-preserving: the **policy precompute** reproduces
`matchIPOrCIDR` exactly (invalid CIDR → fail-closed fallback; unparseable client IP → no
match; every mutator recomputes; default-deny untouched), the kill-switch fix is strictly
more restrictive, connlimit has no underflow/lost-slot interleaving, the reqlog ring copies
under lock with no aliasing, and the update-path gate never dials by default.

**Verification:** targeted suites for `internal/{connlimit,reqlog,threatfeed,upstream,ocsp}`
and the new main-package tests pass, including under `-race`.

---

## Security Findings

### F1 — MEDIUM · R2 publisher egress allow-list retains generic exfiltration channels; R2 wildcard matches any Cloudflare tenant

**File:** `.github/workflows/publish-catalog-r2.yml:88-98`

The allow-list's stated purpose ("a compromised transitive dependency must not be able to
exfiltrate them") is only partially achieved:

- `*.r2.cloudflarestorage.com:443` matches **any Cloudflare account's** R2 S3 endpoint
  (`<accountid>.r2.cloudflarestorage.com`), not just the project's. A compromised dependency
  in the stage/verify steps can `PUT` the `R2_S3_SECRET_ACCESS_KEY` / `CF_CACHE_PURGE_TOKEN`
  to an attacker-owned R2 bucket through the allowed wildcard.
- `storage.googleapis.com:443` allows writes to any attacker-owned GCS bucket.
- `api.github.com:443` / `api.cloudflare.com:443` allow exfil via attacker-credentialed API
  calls (gist creation, DNS record content, …).

- **Attack scenario:** a poisoned Go module (the verify step compiles and runs `package main`
  tests) or compromised CLI dependency exfiltrates the R2 write credentials → attacker can
  overwrite the live catalog pointer at will (availability/DoS; **integrity still protected**
  by in-binary signature verification + the appliance-side rollback floor).
- **Preconditions:** supply-chain compromise of a build/test dependency in the publisher job.
- **Exploitability / likelihood:** low likelihood (requires upstream compromise), moderate
  exploitability once present. **Impact:** update-channel availability; credential loss.
- **Affected assets:** `R2_S3_SECRET_ACCESS_KEY`, `CF_CACHE_PURGE_TOKEN`, live catalog pointer.
- **Recommended fix:** at activation, narrow the wildcard to the exact account endpoint
  (`<account>.r2.cloudflarestorage.com:443` — the runbook already has the owner append hosts);
  evaluate whether `storage.googleapis.com` is actually needed (Go module fetches normally
  terminate at `proxy.golang.org`); document the `api.github.com`/`api.cloudflare.com`
  residual as accepted. Note `assertEgressAllowListWellFormed`
  (`release_workflow_invariants_test.go:187`) currently *requires* the wildcard form — update
  the invariant in the same change.
- **Required tests:** extend the egress invariant to reject the generic wildcard once the
  account-scoped host is pinned.
- **CWE:** CWE-923 (channel restriction) / supply chain. **OWASP:** A08:2021 Software and
  Data Integrity Failures. **Regression risk of fix:** low (workflow-only; invariant test
  updated in lock-step).

### F2 — MEDIUM · `.terraform.lock.hcl` gitignored: no provider hash pinning for the IaC managing the trust guardrails

**Files:** `deploy/terraform/.gitignore:4`, `deploy/terraform/versions.tf` (`~> 4.52`, `~> 6.0`)

The dependency lock file is explicitly excluded, so every `terraform init` (operator apply
**and** the new CI lane in `pr-deep-gate.yml`) re-resolves providers by floating version
constraint with no recorded hashes. Terraform providers are executed code — including during
`validate`.

- **Attack scenario:** a compromised/malicious provider release within the `~>` range (or a
  registry-side compromise) executes on the operator's machine during `apply` — at exactly the
  moment `CLOUDFLARE_API_TOKEN` (R2 admin) and `GITHUB_TOKEN` (repo admin — can edit the `v*`
  ruleset and the release environment) are in the environment.
- **Preconditions:** upstream provider/registry compromise; no local action needed.
- **Impact:** admin-token theft → release-guardrail tampering. **Likelihood:** low.
- **Recommended fix:** commit `.terraform.lock.hcl` (remove from `.gitignore`) with hashes for
  all target platforms (`terraform providers lock -platform=…`); run the CI lane with
  `terraform init -backend=false -lockfile=readonly` so drift fails loudly. This also closes
  the related PR-lane exposure (F-I9 below).
- **CWE:** CWE-494 (download of code without integrity check). **OWASP:** A08:2021.
  **Regression risk of fix:** minimal (adds a file; CI flag).

### F3 — LOW (NEW this window) · Unauthenticated `/ready` on the proxy port discloses CA bundle path, raw load error, and "inspection disabled" state

**Files:** `healthcheck.go:106` (`checks["ca"] = &checkResult{Status: "fail", Detail: detail}`),
detail built in `rootca_startup.go:31-38` (`noteSSLInspectionUnavailable` — includes the
configured CA path and the raw error), served unauthenticated at `main.go:864-865` (`/ready`
on the proxy port; `/health` on the same port exposes the `ssl_inspection: "load_failed"`
enum; `/healthz` on the UI port is `Public: true`).

- **Attack scenario:** any client that can reach the proxy port (i.e., every proxied user,
  including malware on a workstation) polls `GET /ready` and receives
  `"Root CA load/init failed for /data/ca.bundle: <underlying error> — SSL inspection DISABLED
  (TLS traffic is tunnel-only: no scanning/DLP/CDR)"`. This is precise reconnaissance: it
  confirms MITM inspection/DLP/CDR is off (a safe exfiltration window for an insider), and
  discloses the CA bundle filesystem path plus the raw error (which can reveal
  passphrase/decryption state, e.g. `cipher: message authentication failed`).
- **Preconditions:** root-CA load/init failed at startup (wrong `CULVERT_CA_PASSPHRASE`,
  corrupt bundle, unwritable dir) — exactly the degraded state CHAOS-06 makes long-lived —
  plus network reach to the proxy port.
- **Regression assessment:** the *state* (inspection off) was already inferable pre-change
  (the `ca` row was simply absent from `/ready`); the true regression is the **detail string**
  (path + raw error) on an unauthenticated surface. The enum-only exposure on
  `/health`/`/healthz` is a reasonable monitoring trade-off and should stay.
- **Recommended fix:** keep `Status:"fail"` with a generic `Detail:"root CA load failed — see
  server log"` on the unauthenticated surfaces; reserve the path+error detail for the
  admin-only `/api/diagnostics` and the `ca_load_failed` alert payload (both already carry it
  in this window). The CHAOS-06 visibility goal survives with the enum + generic row.
- **Required tests:** unauthenticated `/ready` response must not contain the CA path or the
  underlying error text while the failure is recorded; admin diagnostics still carries both.
- **CWE:** CWE-200 / CWE-209 (error-message information exposure). **OWASP:** A01/A05.
  **Regression risk of fix:** low (string-only; keep the enum for probes).

### F4 — LOW · Stale-catalog watchdog has no periodic evaluation in fetch-disabled or permissive deployments

**Files:** `release_wiring.go:475` (loop gate `wantSeed && cfg.refreshInterval > 0`),
`release_alerts.go:157` (`evaluateCatalogFreshness` invoked only from `runRefresh` and once at
wiring).

- **Failure scenario:** an air-gapped appliance uses the documented trust-safe opt-out
  (`CULVERT_RELEASE_CATALOG_URL=off`) with a manually installed catalog. The refresh loop
  never starts, so the only stale evaluation is the single boot-time call. Booted with >30
  days of validity and running for months, the 30-day threshold crossing is never evaluated —
  `release_catalog_stale` (the stated backstop for a failing re-sign pipeline) never fires;
  the catalog silently lapses and Release Management degrades to `available:false`.
- **Impact:** alert suppression on the exact terminal case the 180-day watchdog exists for —
  update-channel **availability**, not integrity (expiry gating and verification are
  unaffected; fail-closed holds). The Prometheus gauge
  `culvert_release_catalog_expires_in_seconds` does cover this at scrape time.
- **Recommended fix:** run a cheap dedicated freshness ticker whenever a catalog is published,
  independent of `wantSeed` (`evaluateCatalogFreshness` is lock-cheap, no I/O) — or document
  that disabled/permissive deployments must monitor the gauge.
- **CWE:** CWE-778 (insufficient logging/alerting). **Regression risk of fix:** low.

### F5 — LOW (pre-existing pattern, extended this window) · Lock-free policy `Evaluate` scan races with in-place mutators

**Files:** `policy.go:638-640` (`Evaluate` snapshots the `ps.rules` slice header under RLock,
then scans lock-free) vs. mutators that modify the *same* backing array and rule objects under
the write lock: `sortLocked` (`policy.go:595-618` — `sort.Slice` element swaps + in-place
writes of `normFQDN`/`srcIPNet`/`matchedConds`), `Update` (`policy.go:456` — element
overwrite), `Reorder`/`PermutePriorities` (in-place `Priority` writes then in-place sort).

- **Attack scenario:** a request evaluated concurrently with an admin
  `Update`/`Reorder`/`PermutePriorities` can observe a partially-sorted array — transiently
  evaluating a lower-priority allow before a higher-priority deny, or seeing a rule
  twice/skipping one mid-swap. Also a formal Go-memory-model data race. Not
  attacker-triggerable alone: requires a concurrent admin/API mutation. The cluster-sync and
  rollback paths use `ReplaceAll` (fresh slice, fresh pointers) and are safe.
- **This window's contribution:** the two new precomputed fields ride the same window but are
  semantically benign — a torn/nil `srcIPNet` or empty `matchedConds` hits the documented
  fail-closed fallback with identical semantics. The exploitable part (mid-sort ordering)
  predates the window (`normFQDN` + the snapshot-unlock pattern exist at 328c883). Note the
  only concurrency stress test (`TestProxyStress_PolicyChurn`) churns via `ReplaceAll` only,
  so race CI never exercises the vulnerable mutators.
- **Recommended fix:** make every mutator copy-on-write (rebuild a fresh `[]*PolicyRule` with
  fresh pointers, precompute, swap under the lock), or hold `mu.RLock` for the full scan.
- **Required tests:** add `Update`/`Reorder`/`PermutePriorities` to the policy-churn stress
  test under `-race`.
- **CWE:** CWE-362 (race condition). **Regression risk of fix:** moderate (hot path) — do it
  as a dedicated change with the stress test extended first.

### F6 — LOW · Publisher secret-contract wall is blind to bracket-form / `toJSON` secrets access

**File:** `release_workflow_invariants_test.go:332` (`wfRefRE` matches only dot-form
`secrets.NAME`), `:379-388` (`TestPublisherSecretContract`), `:405-413` (any-form ban applied
to `verify-dual-publish.yml` only).

For `publish-catalog-r2.yml` — the workflow that actually holds secrets — an added
`${{ secrets['EXFIL'] }}`, `${{ secrets[format(…)] }}` or `${{ toJSON(secrets) }}` reference
is invisible to the name-set contract and would pass the wall; `assertNoSecretsInAnyIf`
covers `if:` expressions only. **Fix:** assert that every `\bsecrets\b` occurrence inside
`${{ … }}` in the publisher is matched by the dot-form regex, so bracket/`toJSON` forms fail
the wall. **CWE:** CWE-693 (protection-mechanism failure).

### F7 — LOW · Publisher selects the release bundle by glob + `ls | head -n1`; verify workflow was hardened to exact-name but the publisher was not

**File:** `.github/workflows/publish-catalog-r2.yml:165-167` vs. `verify-dual-publish.yml:102`
(exact tag-derived name, pinned by `assertExactAssetSelection`).

Once M1-4 re-sign assets (or any second matching asset) exist on a release, the publisher's
pick becomes lexical-order-dependent; an actor with `contents:write` can attach an
earlier-sorting asset. Staged bytes must still carry a valid pinned-identity signature to
survive the verify step (worst case: publishing a stale-but-valid variant, further bounded by
appliance rollback floors). **Fix:** `--pattern "culvert-release-catalog-${TAG}.tar.gz"` in
the publisher too; extend the exact-name invariant to it. **CWE:** CWE-706.

### F8 — LOW · Stage-substitution guard has a get/head TOCTOU: the promote ETag pin can bind to an object that was never digest-checked

**File:** `.github/workflows/publish-catalog-r2.yml:217-231` (digest check via `get-object`,
ETag captured via a **second** `head-object`), promote pin at `:287`
(`--copy-source-if-match`).

An actor with R2 write can swap the object between the two calls; the promote then pins to
the swapped object, not the digest-verified one. Exploitation requires validly-signed catalog
material (an R2-write attacker can already overwrite the live pointer directly — in-binary
verification + the monotonic `catalog_version` floor remain the real trust boundary, as the
workflow header correctly states). Reported because the step's own comment claims the digest
check closes the substitution case. **Fix:** capture the ETag from the same `get-object`
response used for the digest check. **CWE:** CWE-367 (TOCTOU).

---

## Informational observations (documented/accepted posture — no action required to merge)

- **I1 · No-backend credential fall-through (behavior change, not a widening):** with the #626
  fix, in a no-backend originally-Exempt deployment a request *with* (unverifiable)
  credentials now reaches the inert guard and falls through as `unauth` where it previously
  got an unfulfillable 407 (`proxy.go:323-339`). Equivalent privilege to omitting the header
  (no identity, Stage-2 default-deny backstop) — matches the frozen spec's inert row.
- **I2 · Pre-existing asymmetry:** scoped `CredentialRequired` rules are not enforced in
  no-backend + global-**Default** deployments (`proxy.go:169` — gate skipped entirely),
  whereas the same rule now 407s in no-backend **Exempt** + kill-switch. Consistent with the
  spec; pre-existing at 328c883; recorded because the two no-backend shapes now differ.
- **I3 · Post-swap `holder.Reload()` failure** leaves a verified-but-unloaded catalog on disk
  while refresh reports failure, and `swapCatalogDir` has a syscalls-wide crash window where
  only `release_catalog.bak` exists (next boot: `available:false` until re-fetch — permanent
  in fetch-disabled mode). Content was fully verified pre-swap; in-memory state stays on the
  old catalog (fail-closed). Optional hardening: boot-time `.bak` restore.
- **I4 · Log-format consistency:** new reload/parse error logs use `%v` rather than
  `sanitizeLog`+`%q` (`release_wiring.go`); error chains originate from local post-verification
  files, so injection requires signer compromise or data-dir write — recommend wrapping for
  CWE-117/CodeQL consistency.
- **I5 · Default phone-home + synchronous boot seed:** a zero-config build now fetches
  `catalog.culvertlabs.com` at boot and ~6h (documented M1-2 product decision; trust posture
  unchanged). `runStartupAutoSeed` is synchronous before UI/proxy start — up to 30s boot delay
  when the origin is blackholed.
- **I6 · CF purge token passed as a curl CLI argument** (`publish-catalog-r2.yml:301`) —
  ps-visible on the runner; negligible on ephemeral single-tenant runners.
- **I7 · Protected `release` environment does not gate the R2 publisher** — explicitly
  documented with an upgrade path in `docs/operator/catalog-hosting-r2-activation.md`;
  consider actually taking the upgrade (converts "any merged workflow edit can use R2
  secrets" into "a human approves every publish").
- **I8 · `v*` tag ruleset leaves `creation` unrestricted** (documented trade-off for the
  auto-tag bot); mitigated by gate-approval checks on the tagged SHA, the keyless identity
  binding, and semver-monotonic `catalog_version`.
- **I9 · PR-triggered `terraform init` executes registry providers from PR-controlled
  `versions.tf`** (`pr-deep-gate.yml:434-467`) — equivalent to the repo's existing "PR jobs
  run PR code" posture (contents: read, no secrets, no id-token); closed as a side effect of
  F2's `-lockfile=readonly`.

---

## Regression Analysis — paths explicitly checked and found SAFE

**Auth / policy (fail-closed verified):**
- Kill-switch fix #626: gate entry on `originalEffective` re-arms scoped CR/SSO in the
  no-backend Exempt+kill-switch shape (407 restored); unmatched traffic falls to Stage-2
  default-deny with no identity; backend-present behavior byte-identical. Kill switch is now
  ≥ as restrictive in every enumerated matrix cell; regression tests would be red pre-fix.
- Policy precompute: ordering preserved (sort before precompute; linear first-match scan — no
  index/map introduced); CIDR semantics exact (invalid CIDR → nil → fail-closed fallback;
  unparseable client IP → no match); every mutator recomputes (`Load`/`ReplaceAll`/`Add`/
  `Update`/`Reorder`/`PermutePriorities`); hand-built rules (simulator/CDR) hit the fallback;
  `scheduleLocCache` keyed by admin-configured timezone only (bounded, never
  client-controlled); GeoIP fail-closed untouched; default-deny untouched.

**Limits / DoS:**
- connlimit #625: `Acquire` counts unconditionally, `enabled` gates rejection only; over-cap
  self-undo decrements the same counter (map-entry identity guarded), deletes at ≤0; `Release`
  entry-guarded — interleavings walked, no underflow/lost slot/admit-past-cap across
  disable/enable cycling; map growth bounded by live connections.
- SOCKS5 acquires the per-IP budget before the handshake and defer-releases (CHAOS-02 closed);
  rejection logged with peer IP only.
- reqlog #620: circular buffer entirely under `ringMu`; `Get` two-segment copy verified for
  wrapped/unwrapped/empty cases; snapshots copy into fresh backing arrays (no new aliasing);
  fixed `MaxRing` bound (improved vs. retrim churn).
- Catalog fetch DoS: all reads bounded (`readAllBounded`, 1 MiB) for index, sidecars, and
  every manifest; manifest fan-out is signer-controlled (enumerated only from a
  signature-verified index); 30s client timeout; manual refresh cancellable.

**Release-catalog trust chain (fail-closed verified):**
- `autoSeedCatalog`: stage → read-only re-verify → freshness → floor read (corrupt floor =
  error = fail closed) → rollback check → swap; any error leaves the on-disk catalog
  untouched; the floor is raised only by the authoritative post-swap `holder.Reload()`.
- Auto-seed and the loop run **only** in enforce mode; permissive never fetches; unsigned
  catalogs never auto-trusted. Stale-cache/CDN replay of an older 200 fails the rollback
  check; an eternal-304 MITM can only freeze the last good catalog, bounded by expiry + the
  watchdog.
- ETag validators: committed only via `CommitValidators()` after seed+reload fully succeed;
  rejected catalogs / failed reloads call `InvalidateValidators()` forcing a full re-download
  — the M1-2 pending-commit fix is correct, closing (not introducing) a validator-confusion
  hole.
- SSRF: inline `url.Parse`+scheme+`isPrivateHost` preflight (CodeQL-visible), authoritative
  dial-time per-resolved-IP guard (`safeDialContext`, closes DNS rebinding), per-hop redirect
  guard with a 5-hop cap; lazily-retried provider construction re-runs the guard.
- Redaction: `redactSeedError` replaces the entire embedded URL host-only (covers secret
  **path** segments) before logs/`LastErr`/audit/alerts; `catalog_origin` host-only; full URL
  exposed only for the public baked default; no URL labels in metrics; reload errors replaced
  with a fixed message so data-dir paths don't reach viewers.
- Fail-safe env parsing: `resolveRefreshInterval` — unset/typo/negative ⇒ 6h default, <1m
  clamped (a typo cannot disable the freshness loop); URL disable sentinels exact-match; a
  near-miss typo becomes an override that fails loudly (visible, trust unchanged).
- Alert latching (RT-H2): stale latch re-arms on fresh; failing latch clears on first success;
  boot-after-lapse fires exactly once; `deferStartupAlert`/`flushStartupAlerts` race-safe and
  wired before `loadReleaseManagement` — no queued release alert can be lost; no secrets in
  alert payloads (RISK-003 store untouched).
- RBAC/CSRF/audit: `POST /api/releases/catalog-refresh` — handler `requireRole(RoleAdmin)` +
  `uiRoutes` `MinRole: RoleAdmin, Mutating: true, AuditExpected: true` + audited both
  outcomes + CSRF via `securityMiddleware`; `/api/releases` viewer-read exposes redacted
  status only; route count pinned at 145; no route without metadata.
- Concurrency: `refreshRunMu` serializes runs (stale success cannot overwrite newer failure);
  `statusMu` isolates reads; all `releaseManager` field writes happen-before server-goroutine
  spawn; `PublishedRaw` is observability-only (no serving/dispatch path uses it).

**CI/CD supply chain (verified safe modulo F1/F6–F8):**
- Workflow injection: every untrusted value (`inputs.tag`, `workflow_run.head_branch`,
  `head_sha`, `ref_name`) passed via `env:`, never interpolated into `run:`; TAG anchored to
  strict `^v[0-9]+\.[0-9]+\.[0-9]+$` before use in R2 keys/URLs (closes `v1/../../live`
  traversal); no `pull_request_target` anywhere.
- Pwn-request: publisher checks out the **default branch**, never `workflow_run.head_sha`,
  with `persist-credentials: false`.
- Non-tag refs cannot reach publish: head_branch prefix filter + real-tag existence +
  annotated-tag deref + `TAG_SHA == workflow_run.head_sha` proof.
- Verify→promote binding: create-only stage (`--if-none-match '*'`) → origin digest check →
  real baked-root/pinned-identity verify of the **served** bytes with skip-proof
  (`jq -e` fails closed on empty output) → ETag-pinned server-side copy, index written last,
  no `continue-on-error`, `concurrency: cancel-in-progress: false`.
- Permissions: both new workflows `contents: read` only, no `id-token`; the invariants wall
  catches scalar `write-all`; the dual-verify workflow references zero secrets with an
  any-form `\bsecrets\b` ban.
- Egress fix 15e8dd7 verified: the previously-quoted wildcard failed **closed** (blocked),
  not open; `catalog.culvertlabs.com:443` is exact-host.
- All third-party actions in changed workflows SHA-pinned; `workflow_run` on the default
  branch restores only default-branch caches (no PR cache poisoning path).
- `ci.yml` catalog-spec migration to tested Go (`buildReleaseSpec`): inputs env-mediated;
  `TestResolveGateSpec_MatchesBuild` closes the shell→Go handoff; version encoding injective
  (no floor-shadowing); `NOW` never written into catalog bytes.
- Terraform (modulo F2): tfvars/state gitignored; providers credential-free at rest; no
  public-ACL resources; no wildcard IAM; outputs non-secret.

**Cluster / snapshot parity:**
- CHAOS-01 version-floor: monotonic-up-only CAS ratchet; persisted under the store lock in
  version order, 0600, atomic write; corrupt floor recovers via wall clock; recorded before
  the CA apply (partial failure can only *raise* the floor). DP-side `snap.Version <=
  lastVersion` guard and H5 caps untouched. `GetConfig` redaction for unenrolled callers
  untouched; `ThreatDomainAllowlist` non-sensitive; the `omitempty` removal is nil-guarded on
  apply (old-CP `null` → skip; no spurious wipe), explicit `[]` wipe propagation is the
  intended fail-closed direction with the registry row updated.

**Other:**
- threatfeed #623: URL-level blocking checked **first** and never allowlist-masked (allowlist
  exempts domain-level only — no widening); allowlist removal now re-blocks immediately
  (strictly tighter); canonicalization symmetric across feed keys/allowlist/lookups with no
  asymmetry bypass.
- upstream #606: `List()` stays `URL.Redacted()`; new CB fields carry no credential material;
  request-path logic unchanged.
- OCSP: fail-closed unchanged (all-responders-unreachable ⇒ revoked=true); the new 2-min
  `indeterminateTTL` only shortens how long the *fail-closed* verdict is cached — never caches
  "good" from a failure.
- update.go M0-PR4 gate: default OFF, enabled only by explicit truthy value, write-once
  `atomic.Bool`, dial seam proven by spy test, source-level wall against re-adding the direct
  GitHub call; only a boolean surfaced in `/api/update/status`.
- installer `allow_peers = []` awk fix: correctness only; no new privilege or input surface.
- Logging: every new log line carrying user input uses `sanitizeLog` + `%q`
  (`AUTH_NO_BACKEND_INERT`, `scheduleLocation` warn, domain-allowlist audit).
- E2E `CULVERT_RELEASE_CATALOG_URL=off` additions: the documented trust-safe fetch opt-out —
  verification stays enforced.

---

## Risk Rating

| # | Finding | Severity | New in window? | Fail direction |
|---|---------|----------|----------------|----------------|
| F1 | R2 egress allow-list generic exfil channels / any-tenant wildcard | MEDIUM | Yes (new workflow) | Credential-loss → availability only (integrity held by in-binary verify) |
| F2 | Terraform provider lock file gitignored | MEDIUM | Yes (new IaC) | Supply-chain code execution with admin tokens present |
| F3 | Unauthenticated `/ready` CA path + error + inspection-off detail | LOW | **Yes (regression)** | Information disclosure |
| F4 | Stale watchdog inert in fetch-disabled/permissive mode | LOW | Yes (new feature gap) | Alert suppression (availability) |
| F5 | Policy store in-place mutators vs. lock-free Evaluate | LOW | Pre-existing, extended | Transient precedence inversion under admin churn |
| F6 | Publisher bracket-form secrets blind spot | LOW | Yes (new wall gap) | Guard incompleteness |
| F7 | Publisher glob asset selection | LOW | Yes | Deterministic-publish gap (bounded by signature+floor) |
| F8 | Stage-guard ETag get/head TOCTOU | LOW | Yes | Guard-claim gap (bounded by signature+floor) |

No finding blocks a release. F3 is the only *behavioral* security regression introduced by
the window and is a string-scoping fix. F1/F2 should be scheduled before or at R2 activation.

## Residual Risk

- The real trust boundary for the update channel is in-binary verification (baked
  roots/pinned identity, enforce mode) + the monotonic `catalog_version` floor; every CI-side
  finding above is bounded by it. An attacker holding R2 write credentials can deny updates
  (pointer overwrite) but cannot forge a catalog.
- The `caRuntime` unsynchronised global and the policy-store snapshot-scan pattern (F5)
  remain the two known pre-existing concurrency debts on security-relevant state.
- Bounded-LWW on HA partition (≤TTL) and the documented no-backend Default-mode CR
  asymmetry (I2) are accepted, spec-recorded postures.

## Required Tests (for the recommended follow-ups)

- F3: unauthenticated `/ready`/`/health`/`/healthz` bodies must never contain the CA path or
  raw load error while a failure is recorded (positive: enum present; negative: detail
  absent; admin diagnostics unchanged).
- F5: extend `TestProxyStress_PolicyChurn` to churn via `Update`/`Reorder`/
  `PermutePriorities` under `-race`; then convert mutators to copy-on-write.
- F1/F6/F7: extend `release_workflow_invariants_test.go` — account-scoped R2 host, any-form
  secrets ban on the publisher, exact-name asset selection on the publisher.
- F8: single `get-object` response supplying both digest and ETag (workflow change; pin with
  an invariant that the promote step's ETag variable is produced by the digest-check step).
- F4: freshness-ticker unit test — catalog published + loop disabled ⇒ stale alert still
  fires at threshold crossing.
