# Culvert Technical Risk Register

> **Owner:** Chief Engineering Advisor · **Status:** Living · **Last review:** 2026-07-05 (drift sync)
>
> Risks are things that can go wrong in production or in the supply chain. Structural shortcuts
> live in the [Technical Debt Register](./TECHNICAL-DEBT-REGISTER.md). Some items appear in both
> when a structural shortcut also carries runtime risk; the cross-reference is noted.
>
> **Severity:** BLOCKER (must fix before the relevant production claim) · HIGH · MEDIUM · LOW.
> **Status:** OPEN · MITIGATING · ACCEPTED (with rationale) · CLOSED.
> Every row carries repository evidence. `HV` = hand-verified by the Advisor on the review date.

| ID | Sev | Status | Title | Evidence |
|---|---|---|---|---|
| RISK-001 | HIGH | ✅ CLOSED | Multi-CP HA split-brain (no quorum/fencing) | ADR-0004 safe defaults + ADR-0005 S0–S5 SHIPPED (2026-07-03): etcd fencing lease — Acquire-gated promotion, self-fence, epoch-fenced write sinks, safe auto-failover, GUI/compose/runbook. Legacy (no etcd) keeps the safe-manual posture. **HV** |
| RISK-002 | HIGH | ✅ CLOSED | OIDC introspection path missing SSRF dial guard | fixed `auth_oidc.go:95` (2026-06-28) |
| RISK-003 | HIGH | ✅ CLOSED | Webhook HMAC secret persisted cleartext on disk | `alerts.go`, `alerts_secret.go` |
| RISK-006 | MEDIUM | ✅ CLOSED | Gate config blind spots: `--ignore-unfixed` + `HIGH,CRITICAL` only (masks unfixed/medium) | advisory unmasked report + trivy-native `exp:` dates (2026-07-04) |
| RISK-014 | MEDIUM | ✅ CLOSED | Reachability gate (govulncheck) scans root module only; nested modules unanalyzed | per-module govulncheck in both lanes (2026-07-04) |
| RISK-015 | LOW | OPEN | Single-scanner gate; detection-source divergence (Dependabot 5 vs Trivy DB 3) | trivy run vs Dependabot count, 2026-06-28 |
| RISK-016 | LOW ↓ | MITIGATING | ~~Scanners `@latest`~~ all pinned (tree-verified 2026-07-04); residual: CodeQL non-blocking | gosec v2.27.1 / govulncheck v1.5.0 / go-licenses v1.6.0 / trivy v0.69.3 / Obituary SHA-pinned |
| RISK-ACC-1 | HIGH | ✅ CLOSED | 5 `docker/docker` CVEs in `updater/` | legacy updater removed 2026-07-11 (DEBT-008); dependency tree deleted |
| RISK-005 | MEDIUM | ✅ CLOSED | Interrupted restore can leave `/data` absent | boot guard `checkInterruptedRestore` (`restore.go`) + runbook §8b |
| RISK-008 | MEDIUM | ✅ CLOSED | Username timing oracle enables user enumeration | fixed `store.go` (2026-06-28) |
| RISK-009 | MEDIUM | ✅ CLOSED | `InsecureSkipVerify` admin toggle silent on auth hot path | `auth_oidc.go:96`, `auth_oidc_flow.go:301`, `auth_ldap.go:90` |
| RISK-010 | MEDIUM | ✅ CLOSED | Self-update has no in-binary image signature/digest check | legacy `update.go` removed 2026-07-11 (DEBT-008); successor (maintenance agent) is digest-pinned + Sigstore-verified |
| RISK-011 | MEDIUM | ⚠ STALE→RE-POINTED | ~~Cluster rolling-update auto-rollback unverified~~ cited code REMOVED; concern resolved in successor, new residual = RISK-022 | `update_cluster.go` deleted; successor `inline_rollback.go` verifies revert+health (2026-07-11 audit) |
| RISK-021 | HIGH | OPEN | Fresh/unconfigured proxy runs default-allow + no-auth (silent, advisory-log only) | `rewrite_default_action_startup.go:23-25`, `store.go:470` (HV 2026-07-11) |
| RISK-022 | HIGH | OPEN | Maintenance agent death mid-apply is unrecoverable (no op journal; `MarkAllInterrupted` no-op) | `cmd/culvert-maint/internal/ops/ops.go:468` (HV 2026-07-11) |
| RISK-012 | LOW | ✅ CLOSED | Account lockout is username-keyed (lockout-as-DoS) | two-tier (IP,user)+account keying w/ trusted-IP bypass (2026-07-05); adversarially reviewed 2× |
| RISK-019 | MEDIUM | ✅ CLOSED | Admin-UI per-IP logic keys on direct peer IP; no trusted-proxy XFF extraction (lockout collapses behind an L7 proxy) | trusted-proxy `realClientIP` (2026-07-05); adversarially reviewed |
| RISK-018 | LOW | ✅ CLOSED | Leaked HA `standbyLoop` goroutine races test `logger` swaps (determinism-gate flake) | `resyncCtx(t)` cleanup-cancelled ctx (2026-07-04) |
| RISK-013 | LOW | ✅ CLOSED | `normalizeHost` IDNA failure is fail-open | fail-closed `NormalizeHostStrict` gate at proxy+SOCKS5 dispatch (2026-07-05); adversarially reviewed |
| RISK-020 | LOW | OPEN | Native HTTP/2 inspection: deferred hardening on the opt-in path | `proxy_tunnel_h2.go` — see below |
| RISK-024 | MEDIUM | ✅ CLOSED | Unauthenticated flood evicts other users' in-flight SSO login state (PKCE/SAML capped stores evicted an arbitrary LIVE entry) | fair-share eviction `internal/authstate` + `authStateClientKey` (2026-08-19); gates `auth_login_state_flood_test.go`, RED against the prior policy |
| RISK-023 | LOW | ✅ ACCEPTED | `diagnose tls` probe uses `InsecureSkipVerify` to inspect invalid/expired chains | `diagnose.go` `tlsHandshakeProbe`; bounded, SSRF-guarded, never carries traffic — see below |
| RISK-024 | MEDIUM | ✅ CLOSED | Unbounded stale-JWKS trust: a cached IdP signing key kept authenticating ID tokens forever once refreshes stopped succeeding, so a key REVOKED at the IdP never took effect (revocation opt-out) | introduced by CHAOS-49 (#1117) alongside its correct cache-wipe fix; closed by the `jwksStaleMaxAge` fail-closed ceiling in `auth_oidc_flow.go` (2026-08-18). Gates: `auth_oidc_jwks_stale_ceiling_test.go` (refusal gates reproduced against pre-fix behaviour). Review: `security-reviews/2026-08-18-mcp-pr12-and-idp-registry-window.md` |
| RISK-025 | MEDIUM | ✅ CLOSED | Inbound `X-User-Identity` unscrubbed on ingress: on identity-free paths (default-Exempt / scoped exempt / no-backend) a client-supplied value reached `policyStore.Evaluate` as `SourceIdentity` and the HTTP-path log attribution (CWE-290/807) | unconditional ingress delete + direct `authenticatedIdentity` evaluation + trailer scrub (F1, 2026-08-13), pinned by `authz_identity_ingress_test.go`; residual header transport CLOSED by F6 — typed `ProxyIdentity` plumbing through `handleHTTP` + the inspect chain, nothing stamps or reads `X-User-Identity` internally, ingress/egress scrubs retained as defense-in-depth — see `docs/security-reviews/2026-08-13-x-user-identity-ingress-trust.md` |
| RISK-026 | HIGH | OPEN | MCP Gateway has no per-source admission: one client can monopolize a capability's entire worker pool + queue, PRE-AUTHENTICATION | `runtime.Limits.AdmissionBudget` is documented as a "per-source admission budget", validated, ceiling-checked, exposed as an accessor — and has ZERO enforcement call sites; `Listener.admit` has no notion of a source and `runtime.Request` carries no client address. Admission is step 1, so the flood costs nothing to mount. Options + recommendation (two-tier: coarse pre-auth per-TCP-peer, per-principal after auth) in `security-reviews/2026-08-24-mcp-backend-full-review.md` §4 MCP-05b. **Blocker for exposing an MCP listener beyond a controlled host.** |
| RISK-027 | MEDIUM | OPEN | A degraded or dead MCP listener is invisible to fleet monitoring | MCP has no operator-contract row, no report-only `/readyz` row, no `/healthz` field and no `culvert_mcp_*` series — its health exists only under admin-authenticated `/api/mcp/*`. Every other subsystem with a failure mode follows the `storage_health.go` / `ca_health.go` / `socks5_health.go` pattern. The admin surface itself is truthful (activation failure reports `invalid` + reason, never ready), so this is operability, not correctness. Deliberately not implemented in the 2026-08-24 review: whether MCP influences `/readyz` is an operator-contract decision (it should NOT — an MCP fault must never pull a healthy SWG out of rotation). |
| RISK-028 | MEDIUM | OPEN | Culvert is pinned to a superseded MCP protocol generation | `internal/mcp/protocol/version.go` supports `2025-11-25` / `2025-06-18` and rejects `2026-07-28`, which was released as the FINAL MCP specification on that date (the code comment still described the May 2026 RC; corrected 2026-08-24). Rejection is now a dated, deliberate decision — `2026-07-28` is a stateless redesign that removes the substrate for session-identity binding, lifecycle admission and the session cap. As SDKs default to it, clients and registered upstream servers that cannot fall back become unreachable. Migration architecture + the blocking ADR: `docs/design/mcp/PROTOCOL-MIGRATION-2026-07-28.md`. |

---

## RISK-023 — `diagnose tls` handshake probe disables cert verification · LOW · ✅ ACCEPTED
- **What CodeQL flags:** `diagnose.go`'s `tlsHandshakeProbe` sets `InsecureSkipVerify: true`
  ("go/disabled-certificate-check", high). This is **intentional and inherent to the feature**,
  not a defect.
- **Why it must:** the `diagnose tls` support verb exists to let an operator inspect an endpoint's
  TLS chain — including an **invalid or expired** one — and report `chain_verified` separately (via
  a subsequent `cert.Verify` in `summarizeTLSState`). A handshake against an invalid chain cannot
  complete with verification enabled; this is the same pattern `openssl s_client` uses. Reporting
  validity is the whole point of the verb, so verification is deliberately deferred, not skipped.
- **Why LOW / bounded:** the probe is **SSRF-guarded** (`ssrfControl` on the dialer, private-IP
  refusal), enforces `MinVersion: TLS 1.2`, is bounded by `diagnoseTLSTimeout`, is admin/operator-
  RBAC-gated, and the connection **never carries traffic** — it is opened, its `ConnectionState` is
  copied out, and it is closed. No proxied bytes ever flow over an unverified connection; the
  enforcement path is untouched.
- **Disposition:** ACCEPTED. The CodeQL alert is dismissed with this justification (owner action in
  the Security tab, "used intentionally"). Do not "fix" it by removing `InsecureSkipVerify` — that
  deletes the diagnostic capability. Pinned by `#nosec G402` at the call site with the same rationale.

---

## RISK-020 — Native HTTP/2 inspection deferred hardening · LOW · OPEN
- **Context:** native H2 inspection (`proxy_tunnel_h2.go`) is **opt-in per rule** (`stripAlpn: false`);
  the default and every pre-feature rule keep the HTTP/1.1-downgrade path, so production behavior is
  unchanged until an operator opts in. Reviewed by three independent implementation reviewers per
  milestone (SWG architect, HTTP/2+TLS security, Go runtime) — all APPROVE-WITH-CHANGES, every verified
  finding fixed, no opt-in merge blocker. Security posture: per-stream inactivity watchdog,
  `MaxConcurrentStreams=32` (also the Rapid-Reset cap), 1 MiB frame/header caps, pinned upstream conn
  (no `:authority` SSRF), truncation → RST. Rapid Reset (CVE-2023-44487) + CONTINUATION flood
  (CVE-2023-45288) mitigated by the vendored `golang.org/x/net`.
- **Residual (deferred, documented in `docs/operator/http2-inspection.md`):**
  1. **`:authority` pinning / 421** not enforced — **not a new exposure** (the HTTP/1.1 path forwards the
     inner `Host` to the pinned upstream identically today; single-SAN forged leaf prevents coalescing).
     Tracked as a **shared H1+H2** hardening item, not H2-only.
  2. **Graceful GOAWAY on shutdown** — inspected H2 tunnels are counted + drained, but `ServeConn`
     hard-closes rather than sending a client GOAWAY (bounded by the x/net API). Availability, not
     security.
  3. **Configurability** — stall timeout + `MaxConcurrentStreams` are compile-time constants; exposing
     them as admin-tunable decryption-profile settings (PAN-OS-style) is a planned follow-up.
  4. **Per-connection scan memory** — worst case `maxScanBufferBytes × MaxConcurrentStreams` per
     malicious connection; documented as a capacity-planning note.
- **Why LOW:** opt-in, off by default, bounded, reviewed; each residual is either not-a-new-exposure,
  availability-only, or a usability follow-up.

---

## RISK-001 — Multi-CP HA split-brain · HIGH · ✅ CLOSED 2026-07-03
- **Design:** `docs/adr/0004-ha-split-brain-fencing.md` (the 2-node-no-witness theorem, the rejected
  hand-rolled DP-quorum design with the adversarial-review findings F1–F9, and the Slice 1 / open-
  mechanism split).
- **Slice 1 LANDED (2026-06-30, ADR-0004):** the dangerous *default* is gone.
  - **Auto-failover is OPT-IN and OFF by default** (`--ha-auto-failover` / `auto_failover` API field +
    GUI checkbox). With the default, a standby that loses the leader stays **read-only**, fires
    `ha_manual_failover_required`, and keeps retrying — no unattended self-promotion.
  - **Restart honors the persisted role** (`haRestartAction`): a standby re-enters standby instead of
    self-asserting as a second leader (the verified `main.go:647` bug); a leader resumes with a
    split-brain-risk warning under auto-failover.
  - **`/healthz` exposes `term` + `write_authority`**, so a double-leader is now *detectable* (compare
    terms across both CPs) instead of two indistinguishable `leader:true` bodies.
  - **Explicit promote primitive (Slice 1e, PR #525 review):** `POST /api/cluster/ha/promote` +
    UI button + `HAState.PromoteManually()` make operator manual failover real (it had no endpoint
    before); the CP rolling update (`updateCPWithHA`) now arms a coordinated planned handoff
    (`HAStateBundle.PromoteRequested`) instead of relying on auto-promote, closing a regression
    default-manual introduced. Failback stays deferred.
  - Behavior is re-pinned in `ha_split_brain_failover_evidence_test.go` (assertions flipped to the new
    state) + `ha_autofailover_test.go` / `ha_term_test.go` / `ha_promote_test.go`.
- **Mechanism SHIPPED — ADR-0005 S0–S5 complete (2026-07-03):** the automatic-failover mechanism is an
  **etcd-backed fencing lease** (maintainer chose "big-vendor, self-hosted" → etcd; hand-rolled witness
  rejected by a second adversarial review — findings 1–8 recorded in ADR-0005 with per-slice
  resolutions, plus 4 Codex-review fixes on the S3 fencing surfaces).
  - **S0** — leader records the standby's advertised address (failback target).
  - **S1** — `internal/halease`: Provider contract + etcd backend (epoch = `create_revision`) +
    Fake, dual-backend conformance suite incl. embedded etcd.
  - **S2** — lease wired into leadership: Acquire-gated promotion, keepalive with
    etcd-as-clock self-fence, `WriteAllowed()`, term collapsed to the fencing epoch.
  - **S3** — epoch fencing at every write sink: per-RPC issuance gate (Enroll/RenewCert/
    SyncRevocations), puller-side bundle-epoch verification, DP epoch ratchet.
  - **S4** — lease-arbitrated auto-failover (flag ignored in lease mode) + freshness gate +
    re-promotion hysteresis + demote-and-resync from the S0-recorded ex-standby.
  - **S5** — operator wiring: `-ha-etcd-*`/`-ha-lease-ttl` flags + `cluster.etcd_*` YAML,
    fail-fast on malformed lease config, ghost-lease resume (`acquireLeaseForResume`), GUI lease
    card + `/api/cluster/ha` lease fields, profile-gated compose etcd witness,
    `docs/operator/ha-lease-failover.md` runbook.
- **Residual (accepted + documented, not risk-register material):** (1) deployments WITHOUT etcd stay
  in the ADR-0004 safe-manual posture — split-brain there requires the operator to opt into the legacy
  flag against documented advice; (2) bounded LWW window on partition (≤TTL of unreplicated admin
  writes may be lost on resync) — the chosen F4 posture (option A), documented in the runbook;
  (3) evidence: `TestCL4_LeaseMode_SplitBrainStructurallyPrevented` pins that the double-leader shape
  cannot form in lease mode; legacy-mode CL-4 facts stay pinned for legacy deployments.
- **Owner:** shipped · **Closed:** 2026-07-03 (ADR-0005 S5).

## RISK-002 — OIDC introspection missing SSRF guard · HIGH · ✅ CLOSED 2026-06-28
- **Was (HV):** `NewOIDCAuth` (`auth_oidc.go`) cloned the introspection transport with **no**
  `DialContext = ssrfSafeDialContext`, unlike the sibling `auth_oidc_flow.go:300`. The
  admin-configured introspection URL is reached on every token-validating request → per-request SSRF
  toward `169.254.169.254`/loopback.
- **Fix:** added `transport.DialContext = ssrfSafeDialContext` after the clone (`auth_oidc.go:95`),
  byte-mirroring the flow variant. The guard runs `ssrfControl` post-DNS (DNS-rebind safe).
- **Tests:** 9 server-based OIDC unit tests hit a `127.0.0.1` test IdP, which the new guard correctly
  rejects; updated them to use the existing `allowLoopbackSSRF(t)` seam (the SSRF dialer is a package
  var explicitly swappable in tests). Validated: build, vet, full auth `-race` (59.5s) green.
- **Note:** the OIDC *flow*, SAML, alerts, threatfeed, blocklist, and release-catalog HTTP paths
  already carried the guard; this closes the one introspection path that lacked it.

## RISK-003 — Webhook HMAC secret cleartext at rest · HIGH · ✅ CLOSED
- **Was:** `AlertStore.save()` marshalled `AlertWebhook.Secret` (the HMAC signing key) to `0600` JSON
  in cleartext. The CA bundle was AES-GCM encrypted; this secret was not.
- **Impact:** A read of `alert_webhooks.json` (or a copied data dir) let an attacker forge signed
  alert payloads.
- **Fix (2026-06-30, `alerts_secret.go`):** secrets are now **AES-256-GCM encrypted at rest** under a
  per-data-dir random key (`.alert_webhook_key`, `0600`, generated on first save, cached per path).
  `save()` encrypts a copy before marshalling (`enc:v1:` + base64(nonce‖ciphertext)); `Init()`
  decrypts back into the in-memory cleartext used for HMAC signing. **Fail-closed:** an encrypt error
  aborts the write rather than falling back to cleartext. Legacy cleartext (no `enc:` prefix) loads
  unchanged and is migrated on the next save; an unrecoverable decrypt drops the secret (deliveries
  go unsigned, admin re-enters) instead of signing with garbage.
  - **Export side was already safe:** config export uses `AlertStore.List()`, which strips `Secret`
    (`ui_config.go`), so the "redact on export" half of the recommendation was already in place.
  - **Threat model:** mitigates the stated vectors (reading the webhook JSON; a config-export bundle —
    neither contains the key). It does not defend against an attacker who reads the whole data dir
    including the hidden key file — inherent to local-key encryption-at-rest, and a far higher bar
    than cleartext in a 0600 file.
  - Tests (`alerts_secret_test.go`): no cleartext on disk + `enc:v1:` marker present, decrypt
    round-trip on reload, encrypt/decrypt unit round-trip (empty + legacy passthrough), legacy
    cleartext migrated on save. Webhook HMAC delivery tests still green (signing unaffected).
    Build/vet/lint/`-race`/determinism all green. **Complexity S — closed as recommended.**

## RISK-006 — Trivy gate config blind spots · MEDIUM · ✅ CLOSED 2026-07-04
- **Fix (as recommended):** (1) the blocking gate keeps `--ignore-unfixed` (un-actionable noise is a
  real cost), and a new **non-blocking full-severity pass** (no `--ignore-unfixed`, no severity
  filter, `--show-suppressed` so `.trivyignore`'d findings appear WITH suppression status — trivy
  auto-loads `.trivyignore` from the cwd, so merely omitting `--ignorefile` would not unmask them;
  caught by Codex review on PR #557) posts everything Trivy knows to the job summary — "green
  gate" can no longer silently coexist with masked vulns. (2) `.trivyignore` entries now carry **trivy-native
  `exp:` dates** (better than the recommended CI check — trivy itself stops honoring the ignore
  when the date passes, flipping the blocking gate red and forcing re-triage). Dates were set to
  2026-10-01, aligned to the updater-removal target (DEBT-008/RISK-ACC-1); the file documented
  that extending requires re-validating the reachability rationale, not reflex.
- **Update 2026-07-11:** the updater module was removed (DEBT-008/RISK-ACC-1 CLOSED), so those two
  `docker/docker` masks were retired and `.trivyignore` is now empty. The `exp:`-date mechanism and
  the full-severity non-blocking pass remain the pattern for any future suppression.
- Original finding preserved below for context.

### (was) RISK-006 — Trivy gate config blind spots · MEDIUM · OPEN
- **Current state (trivy-verified 2026-06-28):** The blocking trivy gate runs
  `trivy fs --severity CRITICAL,HIGH --ignore-unfixed --ignorefile .trivyignore`
  (`security-release-gate.yml:135-143`). I ran the *exact* command locally: it exits **0 (green)**
  while an unfiltered scan of the same tree finds **2 HIGH + 1 MEDIUM** real CVEs. The gate cannot
  fail on a vulnerability that (a) has no upstream fix yet (`--ignore-unfixed`), (b) is MEDIUM or
  lower, or (c) is listed in `.trivyignore`. All three masking mechanisms are currently active.
- **Why this matters beyond the updater:** the masked CVEs today happen to be in `updater/` (being
  removed, RISK-ACC-1). But the *configuration* applies to the **root proxy binary** too: a future
  HIGH in a root dependency with no released patch would ship behind a green gate, silently.
  "Green gate" means "no fixed, HIGH/CRITICAL, non-ignored, Trivy-DB-known vuln" — **not** "no
  known vulns on the branch." Dependabot's 5 alerts coexisting with a green gate is the proof.
- **Impact:** Latent — false confidence that a green gate == a clean branch. No current root-module
  exposure (root scans 0 vulns).
- **Recommendation:** Keep `--ignore-unfixed` for the *blocking* gate (un-actionable noise is a real
  cost) but add a **non-blocking, visible "known-unfixed / medium" report** (e.g. a second trivy run
  with `--ignore-unfixed=false --severity MEDIUM,HIGH,CRITICAL` that posts to the log/summary), and
  give every `.trivyignore` entry an `# expires:` date that a CI check enforces. **Complexity S.**
- **Owner:** unassigned · **Target:** this month.

## RISK-014 — Reachability gate covers root module only · MEDIUM · ✅ CLOSED 2026-07-04
- **Fix (as recommended, with one deliberate nuance):** explicit per-module govulncheck steps in
  BOTH lanes (`pr-fast-gate.yml` security-fast job — the merge-blocking one — and
  `security-release-gate.yml` vuln-govulncheck). `cmd/culvert-maint` is **blocking** like the
  root. The former `updater/` advisory step (`continue-on-error`, carrying the RISK-ACC-1 unfixed
  CVEs) was **removed on 2026-07-11** together with the module (DEBT-008 CLOSED), so the per-module
  govulncheck matrix is now just root (blocking) + `cmd/culvert-maint` (blocking).
- Local verification unavailable (org egress still 403s `vuln.go.dev`); the CI runs on this
  branch's PR are the proof. Original finding preserved below.

### (was) RISK-014 — Reachability gate covers root module only · MEDIUM · OPEN
- **Current state:** `vuln-govulncheck` runs `govulncheck ./...` from the repo root
  (`security-release-gate.yml:114`). govulncheck does not traverse separate modules, so
  `updater/go.mod` and `cmd/culvert-maint/go.mod` get **no reachability analysis** — they are
  covered only by trivy (no reachability) plus the hand-written `.trivyignore` reasoning.
- **Impact:** The two secondary binaries' reachable-vuln posture is asserted by prose, not analyzed.
  (Note: I could not run govulncheck locally to independently confirm root-module reachability —
  the org egress policy blocks `vuln.go.dev` with 403. CI is not behind this policy, so the CI run
  is authoritative; this register relies on the CI gate's own govulncheck for root reachability.)
- **Recommendation:** Add a govulncheck step per nested module (`cd updater && govulncheck ./...`,
  same for `cmd/culvert-maint`). When `updater/` is removed (DEBT-008), this shrinks to one extra
  step. **Complexity XS.**

## RISK-015 — Single-scanner gate; detection-source divergence · LOW · OPEN
- **Current state:** Dependabot (GitHub Advisory DB) reports **5** docker/docker alerts; Trivy (its
  own DB) reports **3** of them; the Go vuln DB (govulncheck) is a third source. The blocking gate
  relies on Trivy's DB for dependency-graph coverage. The three sources demonstrably disagree on
  count and timing of advisory ingestion.
- **Impact:** An advisory present in one DB but not yet in Trivy's can pass the gate until Trivy
  ingests it. Low, but it means the gate's recall is bounded by one vendor's DB freshness.
- **Recommendation:** Treat Dependabot as the *advisory* superset and reconcile it against the gate
  periodically (this exercise). Optionally add `osv-scanner` as a second non-blocking source.
  **Complexity S.**

## RISK-016 — Scanners `@latest` / CodeQL non-blocking · MEDIUM → LOW · MITIGATING
- **Drift sync (tree-verified 2026-07-04): the pinning half was already fixed in the tree** —
  gosec `@v2.27.1`, govulncheck `@v1.5.0`, go-licenses `@v1.6.0` (both lanes), trivy `v0.69.3`
  via SHA-pinned setup action, and `KidCarmi/Dependency-Obituary` SHA-pinned with a dated
  comment (`ci.yml:87`). The register was stale, not the gates.
- **Residual (the reason this stays open at LOW):** CodeQL remains advisory — it is in no gate's
  `needs:` and not a required check. Making it merge-blocking is a **branch-protection setting**
  (add the CodeQL check to required status checks), which only the repo admin can flip — it is
  not expressible in repo code. **Action for maintainer:** enable it once comfortable with CodeQL's
  signal-to-noise on this repo; the workflow already runs on the right PR surface (`codeql.yml`).
- *(This was the original RISK-006 before the 2026-06-28 split.)*

## RISK-017 — Alert webhooks never persisted (Init unwired) · MEDIUM · ✅ CLOSED 2026-07-03
- **Found (2026-07-03, while mapping the `internal/alerts` extraction):** `AlertStore.Init(path)` is
  **never called from production code** — only tests call it. `git log -S` confirms no production
  call has ever existed. The process-wide store is constructed with an empty `filePath`, so `save()`
  is a silent no-op for every admin webhook create/update/delete.
- **Impact:** Admin-configured alert webhooks (and their HMAC secrets) **do not survive a restart** —
  security alerting silently stops after any upgrade/restart until the admin reconfigures. The
  RISK-003 encryption-at-rest machinery protects `alert_webhooks.json`, a file production never
  writes; the F16 retry queue DOES persist (`/data/alert_retry_queue.json`), an inconsistency that
  hides the gap. The only durability today is a manually downloaded config export.
- **Fix (2026-07-03, follow-up commit to the extraction):** `AlertWebhooksPath`
  (`<dataDir>/alert_webhooks.json`) added to the persistent-admin-state startup slice
  (resolver + DTO + loader step 4); `globalAlertStore.Init` now runs at startup, so webhooks —
  and their RISK-003 encrypted secrets — survive restart, and the encryption-at-rest machinery is
  live in production for the first time. In the same change `Store.save()` was upgraded from the
  pre-Bucket-4 WriteFile+Rename to `fileutil.AtomicWrite` (fsynced), since the path only now
  became load-bearing. No ordering hazard: the F16 retry loop reads the store through a provider
  closure each 10s tick. Pinned by `TestStore_Persist_RestartRoundTripAndDurability`
  (internal/alerts) — restart round-trip incl. decrypted secret, mode 0600, no tmp leftovers —
  and the slice-resolver path test.

## RISK-ACC-1 — `docker/docker` CVEs in the updater · HIGH · ✅ CLOSED 2026-07-11
- **Was:** 5 CVEs in `github.com/docker/docker v28.5.2`, all in `updater/go.mod` only:
  `CVE-2026-41567` (HIGH), `CVE-2026-42306` (HIGH), `CVE-2026-41568` (MEDIUM), plus
  `CVE-2026-34040`, `CVE-2026-33997` (in `.trivyignore`). None had an upstream fix, so the risk
  was ACCEPTED until the updater module could be removed (resolution path = DEBT-008).
- **Resolution:** the legacy Docker updater was removed on 2026-07-11 (DEBT-008 CLOSED). Deleting
  `updater/go.mod` deleted the entire `docker/docker` dependency tree — `go list -m` across the root
  module and `cmd/culvert-maint` no longer references `github.com/docker/docker`, so all 5 alerts
  are structurally closed (nothing to bump, nothing reachable). The two `.trivyignore` masks were
  retired with the module; the file is kept present-but-empty for the workflows' `--ignorefile`.
- The maintenance agent (`cmd/culvert-maint`) drives Docker via the `docker` CLI over sudo, not the
  Go SDK, so no `docker/docker` dependency was reintroduced.

## RISK-005 — Interrupted restore leaves `/data` absent · MEDIUM · ✅ CLOSED 2026-06-30
- **Was:** `runRestoreCommit` (`restore.go`) does move-aside (`rename /data → /data.bak.<ts>-<pid>`)
  then swap (`rename /data.staging.<ts>-<pid> → /data`). A kill between the two renames left `/data`
  missing; the next normal boot would create a fresh **empty** `/data` and **silently lose the
  operator's data**, with the recovery `.bak` discoverable only by hand.
- **Fix (`checkInterruptedRestore`, `restore.go`):** a boot-time guard, called from `main()` right
  after the one-shot CLI commands (so `--list`/`--cleanup-restore-leftovers` and `--restore` still
  operate on the orphaned state). When `/data` is **absent AND** an interrupted-restore `.bak` sibling
  exists, it **refuses to boot** (`FATAL` + `os.Exit(1)`) and prints the exact recovery moves — REVERT
  (`mv .bak /data`) or, if a correlated `.staging` is present, COMPLETE (`mv .staging /data`). It
  reuses the D1.3c `discoverLeftovers` scanner (sibling-only, exact-name regex, no symlink follow), and
  points at the **newest** `.bak` when several generations exist. A genuine fresh install (no `/data`,
  no `.bak`) is unaffected.
- **Tests (`restore_interrupted_test.go`):** present-dir no-op, fresh-install no-op, bak-only refusal
  with actionable `mv`, bak+staging offers both options, lone-staging does NOT block, newest-bak
  selection.
- **Runbook:** recovery documented in `docs/operator/docker-compose-backup-restore.md` §8b (offline
  `down` → `mv` → `up`, deliberate REVERT vs COMPLETE choice). **Complexity S — closed as recommended.**

## RISK-008 — Username timing oracle · MEDIUM · ✅ CLOSED 2026-06-28
- **Was:** `VerifyAuth` (`store.go`) returned before the bcrypt compare on an unknown username, so a
  valid username paid ~100ms of bcrypt while an invalid one returned near-instantly — a remotely
  measurable user-enumeration oracle.
- **Fix:** on a username miss, run `bcrypt.CompareHashAndPassword(dummyBcryptHash, pass)` against a
  fixed init-time dummy hash (cost = DefaultCost, matching stored hashes) before returning false, so
  a wrong username is timing-indistinguishable from a wrong password.
- **Residual:** the 5-minute auth cache still makes a *repeat* correct-and-cached login fast; the fix
  addresses the primary first-probe enumeration vector. Validated: build, vet, auth/store tests green.

## RISK-009 — `InsecureSkipVerify` toggle is silent · MEDIUM · ✅ CLOSED
- **Was:** `auth_oidc.go`, `auth_oidc_flow.go`, `auth_ldap.go` honored an admin `TLSSkipVerify` flag
  that fully disables cert validation on the credential-bearing channel, with no warning logged.
- **Impact:** A MITM on the LDAP/OIDC path can harvest credentials when the toggle is on.
- **Fix (2026-06-29):** Each provider constructor (`NewOIDCAuth`, `NewOIDCFlowProvider`,
  `NewLDAPAuth`) now emits a loud `logWarnf` WARN at init time when `cfg.TLSSkipVerify` is set,
  naming the credential-harvest/MITM risk and the dev-only intent. Warning fires once at
  construction (not per-request) so it surfaces in startup/reload logs without flooding the hot
  path. Validated: build OK, lint clean on touched lines, `go test -race -run 'OIDC|LDAP|Auth|IdP'`
  green. **Complexity XS — closed as recommended.**

## RISK-010 — Self-update has no in-binary image verification · MEDIUM · ✅ CLOSED 2026-07-11
- **Was:** `apiUpdateApply` (`update.go:496-608`) delegated pull/restart to the external updater
  sidecar; the proxy never verified the pulled image's signature or digest. The Sigstore machinery
  verified *catalogs*, not the image the updater pulled.
- **Impact:** A compromised/misconfigured updater could run an arbitrary image with no proxy-side defense.
- **Resolution path (clarified 2026-07-05):** this gap was **inherent to the legacy tag-based updater
  sidecar**, and its correct fix was *migration, not a patch* — the replacement path already had what
  this asked for (the catalog + maintenance-agent flow pins by digest, `docker pull …@sha256:`, and
  verifies keyless Sigstore signatures with catalog↔image identity parity, P2b-2b).
- **Update (2026-07-11):** the legacy updater sidecar and `update.go` were fully removed under
  **DEBT-008** — `apiUpdateApply` no longer exists. The maintenance agent (Release Management →
  agent `/v1/upgrades/apply`) is now the sole day-2 update path. RISK-010 closes by removal, the
  same move that closed RISK-ACC-1.
- **Where the Sigstore verification actually lives (precision, 2026-07-13):** the keyless
  Sigstore + catalog↔image identity check runs in the **CP release-dispatch planner** *before* it
  calls the agent, not inside the agent handler. The agent's `/v1/upgrades/apply`
  (`handlers_upgrade_apply.go`) admits any ref matching `image_allowlist` — whose default
  (`config.go`) permits **mutable tags** as well as digests — and its `resolve_target` step pins
  the resolved `repo@sha256:` digest but performs **no per-call signature verification**. So the
  no-in-binary-verification gap is closed **for the CP-dispatched path** (the intended and only
  UI/API-exposed one); a caller that reaches the agent socket *directly* (an allowed peer or
  local automation, bypassing CP dispatch) still gets digest-pinning without Sigstore
  verification — a residual bounded by the agent's local-socket + allowlist trust boundary, not a
  UI-reachable one. Narrow the closure claim accordingly rather than reading it as "no residual on
  any surface." See RISK-022 for the separate agent-death-mid-apply residual on the successor.

## RISK-011 — Rolling-update auto-rollback unverified · MEDIUM · ⚠ STALE→RE-POINTED 2026-07-11
- **Was:** `triggerAutoRollback` (`update_cluster.go:804-852`) re-pushed the previous tag but never
  confirmed the node reverted; could mark `rollback_failed` while the node ran the broken version.
- **Update (2026-07-11 failure-mode audit, HV):** the cited symbol and file **no longer exist** —
  the legacy cluster updater was removed (DEBT-008). The successor is the maintenance-agent inline
  auto-rollback (`cmd/culvert-maint/internal/server/inline_rollback.go` + `rollback_stages.go`), which
  **does verify the revert**: `imageRollbackStages` runs `rollback_pull → rollback_restart →
  rollback_health → rollback_verify`, and `rollback_verify` asserts the prior digest is in the running
  image's `RepoDigests` (`rollback_stages.go:70-124`); `guardInlineRollback` sets `rollbackSucceeded`
  only after that passes (`inline_rollback.go:118`). **The original concern is resolved in the
  successor.** The register entry's citation is stale.
- **Re-pointed residual → RISK-022:** the *new* unverified-recovery gap on this surface is
  agent-death mid-apply (no persisted op journal; no reconciliation). RISK-011 should be CLOSED (concern
  resolved) with RISK-022 carrying the successor's residual.

## RISK-021 — Fresh appliance runs default-allow + no-auth (silent) · HIGH · OPEN
- **Found (2026-07-11 failure-mode audit, HV):** the policy engine's in-memory zero value is deny
  (`proxy.go:16`), but the first-boot startup slice **deliberately flips the default action to
  `"allow"` (passthrough)** when no rules and no `default_action` are configured
  (`rewrite_default_action_startup.go:23-25` → `setDefaultPolicyAction("allow")`), and the shipped
  `docker-compose.yml` passes no `default-action` flag. Combined with credential-only `AuthEnabled()`
  (false until an admin exists, `store.go:470`), a fresh appliance with the proxy port reachable is an
  **open forwarding proxy**. The only signal is one advisory log line — no degraded `/ready` state, no
  alert, no admin banner.
- **Impact:** an operator who exposes the proxy port before completing hardening runs an open
  relay / silent-bypass on day 0. Contradicts the headline "Default deny (Zero Trust)" architecture
  claim; the open posture is a documented onboarding tradeoff but is **silent**, which is the defect.
- **Recommendation:** surface passthrough+no-auth as a degraded `/ready` state + admin banner +
  `security_posture_open` alert (mirror the CHAOS-06 CA-visibility pattern); the maintainer decides
  whether an internet-exposed first boot should hard-refuse to bind until setup completes. **Complexity S.**
  Acceptance test: `FAILURE-INJECTION-TEST-PLAN.md` T1.

## RISK-022 — Maintenance-agent death mid-apply is unrecoverable · HIGH · OPEN
- **Found (2026-07-11 failure-mode audit, HV):** the maintenance agent holds operation state **only in
  memory** (`ops.Manager.active`, `ops.go:206`); there is no persisted op journal, and
  `MarkAllInterrupted()` is a literal `return 0` (`ops.go:468`, called at agent startup `main.go:130`).
  A process kill between retag (`tagAndUp`) and the health-gate leaves Docker in an unknown partial
  state (fixed tag `culvert/proxy:pinned` advanced to the new digest, `up` possibly half-done) with
  **no reconciliation and no automatic rollback** on the next agent start; the op is not queryable.
- **Impact:** an interrupted upgrade (agent crash, host reboot mid-apply, OOM) can strand the appliance
  with no automatic recovery — manual `docker` surgery required. This is the successor's residual that
  RISK-011 was re-pointed to.
- **Recommendation:** persist a minimal op journal (op id + phase + target/prior digest via
  `AtomicWrite`) and make `MarkAllInterrupted()` reconcile Docker (running digest vs journal) on
  restart, resuming or rolling back. **Complexity M.** Acceptance test: `FAILURE-INJECTION-TEST-PLAN.md` T3.

## RISK-012 — Username-keyed lockout (DoS) · LOW · ✅ CLOSED 2026-07-05
- **Was:** `internal/lockout` keyed the login lockout by username ONLY, so any remote party who
  knew (or guessed) an admin username could send 5 unauthenticated login POSTs and lock that
  admin out globally — lockout-as-DoS.
- **Fix (two-tier keying, `internal/lockout/lockout.go`):**
  - **Tier 1 — pair lock:** 5 failures from one `(clientIP, username)` pair locks THAT pair for
    15m. A username-flood now locks only the attacker's own pair; the real admin's IP is
    untouched.
  - **Tier 2 — account lock:** 20 failures for a username across ALL IPs locks the account, as a
    backstop against distributed/IP-rotating brute force — but client IPs that previously logged
    in successfully (trusted, `TrustTTL=30d`, bounded `trustMaxIPs=8`) BYPASS the account lock, so
    the flood cannot lock out a returning admin from a known-good IP.
  - `clientIP` is the direct peer (`net.SplitHostPort(r.RemoteAddr)`), NOT `X-Forwarded-For` — so
    an attacker on a directly-exposed deployment cannot spoof the key to evade their own pair lock
    or forge a victim's trusted IP.
  - Setup endpoint uses the **pair-only** path (`CheckPair`/`RecordPairFailure`) — pure per-IP,
    no account tier — because there is no account to protect pre-provisioning and an account-wide
    counter on the reserved `"setup"` user would let a few IPs globally block bootstrap (the exact
    DoS class; caught by adversarial review as F1 and fixed before merge).
- **Adversarially reviewed (2×) before merge.** Core mechanics (lock math, `secondsRemaining`,
  concurrency under one mutex, trust-grant integrity, Cleanup coverage of both maps + trust set)
  verified sound and test-pinned (`lockout_test.go` two-tier + pair-only regression guards).
- **Accepted residuals (documented, not defects):**
  - *Brute-force budget* — an attacker with ≥4 IPs gets 20 password guesses before any lock (vs 5
    under the old scheme); bcrypt + the 300 ms per-attempt delay remain the real barrier, and 20
    is the chosen midpoint between brute-force resistance and DoS-lockout risk. A paced attacker
    staying under the window cap is an inherent property of any windowed counter.
  - *Untrusted-IP admin during an active flood* — a fresh-deploy / new-location admin with no live
    trust grant can still be caught by the account lock during a distributed flood (re-trippable
    every 15m). Strictly better than the username-only original; inherent to IP-based keying.
  - *Reverse-proxy topologies* — **CLOSED via RISK-019** (2026-07-05): the trusted-proxy-aware
    `realClientIP` now feeds the lockout keys, so behind a configured trusted proxy the tiers key on
    the real client again instead of collapsing onto the proxy IP.

## RISK-019 — Admin-UI per-IP logic keys on the direct peer IP (no trusted-proxy extraction) · MEDIUM · ✅ CLOSED 2026-07-05
- **Was:** the admin UI derived client IP from `r.RemoteAddr` everywhere (login lockout, admin-API
  rate limiter, admin-IP allowlist, audit actor). Behind an L7 proxy that terminates TCP, every
  request presented the proxy's IP, so the RISK-012 two-tier lockout collapsed toward one shared
  pair (5 failures lock the admin globally) and per-IP rate limiting / audit attribution lost
  meaning — uncorrectable via config.
- **Fix:** `realclientip.go::realClientIP(r)` — a trusted-proxy-aware resolver. It returns the
  direct peer UNLESS that peer is in a configured trusted-proxy CIDR set (`trustedProxyNets`), in
  which case it returns the rightmost `X-Forwarded-For` hop NOT in the trusted set (the real client
  behind the proxy chain). Empty set = always the direct peer. **The gate is the whole security
  argument:** a direct attacker's peer is not in the trusted set, so their `X-Forwarded-For` is
  never honored — they cannot forge a victim's IP or evade their own lockout (pinned by
  `TestRealClientIP_SpoofDefense`). Adopted at all admin-side sites: `apiAuthLogin`,
  `apiSetupComplete`, the `apiLimiter` gate + `uiIPGuardMiddleware` allowlist (`ui_middleware.go`),
  `auditActor` (`ui_helpers.go`), and the cluster error-budget audit actor (`update_cluster.go`).
  The proxy DATA path (`handleRequest`'s `rl`/`connLimiter`/`ipf`) is deliberately untouched — those
  are direct client connections, not behind the admin reverse proxy.
- **Config (full GUI parity):** `-trusted-proxy-cidrs` flag + `proxy.trusted_proxy_cidrs` YAML seed;
  `POST/GET /api/settings/network` (`trusted_proxy_cidrs`); admin-durable via
  `AdminSettings.TrustedProxyCIDRs`; UI field in the Network & TLS panel; `trusted_proxy_cidrs`
  config-surface row (admin-durable only — per-node proxy topology, deliberately NOT cluster-synced).
  Invalid CIDRs reject the whole update (API) or fail safe to "no trust" (startup/admin_settings).
- **Adversarially reviewed before merge** (spoof defense, XFF parsing, the `uiIPGuard` allowlist
  bypass path — all DEFEATED; the review confirmed the allowlist is *tightened*, not weakened).
  Two review findings fixed in the same change: **F1** — an empty persisted trust list now wipes a
  YAML seed via a `TrustedProxyCIDRsSaved` sentinel (a security control must not fail toward *more*
  trust on restart); **F2** — `realClientIP` returns the canonical `ip.String()` so a non-canonical
  XFF spelling (`::ffff:1.2.3.4`) can't fork the per-IP lockout key. Both pinned by tests.
- **Accepted residual (F3, operational):** the trust contract assumes the configured proxy
  actually sets/overwrites `X-Forwarded-For`. If an operator trusts a proxy that forwards a
  client-supplied XFF verbatim, or that never sets XFF (collapsing every request onto the proxy IP),
  the protection degrades — this is a deployment misconfiguration outside the code's control,
  flagged in the `config.example.yaml` / API-field guidance.

## RISK-018 — Leaked HA standby goroutine races test logger swaps · LOW · ✅ CLOSED 2026-07-04
- **Root cause (narrower than first mapped):** three `ha_failover_test.go` tests seeded
  `SetResyncMaterial(context.Background(), …)`. The leak interleaving: the test's `h.Stop()`
  closes the CURRENT `stopCh`, but the keepalive goroutine can already be mid-`selfFence`; its
  `enterStandbyResync` then calls `StartAsStandby` AFTER Stop — fresh `stopCh` nobody closes,
  ctx = Background → immortal loop retrying `HASync` every 5s across the rest of the suite,
  racing any test that swaps the `logger` global. **Production was never exposed:** the resync
  ctx there is the process lifecycle ctx (`cluster_startup.go:71,100`), so shutdown always kills
  a post-Stop resync loop; the standby-loop/Stop design is unchanged.
- **Fix:** `resyncCtx(t)` — a cleanup-cancelled ctx seeded at all three sites, so any loop
  spawned under ANY Stop/fence interleaving dies with its test. Verified: HA + SAML suites
  `-race -count=2 -shuffle=on` ×3 green.
- Original finding preserved below.

### (was) RISK-018 — Leaked HA standby goroutine races test logger swaps · LOW · OPEN
- **Observed (PR #560 Fast-Gate run 28705150574, `-race`):** `HAState.syncFromLeader`
  (`ha.go:477`, `logger.Printf`) racing `TestAuthSAMLCallbackLogsProviderRejection`'s cleanup
  (`ui_auth_saml_test.go:31`, `logger = origLogger`). The reading goroutine was created via
  `enterStandbyResync → StartAsStandby` (`ha_failover.go:138`) — an HA failover test's standby
  loop left RUNNING after its test ended, still retrying `HASync` ("sync failed (28/3)" in the
  log) while an unrelated test swapped the `logger` global. Ordering-dependent: shuffle decides
  whether a logger-swapping test runs while the leaked loop is alive. **Test-infra only** — no
  production code path swaps `logger` at runtime.
- **Impact:** flaky `-race` gate (blocks unrelated PRs); a leaked standby loop can also distort
  other tests' HA state.
- **Recommendation:** whichever HA test drives `enterStandbyResync` must stop the standby loop
  in cleanup (the loop honors its stop channel/ctx — audit `ha_failover_test.go` /
  `ha_failback_test.go` cleanups); consider a `TestMain`-level leak check for `standbyLoop`
  goroutines on the HA suite. **Complexity S.** Not attempted inside PR #560 (out of that PR's
  diff; HA test lifecycle deserves its own reviewed change).

## RISK-013 — `normalizeHost` IDNA fail-open · LOW · ✅ CLOSED 2026-07-05
- **Was:** `hostutil.NormalizeHost` returned the raw lowercased host on `idna.ToASCII` error, so a
  host with an invalid punycode label flowed un-normalized into every downstream matcher
  (blocklist, threat feed, policy FQDN, URL category) — a fail-open in a security-relevant
  canonicalization step.
- **Fix:** a fail-CLOSED core `hostutil.NormalizeHostStrict(host) (norm, ok)` returns `ok=false`
  on IDNA failure. The request-path dispatch gates call it and REJECT before any matcher runs:
  `handleRequest` (`proxy.go`, HTTP 400 `INVALID_HOST`, BEFORE `preDispatchBlocked` and
  `policyStore.Evaluate`) and the SOCKS5 handler (`socks5.go`, reply 0x02). `NormalizeHost`
  (still fail-open) is retained ONLY for admin-entered PATTERNS and store keys, where literal
  fallback matching is acceptable — it now delegates to the strict core.
- **Adversarially reviewed before merge:** the gate closes the asymmetry on every primary path
  (HTTP/CONNECT/WebSocket via `handleRequest`; SOCKS5), with no false-positive DoS (the IDNA
  failure set is invalid-punycode only — IPv6, underscores, hyphens, trailing dot, Unicode all
  pass). Empirically probed; no legitimate client emits invalid punycode.
- **Accepted residual (LOW, tracked):** the CDR inner-request evaluation
  (`cdr_proxy.go` `cdrPolicyStore.Evaluate(..., req.Host, ...)`) still normalizes the decrypted
  INNER `Host` fail-open. Not a blocklist/policy/threat bypass (those decided on the gated OUTER
  host), and inner-`Host` CDR matching is independently spoofable with any VALID host, so the
  IDNA-invalid vector adds only marginal risk. Fix if pursued: gate `req.Host` with
  `normalizeHostStrict` inside the inspect inner loop (fail the CDR decision closed), or key CDR
  policy on the gated outer `hostOnly`.

---

### Review log
- **2026-06-28** — Register created from the baseline audit. RISK-001/002 hand-verified; remainder
  on sub-reviewer evidence. No items closed yet.
- **2026-06-28 (PM)** — **Security-gate validation exercise.** Ran trivy 0.71.2 locally (DB from
  `mirror.gcr.io`), replicating the exact CI gate command and diffing against an unfiltered scan.
  Findings: all dependency vulns are in `updater/go.mod` (`docker/docker v28.5.2`, 5 CVEs, no
  upstream fix); root proxy binary and `cmd/culvert-maint` scan **clean**. Split original RISK-006
  into RISK-006 (gate config blind spots, trivy-verified), RISK-014 (govulncheck root-only),
  RISK-015 (scanner-DB divergence), RISK-016 (original `@latest`/CodeQL finding). Added RISK-ACC-1
  (updater docker CVEs, ACCEPTED pending DEBT-008 removal — maintainer working on it).
  Limitation: govulncheck reachability could not be run locally (`vuln.go.dev` blocked by org
  egress policy, 403); CI's own govulncheck remains authoritative for root reachability.
- **2026-06-29** — **RISK-009 CLOSED.** Added init-time WARN logs to the three credential-channel
  auth constructors (`NewOIDCAuth`, `NewOIDCFlowProvider`, `NewLDAPAuth`) guarded by
  `cfg.TLSSkipVerify`. Resolved a gofmt-induced `whyNoLint` finding on the pre-existing
  `//nolint:gosec` in `auth_oidc_flow.go` by adding an explanation. Build/lint/auth-race tests green.
- **2026-06-30** — **RISK-003 CLOSED.** Webhook HMAC secrets are now AES-256-GCM encrypted at rest
  under a per-data-dir key (`alerts_secret.go`); `AlertStore.save()`/`Init()` encrypt/decrypt around
  the cleartext in-memory form used for signing, fail-closed on encrypt error, and migrate legacy
  cleartext on next save. Export was already redacted via `List()`. Tests prove no cleartext on disk
  + reload round-trip; delivery/HMAC tests still green.
- **2026-06-30** — **RISK-001 → HIGH/MITIGATING (Slice 1 landed).** `docs/adr/0004-ha-split-brain-fencing.md`
  records the design: the 2-node-no-witness theorem, a hand-rolled DP-quorum proposal **rejected** by
  adversarial review (F1 stale-quorum dual-majority, F4 silent data loss, F6 ungated CA issuance, F7
  term-tie), and a Slice-1 / open-mechanism split. Slice 1 shipped: auto-failover is now OPT-IN and OFF
  by default (`--ha-auto-failover`/API/GUI), restart honors the persisted role (`haRestartAction` — a
  standby no longer self-asserts as a second leader, the verified `main.go:647` bug), and `/healthz`
  exposes `term` + `write_authority` so a double-leader is detectable. Severity dropped BLOCKER→HIGH
  (no longer unsafe-by-default). Residual: *safe automatic* failover is the open mechanism decision
  (Advisor recommends lease+witness). Re-pinned by the flipped `ha_split_brain_failover_evidence_test.go`
  + `ha_autofailover_test.go`/`ha_term_test.go`.
- **2026-06-30** — **RISK-005 CLOSED.** Boot-time guard `checkInterruptedRestore` (`restore.go`),
  called from `main()` after the one-shot CLI commands, refuses to start when `/data` is absent AND an
  interrupted-restore `.bak` sibling exists — instead of silently booting on an empty dir and losing
  data. Prints actionable REVERT / COMPLETE `mv` moves (newest `.bak`), reusing the D1.3c
  `discoverLeftovers` scanner; fresh installs unaffected. Tests in `restore_interrupted_test.go`;
  recovery runbook in `docs/operator/docker-compose-backup-restore.md` §8b.
- **2026-07-04** — **Gate-hardening pass.** RISK-014 CLOSED: per-module govulncheck in both lanes
  (culvert-maint blocking; updater advisory with RISK-ACC-1 rationale — converts the prose
  unreachability claim into analysis). RISK-006 CLOSED: advisory full-severity unmasked trivy
  report + trivy-native `exp:2026-10-01` dates on both `.trivyignore` entries (self-enforcing;
  gate goes red when the date passes). RISK-016 drift-synced MEDIUM→LOW/MITIGATING: all scanner
  pins were already fixed in the tree (register was stale); sole residual is CodeQL-as-required-
  check, a branch-protection toggle only the repo admin can set. DEBT-010 found already resolved
  in the tree (delta gate retired by CI-REDESIGN step 7) — closed in the debt register.
- **2026-07-03** — **RISK-001 CLOSED.** ADR-0005 S0–S5 shipped in full: etcd-backed fencing lease
  (`internal/halease`) arbitrates every path to HA leadership — Acquire-gated promotion, keepalive
  self-fence with etcd as the clock, epoch-fenced write sinks + DP ratchet, lease-arbitrated safe
  auto-failover with freshness/hysteresis gates, demote-and-resync failback, ghost-lease-safe leader
  restart, and the S5 operator surface (flags/YAML/GUI/compose witness/runbook). Split-brain is
  structurally prevented in lease mode (pinned by `TestCL4_LeaseMode_SplitBrainStructurallyPrevented`);
  legacy (no etcd) deployments keep the ADR-0004 safe-manual default. Residuals accepted + documented:
  bounded-LWW window ≤TTL on partition (F4 option A) and the legacy opt-in flag, both in
  `docs/operator/ha-lease-failover.md`.

- **2026-07-11** — **Production Failure-Mode & Day-2 audit (evidence pass, no code change).** Six
  parallel failure-domain sweeps + ~12 hand-verifications produced
  `docs/engineering/PRODUCTION-FAILURE-MODE-AUDIT.md`, `DAY2-OPERATIONS-READINESS.md`,
  `FAILURE-INJECTION-TEST-PLAN.md`. Register updates (strong-evidence only): **RISK-021** (fresh
  appliance default-allow + no-auth, silent — HIGH, HV), **RISK-022** (maintenance-agent death
  mid-apply unrecoverable, `MarkAllInterrupted` no-op — HIGH, HV), **RISK-011** re-pointed to
  STALE→RE-POINTED (cited `update_cluster.go` removed; concern resolved in the successor
  `inline_rollback.go` which verifies revert+health; residual carried by RISK-022). Validated-at-HEAD:
  CHAOS-01 and CHAOS-24 (revocation sync, `controlplane_client.go:140`) found **already closed**;
  CHAOS-05/06/07/09/10/11/12/16/17/22/27/33 confirmed **still open** with fresh file:line evidence.
  Governance note: the CHAOS review series has an **ID collision** (07-07 and 07-10 both define
  CHAOS-22…27 differently) — recommended renumbering to a single append-only ledger. Full backlog
  (P0–P3) in the audit doc §14.
- **2026-07-05** — **RISK-012 + RISK-013 CLOSED (one focused security PR).**
  RISK-012: two-tier `(clientIP,username)`-pair + account lockout with trusted-IP bypass
  (`internal/lockout`), replacing username-only keying that let a remote party lock an admin out
  with 5 unauthenticated POSTs. RISK-013: fail-closed `NormalizeHostStrict` gate at the proxy +
  SOCKS5 dispatch, replacing the fail-open IDNA normalization that let an invalid-punycode host
  reach every matcher un-normalized. Each fix adversarially reviewed before merge (RISK-012 by two
  independent reviewers). The RISK-012 review caught a real HIGH regression pre-merge — the setup
  endpoint's reserved `"setup"` user aggregating into the account tier (global bootstrap DoS) —
  fixed with a pair-only limiter path. New **RISK-019** (MEDIUM, OPEN) filed for the cross-cutting
  trusted-proxy client-IP gap the review surfaced (F4). RISK-013 review recorded one LOW residual
  (CDR inner-`Host` fail-open). Full `-race ./...` green.
