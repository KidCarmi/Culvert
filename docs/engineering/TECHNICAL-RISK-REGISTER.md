# Culvert Technical Risk Register

> **Owner:** Chief Engineering Advisor · **Status:** Living · **Last review:** 2026-06-28
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
| RISK-ACC-1 | HIGH | ACCEPTED | 5 `docker/docker` CVEs in `updater/` (no upstream fix) | `updater/go.mod`; resolution = DEBT-008 |
| RISK-005 | MEDIUM | ✅ CLOSED | Interrupted restore can leave `/data` absent | boot guard `checkInterruptedRestore` (`restore.go`) + runbook §8b |
| RISK-008 | MEDIUM | ✅ CLOSED | Username timing oracle enables user enumeration | fixed `store.go` (2026-06-28) |
| RISK-009 | MEDIUM | ✅ CLOSED | `InsecureSkipVerify` admin toggle silent on auth hot path | `auth_oidc.go:96`, `auth_oidc_flow.go:301`, `auth_ldap.go:90` |
| RISK-010 | MEDIUM | OPEN | Self-update has no in-binary image signature/digest check | `update.go:496-608` |
| RISK-011 | MEDIUM | OPEN | Cluster rolling-update auto-rollback unverified | `update_cluster.go:804-852` |
| RISK-012 | LOW | ✅ CLOSED | Account lockout is username-keyed (lockout-as-DoS) | two-tier (IP,user)+account keying w/ trusted-IP bypass (2026-07-05); adversarially reviewed 2× |
| RISK-019 | MEDIUM | ✅ CLOSED | Admin-UI per-IP logic keys on direct peer IP; no trusted-proxy XFF extraction (lockout collapses behind an L7 proxy) | trusted-proxy `realClientIP` (2026-07-05); adversarially reviewed |
| RISK-018 | LOW | ✅ CLOSED | Leaked HA `standbyLoop` goroutine races test `logger` swaps (determinism-gate flake) | `resyncCtx(t)` cleanup-cancelled ctx (2026-07-04) |
| RISK-013 | LOW | ✅ CLOSED | `normalizeHost` IDNA failure is fail-open | fail-closed `NormalizeHostStrict` gate at proxy+SOCKS5 dispatch (2026-07-05); adversarially reviewed |

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
  when the date passes, flipping the blocking gate red and forcing re-triage). Dates set to
  2026-10-01, aligned to the updater-removal target (DEBT-008/RISK-ACC-1); the file documents
  that extending requires re-validating the reachability rationale, not reflex.
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
  root. `updater/` is **advisory** (`continue-on-error`): it carries the RISK-ACC-1 accepted
  unfixed CVEs, so a reachable finding has no fix short of removal — but the run converts the
  `.trivyignore` prose unreachability claim into actual reachability analysis, and any finding
  there invalidates the acceptance and must be triaged (comment in both workflows says exactly
  that). Flips to moot when DEBT-008 deletes the module.
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

## RISK-ACC-1 — `docker/docker` CVEs in the updater · HIGH · ACCEPTED
- **Current state (trivy-verified 2026-06-28):** 5 CVEs in `github.com/docker/docker v28.5.2`,
  all in `updater/go.mod` only: `CVE-2026-41567` (HIGH), `CVE-2026-42306` (HIGH),
  `CVE-2026-41568` (MEDIUM) — confirmed by local trivy — plus `CVE-2026-34040`, `CVE-2026-33997`
  (in `.trivyignore`). **None have an upstream fix.** The root proxy binary and `cmd/culvert-maint`
  are unaffected (0 vulns).
- **Why accepted, not fixed:** (1) no upstream patch exists, so there is nothing to bump to;
  (2) the entire legacy Docker updater is being **removed** (maintainer in progress; DEBT-008),
  which closes all 5 at once; (3) bumping dependencies in code slated for deletion is wasted work.
- **Acceptance conditions / expiry:** this acceptance is valid **only until the updater module is
  removed**. If updater removal stalls, re-evaluate: confirm the `.trivyignore` reachability
  rationale still holds and that the updater is not exposed to untrusted Docker registry/plugin input.
- **Resolution:** DEBT-008 (remove legacy updater). **Owner:** maintainer · **Target:** with DEBT-008.
- **Re-verified 2026-07-03:** `go list -m -u github.com/docker/docker` in `updater/` reports no
  newer version — still no upstream fix, acceptance conditions still hold. The GitHub Dependabot
  banner shown on every push ("5 vulnerabilities, 3 high") maps to THIS entry (the updater-only
  CVE set); it is not an unhandled finding.

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

## RISK-010 — Self-update has no in-binary image verification · MEDIUM · OPEN
- **Current state:** `apiUpdateApply` (`update.go:496-608`) delegates pull/restart to the external
  updater sidecar; the proxy never verifies the pulled image's signature or digest. The Sigstore
  machinery verifies *catalogs*, not the image the updater pulls.
- **Impact:** A compromised/misconfigured updater can run an arbitrary image with no proxy-side defense.
- **Recommendation:** Verify a pinned digest/signature in-binary before accepting an applied update.
  **Complexity M.**

## RISK-011 — Rolling-update auto-rollback unverified · MEDIUM · OPEN
- **Current state:** `triggerAutoRollback` (`update_cluster.go:804-852`) re-pushes the previous tag
  but never confirms the node reverted; it can mark `rollback_failed` while the node still runs the
  broken version. No failure-path tests.
- **Impact:** "Auto-rollback" cannot be trusted to restore service; mid-rollout failure can strand a
  mixed-version cluster.
- **Recommendation:** Post-rollback health verification + failure-path tests. **Complexity M.**

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
  bypass path). Residual (documented): the design assumes the trusted proxy sets/overwrites XFF
  correctly — a proxy that blindly forwards a client-supplied XFF is an operator misconfiguration
  outside the trust contract.

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
