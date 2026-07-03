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
| RISK-001 | HIGH | MITIGATING | Multi-CP HA split-brain (no quorum/fencing) | Slice 1 landed (ADR-0004): auto-failover OPT-IN/OFF, restart honors role, term-visible `/healthz`. Safe-automatic failover (mechanism) still open. **HV** |
| RISK-002 | HIGH | ✅ CLOSED | OIDC introspection path missing SSRF dial guard | fixed `auth_oidc.go:95` (2026-06-28) |
| RISK-003 | HIGH | ✅ CLOSED | Webhook HMAC secret persisted cleartext on disk | `alerts.go`, `alerts_secret.go` |
| RISK-006 | MEDIUM | OPEN | Gate config blind spots: `--ignore-unfixed` + `HIGH,CRITICAL` only (masks unfixed/medium) | `security-release-gate.yml:135-143` — **trivy-verified 2026-06-28** |
| RISK-014 | MEDIUM | OPEN | Reachability gate (govulncheck) scans root module only; nested modules unanalyzed | `security-release-gate.yml:114` vs `updater/go.mod`, `cmd/culvert-maint/go.mod` |
| RISK-015 | LOW | OPEN | Single-scanner gate; detection-source divergence (Dependabot 5 vs Trivy DB 3) | trivy run vs Dependabot count, 2026-06-28 |
| RISK-016 | MEDIUM | OPEN | Scanners installed `@latest`; CodeQL non-blocking | `security-release-gate.yml:52,110,252`; `ci.yml:72` |
| RISK-ACC-1 | HIGH | ACCEPTED | 5 `docker/docker` CVEs in `updater/` (no upstream fix) | `updater/go.mod`; resolution = DEBT-008 |
| RISK-005 | MEDIUM | ✅ CLOSED | Interrupted restore can leave `/data` absent | boot guard `checkInterruptedRestore` (`restore.go`) + runbook §8b |
| RISK-008 | MEDIUM | ✅ CLOSED | Username timing oracle enables user enumeration | fixed `store.go` (2026-06-28) |
| RISK-009 | MEDIUM | ✅ CLOSED | `InsecureSkipVerify` admin toggle silent on auth hot path | `auth_oidc.go:96`, `auth_oidc_flow.go:301`, `auth_ldap.go:90` |
| RISK-010 | MEDIUM | OPEN | Self-update has no in-binary image signature/digest check | `update.go:496-608` |
| RISK-011 | MEDIUM | OPEN | Cluster rolling-update auto-rollback unverified | `update_cluster.go:804-852` |
| RISK-012 | LOW | OPEN | Account lockout is username-keyed (lockout-as-DoS) | `lockout.go:36,60` |
| RISK-013 | LOW | OPEN | `normalizeHost` IDNA failure is fail-open | `security.go:34-37` |

---

## RISK-001 — Multi-CP HA split-brain · HIGH · MITIGATING
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
- **Residual (why still HIGH, not closed):** *safe automatic* failover on UNPLANNED leader loss does
  not exist yet. Under the opt-in `--ha-auto-failover`, a surviving-leader partition can still
  split-brain (no demote/fence/reconcile); failback is deferred. The default-manual posture is safe.
- **Mechanism DECIDED + PARKED at S0 (2026-07-01, ADR-0005):** the automatic-failover mechanism is an
  **etcd-backed fencing lease** (maintainer chose "big-vendor, self-hosted" → etcd; hand-rolled witness
  rejected by a second adversarial review — findings 1–8 recorded in ADR-0005 with per-slice
  resolutions). **S0 (record the standby's advertised address — the failback prerequisite) is
  SHIPPED**; S1–S5 (etcd LeaseProvider, keepalive/self-fence/demote, epoch fencing at every write sink
  + DP propagation, acquire-on-loss + failback, flags/GUI/docs) are deliberately deferred in favour of
  the decomposition program. The etcd runtime dependency has NOT been taken yet — parking before S1 is
  the cheap pause point. F4 posture on resume: documented bounded-LWW (option A).
- **Posture while parked:** safe by default (manual failover, explicit promote, planned handoff,
  term-visible `/healthz`) for any topology; **automatic** failover remains opt-in-with-documented-risk
  until S1–S5 ship.
- **Owner:** unassigned · **Target:** resume at ADR-0005 S1 when prioritised.

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

## RISK-006 — Trivy gate config blind spots · MEDIUM · OPEN
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

## RISK-014 — Reachability gate covers root module only · MEDIUM · OPEN
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

## RISK-016 — Scanners installed `@latest`; CodeQL non-blocking · MEDIUM · OPEN
- **Current state:** The gate installs its own scanners from `@latest`
  (`security-release-gate.yml:52` gosec, `:110` govulncheck, `:252` go-licenses) and runs
  `KidCarmi/Dependency-Obituary@main` (`ci.yml:72`). CodeQL is in no gate's `needs:` (advisory only).
- **Impact:** The gate meant to catch supply-chain risk is itself unpinned and non-reproducible;
  deep SAST findings never block a merge.
- **Recommendation:** Pin scanner versions (or vendor), SHA-pin the `@main` action, add CodeQL to
  the blocking set. **Complexity S.** *(This was the original RISK-006 before the 2026-06-28 split.)*

## RISK-017 — Alert webhooks never persisted (Init unwired) · MEDIUM · OPEN
- **Found (2026-07-03, while mapping the `internal/alerts` extraction):** `AlertStore.Init(path)` is
  **never called from production code** — only tests call it. `git log -S` confirms no production
  call has ever existed. The process-wide store is constructed with an empty `filePath`, so `save()`
  is a silent no-op for every admin webhook create/update/delete.
- **Impact:** Admin-configured alert webhooks (and their HMAC secrets) **do not survive a restart** —
  security alerting silently stops after any upgrade/restart until the admin reconfigures. The
  RISK-003 encryption-at-rest machinery protects `alert_webhooks.json`, a file production never
  writes; the F16 retry queue DOES persist (`/data/alert_retry_queue.json`), an inconsistency that
  hides the gap. The only durability today is a manually downloaded config export.
- **Recommendation:** wire `globalAlertStore.Init(filepath.Join(dataDir, "alert_webhooks.json"))`
  into the persistent-admin-state startup slice (a deliberate behavior change: webhooks configured
  after the fix will load on boot and RISK-003 encryption becomes live in production for the first
  time). Also consider migrating `Store.save()` to `fileutil.AtomicWrite` (it still uses
  non-fsynced WriteFile+Rename, pre-Bucket-4 style). **Complexity S.** The extraction itself was
  kept behavior-preserving; this is a separate follow-up unit.

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

## RISK-012 — Username-keyed lockout (DoS) · LOW · OPEN
- `lockout.go:36,60`: an attacker who knows an admin username can deliberately lock it out; restart
  clears all lockouts (also the informal break-glass). Consider IP+user keying. **Complexity S.**

## RISK-013 — `normalizeHost` IDNA fail-open · LOW · OPEN
- `security.go:34-37`: on IDNA error the original host is returned, potentially letting a malformed/
  homograph host evade an FQDN rule. Narrow but a fail-open in a security-relevant normalization step.

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
