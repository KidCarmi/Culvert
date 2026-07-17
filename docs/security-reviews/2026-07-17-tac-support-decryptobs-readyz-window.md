# Security Regression Review — TAC supportability framework, decryption-observability P1, and DP `/ready` health (window d5585d5 → 061b518)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-07-17
> **Baseline:** `d5585d5` — end of the previous review's window
> (`docs/security-reviews/2026-07-16-maint-journal-policy-draft-import-id-window.md`)
> **Head:** `061b518` (`origin/main`)
> **Scope reviewed:** every code-bearing change in the window — ~40 first-parent
> merges (PRs #758–#801), reviewed as six parallel deep passes (OIDC/policy;
> TAC support/sealed-export/redaction; decryptobs/proxy/socks/crashguard;
> healthcheck/readyz/cluster/maint; plus two deeper support and decryptobs
> sub-passes) with orchestrator spot-checks against the working tree at `061b518`.
>
> The window is dominated by: the **TAC supportability appliance framework**
> (#788 M1–M4, #794 sealed export, #796/#798 diagnose verbs) — `internal/support`,
> `internal/redaction`, `internal/sealbox`, `support_*.go`, `ui_support.go`,
> `diagnose.go` (~13k net-new lines); the **decryption-observability** slices
> (ADR-0011 P1, #758/#786/#792/#795/#801) — `internal/decryptobs`,
> `decryption_observability.go`; **OIDC identity binding + policy hardening**
> (#738) — `auth_oidc.go`, `policy.go`, `policy_refs.go`; **crashguard** panic
> recovery (`crashguard.go`); and the **DP `/ready` dependency-health** rows
> (CHAOS-09, `readyz_dp_health.go`).

---

## Executive summary

**Verdict: no CRITICAL or HIGH security regressions.** The window is overwhelmingly
net-new *defensive* surface built to a high standard — a supportability framework
with a four-layer fail-closed redaction wall, true end-to-end sealed export
(NaCl anonymous box with low-order-key rejection), SSRF-guarded diagnostics, and
approval-gated exfil — plus genuine hardening of the OIDC identity path
(authorization subject now bound exclusively to the introspected token, never the
attacker-supplied Basic username) and the auth cache.

The privileged host boundary (the `culvert-maint` sudoers allowlist, the cosign
image-trust gate, the RISK-022 reconcile trust gate) is intact and has **no live
destructive caller**. The decryption-observability wiring is provably **write-only**:
which sessions get inspected / bypassed / failed-open is byte-identical to the
baseline, verified under `-race`.

**Four LOW findings were fixed in this PR; six lower-severity residuals are
recorded as recommendations. One pre-existing MEDIUM (object-reference-ID import,
prior-window F1) is unchanged — neither closed nor worsened.**

| ID | Sev | Class | Status |
|----|-----|-------|--------|
| **R1** | LOW | Info disclosure on unauthenticated `/ready` (CWE-209/497) | **FIXED** |
| **R2** | LOW | Audit-integrity TOCTOU on `cert_verify` (CWE-367→778) | **FIXED** |
| **R3** | LOW | Data race on `clusterRole` in bundle build (CWE-362) | **FIXED** |
| **R4** | LOW | Unbounded client-controlled `correlationID` (CWE-770) | **FIXED** |
| R5 | LOW | Scrubber misses `token=`/`sig=` query secrets in kept URLs | Recorded |
| R6 | LOW | Retained-secret consent preview visible below approver role | Recorded |
| R7 | LOW | Threat-model claims single-flight/resource-refusal not in code | Recorded |
| R8 | LOW | Native-ALPN inspected sessions emit no `dec` block (audit gap) | Recorded (documented follow-up) |
| R9 | INFO | Sealbox envelope header not AEAD-bound (future-version note) | Recorded |
| R10 | INFO | Bundle "tamper detection" is a self-hash, not a signature | Recorded (wording) |
| F1(prior) | MEDIUM | Object-ref IDs imported verbatim vs ID-authoritative eval | **Unchanged** |

---

## Security findings

### R1 — LOW (FIXED): unauthenticated `/ready` leaked DP cert-renewal error internals

**File:** `readyz_dp_health.go` (`appendDPHealthChecks`), served at `main.go:895`
(`handleReady`), populated from `dp_enrollment.go:396` / `readyz_dp_health.go`.

`/ready` is served directly by the proxy handler on the proxy port with **no
authentication** (`main.go:891-896`), and `handleReady` encodes every check's
`Detail` string with no redaction. The new DP `node_cert` readiness row embedded
the raw last cert-renewal error verbatim:

```
node certificate expires in N day(s) and renewal is failing (last error: <lastErr>)
```

`lastErr` originates from `renewDPCert`/`tryRenewDPCert` (`dp_enrollment.go`):
`"connect to CP: %w"` / `"RenewCert RPC: %w"` wrap gRPC dial errors that carry the
**internal Control-Plane IP:port** (e.g. `dial tcp 10.x.x.x:9443: connect: connection
refused`); `"write cert: %w"` wraps `os.WriteFile` errors carrying **absolute
on-disk paths**. The `cp_poll` row additionally quantified how long the CP had been
unreachable (internal cluster state).

**Regression, not merely new code:** the *same window* deliberately hardened the
sibling `appendStateFileChecks` to emit a fixed non-path string (`"state file
quarantined … see server logs"`) precisely because `/ready` is unauthenticated —
that was the prior review's F3. The DP rows re-opened the identical
error-message-disclosure class a few lines below, so it reads as an oversight.

- **Attack scenario:** any client that can reach the proxy port issues a single
  unauthenticated `GET /ready` against a DP node whose cert renewal is currently
  failing (cert inside the 30-day window or expired — common during a CP outage,
  which is exactly when probes are polled hardest). It learns the CP address, the
  DP role, the on-disk layout, and that the node is serving frozen policy.
- **Impact:** reconnaissance aiding lateral movement. Info disclosure only;
  no enforcement impact.
- **CWE-209 / CWE-497. OWASP A01/A05:2021. Severity LOW. Regression: yes (in-window).**

**Fix:** `node_cert` now carries only the non-sensitive days-left signal and points
at the server logs for the cause (mirroring `appendStateFileChecks`); the raw error
stays in logs + the CHAOS-12 alert + authenticated diagnostics. `cp_poll` no longer
quantifies the outage duration. The full renewal error remains available to
operators through authenticated surfaces.

### R2 — LOW (FIXED): audit-integrity TOCTOU — `cert_verify` re-resolved against the live profile store

**File:** `decryption_observability.go` (`inspectedOutcome`), call site
`proxy_tunnel.go` (block build after both handshakes complete).

The inspected `dec.cert_verify` field was re-derived at record time by calling
`resolveInspectSkipVerify(match, dec.SkipVerify)`, which reads the **live,
runtime-mutable** decryption-profile store (`resolveDecryptionProfile`). The
handshake's actual verification posture was fixed earlier when
`upstreamInspectTLSConfigForMatch` built `upstreamTLSCfg` — and the entire upstream
TCP+TLS handshake (up to seconds under a slow origin) sits between the two.

- **Failure scenario (false assurance):** a rule binds a profile with
  `CertVerification:"skip"`; the origin leg runs with `InsecureSkipVerify=true`.
  During the handshake an admin deletes/renames the profile, or a CP→DP
  `ConfigSnapshot` apply replaces the store fleet-wide. Block-build re-resolves and
  now records `cert_verify:"verified"` for a session whose upstream certificate was
  **never** verified (the inverse is equally possible). Profile mutation is not
  exotic — CP config syncs re-apply profiles routinely.
- **Impact:** an inaccurate security audit record — the SIEM/audit surface reports
  the opposite of what the session did. Enforcement is unaffected (the handshake
  used the config built pre-mutation).
- **CWE-367 (TOCTOU) → CWE-778 (insufficient/incorrect logging). Severity LOW.
  Regression: new code (audit-integrity defect in this window's feature).**

**Fix:** `inspectedOutcome` now takes the effective skip **captured** from the
handshake's own config (`upstreamTLSCfg.InsecureSkipVerify` — the ground truth of
what the session did) instead of re-resolving. The profile-precedence
(`"skip"`/`"strict"`/`"permissive"` over inline `SkipVerify`) is already baked into
that config at build time, so the captured value carries the Codex-#801 precedence
without a second, racy resolution.

### R3 — LOW (FIXED): data race on `clusterRole` in the support-bundle builder

**File:** `ui_support.go` (`buildSupportBundle`).

`buildSupportBundle` read `clusterRole.nodeID` / `clusterRole.role` with no lock,
while `clusterRole` is documented (`controlplane.go:258-261`) as protected by
`clusterRoleMu` and is mutated at runtime by `enableControlPlane` (`main.go`) and DP
enrollment (`dp_enrollment.go`). The same window's `diagnoseCluster`
(`diagnose.go`) correctly takes `clusterRoleMu.RLock()`, so this is a copied
un-locked read, not a new class.

- **Impact:** torn/stale node identity in the bundle manifest; `-race` CI flake risk.
  Not attacker-controlled; no confidentiality impact.
- **CWE-362. Severity LOW. Regression: new code.**

**Fix:** snapshot `clusterRole` under `clusterRoleMu.RLock()` before the build,
matching `diagnoseCluster`.

### R4 — LOW (FIXED): unbounded client-controlled `correlationID` in crashguard

**File:** `crashguard.go` (`recordCrash`, via `withAdminPanicRecovery` passing
`r.Header.Get("X-Request-ID")`).

The panic value (`crashMsgMax=512`) and stack (`crashStackMax=4096`) are bounded,
but `correlationID` — the client-supplied `X-Request-ID` on the admin plane — was
`sanitizeLog`-scrubbed for control chars yet never length-bounded, then stored
verbatim in `lastCrash.CorrelationID`, the ERROR log, and the audit-ring `Detail`.

- **Impact:** a large `X-Request-ID` on a request that triggers a recovered admin
  panic is stored/logged unbounded (a few MB worst case). Low exploitability
  (admin-gated route, throttled 1/sec/component, header size capped by
  `MaxHeaderBytes`). Inconsistent with the file's own truncation discipline.
- **CWE-770. OWASP A04:2021. Severity LOW. Regression: new code.**

**Fix:** bound `correlationID` to `crashCorrIDMax=128` before storing/logging,
matching `crashMsgMax`/`crashStackMax`.

---

## Recorded residuals (not changed in this PR)

- **R5 — LOW (scrubber precision):** `internal/redaction/scrubber.go`'s
  `credential_assignment` keyword set does not match a bare `token=`/`sig=`/
  `signature=` query parameter. An operator-configured `cdr.Endpoint`
  (classified INTERNAL and **kept**) like `https://sluice.internal/cb?token=SECRET`
  would survive scrubbing into `sections/cdr.json`. Backstopped by the mandatory
  admin-preview gate (it appears in `retained_preview`). *Recommendation:* add
  `token`/`sig`/`signature` to the keyword-gated value rule **with a value guard**
  to avoid over-redacting benign `key=`/`sort_key=` values — deferred because the
  false-positive surface needs product judgement, not an unattended change.
- **R6 — LOW (least-privilege):** `apiSupportBundleReport` attaches
  `retained_preview` (post-scrub kept INTERNAL free-form values, which "can carry a
  bare secret the precision-first scrubber cannot catch") to **RoleOperator+**,
  while approval is **RoleAdmin**, and it is served for `pending` bundles. Not an
  escalation (the preview is a strict subset of what an operator may download after
  approval, and it is never tarred), but the approver's-backstop data is readable
  one role below the approver. *Recommendation:* gate `retained_preview` at
  `RoleAdmin`.
- **R7 — LOW (governance drift):** `docs/support/SUPPORTABILITY-THREAT-MODEL.md`
  claims a "single-flight per node" control (`TestBundleSingleFlight`) and a
  resource-critical L3/L4 refusal (`TestDebugLevelPerfBounded`); neither the control
  nor the named tests exist. Real mitigations do exist (admin-only, per-IP rate
  limit, 256 MiB disk preflight, keep-10 retention, per-section byte budgets), so
  residual exposure is a self-inflicted CPU burst by an already-trusted admin.
  *Recommendation:* add the single-flight guard around `createSupportBundle` **or**
  amend the threat-model rows to the shipped controls.
- **R8 — LOW (audit gap, documented follow-up):** native-ALPN inspected sessions
  (`proxy_tunnel_h2.go`) emit **no** `dec` block, so a SIEM query auditing
  `dec.cert_verify:"skipped"` silently misses that population. Absence, not false
  assurance; explicitly a later ADR-0011 slice. *Recommendation:* land the
  follow-up before any coverage view treats a missing `dec` key as `not_decrypted`.
- **R9 — INFO:** `internal/sealbox` prepends a 9-byte magic+version header that is
  **not** fed to the sealed box as AAD (NaCl sealed boxes take no AAD).
  Unexploitable at one version (any header tamper fails parse; ciphertext tamper
  fails Poly1305), but a future `0x02` envelope must bind the version
  cryptographically (in-band, or an AAD-capable AEAD). *Recommendation:* comment
  the constraint in the file now.
- **R10 — INFO (wording):** `support_validate.go` / the `validate` route note
  describe a self-referential re-hash of the tar as "tamper detection." It detects
  corruption/truncation, not malicious tampering (anyone who rewrites the tar
  recomputes all hashes). *Recommendation:* soften to "integrity/corruption check"
  until manifest signing lands; do not present `ok:true` as proof of authenticity.

### Pre-existing (prior-window F1) — MEDIUM, unchanged

Policy rule object-reference IDs (`DestCategoryGroupID`, `DecryptionProfileID`) are
still imported/rolled-back verbatim from the file (`ReplaceAll`) while policy
evaluation is **ID-authoritative** (name is only a fallback on a *dangling* ID). A
tampered/hand-authored backup can carry a rule that displays one object name while
enforcing against a different live object. #738/#766 did **not** worsen this (and
`policy_refs.go`'s reference-walk was hardened to agree with the ID-authoritative
match path on dangling IDs — a latent fail-open closed), but it did not close it.
*Recommendation (unchanged):* on import, re-resolve object-reference IDs by name
against the target node's stores, or strip them so eval re-binds by name.
CWE-345 / OWASP A01. Severity MEDIUM, pre-existing.

---

## Regression analysis (what was verified safe)

- **OIDC identity (#738) — hardened, no regression.** Authorization subject is now
  bound exclusively to the introspected token claims; the Basic username is an
  untrusted transport hint, never the authenticated subject. `introspect` fails
  closed when no canonical `sub`/`username` claim is present (previously fell back
  to the attacker-chosen username), strict JSON decode rejects oversized/trailing/
  multi-value bodies, `exp` fails closed on `null`/string/fractional/out-of-range,
  boundary-expiry fails closed, and the positive cache is re-keyed to token-only
  with a fail-closed identity invariant. `proxy.go`'s
  `resolveAuthIdentityWithSnapshot` removes an empty-backend identity-spoof path.
- **Policy engine (#738) — hardened.** Copy-on-write rule publication with a shared
  atomic counters cell (race-safe under `-race`), strict-ULID rule-ID integrity
  (identity taken from the stored rule, never the request body), and draft
  engagement aligned to the write path (a stranded staged Deny can no longer be
  silently lost).
- **TAC support framework — structurally secret-free.** Four-layer fail-closed
  redaction (unclassified → SENSITIVE/masked, SECRET dropped, NEVER_EXPORT
  unreachable by construction, per-section class ceiling drop-on-exceed, raw-gate
  rejects any struct that bypassed classification); no collector reads session
  HMAC / CA passphrase / IdP secrets / bind passwords / enrollment tokens (presence
  bools only); the consent preview is never tarred; bundle IDs regex-gated at every
  path join; tmp+rename atomic writes; **PENDING-state-first** create ordering
  closes the crash→grandfathered-READY approval-bypass window; export is
  approval-gated identically for plain / passphrase / sealed downloads.
- **Sealed export crypto (`internal/sealbox`) — correct by construction.** NaCl
  anonymous sealed box (X25519 + XSalsa20-Poly1305); output-based low-order-key
  rejection (`curve25519.X25519` error + constant-time all-zero backstop) covers
  every small-order-point encoding; fresh ephemeral key per seal (no nonce reuse);
  single opaque open error (no decrypt oracle); appliance holds no decrypt key.
- **Diagnostics — SSRF-guarded, no egress.** `diagnose dns` refuses the whole
  result if any resolved address is private; `diagnose tls` does a private-IP
  preflight **plus** connect-layer `ssrfControl` (DNS-rebinding backstop); the sole
  `InsecureSkipVerify` in the tree is this diagnostic (RISK-023 accepted, TLS-1.2
  floor, never carries traffic, chain validity reported separately). Three test
  walls (import / source / runtime canary) pin the no-egress property.
- **Decryption observability — write-only.** `resolveSSLAction` → `resolveSSLDecision`
  refactor is byte-identical in the action/fail-open/cache-consult logic; no new
  autoexclude learn/consult (no poisoning vector); all categorical fields pass
  compile-time-switch `Valid()` bounding; no `dec` field feeds Prometheus; `Host`
  duplicates the pre-existing top-level entry host.
- **crashguard — fail-closed.** Every `recover()` is record-only-then-return (proxy)
  or record-then-500-if-uncommitted (admin); `http.ErrAbortHandler` is re-panicked;
  the raw panic value is bounded and **never** logged/metered; component labels are
  a fixed enum capped at 32 (no attacker-controlled cardinality).
- **Maintenance-agent reconcile trust gate (RISK-022 PR-E1c) — intact, dormant.**
  `reconcileDecision` still fails closed (`invalid_record_ref`) when a record ref
  fails re-validation; `validateReconcileRefs`/`validateRecordRef` enforce
  repo-bound pin + ref⇔digest consistency; **zero non-test callers** — the acting
  boot hook remains unshipped. No tampered-journal path drives a privileged docker
  action without cosign/trust re-validation.
- **Control-plane gRPC — unchanged gating.** Enroll still gated by
  `haIssuanceAllowed()` (epoch/fencing) + per-IP rate limit + atomic
  token-consume; the expired-node re-enrollment path requires a fresh admin token
  AND a provably-expired prior cert (fail-closed) and revokes the superseded serial;
  GetConfig SessionHMAC/IdP redaction for non-enrolled callers is untouched.

---

## Files changed by this PR

- `readyz_dp_health.go` — redact DP `node_cert` / `cp_poll` details on the
  unauthenticated `/ready` (R1).
- `readyz_dp_health_test.go` — assert the raw renewal error and outage duration are
  absent while days-left is retained (R1 regression guard).
- `decryption_observability.go` — `inspectedOutcome` captures the effective skip
  from the handshake config instead of re-resolving (R2).
- `proxy_tunnel.go` — pass `upstreamTLSCfg.InsecureSkipVerify` into
  `inspectedOutcome` (R2).
- `decryption_populate_test.go` — thread the captured skip; rework the #801 test to
  prove the end-to-end capture; add `TestInspectedOutcome_CertVerifyCapturedNotRederived`
  (R2 TOCTOU regression guard).
- `ui_support.go` — locked snapshot of `clusterRole` in `buildSupportBundle` (R3).
- `crashguard.go` — bound `correlationID` to `crashCorrIDMax=128` (R4).
- `docs/security-reviews/2026-07-17-tac-support-decryptobs-readyz-window.md` — this
  review.

## Required tests (shipped)

- `TestHandleReady_NodeCertRenewalFailing_FailRowAndRecovery` — now asserts the
  `node_cert` detail carries days-left but **not** the raw renewal error / "last
  error" (negative regression guard).
- `TestHandleReady_CPPollFailingSustained_ReportOnlyFailRow` — asserts the `cp_poll`
  detail does not leak the outage duration.
- `TestInspectedOutcome_CertVerifyFromEffectiveSkip` — reworked to prove the
  end-to-end handshake-config → captured → recorded flow (Codex #801 precedence).
- `TestInspectedOutcome_CertVerifyCapturedNotRederived` — new: a profile mutation
  after the config is built must not change the recorded `cert_verify` (TOCTOU).

All touched suites pass under `go test` and `go test -race`; `gofmt`/`go vet` clean.

## Residual risk

- **R5–R10 and prior-F1 are deliberately left as recommendations** — R5/R6 need a
  product decision on redaction breadth vs. over-redaction and role UX; R7/R10 are
  documentation/governance reconciliation; R8 is a scheduled follow-up slice; R9 is
  a forward-looking constraint. None is exploitable without either an
  already-trusted admin/operator or a not-yet-shipped envelope version.
- The pre-existing MEDIUM (object-reference-ID import) remains the highest-value
  open item and should be scheduled for a dedicated PR (re-resolve-by-name on
  import/rollback).
- The four fixed items are low-severity and low-blast-radius; the fixes are
  minimal, behavior-preserving for the security-relevant decision paths, and add
  negative regression guards so the same classes cannot silently return.
