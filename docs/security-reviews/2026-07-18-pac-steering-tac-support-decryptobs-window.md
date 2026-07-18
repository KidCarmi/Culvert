# Security Regression Review — PAC steering & Exception Intelligence, TAC support-bundle export, decryption observability, cluster scale-up (window `937b17f → 800e4c7`)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-07-18
> **Baseline:** `937b17f` — the previous review commit (`docs/security-reviews/2026-07-16-maint-journal-policy-draft-import-id-window.md` and the `eea0e8f` CHAOS-09 addendum)
> **Head:** `800e4c7` (`origin/main`)
> **Scope reviewed:** every code-bearing change in the window — 66 first-parent
> merges (PRs #758–#856) — reviewed as four parallel deep passes (support/TAC,
> PAC, decryption observability, cluster/control-plane), each doubled for
> cross-check, plus orchestrator spot-checks and independent verification of every
> reported finding against the working tree at `800e4c7`.
>
> The window is dominated by four net-new feature surfaces:
> - **PAC Exception Intelligence / traffic steering** — steering profiles, proxy
>   pools, per-profile PAC endpoints, DIRECT-bypass governance, publish/rollback
>   lifecycle, simulate/analyze/diff (`internal/pac/*`, `pac_*.go`).
> - **TAC supportability framework (M1–M5)** — support-bundle export incl. the
>   NaCl recipient-sealed (E2E) export, recipient registry, age/size retention
>   janitor, diagnose verbs, manifest/export-history views (`support_*.go`,
>   `internal/sealbox`).
> - **Decryption observability (ADR-0011)** — the nested `dec` block, failure-feed
>   rows, host/SNI redaction posture, coverage/failure metrics, health API
>   (`decryption_*.go`, `internal/decryptprofile`, `internal/autoexclude`).
> - **Cluster scale-up** — 2 M blocklist caps, 128 MiB gRPC frame, opt-in gzip,
>   version-conditional GetConfig, fail-closed commit/HA, `certVerification=permissive`
>   retirement (`controlplane_*.go`, `ha.go`, `config_surfaces.go`).

---

## Executive summary

**Verdict: no CRITICAL or HIGH security regressions.** The window is
predominantly hardening — fail-closed config commit, empty-config refusal,
corrupt-state quarantine, a correct NaCl sealed-export with low-order-key
rejection, a tightened `permissive`-retirement that moves strictly toward
fail-closed, and layered PAC JS-injection defenses. The privileged/trust
boundaries reviewed (CP↔DP mTLS, secret redaction in `GetConfig`, the sealbox
crypto, the C2 route-metadata RBAC) are byte-identical or strengthened.

**Seven findings are recorded. All are admin/operator-gated governance,
accountability, or amplified-DoS issues — none is an unauthenticated
authentication/authorization bypass or a secret leak.** Five have code fixes in
this PR (two MEDIUM governance regressions, two LOW accountability gaps, one LOW
contract-clarity doc). Two are documented for a follow-up because their fix is a
protocol/design decision rather than a contained regression fix.

| # | Severity | Area | Status |
|---|----------|------|--------|
| F1 | MEDIUM | PAC DIRECT typed-confirmation launderable via **config import** | **FIXED** |
| F2 | MEDIUM | PAC DIRECT typed-confirmation missed on **dormant-enable** through publish/rollback | **FIXED** |
| F3 | MEDIUM | Sealed support-bundle export omits recipient identity from the audit trail | **FIXED** |
| F4 | LOW | Recipient-key rotation audit records only the new fingerprint | **FIXED** |
| F5 | LOW | `decRedactHosts` toggle contract over-promised in its own doc | **FIXED (doc)** |
| F6 | MEDIUM* | Unauthenticated `GetConfig` config-disclosure + amplification (pre-existing, scaled 10× this window) | **DOCUMENTED** |
| F7 | LOW | Config-apply reachable-memory peak raised ~30×; `GOMEMLIMIT` doesn't bound it | **DOCUMENTED** |

\* F6 is a pre-existing exposure amplified by this window; its fix is a
bootstrap-protocol change, out of scope for a contained regression fix.

---

## Findings

### F1 — MEDIUM — Config import bypassed the PAC DIRECT typed-confirmation guardrail (policy bypass)

**CWE-862 (Missing Authorization) / CWE-1220 · OWASP A01 · REGRESSION (new-feature gap).**
**Files:** `ui_config.go` (`apiConfigImport`, `importPACPreValidationOK`), vs the guardrail on `pac_profiles_api.go` (`pacGuardDirectCRUD`) and `pac_publish_api.go` (publish/rollback).

A PAC profile that steers traffic **DIRECT** routes that traffic around the
secure gateway entirely — no TLS inspection, no policy, no DLP. The interactive
CRUD, publish, and rollback paths all demand a typed `confirmDirect`
acknowledgement before a change that newly makes DIRECT reachable can go live.
**The config-import path (`POST /api/config/import`) gated PAC profiles behind
only a _structural_ validation (`ValidateProfilesConfig`)** — it never evaluated
the DIRECT delta. Because rollback re-evaluates the guardrail precisely because a
prior in-system revision "is not sufficient — the threat posture may differ now,"
an *externally-sourced* import — a tampered backup, a shared "template" config —
was the least-trusted mutation path yet the only one skipping the check. An
imported enabled DIRECT profile installs immediately, is served by
`servePACProfileFile`, and cluster-syncs to every DP.

- **Attack scenario:** an admin imports a config blob of uncertain provenance
  (config supply-chain); the blob carries an enabled availability-mode or
  `privateNetworks:direct` profile. Structural validation passes; traffic to the
  named destinations silently bypasses the gateway fleet-wide, with no typed
  acknowledgement.
- **Fix (this PR):** `importPACDirectGuardOK` runs the identical
  `pac.EvaluatePublish` engine per enabled candidate profile against the live
  revision; an import that introduces new DIRECT paths is **rejected 409
  fail-closed** unless the admin opts in with `confirmDirect=true` (mirroring the
  interactive friction). The dry-run preview now also surfaces `newDirectPaths` /
  `requiresConfirmDirect` so the delta is visible before commit, and a confirmed
  DIRECT import is logged.
- **Tests:** `config_import_pac_direct_test.go` (reject-without-confirm →
  fail-closed no-install; confirm → install; disabled-DIRECT → no friction).

### F2 — MEDIUM — DIRECT confirmation launderable by enabling a *dormant* DIRECT profile through publish/rollback

**CWE-862 · OWASP A01 · REGRESSION (incomplete propagation of fix `e8e7b68`).**
**Files:** `internal/pac/publish.go` (`EvaluatePublish` / `newDirectPaths`), `pac_publish_api.go`.

Commit `e8e7b68` closed a gap where enabling a *disabled* (dormant) DIRECT
profile makes its bypass reachable to clients for the first time and must require
confirmation — but the normalization ("a disabled active spec is not a live
DIRECT baseline") lived **only** in `pacGuardDirectCRUD`. The publish and
rollback lifecycle handlers call `pac.EvaluatePublish` directly, and
`newDirectPaths` compared the draft's DIRECT rules against `active.Rules`
**without regard to `active.Enabled`**. So the exact operation gated on the CRUD
`PUT` path — create-disabled-with-DIRECT, then flip enabled — sailed through
`publish`/`rollback` with no confirmation.

- **Fix (this PR):** moved the dormant-active normalization into the shared
  `EvaluatePublish` engine (gated on `draft.Enabled`, matching the CRUD guard's
  intent), so publish, rollback, config-import, and CRUD all agree and the
  confirmation cannot be laundered through any call site. The CRUD guard's own
  normalization remains (idempotent, defense-in-depth).
- **Tests:** `internal/pac/publish_dormant_direct_test.go`
  (dormant-enable → confirmation required; enabled→enabled cosmetic edit → no
  churn). Existing `TestEvaluatePublish_PrivateDirectRequiresConfirmation`
  re-verified: the disabled-draft baseline case correctly stays un-normalized.

Both F1 and F2 are governance guardrails, **not** authorization boundaries —
every affected path already requires `RoleAdmin`. The defect is that a
high-friction, deliberate typed acknowledgement (the control that stops an
operator from *accidentally* opening a fleet-wide inspection bypass) was
launderable through alternate admin paths.

### F3 — MEDIUM — Sealed support-bundle export did not record the recipient (unattributable exfiltration)

**CWE-778 (Insufficient Logging) · OWASP A09 · REGRESSION (new surface).**
**File:** `support_export.go` (`apiSupportBundleExportSealed`).

The recipient-sealed export is the *governed* exfiltration channel: a bundle is
sealed to a recipient's X25519 public key, admin-gated recipient registration
publishes the key fingerprint as the out-of-band trust anchor. But the audit
event recorded only `object=<bundleID>, detail="csb/1"` — **not** the recipient.
An operator sealing an approved bundle to `tac-prod` and an operator sealing it
to their **own** key left a byte-identical trail, so the recipient-registry
governance was defeatable without a trace (an operator may seal to an arbitrary
raw pasted key). This is an accountability weakness, not a confidentiality
widening — an operator can already plain-download the same bytes post-approval —
but the sealed path's audit was weaker than its own design implied.

- **Fix (this PR):** the audit detail now records
  `format=csb/1 recipient=<name|(unregistered)> fp=<full SHA-256 fingerprint>`,
  making seal-by-name vs raw-key exports distinguishable and naming the exact key.
- **Tests:** `support_export_sealed_attribution_test.go`
  (registered-recipient name+fp recorded; raw key flagged `(unregistered)` + fp).

### F4 — LOW — Recipient-key rotation audit recorded only the new fingerprint

**CWE-778 · OWASP A09 · new surface.** **File:** `support_recipients.go` (`handleRecipientRotate`).

In-place rotation preserves the recipient *name* binding while the key silently
changes under every future seal-by-name, so this audit entry is the only control
on a compromised-admin key-swap ("rotate `tac-prod` to an attacker key, wait for
the routine seal-by-name export, rotate back"). The event recorded only the
replacement fingerprint, so reconstructing the swap required correlating older
(possibly-evicted) ring entries.

- **Fix (this PR):** switched to `auditEventDiff` recording `fp <old> -> <new>`
  (old fingerprint captured before the rotate; before/after diff populated).
- **Test:** `TestSupportRecipientRotate_AuditRecordsOldAndNew`.

### F5 — LOW — `decRedactHosts` toggle over-promised in its own contract doc

**CWE-532 (Sensitive Info in Log) · OWASP A09 · partial / doc-only.**
**File:** `decryption_redaction.go` (contract framing), `decryption_metrics.go`.

The §4 host/SNI redaction posture hashes the nested `dec.host`/`dec.sni`
sub-fields on every decryption record — verified complete across all emission
paths (bypass/rescue/inspect/non-TLS/failure feed; metrics, trend, and health API
carry no host at all). But the toggle deliberately does **not** touch the
top-level request-log `Host` column or a rule's `LogFullURI` URI — behavior that
is intentional and consistent across *all* feed rows (pinned by
`TestRecordDecryptFailureEntry_RedactsHost`). The file's own doc comment framed
the toggle as redacting "the host and SNI in every projected decryption record,"
which over-promised relative to that deliberate scope; and because a failed
decryption previously recorded *nothing*, the new failure-feed rows do add a
host-bearing record for undecryptable hosts.

- **Decision:** the top-level-host-plaintext behavior is a deliberate,
  test-pinned design (redacting only failure rows would create inconsistency with
  every other feed row). Per the "never change security behavior unless required"
  rule, the correct fix is to make the **contract precise**, not to change runtime
  behavior. The doc now states exactly what is and is not redacted (dec-block
  sub-fields only; the primary Host column and `LogFullURI` rows are unaffected by
  design; the 48-bit hash is a correlation-privacy control, not a secret).

### F6 — MEDIUM (amplified pre-existing) — Unauthenticated `GetConfig` is a config-disclosure + ~60–120 MiB amplifier — DOCUMENTED

**CWE-770 / CWE-400 · OWASP A05 · pre-existing surface, magnitude scaled ~10× this window.**
**Files:** `controlplane_server.go` (`GetConfig`), `controlplane_tls.go` (`VerifyClientCertIfGiven`), `controlplane_snapshot.go` (caps).

The cluster gRPC listener uses `tls.VerifyClientCertIfGiven` and `GetConfig` is
deliberately reachable pre-enrollment (bootstrap). **Secret redaction is intact —
`SessionHMAC`/`IdPProfiles` are zeroed for non-enrolled callers (no secret leak).**
But any client that completes a TLS handshake **with no certificate** receives
the entire redacted snapshot (now up to 2 M blocked hosts, all policy rules, PAC
steering, threat-feed data) and drives a fresh `json.Marshal` (~60 MiB) + up to
128 MiB egress per call, with **no rate limit** (only `Enroll` is rate-limited)
and no per-version marshaled-bytes cache. This window's 10× cap raise (2 M
blocklist / 128 MiB frame) amplified both the disclosure magnitude and the
per-request work by the same factor. Two adjacent pre-auth oracles: the
`ServableConfig` rejection reason and a `KnownVersion` binary-search version
oracle are evaluated before any identity check.

- **Why documented, not fixed here:** the fix — gate the full snapshot on
  `callerIsEnrolledNode` and serve a minimal bootstrap subset otherwise, plus
  per-version byte caching and an unenrolled-caller rate limit — changes the
  enrollment/bootstrap protocol and risks breaking the initial-poll flow if done
  without careful design. That is a genuine scope/design decision, not a contained
  regression fix. **Recommended for a dedicated follow-up.**

### F7 — LOW (accepted) — Config-apply reachable-memory peak raised ~30×; `GOMEMLIMIT` does not bound it — DOCUMENTED

**CWE-770 · OWASP A05 · accepted risk.** **Files:** `controlplane_snapshot.go`, `memory_backstop.go`.

At 2 M hosts the DP-side build-then-swap apply has a reachable peak of ~410–470
MiB (new maps built while old are live atop the unmarshaled slice + wire buffer).
`debug.SetMemoryLimit` reclaims only *garbage*, not reachable memory, so a DP
sized below ~1 GiB could OOM on a legitimate max-size config. **Not
untrusted-exploitable** — only the mTLS-authenticated CP the DP pins to can push
a snapshot (config is pulled; `controlplane_tls.go` is unchanged), and a
compromised CP already has strictly greater capability. Bounded by the 128 MiB
frame + commit-time count/byte validation. **Real bound is the documented DP
minimum-memory sizing guidance** (`docs/operator/cluster-config-capacity.md`);
the in-code follow-up is a streaming/chunked apply.

---

## Verified safe (no regression) — substantiated highlights

- **Sealbox crypto (`internal/sealbox`)** — NaCl anonymous sealed box (X25519 +
  XSalsa20-Poly1305). Low-order/all-zero-shared-secret keys rejected **result-based**
  via `curve25519.X25519(probe, pub)` erroring (covers all 8 canonical low-order
  points + non-canonical encodings — stronger than a blocklist), with a
  constant-time all-zero backstop; enforced on the raw-paste path, on every
  registry read (on-disk tampering can't reintroduce a weak key), and inside
  `Seal`. `Open` returns a single opaque error (no oracle). Appliance holds no
  decrypt capability (true E2E). Full-length SHA-256 fingerprint.
- **PAC JS injection** — every admin/imported string reaching the compiled PAC is
  emitted through Go `%q` (`strconv.Quote`); proxy hosts additionally punycoded +
  label-validated (ASCII `[a-z0-9_-]`), wildcard patterns alphabet-restricted,
  ports are ints. `servePACProfileFile` rejects any non-`ValidIdentifier`
  (`^[a-z0-9][a-z0-9-]{0,63}$`) id with 404 and is the only new public route
  (`/pac/`, allowlisted in `uiAuthMiddleware`) — no traversal, no injection, no
  route shadowing of the `/api/pac/*` admin routes. No server-side dial of pool
  endpoints ⇒ no SSRF.
- **`certVerification=permissive` retirement** — fail-closed: write paths reject
  it (400), bulk paths (disk load / import / rollback / CP→DP apply) migrate it to
  `strict` before `Validate` with an audit-visible diagnostic. No new
  verification-skipping runtime path introduced.
- **Autoexclude (fail-open decryption-exclusion cache)** — classifier byte-unchanged
  and not widened; fail-close/no-profile rules never populate or consult the cache
  (un-poisonable); scope isolation `(scopeID, host)` intact; metric labels bounded
  (`_other_` fold); connect-failure recording records taxonomy only and never
  learns.
- **CP↔DP mTLS / enrollment / redaction** — `controlplane_tls.go` untouched;
  `verifyNode`/`callerIsEnrolledNode` unchanged; the two `Sensitive`+`ClusterSynced`
  fields (`session_hmac`, `idp_profiles`) still zeroed for non-enrolled callers,
  walled by `config_surfaces_test.go`. New synced fields `PACProfiles`/`PACPools`
  carry no credentials (host/port/rules only) → correctly non-`Sensitive`, fully
  wired (capture/apply/diff/wire-wipe parity).
- **Fail-closed cluster commit / HA** — empty-config refusal (`Unavailable` → DP
  keeps last-good, never default-allow); `applyHABundle` aborts resync on a
  rejected config instead of marking sync-OK; a DP's reported config version is
  set only after a successful apply; gzip is opt-in DP-side and CP-first
  (mixed-version safe); grpc-go bounds gzip on the decompressed frame (no bomb).
- **Support RBAC / retention / paths** — every new export/manifest/recipient/
  retention/diagnose route's `requireRole` matches its C2 metadata; exports are
  admin-approval-gated + operator-RBAC-gated + audited; retention prune serialized,
  byte-credited only on confirmed removal, evicts by re-validated on-disk dir name
  (no traversal); diagnose verbs emit counts/timestamps only (no snapshot values,
  no secrets); files written `0600` in `0700` dirs, atomic tmp+rename, fail-closed
  on corrupt registries.
- **admin_settings quarantine** — strictly safer than the prior silent-default:
  corrupt file moved aside (mode preserved, keeping `0600` on `metrics_token`) with
  alert + `/readyz` surfacing; EACCES deliberately not quarantined.

## Non-fix observations (documented, no code change)

- **Recipient DELETE is `operator` while add/rotate are `admin`** (`support_recipients.go`)
  — deliberate per route metadata; deletion cannot redirect an export (lookup
  fails closed, no silent fallback), so not a widening. Optional hardening: raise
  DELETE to `admin` for trust-store parity.
- **Replay paths (`import`/rollback/CP-apply) call `pacProfiles.Set` outside
  `pacProfilesAPIMu`** — `ProfileStore.Set` is internally locked (no memory-safety
  issue); worst case is a lost update vs a concurrent admin `PUT`. Pre-existing
  replay-path pattern; F1's guard now runs before the import `Set`.
- **Background retention janitor self-eviction race** — a narrow residual past
  `05cf780`; availability-only, requires a store dominated by evidence-exempt
  bundles at the 2 GiB ceiling.
- **`/health`,`/ready`,`/metrics` answer on absolute-URI proxied requests** —
  pre-existing; the new PAC-route `r.URL.Host == ""` guard shows the fix pattern.

---

## Tests added

| Test file | Guards |
|-----------|--------|
| `internal/pac/publish_dormant_direct_test.go` | F2 — dormant-enable requires DIRECT confirmation; enabled→enabled no churn |
| `config_import_pac_direct_test.go` | F1 — import DIRECT guard (reject/confirm/disabled-no-friction, fail-closed no-install) |
| `support_export_sealed_attribution_test.go` | F3/F4 — sealed export records recipient name+fp; raw-key flagged; rotation old→new |
| `pac_profiles_root_test.go` (amended) | round-trip import now acknowledges DIRECT via `confirmDirect=true` |

## Residual risk

F6 (unauthenticated `GetConfig` disclosure/amplification) and F7 (config-apply
memory peak) remain open by design decision — both are gated behind the cluster
mTLS listener / bootstrap posture and neither leaks a secret, but F6 in
particular should be scheduled: enroll-gate the full snapshot, cache marshaled
bytes per version, and rate-limit unenrolled callers. All other findings are
fixed with red/green regression tests; the full module test suite (`go test ./...`)
is green.
