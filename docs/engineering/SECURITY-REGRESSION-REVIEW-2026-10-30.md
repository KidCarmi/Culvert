# Security Regression Review — 2026-10-30

**Scope.** `7262622…9eb4281` (`origin/main`) — the 24 h since the 2026-10-29
review, 8 merged pull requests (#1753 #1755 #1756 #1757 #1758 #1759 #1760
#1761), 37 files, +3,389/−79. Ten production Go files changed; the rest is
tests, roadmap and operator documentation.

| PR | Change | Security surface |
|---|---|---|
| **#1757** | `SEC-SETUPANCHOR-1` — any admitted roster account anchors first-run setup, on both the in-memory and durable sides | authentication, authorization, persistence |
| **#1758 / #1756** | `SEC-AUTHENABLED-1` — a roster with accounts but no usable admin is an active authentication backend; SOCKS5, the SSE re-check and the HTTP proxy all fail closed on it | authentication, proxy, admin control plane |
| **#1755** | CHAOS-104 — the dual-CA overlap is reinstated after a restart inside a cluster-CA rotation; CHAOS-105 — five unguarded background-worker rounds | cryptography, trust anchors, mTLS, availability, audit |
| **#1756** | `benchgate` refuses a zero benchmark result; a policy decision-snapshot bench and its floor | CI gate |
| **#1759** | Three flaky timing gates made deterministic | test gate integrity |
| **#1753 / #1760 / #1761** | Terminology governance review; roadmap and package-isolation records | documentation only |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed 24 h ago?** Every finding is measured against the base
revision, not against an ideal.

**Method.** Each change read through its production callers rather than its diff
hunks. `SEC-SETUPANCHOR-1`'s durable mirror was checked against
`loadUIUsersFile`'s actual admission test line by line rather than against its
own doc comment. The CHAOS-104 trust-anchor restore was traced through every
writer and consumer of the secondary slot, and its fingerprint format compared
on both sides of the durable record. Three hypotheses about CHAOS-105's guards
converting a fail-closed crash into a stuck fail-open control were formed and
**disproved** against the owners' invariants (see §3). The one finding that
survived the disproof pass was then **proved end to end** — the operator-facing
claim rendered from live process state in the same breath as the real
`handleRequest` answer it contradicts — because a diagnostic is only wrong
against what the gateway actually does.

---

## 1. Executive Summary

**No security regression was introduced in this window.** All three
security-relevant changes move the posture forward, and each fails closed in
the direction its own doc comment claims. That was verified, not taken on
trust.

The review found **one confirmed regression in operator-facing guidance**,
introduced by `SEC-AUTHENABLED-1` itself: the Auth Exempt break-glass
kill-switch row on the operator contract now predicts the **opposite** of what
the gateway does in exactly the state that fix created. It is report-only — no
enforcement is weak — but an operator following it during an incident would
take a full traffic outage the contract told them could not happen, and the row
names the wrong repair. It is fixed and gated here. A second, latent item in
the same window — two new roster reads that dropped out of the
operator-contract roster wall's coverage — is fixed with it.

| # | Finding | Severity | Status |
|---|---|---|---|
| **S-1** | The `auth_exempt_kill_switch` row reports `killSwitchBackendNone` for the roster-without-verifier state `SEC-AUTHENABLED-1` created, and claims formerly exempt traffic "is decided by the remaining authentication rules and Stage 2 policy". The gateway in fact answers **407 with an unsatisfiable challenge** and refuses every one of them. Proved end to end | **LOW** security / **MEDIUM** operational (introduced this window; misleading break-glass guidance, wrong remediation) | **FIXED + gated** |
| **S-2** | `AuthEnabled()` and `IsConfigured()` both became roster reads in this window and neither was added to the operator-contract wall's `rosterAccessorMethods`, leaving two unregistered paths from a contract row to roster state | **LOW** (introduced this window; latent — no live violation) | **FIXED + verified to flag nothing** |

Surfaces reviewed and found **clean**: `SEC-AUTHENABLED-1`'s three enforcement
sites and its empty-backend sentinel; `SEC-SETUPANCHOR-1`'s in-memory predicate
and its durable mirror's loader parity; CHAOS-104's trust-anchor restore (path
guard, rotation-record precondition, window check, production CA validator,
SHA-256 pin, re-encode from the verified certificate, and `AllCACertsPEM`'s
independent expiry re-check at use); CHAOS-104's boot ordering; CHAOS-105's five
guarded rounds; the three flaky-gate fixes; and the CI / dependency surface —
**no gate was weakened**: `benchgate` gained a refusal, every flaky-gate change
preserved or sharpened its assertion, and `git diff` across the whole window on
`go.mod` and `go.sum` is **empty** (the `go.sum` churn in #1755 restored main's
content exactly), with no `.golangci.yml`, `Makefile`, `Dockerfile` or
`GOTOOLCHAIN` change.

---

## 2. Security Findings

### S-1 (LOW security / MEDIUM operational, introduced this window) — the kill-switch row predicts the opposite of what the gateway does

`SEC-KSROSTER-1`. **Fixed and gated in this change.**

`SEC-AUTHENABLED-1` added a term to `resolveRequestAuth`
([proxy.go](../../proxy.go)):

```go
rosterWithoutVerifier := !credCapable && cfg.AuthEnabled()
authRequired := credCapable || ssoCapable || rosterWithoutVerifier || originalEffective == OutcomeExempt
```

and excluded that state from the no-backend inert guard, so the forced-Default
arm emits a 407. That is the **correct** fail-closed answer for a roster that
holds accounts but can verify nothing, and the owner accepted it as a
traffic-breaking change.

`currentKillSwitchBackend` ([auth_killswitch_diag.go](../../auth_killswitch_diag.go))
was not updated with it. Its own doc comment says it "mirrors the Stage-1
gate's backend term in `resolveRequestAuth`", and it did — before the term
moved. Both of its probes are false in that state (`GetUser()` is empty because
`loadUIUsersFile` sets the legacy pair only from a record whose **effective**
role is admin, and no provider is wired), so it answered
`killSwitchBackendNone`, whose row reads:

> …but no credential or SSO provider is usable on this node (none is enabled,
> or an SSO profile failed to load), so this **does not make formerly exempt
> clients authenticate**: their requests are decided by the remaining
> authentication rules and **Stage 2 policy**

**Attack scenario.** This is not an attacker-reachable bypass; the exposure is
an operator acting on a false signal during an incident. An administrator of a
gateway in the clamped or legacy-roster state opens the Auth Policy panel
mid-incident, reads the contract row saying the kill switch adds no
authentication on this node, engages the break-glass to suppress every Exempt
rule — and takes the entire formerly-exempt client population offline, because
each one now receives a 407 nothing can satisfy. The row's remediation then
sends them to Identity Providers to fix a profile that does not exist, instead
of to `--reset-password`, which is the only repair.

**Preconditions.** A local-roster deployment whose roster holds admitted
accounts with **no present admin** and **no provider**, reached by either of
`SEC-SETUPANCHOR-1`'s two recorded routes with no prior authority on the
target: `loadedRosterRole`'s least-privilege clamp on a restore of a backup
from a build that enrolls a role this one does not, or a legacy pre-RBAC roster
whose empty role is never `RoleAdmin`. Plus the kill switch engaged (env
`CULVERT_AUTHBYPASS_DISABLE` or the runtime toggle).

**Exploitability.** Not attacker-driven. The *misreport* is deterministic and
needs no race: it is what the row says on every render in that state.

**Likelihood.** Low — it needs the clamped/legacy roster and an engaged
break-glass together. Worth fixing anyway because the two conditions correlate:
the break-glass is engaged during an incident, and a downgrade restore is an
ordinary incident-recovery action.

**Impact.** Availability, not confidentiality or integrity: a full outage of
formerly-exempt proxy traffic, taken deliberately on the strength of a row that
said it would not happen, with the diagnostics report pointing at the wrong
repair. No authentication or authorization decision is weakened — enforcement
is correctly fail-closed throughout.

**Affected assets.** The operator contract, the diagnostics report, the support
bundle and the dashboard roll-up that carry this row; and, through the
operator's action, proxy availability for every formerly-exempt client.

**Proof (not inferred).** Rendered from live process state, with the real
request path driven in the same state:

```
currentKillSwitchBackend() = 0 (none=0 notLoaded=1 live=2)
ROW auth_exempt_kill_switch [warn]: …so this does not make formerly exempt
    clients authenticate: their requests are decided by the remaining
    authentication rules and Stage 2 policy
ACTUAL gateway answer: 407  Proxy-Authenticate="Basic realm=\"Culvert\""
```

**Recommended fix / safe implementation (applied).** A fourth backend state
rather than a relaxation of the existing three:

- `killSwitchBackendNoVerifier` is appended to the enum (appended, so no
  existing ordinal moves).
- `currentKillSwitchBackend` returns it when, with neither a credential-capable
  validator nor a live interactive provider, `cfg.AuthEnabled()` is still true
  — which is *exactly* `resolveRequestAuth`'s `rosterWithoutVerifier`
  discriminator, read here as a boolean and nothing more. Placed inside the
  existing `!credCapable && !sso` branch, which is the only branch where the
  row would otherwise have said "none"; a live SSO provider still classifies
  `killSwitchBackendLive`, correctly, because the gate is armed and fulfillable
  then.
- The row states the **refusal** rather than a challenge, because that is what
  the client observes, and leads its operator action with the
  `--reset-password` break-glass while keeping each layer's own remediation
  intact as a suffix.
- `cfg != nil` is checked, matching the function's existing defensive shape.

Report-only throughout: no enforcement predicate, policy, persistence or
credential path is touched. The fix deliberately does **not** change
`resolveRequestAuth` — the 407 is the intended posture, and the defect was the
report, so changing enforcement to match a wrong row would have been the
regression.

**Required tests (all present).**
[auth_killswitch_roster_backend_test.go](../../auth_killswitch_roster_backend_test.go)
is a **differential oracle** between the row and the enforcement path: each
defect gate renders the row from live process state and drives the real
`handleRequest`, and requires the two to agree. Asserting the enum alone would
not have caught the original defect, because the enum was self-consistent — it
was the enforcement path that moved.

| Test | Class |
|---|---|
| `ClampedAdminRosterIsNotNoBackend` | authentication / authorization, regression, end-to-end |
| `LegacyEmptyRoleRosterIsNotNoBackend` | backward compatibility, regression, end-to-end |
| `GenuineNoBackendUnchanged` | negative control — pins **both** the `None` row and its Stage-2 403 fall-through, so a fix that changed enforcement fails here |
| `AdminRosterUnchanged` | negative control (live verifier) |
| `NoVerifierRowShape` | boundary — all three kill-switch layer combinations, and the clear-switch case that must contribute nothing |
| `NilConfigDoesNotPanic` | malformed state (the probe runs on the admin plane and must not panic it) |
| `ConcurrentProbesAgree` | concurrency (`-race`, 16 readers) |

Each defect gate was **verified to FAIL against the pre-fix tree** (probe
reverted in place): `want killSwitchBackendNoVerifier (3), got 0`, plus the
stale row text and the missing break-glass. `GenuineNoBackendUnchanged` passed
in that same reverted tree, which is what makes it a control rather than a
restatement of the fix.

**CWE.** CWE-440 (expected behavior violation), with CWE-684 (incorrect
provision of specified functionality) and CWE-1059 (insufficient or incorrect
documentation of behavior). **OWASP.** A09:2021 Security Logging and Monitoring
Failures; A04:2021 Insecure Design.

**Regression risk of the fix.** Low and bounded: one new enum value, one new
branch reached only where the old code returned `killSwitchBackendNone`, and
one new row rendering. The two pre-existing rows are untouched and pinned by
the pre-existing tests plus a new control.

### S-2 (LOW, latent, introduced this window) — two new roster reads dropped out of the operator-contract wall

**Fixed in this change.**

`rosterRowExceptions` in
[operator_contract_wall_test.go](../../operator_contract_wall_test.go) is a
static wall: it walks everything reachable from `buildOperatorContract` and
fails the build if a function reads a roster primitive — or consumes one that
does — without being classified, so a row rendering roster state cannot ship
without being redacted below admin. Its recorded origin (Codex P2, PR #1545) is
exactly the omission it now prevents: "a new check calling
`collectAdminUsernames()` and rendering `len(inv.names)` used to pass every
wall without being redacted."

The primitive list is name-based:

```go
rosterAccessorMethods = []string{"ListUIUsers", "UserHasTOTP", "GetUser",
    "hasLocalAdministrator", "rosterPersistTarget", "rosterWriteEvidence"}
```

`AuthEnabled` and `IsConfigured` were correctly absent, because before this
window neither touched the roster. `SEC-SETUPANCHOR-1` gave `IsConfigured` a
`len(c.uiUsers) > 0` term and `SEC-AUTHENABLED-1` gave `AuthEnabled` the same
one — both now answer a question *about the roster* — and nothing re-listed
them.

**Preconditions / exploitability / impact.** Nothing leaks through either today
and this is stated as verified, not assumed: both return a boolean existence
fact, and every function reachable from `buildOperatorContract` that calls
either is already classified for other roster reads it makes
(`readRosterDurabilityFacts` via `rosterPersistTarget`/`hasLocalAdministrator`,
`currentKillSwitchBackend` via `GetUser`). The exposure is **forward-looking**:
a future contract row that reads roster state through `IsConfigured()` or
`AuthEnabled()` would pass the wall unclassified and unredacted, which is the
single failure mode the wall exists to prevent.

**Recommended fix (applied).** Both names are added to
`rosterAccessorMethods`, and the list's doc comment records why a `Config` read
that answers a question about the roster belongs there whatever its name
suggests. `currentKillSwitchBackend`'s registered reason is updated to name
`AuthEnabled()` and the four-state enum.

**Verification that it over-closes nothing.** The widened list was run against
the full wall **before** any other change in this branch: it flags **nothing**
in the current tree. Both already-classified consumers keep their existing
`rosterProbe` / `rosterInput` kinds, so no row's redaction changes.

**CWE.** CWE-1053 (missing documentation for design) as the proximate shape;
the class it guards is CWE-359 (exposure of private information) / CWE-200.
**OWASP.** A01:2021 Broken Access Control (the control that enforces it),
A09:2021.

**Regression risk of the fix.** None to runtime: it is a test-gate list. The
only risk was over-closing — a false wall failure — and that is measured above.

---

## 3. Regression Analysis — surfaces reviewed and found clean

Three hypotheses were formed deliberately against the most dangerous reading of
each change, then **disproved** against the owners' own invariants. They are
recorded because a disproof is evidence and an unstated one is not.

**`SEC-AUTHENABLED-1` (#1756/#1758) — sound, and the second half is what makes
it so.** Changing `AuthEnabled()` alone would have been a *worse* posture than
leaving it: SOCKS5 would have demanded USERPASS while `verifyAuthFrom`'s
`snapshot.user == ""` sentinel still answered `true`, turning "USERPASS
required" into "any USERPASS accepted". The commit closes both halves from one
snapshot taken under one lock (`authBackendSnapshot.hasRoster`), so the two can
never disagree across a concurrent roster change. The HTTP proxy's follow-up
(`3af65c9`) arms the gate **and** removes the state from the inert guard; armed
without the second change, the guard would have swallowed the challenge. Fresh
gateways (no accounts) are byte-identical, held by negative controls on the
real SOCKS5 listener and the real SSE re-check.

**`SEC-SETUPANCHOR-1` (#1757) — the durable mirror's loader parity verified
directly.** `rosterBytesConfigure` now admits any record whose `PassHash`
decodes as hex, dropping both the role and the username terms. Checked against
`loadUIUsersFile` at this revision rather than against the comment: its only
admission test *is* `hex.DecodeString(rec.PassHash)`, and it keys `c.uiUsers`
by whatever username the record carries, the empty string included — so the
mirror and `len(c.uiUsers) > 0` agree exactly, including on the
empty-`PassHash` edge (`hex.DecodeString("")` succeeds on both sides). The
envelope-vs-bare-array precedence matches the loader's, and an envelope with no
`users` key is corrupt to both, leaving the window open on both. Every new term
makes the predicate *more* true, so it can only close the window.

**CHAOS-104 (#1755) — a new trust anchor read from disk, and the layering holds.**
This is the window's only change that *re-adds* a CA to the Control Plane's
mTLS client-CA pool from a file, so it was read as an attack surface. Six
independent conditions must all hold: `safeCAPath`; a rotation recorded with a
non-empty `OldFingerprint`; `time.Now().Before(st.OldExpires)`;
`parseAndValidateCACert` (the production validator — rejects a non-CA, an
expired and a not-yet-valid certificate); `hex(sha256(cert.Raw)) ==
st.OldFingerprint`; and what enters the pool is **re-encoded from that one
verified certificate**, so extra PEM blocks in the backup cannot ride along.
Three things were checked rather than assumed:

- **Fingerprint format parity.** `commitImport` records
  `hex.EncodeToString(sha256.Sum256(ca.secondaryCert.Raw))` and the restore
  compares `hex.EncodeToString(sha256.Sum256(cert.Raw))` — same hash, same
  encoding, same input. A mismatch would have failed closed (no restore), but
  it would have made the fix inert; it is not.
- **No "retired early" re-add.** `CleanupSecondary` is the *only* path that
  nils the secondary slot, it does so only once `time.Now().After(secondaryExp)`,
  and it then calls `ClearCARotation` — so there is no state in which an
  operator has retired the overlap while the rotation record survives for the
  restore to resurrect. `AllCACertsPEM` *also* re-checks
  `time.Now().Before(secondaryExp)` at every use, so even a restored secondary
  is time-bounded independently of the restore's own window check, and
  `exp = min(st.OldExpires, cert.NotAfter)` never extends trust past the
  certificate's own validity.
- **Boot ordering.** The restore reads the durable rotation record, so it is
  inert if the cluster store has not loaded. `loadCluster` calls
  `globalClusterStore.Load` before any role branch reaches
  `activateControlPlane` → `initClusterCA` → `InitOrLoad`, and
  `globalClusterStore` is a non-nil package var, so there is no nil receiver
  and no empty-record window. The private key is **not** restored — only the
  certificate — so nothing can sign with the retired CA.

The lock discipline is the one CHAOS-50/51 established on this type: the
durable read happens before `ca.mu`, the re-check under the write lock refuses
if an import landed in between, and `onRotate` runs with `ca.mu` released.

**CHAOS-105 (#1755) — three fail-open hypotheses, all disproved.** `runGuarded`
is per-round, not per-goroutine, and every recovery increments
`culvert_crash_records_total{component}`, writes a bounded `lastCrash` and adds
a system-actor audit entry, so a deterministic repeating panic is loud rather
than silent.

- *Hypothesis: a swallowed panic strands the elevated debug capture level past
  its TTL, where the pre-change crash would have reverted it.* **Disproved.**
  [support_debug_level.go](../../support_debug_level.go)'s invariant 2 computes
  the **effective** level from the persisted expiry at read time; the watchdog
  is only an active cleaner and auditor, and correctness explicitly does not
  depend on it running. A permanently panicking watchdog cannot widen capture.
- *Hypothesis: a panicking retention sweep strands support bundles past their
  age and size caps.* **Disproved as a regression.** Pre-change the same panic
  killed the process into a boot-sweep crash loop, which pruned nothing either;
  the `supportMinFreeBytes` preflight still refuses new builds. Post-change is
  strictly better on availability and no worse on retention.
- *Hypothesis: `sseBroadcaster`'s new injectable `round` field can be nil in
  production, making the dashboard permanently dead.* **Disproved.**
  `newSSEBroadcaster` is the only construction path in the tree and always
  assigns `b.round = b.tick`; there is no struct literal anywhere else.

One genuine, non-security consequence is recorded: if `debugLevelWatchdogTick`
panics *after* removing the expired state file, the `auto_revert` audit line is
skipped for that tick because `expired` keeps its zero value. The revert itself
is already durable, the crash is separately audited, and the next tick is a
no-op, so no state is wrong — only one informational entry is missing on a path
that previously ended the process.

**Test-gate integrity (#1759) — no assertion weakened.** All three changes
preserve or sharpen their control. The DNS gate still requires *exactly* 2
resolver calls and now gives stacked refreshes a 50 ms window to manifest
first, so it can only get stricter. The alerts budget gate replaces a
wall-clock elapsed bound — which charged real disk writes against the budget —
with "at most one attempt may start after the deadline", which is the precise
property; removing the budget entirely would still be caught by the
co-resident `attempts >= total` assertion. The syslog gate moves `start`
*earlier*, so it measures more, not less.

**CI and dependencies (#1755/#1756) — no gate weakened.** `git diff` on
`go.mod` and `go.sum` across the whole window is empty: #1755's 396-line
`go.sum` deletion reverted local `go mod download all` churn back to main's
exact content, and no dependency moved. `benchgate` gained a **refusal** (a
zero benchmark result is no longer accepted as a pass) and kept its scheduled
fixture matching. No workflow, linter-config, Makefile, Dockerfile or
`GOTOOLCHAIN` change exists in this window.

---

## 4. Residual Risk

- **S-1's underlying posture is unchanged and intended.** A clamped or legacy
  roster still refuses all proxy traffic under the Default outcome until
  `--reset-password` restores an admin. That is `SEC-AUTHENABLED-1`'s accepted
  traffic-breaking behaviour, not a residual defect. What this change alters is
  only whether the operator is told the truth about it.
- **The remediation path is a single break-glass.** `--reset-password` is now
  named by the kill-switch row and by the `admin_roster_durability` row, but it
  is still a CLI action requiring host access. A deployment that reaches the
  clamped state and has lost host access has no in-band recovery. Pre-existing;
  out of scope here.
- **`auth_cr_no_credential_provider` remains accurate but incomplete.** In the
  roster-without-verifier state its FAIL row correctly says no credential-capable
  validator is configured, but its operator action lists "configure a local
  account, a legacy auth provider, or an OIDC IdP" without naming
  `--reset-password` for the clamped case. Not wrong, and it fires only when CR
  rules exist, so it was left alone rather than widened in the same change.
- **The operator-contract wall is name-based.** S-2's fix lists two more method
  names; it does not make the wall detect a roster read through a *new* accessor
  nobody lists. The structural fix would be to key on the `c.uiUsers` field read
  rather than on method names. Recorded as the class fix, not attempted here.
- **CHAOS-104's `.bak` is still a predictable path.** Trust in it rests
  entirely on the durable SHA-256 pin, which is the right dependency: planting
  the file requires already holding the outgoing CA's public certificate, which
  grants nothing. The key `.bak` beside it is the real asset and is unchanged
  by this window (`AtomicWrite`, `0600`, encrypted at rest when enabled).
- **CHAOS-104 does not cover a rotation whose `.bak` write failed.** The
  operator is now told at the console, but the overlap is genuinely
  unrecoverable across a restart in that case. Documented, fail-closed (new CA
  only), and the correct trade: failing the rotation instead would strand the
  fleet on an expiring CA.

---

## 5. Verification

Toolchain from [go.mod](../../go.mod) (`toolchain go1.27.3`), taken from the
`toolchain` line and not the `go` minimum.

| Check | Command | Result |
|---|---|---|
| Vet | `go vet .` | pass |
| New gates | `go test -run 'TestKillSwitchBackend\|TestAuthExemptKillSwitch' .` | **pass** |
| New gates under race | `go test -race -run 'TestKillSwitchBackend' .` | **pass** |
| Defect gates vs pre-fix tree | probe reverted in place, same gates re-run | **FAIL as designed** (`want 3, got 0`; stale row text; missing break-glass) — and `GenuineNoBackendUnchanged` **passed** in that tree, proving it is a control |
| Roster wall, widened list, before any other change | full wall suite | **0 new findings** |
| Root suite | `go test -count=1 -timeout=40m .` | **pass** (601 s) |
| Guidance checker | `python3 docs/agent-context/check.py` | pass (exit 0) |
| Gate lint (blocking form) | `golangci-lint run --timeout=10m --new-from-rev origin/main`, linter **v2.15.0 built with go1.27.3** — installed per the pinned gate, not the container's `PATH` copy | **0 issues** (exit 0) on the second run; the first reported one `gocritic unnamedResult` on the new gate file's `proxyAnswer`, fixed by naming its results |

The pinned linter was built with the `go.mod` toolchain rather than taken from
the container's `PATH`, which the conventions record as the step whose omission
has repeatedly been logged as "local lint is unavailable".

**Not run, and why.** `benchgate`, the chaos-tagged suites, a full-tree lint
differential against the base, and the hosted QA/CodeQL gates. Nothing
allocation-, feed- or concurrency-shaped changed here: the production delta is
one enum value, one branch in a diagnostics probe and two strings, and the only
other edit is a test-gate list. The full-tree complexity comparison that
`--new-from-rev` cannot see is not material for a change that adds one `if` to
a function well under the configured `cyclop` threshold, but it was not
measured, so it is listed here rather than claimed. A passing local check is
not a passing hosted review or merge gate.
