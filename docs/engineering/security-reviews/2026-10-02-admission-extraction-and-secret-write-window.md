# Security review — the admission/shutdown engine extraction, the Basic-auth chokepoint, and the secret-write sweep

**Date:** 2026-10-02
**Reviewer role:** Security Regression Engineer (scheduled run)
**Scope reviewed:** `1f7f42c..3fcc07e` plus the un-reviewed tail of the previous
window (`f13479b..1f7f42c`) — everything merged since the
`2026-09-24` review. PRs #1420, #1501, #1508, #1522, #1523, #1524, #1525 and the
security-labelled commits of 2026-09-26 (#1429, #1446, #1448, #1467, #1469,
#1483, #1490, #1491, #1493). ~110 files.

The window's dominant change is a **refactor that relocated the two per-request
admission gates** — `IPFilter` and `RateLimiter` — out of `security.go` into
`internal/admission`, and the ordered shutdown executor into `internal/shutdown`.
That is the highest-risk class this role exists for: a pure-motion change to
code whose correctness is a security property, where nothing in the diff *looks*
like a policy decision.

---

## 1. Executive summary

**The extraction is faithful.** A function-body differential against the
pre-refactor tree (comments normalised) shows that of 52 moved functions,
**47 bodies are byte-identical** and the 5 that changed did so only by
substituting a per-instance field for a process global or an exported name for
an unexported one. Every gate whose body decides an allow/deny — `IPFilter.Allowed`,
`ipFilterView.contains`, `prefixSet.contains`, `RateLimiter.IsExempt`,
`clientBucket.expire/add/grow`, `clusterCountStore.FreshCount/Apply` — is
unchanged. The CHAOS-61 freshness invariants (both halves of `Armed`,
`!Applied ⇒ Stale`, negative age ⇒ stale, derived-never-latched) survive
verbatim, as do the CHAOS-56 shutdown invariants (recursive reserve, grace
carved out of the slice rather than added on top, the phase horizon) and the
3s/1s watchdog timing.

**Three findings, none of them a regression the refactor introduced** (the
third was found by review of the second's fix):

1. **MEDIUM — `backupCAFiles` writes the cluster CA private key through a
   predictable path with `os.WriteFile`.** This is the one production writer of
   private key material that the SEC-SECRETWRITE-1 sweep (#1467) did not reach,
   because that sweep was scoped to writers introduced in its own window and
   `backupCAFiles` predates it. The asset is larger than any of the four that
   were fixed. **Fixed in this PR.**
2. **LOW–MEDIUM — a failed re-authentication on `POST /api/auth/change-password`
   left no audit record.** The handler's missing *lockout* is a deliberate,
   recorded trade-off; its missing *evidence* was not recorded anywhere, which
   made the single unlocked password oracle in the admin API also the single
   silent one. **Fixed in this PR.**
3. **LOW — the audit *Actor* was unbounded product-wide** (`auditActor`), so the
   fix for finding 2 bounded the `Object` and left the identity it rebuilds from
   the session full-length — in the audit ring and in the five other stores that
   persist `auditActor`'s result. Caught by Codex review of this PR.
   **Fixed in this PR.**

Nothing in the window weakened authentication, authorization, policy
precedence, TLS, or fail-closed behaviour. Three of the window's own commits
(#1420 SEC-BASIC-1, #1467 SEC-SECRETWRITE-1, #1448 SEC-RBAC-ROLE-1) are
security *improvements* that I re-derived and found sound.

---

## 2. What was verified, and how

### 2.1 `internal/admission` extraction (#1522 / #1523 / #1524) — no regression

| Property | Method | Result |
|---|---|---|
| Decision logic unchanged | AST-level function-body differential vs `1f7f42c:security.go` | 47/52 bodies byte-identical; 5 differ only by global→field or name export |
| `Allowed` fail-closed semantics | body identity + `go test ./internal/admission` | unchanged |
| `prefixSet` family normalisation (the fail-OPEN trap for a blocklist) | body identity of `buildPrefixSet`/`PrefixFromIPNet`/`contains` | unchanged |
| Rate-limit window arithmetic | body identity of `expire`/`add`/`grow` | unchanged |
| Exempt-list semantics (raw-string keying, mapped probe must stay non-exempt) | body identity of `IsExempt` + relocated differential tests | unchanged |
| View-republish contract (a mutator that forgets to publish is a *silent security failure*) | `Test{IPFilterView,RLExemptView}_EveryMutatorRepublishes` + `MutatorInventoryIsComplete` relocated and passing; inventory selector is token-scoped so the new non-exempt methods are legitimately out of scope | intact, non-vacuous |
| No-in-place-mutation half | `-race` concurrent reader/mutator tests relocated | intact |

**The genuinely new risk this refactor creates is instance identity.** Process
globals (`clusterRateLimitEnabled`, `clusterCounts`) made "who writes, who
reads" irrelevant; per-instance ownership makes it security-relevant. A gossip
loop arming instance A while the request path decides on instance B would
silently degrade a cluster-wide limit to a per-node limit, with every freshness
surface reporting healthy. **Verified not to have happened:** there is exactly
one `*RateLimiter` (`admission.go:16`), `controlplane_client.go:212` passes that
same `rl` into `rateLimitGossipLoop`, and `proxy.go:1486` / `socks5.go:436` /
`ui_cluster.go:386` / `metrics.go:1270` all read it. No second instance exists
in production code.

Also checked: the new `rateLimitWireDeltas` DTO adapter preserves `nil`
(so an empty gossip stays JSON `null`) and keeps the `json` tags byte-identical,
so there is no wire-format change; the armed-gated metric emission
(`if crl := rl.ClusterFreshness(); crl.Armed`) is preserved, so a node that is
not rate limiting still emits no `culvert_cluster_ratelimit_*` gauge.

### 2.2 `internal/shutdown` extraction (#1522) — no regression

All shared-name bodies identical; the four renamed ones (`hookBudget`,
`runShutdownHook`, `RunAll`, `partitionAt`) differ only by receiver and by
reading `r.timing()` instead of two package vars. `timing()` falls back to
`DefaultGrace` (3s) and `DefaultMinSlice` (1s) — the same values the old
`var`s held — and production constructs the registry with `Logf` only, so the
defaults apply. The SEC-SHUT-1 property that matters (the grace is **shared by
the phase** via one horizon, and the slack is carved **out of** each hook's
slice rather than added on top) is present verbatim. Converting the old mutable
`var` timing to injected `Options` is the ADR-0037 direction, not a weakening.

### 2.3 SEC-BASIC-1 (#1420) — sound and complete

Re-derived independently:

- **Completeness:** all three `r.BasicAuth()` call sites
  (`ui_middleware.go:294`, `ui_auth.go:245`, `events.go:155`) route through
  `verifyUIBasicAuth`. No fourth exists.
- **Ordering:** the password check precedes the TOTP-enrolment refusal, which is
  correct — refusing first would turn a public endpoint into a 2FA-enrolment
  oracle for an unauthenticated caller.
- **Budget accounting:** the per-IP unit is reserved before any bcrypt, refunded
  on success and on a lockout refusal (which costs no bcrypt), and *kept* on the
  TOTP refusal (which does cost one). A TOTP refusal is deliberately not charged
  to the per-account lockout — charging it would let a caller who does *not*
  know the password lock the account out by replaying any Basic request.
- **The new budget primitive** (`lockout.APIRateLimiter.Reserve`/`Refund`) is
  correct where it is easiest to get wrong. The claim is atomic under the lock,
  so there is no check-then-charge window a concurrent wave could all pass; and
  the refund is bound by **pointer identity** to the `apiRateEntry` it was
  claimed in (`e != r.entry`), not merely by an age check — a new window
  allocates a new entry, so a refund crossing the boundary cannot mint capacity
  in the new window. The `count <= 0` floor and the no-op zero `Reservation`
  close the remaining two.
- **The new limiter's map is bounded.** `basicAuthFailLimiter` is keyed by
  client IP and is reachable unauthenticated through the public
  `/api/auth/status`, so a limiter whose `Cleanup` was never wired would have
  been a slow memory exhaustion introduced *by* the security fix. It is wired —
  `connlimit_startup.go:100`, inside the CHAOS-24-guarded cleanup round
  alongside `rl`, `loginLimiter` and `apiLimiter`.
- **The wall** (`TestSECBASIC1_VerifyUIUserHasNoOtherRequestPathCaller`) is
  AST-based, carries a not-vacuous guard, and its three allowances are each
  justified. Finding 2 below is the gap in one allowance's *stated reasoning*,
  not in the wall.

### 2.4 SEC-SECRETWRITE-1 (#1467) — sound, one writer short

`fileutil.AtomicWrite` is the right primitive: `os.CreateTemp(dir, base+".tmp.*")`
is random and `O_EXCL`, so no symlink can be pre-planted at the temp path, and
the final `os.Rename` replaces a link planted at the target. The CDR staging
path correctly uses `fileutil.WriteFileExclusive` instead, with the rendezvous
reasoning recorded. Sweeping **from the primitive** (as the repo's own
governance lesson requires) over every production `os.WriteFile`: all four
originally-named writers are fixed; `dp_enrollment.go` / `ha.go` matches are
comments; `cdrstore.go:465` writes an empty marker. **One real writer remained
— `enrollment.go:1118`.** See §3.1.

### 2.5 Other window items

- **#1468** on-demand backup trigger: `POST /api/backups` is
  `MinRole: RoleAdmin, Mutating, AuditExpected`; the `GET` listing is viewer and
  returns archive names, not contents. Correct posture.
- **#1448 SEC-RBAC-ROLE-1, #1429 SEC-TOTP-1, #1446 CHAOS-69, #1469 CHAOS-70,
  #1483 alert-producer bounding, #1491 installer passphrase length,
  #1493 release-gate "nothing ran" refusal**: read and cross-checked against
  their own walls; all fail closed and all carry defect-verified gates.
- **#1525** frontend lockfile refresh: transitive dependency bump only; no
  source change, and `frontend/dist` is the only embedded artifact.
- **#1501 / #1508** and the `-race` gate skips: test-only scheduling changes.
  The `CheckRequestURL` ns/op gate is skipped under `-race` (a timing gate that
  can flake gets muted — the repo's standing rule); its correctness
  differential and alloc gate still run.

---

## 3. Findings

### 3.1 MEDIUM — the cluster CA private key is backed up through a predictable path with `os.WriteFile`

**File:** `enrollment.go`, `backupCAFiles`
**CWE:** CWE-59 (link following) + CWE-732 (incorrect permission assignment) → CWE-522
**OWASP:** A01:2021 (Broken Access Control) / A04:2021 (Insecure Design)
**Severity:** Medium (Low likelihood × Critical impact)
**Regression risk of the fix:** negligible — primitive swap only

**Affected asset.** The cluster CA private key. It is Culvert's second trust
root: it signs every Data Plane node certificate, so whoever holds it can mint a
node cert, enrol as a DP and receive the full `ConfigSnapshot` — which carries
`SessionHMAC` (admin-session forgery) and the IdP secrets.

**Attack scenario.** On CA rotation or import, `backupCAFiles` writes
`<cadir>/cluster-ca.crt.bak` and `<cadir>/cluster-ca.key.bak` with
`os.WriteFile`. Both names are fixed and therefore predictable. An attacker who
can create files in the CA directory — a co-tenant process, a compromised
non-root service sharing the data volume, a container sidecar with the volume
mounted — pre-plants either:

1. a **symlink** at `cluster-ca.key.bak` pointing anywhere they can read.
   `os.WriteFile` opens `O_WRONLY|O_CREATE|O_TRUNC`, which *follows* the link, so
   the next rotation deposits the private key at the attacker's chosen path
   (and the cert half gives an arbitrary-write/clobber primitive); or
2. an **empty file at mode 0666**. `os.WriteFile`'s `perm` argument applies only
   on *creation*, so the key is written into the pre-existing file and the
   world-readable mode survives.

**Preconditions.** (a) local write access to the CA directory by another
principal; (b) a CA rotation or import occurs (unattended at −30d, per
`clusterCARenewalWindow`); (c) for the plaintext variant,
`CULVERT_CLUSTER_CA_ENCRYPT` unset — the default.

**Exploitability / likelihood.** Low — it needs a local foothold with write
access to `<dataDir>`. **Impact if reached: critical.** Note the preconditions
are *the same class* the project already accepted as in-scope when it fixed the
other four writers; this one simply fell outside the sweep's declared window.

**Fix applied.** Both `.bak` writes now use `fileutil.AtomicWrite`, which
creates a random `O_EXCL` temp beside the target, chmods and fsyncs it, then
renames over the target. The **posture is unchanged** — the plaintext branch is
still plaintext (that is the recorded CA-3 trade), and the encrypted branch
already routed through `secret.SealToFile` → `AtomicWrite`. Only the primitive
changed.

### 3.2 LOW–MEDIUM — a failed re-authentication leaves no audit record

**File:** `ui_auth.go`, `apiAuthChangePassword`
**CWE:** CWE-778 (Insufficient Logging) — enabling CWE-307 (improper restriction of authentication attempts)
**OWASP:** A09:2021 (Security Logging and Monitoring Failures)
**Severity:** Low–Medium
**Regression risk of the fix:** none — purely additive evidence; no authentication decision changes

**Attack scenario.** `POST /api/auth/change-password` re-verifies the caller's
current password before accepting a new one. By the window's own analysis
(#1420's wall) it is the only credential check in the admin API that consults
**no lockout** — a deliberate trade, because charging `loginLimiter` here would
let a session holder lock themselves out of the login flow. But it also audited
**only on success**: the `403 current password is incorrect` branch wrote
nothing. So a caller holding a stolen or hijacked session (cookie theft, XSS,
an unattended workstation, a malicious lower-privileged insider using their own
session) could guess the account's password at the mutating `apiLimiter`'s rate,
indefinitely, with **zero trace in the compliance record**.

**Why it matters when the attacker already has a session.** The password is
durable persistence that survives session revocation and TTL expiry, and may be
reused elsewhere; learning it also enables the change that locks the real
operator out. Every sibling rejection in the same file audits
(`auth.login.fail`, `auth.basic.fail`) — this one was the outlier.

**Preconditions.** A valid admin-UI session for the target account. Not
reachable unauthenticated (the handler refuses with 401 before the verifier when
`sessionAdmin(r)` is empty).

**Fix applied.** The rejection now emits
`auth.password_change.fail` with a `truncateForAudit`'d actor. The action name is
deliberately distinct from `auth.password_change.refused`, which
`refuseRosterChange` already uses for the *persistence* refusal — an operator
must be able to tell "wrong password" from "the disk failed". The lockout
trade-off is **not** changed. Not a write amplifier (CHAOS-63): the path needs a
valid session and is a `POST`, so `securityMiddleware`'s mutating-method
`apiLimiter` bounds its rate exactly as it bounds `apiAuthLogin`'s own audited
failures.

**Governance note.** #1420's wall recorded this allowance's residual as "it
consults no lockout" — accurate but incomplete, and the incompleteness is what
let the audit gap persist unnoticed. The note now enumerates *which* controls are
absent. **When recording a residual, name every control that is missing; a
reader takes the named one as the whole gap.**

### 3.3 LOW — the audit *Actor* was unbounded, product-wide (found in review of 3.2's fix)

**File:** `ui_helpers.go`, `auditActor`
**CWE:** CWE-778 / CWE-770 (allocation without limits)
**Severity:** Low
**Found by:** Codex review on PR #1532

The first version of 3.2's fix passed `truncateForAudit(username)` as the audit
**Object** and claimed in its comment that "the actor is session-derived and
still truncated". That was **false**: `auditEvent` derives the **Actor**
independently via `auditActor`, which rebuilt `name + "@" + ip` from the session
with no bound. Measured against that tree, a 300-byte configured account name
produced a **314-byte Actor**. And the gate that was supposed to catch it was
named `AuditActorIsBounded` while asserting only on `Object` — a test that reads
as if it covered the property it is named for.

**It is broader than this handler.** `auditActor`'s result is not only the audit
ring's Actor: call sites persist it into the MCP tool-trust store, policy-learning
decision records, CDR receipts, PAC lifecycle operations, support-bundle approval
state and support-recipient records. So every audited admin action by an oversize
configured account retained the full name in each of those stores. Severity stays
**Low** because the name is *configured*, not attacker-chosen — this is a
retention bound, not an unauthenticated amplifier.

**Fix:** bound it at the **chokepoint** (`auditActor`), not at the call site.
Bounding per call site is precisely what hid the defect — the call sites were
already applying `truncateForAudit` to the Object, so each one *looked* bounded.
This is CLAUDE.md's own governance lesson arriving again: **enumerate the class
from the PRIMITIVE, not from the file being edited.** The gate now asserts both
fields plus the chokepoint directly, with a control requiring an ordinary name to
pass through verbatim — the cheapest way to pass a bound is to truncate
everything, which would rewrite every audit actor in the product.

**The transferable rule:** *a comment asserting that a value is bounded is a
claim about every field the value reaches, not about the argument in front of
you — and a gate must assert the property it is named for.*

---

## 4. Regression analysis

| Change | Class | Verdict |
|---|---|---|
| `security.go` → `internal/admission` | pure motion over per-request allow/deny | **No regression** — 47/52 bodies identical, 5 differ only by global→field/name export, single-instance wiring verified, walls relocated and non-vacuous |
| process globals → per-limiter cluster state | ownership | **No regression** — one `rl`; gossip, request path, UI and metrics all read it |
| `[]RateLimitDelta` → `[]HotCount` + adapter | DTO boundary | **No regression** — nil preserved, JSON tags identical |
| `runtime_shutdown.go` → `internal/shutdown` | pure motion over durability ordering | **No regression** — bodies identical, 3s/1s defaults preserved, phase horizon intact |
| mutable timing `var`s → injected `Options` | test seam | **Improvement** (ADR-0037) |
| `verifyUIBasicAuth` chokepoint | new auth control | **Improvement** — closes 2FA/lockout/rate-limit/audit bypass |
| `fileutil.AtomicWrite` for 4 key writers | hardening | **Improvement**, one writer short (§3.1, now closed) |
| `apiAuthChangePassword` (new in window) | new credential check | **Had an evidence gap** (§3.2, now closed) |

---

## 5. Tests added

`enrollment_ca_backup_secretwrite_test.go` (7) — 3 defect gates (planted key
symlink, planted cert symlink, pre-planted 0666 file), each **verified FAILING**
against the reintroduced `os.WriteFile` shape; 4 controls (both artifacts still
written at 0600, nil key still writes the cert, a second rotation still
replaces the backup, no temp left behind), each **verified FAILING** against a
`backupCAFiles` that writes nothing — because deleting the dual-CA overlap
recovery copy is the cheapest way to pass every defect gate.

`auth_change_password_reauth_audit_test.go` (7) — 4 defect gates (the rejection
is audited; repeated failures each leave evidence; the actor is bounded per
CHAOS-63; concurrent failures are recorded, for `-race`), each **verified
FAILING** against the pre-fix branch; 3 controls (a success is not recorded as a
failure, a malformed body is not a credential failure, an unauthenticated caller
writes nothing), the first two **verified FAILING** against the obvious wrong
fix of auditing unconditionally on entry. Audit assertions scan for a
`(Actor, Action, Object, TS≥baseline)` tuple with a unique TEST-NET-2 client
address rather than comparing ring lengths — the ring is bounded at 500 and
saturates under `-count=2 -shuffle=on`.

---

## 6. Residual risk

- **The lockout residual on `/api/auth/change-password` stands** (§3.2). A
  session holder can still guess the account password at the mutating limiter's
  rate; it is now *visible*, not prevented. Preventing it needs a design
  decision about what a self-lockout should do, which is out of scope for a
  regression fix.
- **`backupCAFiles` remains best-effort and plaintext** when
  `CULVERT_CLUSTER_CA_ENCRYPT` is unset (recorded as CA-3). This review changed
  the write primitive, not that posture.
- **`AU-3e`** (the pre-existing admin-plane username-enumeration oracle reached
  by repetition, via the negative auth cache) is unchanged and still recorded.
- **`enrollment.go`'s `.crt.bak`** write is now atomic, but the CA directory's
  own permissions remain the primary control; nothing here substitutes for
  `<dataDir>` not being writable by other principals.
- The admission/shutdown extractions are verified faithful **as motion**. They
  did not re-derive the underlying engines, so every pre-existing open register
  row for those engines (PX-6 — the front-door limiters still ship disabled;
  `pollConfig`'s double `failCount` increment; HA-1's config-staleness posture)
  is untouched and still open.
