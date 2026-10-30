# Security Regression Review — 2026-10-29

**Scope.** `f31744c…7262622` (`origin/main`) — the 24 h since the 2026-10-28
review, 7 merged pull requests (#1746 #1747 #1748 #1749 #1750 #1751 #1752),
32 files, +3,527/−42.

| PR | Change | Security surface |
|---|---|---|
| **#1748 / #1749** | CHAOS-103 — a single-writer lock on `/data`, and the first-run bootstrap window decided from the DURABLE roster | authentication, authorization, startup, persistence |
| **#1751** | `decryptprofile.Store` gains a stable-ID index so the per-stream resolve is O(1) | proxy, TLS inspection, policy |
| **#1746** | `install.sh` no longer replaces an at-rest passphrase it could not read | secrets, crypto at rest |
| **#1747** | An operator-contract row for failing alert delivery | admin control plane, information disclosure |
| **#1750** | `benchgate` extended to `internal/decryptprofile`; verification doc follows | CI gate |
| **#1752** | `go-jose/v4` 4.1.4 → 4.1.6 (indirect) | crypto, supply chain |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed 24 h ago?** Every finding is measured against the base
revision, not against an ideal.

**Method.** Each change read through its production callers rather than its diff
hunks. The bootstrap-window derivation was executed against the real
`loadUIUsersFile` as a differential oracle rather than reasoned about; the
`decryptprofile` index was traced to every mutation path and every `Store`
construction path; the writer lock was read against its position in `main`. The
one finding that survived the disproof pass was then **proved end to end** — an
unauthenticated request driven through the real `uiAuthMiddleware` and the real
`requireRole(RoleAdmin)` door — because a predicate is only interesting through
the door it opens.

---

## 1. Executive Summary

**No security regression was introduced in this window.** The CHAOS-103 work is
a substantial net improvement to exactly the surface it targets.

The review did, however, find a **confirmed unauthenticated administrative
bypass** on the surface CHAOS-103 was built to protect. It is **not** a
regression — it predates this window — but it is in the same class CHAOS-103
closed, it defeats CHAOS-103's new durable backstop, and the new backstop
reproduced it faithfully, so the control shipped this window with a hole in the
class it exists to cover. It is fixed and gated here.

| # | Finding | Severity | Status |
|---|---|---|---|
| **S-1** | A roster holding accounts but **no present admin** reopens the unauthenticated first-run bootstrap window. `loadedRosterRole`'s least-privilege clamp and a legacy pre-RBAC roster both reach that state with no prior authority. Proved end to end: anonymous `GET /api/auth/users` → **200 with `RoleAdmin`** | **HIGH** (pre-existing; auth bypass. Not a regression — the new durable backstop mirrored it) | **FIXED + gated** |
| **S-2** | CHAOS-103 made the public, unauthenticated `/api/setup/status` do a roster-file read **and a JSON parse per request** while the window is open | LOW (introduced this window; bounded, operator-controlled input) | Reported — see the note on why a size cap is the wrong fix |
| **R-1** | `AuthEnabled()` carries the same `c.user`-only shape as S-1. In the clamped-roster state it answers **false**, which selects the SOCKS5 **no-auth** method and makes `sseAuthStillValid` return true unconditionally | MEDIUM (pre-existing; different domain) | Reported here; the owner later approved a fix, now landed as `SEC-AUTHENABLED-1`, covering SOCKS5, SSE and the HTTP proxy (see the R-1 update in §2) |

Surfaces reviewed and found **clean**: the `/data` single-writer lock (verdict
semantics, platform degradation, position in `main`), the bootstrap-window
derivation's one-directional safety property, the `decryptprofile` stable-ID
index (every mutation path and the single `Store` construction path), the alert
delivery diagnostics row (counts only, no name/URL/error text; `globalAlertStore`
is eagerly non-nil), the `install.sh` unreadable-`.env` guard, and the CI /
dependency surface — **no gate was weakened**: `benchgate` gained a package,
`go-jose/v4` moved forward, and no `.golangci.yml`, `Makefile`, `Dockerfile` or
`GOTOOLCHAIN` change exists in this window.

---

## 2. Security Findings

### S-1 (HIGH, pre-existing) — a roster with no present admin reopens the unauthenticated bootstrap window

`SEC-SETUPANCHOR-1`. **Fixed and gated in this change.**

`uiAuthMiddleware` ([ui_middleware.go](../../ui_middleware.go)) injects
`RoleAdmin` into **every unauthenticated request** while the first-run bootstrap
window is open — the documented behaviour that makes a brand-new install
reachable before an admin account exists. CHAOS-103 correctly moved that gate
behind `bootstrapWindowOpen()`, which asks `cfg.IsConfigured()` first and the
durable roster second.

`IsConfigured()` ([store.go](../../store.go)) anchored on four terms, of which
the only roster-derived one is `c.user != ""`. `loadUIUsersFile` sets `c.user`
**only** from a record whose EFFECTIVE role — after the loader's clamp — is
admin:

```go
if rec.Role == RoleAdmin && c.user == "" {
	c.user = rec.Username
	c.passHash = hash
}
```

So a roster that *plainly records a completed setup* leaves every term false,
and the appliance reopens its first-run window as a fully anonymous admin
control plane.

**Attack scenario.** Two routes reach that state, **neither requiring any prior
authority on the target**:

1. **The least-privilege clamp.** `loadedRosterRole` clamps a role this build
   does not enroll to `RoleViewer` — deliberately, to fail CLOSED against the
   role-based privilege escalation its own doc comment describes. Its recorded
   reachable source is "a restore of a backup taken by a newer build that
   enrolls a role this one does not (the downgrade case)". When the roster's
   only admin is the clamped record, the clamp removes the last admin, and with
   it the setup anchor. **A control written to fail closed is what opens the
   door** — the clamp did exactly its job, and the composition inverted the
   result.
2. **A legacy pre-RBAC roster.** An empty `role` is never equal to `RoleAdmin`,
   and `loadedRosterRole` deliberately preserves it. Such an account signs in
   and is promoted to admin by the middleware's own "sessions without role =
   admin" compat branch — so the deployment is configured and functioning, and
   served an anonymous admin plane on **every boot**.

CHAOS-103's durable backstop did not help: `rosterBytesConfigure` mirrored the
clamp through `effectiveRosterRoleQuiet` and so agreed with the in-memory
predicate **precisely where that predicate was wrong**. The existing
differential oracle did not catch it either, because it asserts only the
one-directional property (`anchor ⇒ loader configured`) and logged both the
viewer-only and unenrolled-role cases as `KNOWN CONSERVATIVE` — safe for the
*mirror*, while the *loader* was the thing that was wrong.

**Preconditions.** A local-roster deployment: no IdP provider wired
(`c.provider == nil`), the global default not `Exempt`, and no legacy-LDAP
retirement sentinel — any one of those independently anchors setup. Reachable
over whatever network can reach the admin UI.

**Exploitability.** Trivial, unauthenticated, no race and no special tooling:
one HTTP request. **Confirmed end to end** against the real middleware chain,
not inferred — anonymous `GET /api/auth/users` returned **200** with
`RoleAdmin` injected and `requireRole(w, r, RoleAdmin)` **ALLOWED**.

**Likelihood.** Moderate for route 1 (a downgrade restore is an ordinary
recovery action, and the state is silent — the appliance keeps serving); higher
than it looks for route 2, where it is the steady state of any surviving
pre-RBAC roster.

**Impact.** Complete administrative compromise of a configured gateway:
`POST /api/setup/complete` replaces the roster wholesale, policy and SSL-bypass
writes land on the live volume, and the config-version series is writable. The
same anonymous authority CHAOS-103 documented and measured for the second-process
case, reached here on a *single*, ordinary process.

**Affected assets.** The admin roster, policy and SSL-bypass rules, admin
settings, the config-version series, and every secret the admin API can read
back or rotate.

**Recommended fix / safe implementation (applied).** Any **admitted** roster
account is a setup anchor, independent of its role, on **both** sides:

- `IsConfigured()` gains a `len(c.uiUsers) > 0` term.
- `rosterBytesConfigure()` drops the role term, counting any record the loader
  admits (its hash decodes as hex — the loader's own admission test). The
  username term went with it: the loader keys `c.uiUsers` by whatever username a
  record carries, the empty string included, so requiring a non-empty one would
  have diverged in the direction that leaves the window **OPEN**.

Setup created the roster; a roster with no usable admin is a **LOCKOUT** for the
`--reset-password` break-glass to repair — which the `admin_roster_durability`
diagnostics row already exists to name — never grounds to grant authority to
callers who hold none. The new term only ever makes the predicate MORE true, so
it can only **CLOSE** the window, never open one.

The first-run and rollback paths are untouched because both carry an **empty**
roster: a quarantined corrupt roster (CHAOS-05) still loads none, and
`SetAuthDurably`'s compensation restores "no accounts, empty legacy pair".
Over-closing was the real risk here and it is held by five negative controls.

**Required tests (all present).**
[setup_anchor_roster_test.go](../../setup_anchor_roster_test.go) — the anonymous
cases drive **real requests** through `uiAuthMiddleware` and `requireRole`
rather than asserting the predicate:

| Test | Class |
|---|---|
| `ClampedAdminDoesNotReopenTheWindow` | authorization / authentication, regression |
| `LegacyEmptyRoleDoesNotReopenTheWindow` | authentication, backward compatibility |
| `ViewerOnlyRosterClosesTheDurableWindow` | the CHAOS-103 second-process path |
| `NegativeControls` (5 cases) | negative, malformed input, boundary |
| `RollbackKeepsTheWizardRetryable` | feature interaction (real snapshot/restore path) |
| `ConcurrentReadersAgree` | concurrency (`-race`) |
| `HexBoundary`, `EmptyUsernameRecordAnchorsLikeTheLoader` | boundary, loader parity |

**CWE.** CWE-288 (authentication bypass using an alternate path), with
CWE-305 (authentication bypass by primary weakness) and CWE-863 (incorrect
authorization). **OWASP.** A01:2021 Broken Access Control; A07:2021
Identification and Authentication Failures.

**Regression risk of the fix.** Low, and measured: the full root suite is green,
a shuffled all-package run is green, and the pinned gate linter reports **zero**
new issues (identical per-file counts against the base, complexity linters
included).

**One consequence worth recording.** The new term made a long-standing test
idiom observably incomplete. `cfg.SetAuth("", "")` was how ~41 test sites
expressed "no auth configured", and it clears only the legacy pair — correctly,
since clearing a credential must never delete admin accounts. Because `cfg` is
process-global and shared, a test that seeded an account without restoring it
left it visible to every later test, and 15 setup/auth-disabled tests then read
that leaked account as a configured appliance. Each of the 15 **passes in
isolation**, which is what identified the cause as leakage rather than a
behaviour change. `clearLocalAuthForTest` is the complete form **and** restores
what it found, so the leak is fixed rather than tolerated.

### S-2 (LOW, introduced this window) — the public setup-status route now reads and parses the roster file per request

`apiSetupStatus` is on `isPublicUIAuthPath`'s allowlist (`/api/setup*`), so it
is reachable with no credentials by design. CHAOS-103 changed its answer from
pure in-memory state to `bootstrapWindowOpen()`, which — while the window is
open — calls `durableSetupComplete()`, and that does an `os.ReadFile` plus a
`json.Unmarshal` of the whole roster **on every request**. The positive verdict
latches (`durableSetupAnchorSeen`), but the **negative** one deliberately does
not, so the read repeats for as long as the window stays open.

**Attack scenario.** An unauthenticated client loops `GET /api/setup/status`,
driving one file read and one full-roster JSON parse per request.

**Preconditions.** The window must be open. After S-1's fix the interesting case
narrows to a **corrupt** roster: `rosterBytesConfigure` returns false, the latch
never closes, and CHAOS-05 keeps the appliance serving in exactly that state. A
genuinely fresh install reads a missing file (cheap `ENOENT`).

**Exploitability / likelihood / impact.** Low on all three: no amplification
beyond disk read speed, the file's size is operator-controlled rather than
attacker-controlled, and the pre-existing admin-plane rate limiting applies. It
is recorded because it is a *new* unauthenticated I/O path, not because it is
dangerous today.

**Recommended fix — and a warning about the obvious one.** Do **not** bound the
read with a size cap. A truncated read fails `rosterBytesConfigure`, which
returns false, which leaves the bootstrap window **OPEN** — a size cap on this
path fails *open*, converting a cheap DoS into S-1. The safe shape is a small
time-based throttle on the **negative** verdict (re-read at most once per ~1 s),
which caps the repetition while delaying window closure by at most that
interval. Not applied here: it is a performance change on an
authentication-critical path, outside this change's scope, and it belongs to the
CHAOS-103 owner.

**CWE.** CWE-400 (uncontrolled resource consumption). **OWASP.** A04:2021
Insecure Design.

---

## 3. Residual Risk

**R-1 (MEDIUM, pre-existing, deliberately not changed).** `AuthEnabled()` is
`c.user != "" || c.provider != nil` — the same `c.user`-only shape as S-1,
without the Exempt and retirement terms. In the clamped-roster state it answers
**false**, and that was verified, not inferred:

- [socks5.go](../../socks5.go) — `if !cfg.AuthEnabled()` selects the SOCKS5
  **no-auth** method (`0x05 0x00`), so SOCKS5 proxy authentication is off.
- [events.go](../../events.go) — `sseAuthStillValid` returns true
  unconditionally, so a revoked or expired session keeps receiving live
  telemetry mid-stream.

A downgrade restore therefore silently disables SOCKS5 proxy auth as well as
opening the admin plane. `len(c.uiUsers) > 0` would be semantically right here
too — roster accounts *are* an active authentication backend, which
`VerifyUIUser` checks first. It is **not** changed here for three reasons:
it is a different domain with its own recorded Slice-5 decoupling history; the
change would turn SOCKS5 auth **on** for any deployment currently relying on
that fail-open, which is a live traffic-breaking behaviour change rather than a
test-visible one; and "fail-open/fail-closed is domain-specific, not a slogan".
It is the top item for owner decision. (Noted in passing: `AuthEnabled`'s doc
comment still describes an `OutcomeExempt` term its body no longer has.)

**R-1 update (2026-10-30): fixed as `SEC-AUTHENABLED-1`, with owner approval.**
`AuthEnabled()` now includes the `len(c.uiUsers) > 0` term, so SOCKS5 requires
USERPASS and the SSE re-check runs. `verifyAuthFrom`'s empty-backend sentinel
reads the same term and now refuses. Without that change, requiring USERPASS
would have accepted any credential. In the clamped or legacy state, SOCKS5
therefore refuses every client until `--reset-password` restores an admin.
That is the traffic-breaking change described above, which the owner accepted.
The stale doc comment is corrected.

The HTTP proxy had the same gap. `resolveRequestAuth` armed Stage-1 only for a
credential-capable or SSO backend, so this state passed unauthenticated under
the Default outcome. It is now covered: a roster with accounts but no verifier
arms the gate and is excluded from the no-backend inert guard. The Default
outcome therefore answers with the existing 407 challenge. Exempt outcomes are
unchanged. See the CHANGELOG entry and `auth_enabled_roster_test.go`.

**Other residual items.**

- `rosterBytesConfigure` anchors only on the roster **file**. A deployment whose
  sole setup anchor is an IdP provider or the legacy-LDAP sentinel still has no
  durable term, so CHAOS-103's backstop does not cover the second-process case
  there. Pre-existing and documented as a degradation; the writer lock is the
  class fix.
- `CULVERT_ALLOW_MULTIPLE_WRITERS=1` is a genuine escape hatch. With S-1 fixed,
  the durable backstop now holds for a clamped or legacy roster when it is used.
- The lock file is opened `O_CREATE|O_RDWR` without `O_NOFOLLOW`. An attacker who
  can plant a symlink in `/data` can make the process `flock` an arbitrary file;
  nothing is written through the descriptor, and such an attacker already owns
  the state plane. Noted, not a finding.
- `go-jose/v3` v3.0.5 remains in the module graph alongside the bumped v4.

---

## 4. Verification

Toolchain from [go.mod](../../go.mod) (`toolchain go1.27.3`); linter from the
blocking gate ([pr-fast-gate.yml](../../.github/workflows/pr-fast-gate.yml),
`v2.15.0`), built with that toolchain, **not** the container's `PATH` copy.

| Check | Command | Result |
|---|---|---|
| Build | `go build ./...` | pass |
| Root suite | `go test -count=1 -timeout=40m .` | **pass** (566 s) |
| All packages, shuffled | `go test -count=1 -shuffle=on ./...` | **pass** |
| New gates under race | `go test -race -run 'TestSetupAnchor_' .` | pass |
| Gate lint (blocking form) | `golangci-lint run --new-from-rev origin/main` | **0 issues** |
| Full-tree lint vs base | `golangci-lint run` on branch and on `origin/main` | **175 = 175**, identical per-linter counts; identical per-file counts for every file touched |
| Guidance checker | `python3 docs/agent-context/check.py` | pass |

The 15 pre-existing tests that surfaced the leaked-roster idiom were each run
**in isolation** before being touched, to establish that the cause was
cross-test state and not a behaviour change.

**Not run, and why.** `benchgate`, the chaos-tagged suites and the hosted
QA/CodeQL gates: no allocation-, concurrency- or feed-shaped behaviour changed
here, and a passing local check is not a passing hosted gate. The `decryptprofile`
index was reviewed and its package suite run, but its new `benchgate` arm is
hardware-sensitive and belongs to CI.
