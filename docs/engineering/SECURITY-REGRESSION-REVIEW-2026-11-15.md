# Security Regression Review — 2026-11-15

**Scope.** `feb11e8…0b11474` (`origin/main`) — the window since the 2026-11-13
review, 14 merged pull requests (#1855 #1883 #1884 #1885 #1886 #1887 #1888 #1889
#1890 #1891 #1892 #1894 #1896 #1897), 59 files, +6,049/−181. No review ran on
2026-11-14, so this window covers two days.

| PR | Change | Security surface |
|---|---|---|
| **#1883** | `fix(auth)`: SEC-UISESS-DEMOTE-1 — the roster role becomes a **ceiling** on every request, so a demotion takes effect on sessions already held instead of at their expiry. New `Config.UIUserRole` | **admin-plane authorization**; a live privilege-reduction control is new attack surface in both directions (it must not elevate, and it must not lock out the pre-RBAC compat case) |
| **#1892 / IM-007 / ADR-0045** | `refactor`: the trusted-proxy set and the X-Forwarded-For walk move to `internal/realclientip`; main keeps one application instance and thin wrappers | **client-IP spoofing** — the value feeds the admin-UI per-IP lockout, the rate-limit key and every audit line (RISK-019) |
| **#1887** | `fix(install)`: `env_put` takes its LOCK file and staging file the same way it already took `.env`, so a re-run against a stack dir owned by another user no longer aborts | **privileged installer file handling**; `.env` holds the stack's secrets. **Finding A is here** |
| **#1855** | `feat(contracts)`: the product-contracts registry, `cmd/contractcheck`, and a `pull_request_target` gate. The gate is **fully automated** — the approver list, `Review/Approved` and the PR's own CODEOWNERS additions were removed | **CI/supply chain** — a `pull_request_target` workflow is the classic poisoned-pipeline target, and a review control was deliberately retired |
| **#1890 / CHAOS-119** | Crash-plane reporting for five background rounds (release catalog refresh + stale watchdog, SaaS feed refresh, HA leadership resume, CP-address publish retry); per-stage panic guards on the MCP telemetry **shutdown** drain; `maxCrashLabels` 32 → 128 | **unsafe panic recovery / fail-closed integrity**, and a cardinality cap whose whole purpose is bounding attacker-shaped labels |
| **#1886 / #1896** | Diagnostics rows for an unreachable ClamAV daemon and a failing OTLP export | **fail-open visibility** and **information disclosure** — both rows are readable by the `viewer` role |
| **#1889** | The 2026-11-13 review itself, plus `fix(enroll)`: the dropped-record re-enrollment alert detail now names the node, so a fleet-wide batch is not collapsed to one dedup key; `sanitizeLog` applied before the detail is built | **alert-plane dedup cardinality** (client-supplied node ID) and **CWE-117** in an audit record and a webhook body |
| **#1897** | `fix(install)`: register Docker's repo with dnf5's `addrepo` on Fedora 41+ | **package-source trust** on a privileged installer path |
| **#1888** | `test(bench)`: the HTTP forward benchmark stops charging a 32 KiB buffer production never allocates; new `proxy_http_readerfrom_test.go` | measurement and a pinned production property — **no production proxy change** (`proxy.go` is byte-identical across the window) |
| **#1884 / #1885 / #1891 / #1894** | Terminology (`enrolment` → `enrollment`) in operator text and tests, the cluster-state-recovery runbook, one test-isolation fix, and the 2026-11-14 terminology governance record | operator remediation accuracy and test hygiene (no runtime behavior) |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed at `feb11e8`?** Every verdict below is measured against
that revision, not against an ideal.

**Method.** This window's weight sits on three claims, each of the shape "a
security control's shape changed but its decision did not". A claim like that is
only worth what the invariant behind it is worth, so each was checked against
the invariant rather than against its commit message, and **the two load-bearing
assertions in commit comments were re-derived from source rather than accepted**:

- *"Culvert has no dynamic crash labels"* — the premise of the `maxCrashLabels`
  32 → 128 raise. Enumerated every `component` argument reaching `recordCrash`
  and the `runGuarded*` family: all are compile-time constants or string
  literals (`crashComponent*`, `dpComponent*`, `ha*Component`, and six
  literals), and `crashThrottleAllow` keys the map on `component` **alone** —
  the client-supplied `X-Request-ID` correlation id is not part of the key. The
  cap therefore bounds a fixed set, and raising it cannot grow a
  request-shaped map. The raise also **corrects an inverted failure**: the
  counter folds an overflowing label into `other`, but `crashThrottleAllow`
  *suppresses* the record, log line and audit entry entirely, and slots are
  first-crash-wins and never pruned — so the 32 went to the frequent
  request-path components and the rare high-severity background rounds lost
  their evidence. Not a regression; a reporting fix.
- *"the alert dedup key is `event + ":" + Detail`, so a constant detail
  collapses a fleet-wide batch"* — confirmed at `internal/alerts/store.go:668`.
  The obvious counter-question is whether making the key **per-node** lets a
  client-supplied `NodeID` mint unbounded dedup keys. It cannot: the map is
  hard-capped by `maxDedupEntries` with a counted eviction path (CHAOS-27), and
  the row is reachable only when `NodeRecordWasDropped(nodeID)` already holds —
  the node ID must match a record this process dropped — behind a single-use
  token. Cardinality is bounded by the drop set, not by the caller.

The installer change is the one that did **not** survive its invariant, and the
finding below was **reproduced in a failing test before being fixed**. The
reproduction itself was then **mutation-checked twice**: a first version of the
harness passed with the fix reverted (its `sudo` stub runs with the test's own
dropped privileges, so it could not carry out the root action whose absence it
claimed to prove), and the tests were restructured to assert effects that are
real at the privilege the test actually has. Gates run at this SHA are listed
under *Verification*.

**One finding — Medium, in `scripts/install.sh`, fixed here.** No security
regression in the session role ceiling, the client-IP extraction, the crash
plane, the contracts gate, the diagnostics rows or the enrollment alert. Five
residual risks recorded, two of them pre-existing and deliberately left alone.

---

## Finding A — `env_put` follows a link planted at its lock path (Medium)

**File.** [`scripts/install.sh`](../../scripts/install.sh), `env_put()`, the
lock-ownership block added by #1887.

**What it is.** `env_put` serializes its read/modify/write transaction on
`"$file.lock"` (`.env.lock`, beside the stack's `.env`). Three users of that
path all follow symlinks, and #1887 added the two privileged ones:

```sh
if [[ -e "$lock" && ! -w "$lock" ]]; then
  sudo chown "$(id -un)" "$lock" 2>/dev/null || true
elif [[ ! -e "$lock" && ! -w "$dir" ]]; then
  sudo touch "$lock" 2>/dev/null && sudo chown "$(id -un)" "$lock" 2>/dev/null || true
fi
...
) 9>"$file.lock"
```

`sudo touch` **creates** the link's target as root; `sudo chown` hands it to the
invoking sudoer; and the pre-existing `9>"$file.lock"` redirection **truncates**
whatever the link points at, with the invoker's own privileges, on every call.

**Why `.env.lock` is the sharp path, and why this is a regression rather than a
restatement.** The block is a deliberate clone of the one above it, which does
the same two `sudo` calls on `$file` itself — so the *class* is pre-existing.
What is new is where it now points. `.env` **exists** after a first install, so
`[[ ! -e "$file" ]]` is false and the `sudo touch` creation branch is
effectively dead on a re-run. `.env.lock` normally does **not** exist, so on the
first `env_put` after an upgrade to this version the creation branch is live —
the strongest of the three primitives (create an arbitrary path as root, then
own it) became reachable on an ordinary upgrade. `-e` is **false** for a
dangling symlink, so neither existing condition can even see that case.

**Attack scenario.**

1. A deployment keeps its stack directory writable by an account that is not the
   operator's — a group-writable `/srv/culvert` shared by several operators, or
   a dir left owned by the non-root account that ran the first install. This is
   not a hypothetical topology: it is precisely the one #1887 was written to
   support ("a stack dir that belongs to another user").
2. That account plants `/srv/culvert/.env.lock` as a symlink to
   `/etc/sudoers.d/zz-local` (absent).
3. An operator with sudo re-runs `install.sh` — a routine upgrade. `env_put` is
   called unconditionally at top level (`env_put CULVERT_INSTALL_CHANNEL …`).
4. The stack dir is not writable by the operator, `-e "$lock"` is false for the
   dangling link, so `sudo touch "$lock"` **creates `/etc/sudoers.d/zz-local` as
   root** and `sudo chown <operator>` makes it writable by the operator — hence
   by anything running as the operator.

The lower-privilege variant needs no sudo and no unusual ownership at all: point
the link at a file the *operator* can write (their `~/.ssh/authorized_keys`,
their crontab) and the `9>` redirection truncates it on the next run.

**Preconditions.** Write access to the directory holding `.env` by an account
other than the one running the installer, and that operator re-running
`install.sh` with sudo. No network access and no Culvert credentials are
required.

How reachable that directory is depends on how the stack was sited.
`INSTALL_DIR="${CULVERT_DIR:-/srv/culvert}"`: the **default** is
`/srv/culvert`, which a sudo or cloud-init first install leaves root-owned
`0755` — not plantable, and the strongest mitigation here. But `CULVERT_DIR`
accepts a **relative** override (the script canonicalizes it with `cd`, and its
own comment names `"culvert-stack"` as an example), which resolves under the
operator's `$PWD` — a home or shared working directory. And the foreign-owned
case this whole block was written for is, by construction, a stack directory
that belongs to **another account**. So the topology is not the default, but it
is one the script explicitly supports and one of its two supported shapes puts
the planting account and the sudo-capable account on the same directory.

**Exploitability.** Low complexity — one `ln -s`, then wait for a routine
upgrade. **Likelihood:** low; it needs a multi-user or group-writable
deployment directory, which is a real but not default topology.
**Impact:** high where it applies — arbitrary root-owned file creation handed to
the invoking sudoer is a local root path; the unprivileged variant is arbitrary
file truncation. **Affected assets:** the appliance host's filesystem integrity,
the operator account, and `.env` itself (the stack's secrets).

**Severity: Medium.** High impact, low likelihood, narrow precondition.
**Regression risk of the fix: low** — it adds a refusal on a path that has no
legitimate non-regular form, and the one code path it sits in front of is
covered by its own existing test.

**CWE-59** (improper link resolution before file access), **CWE-61** (UNIX
symlink following); contributing **CWE-367** (TOCTOU) for the residual noted
below. **OWASP:** A01 Broken Access Control (local privilege boundary); A04
Insecure Design for the clone-without-re-deriving-the-threat pattern.

**Fix (applied).** Refuse a lock path that is a symlink or any non-regular
file, and degrade through the warn-and-skip path `env_put` already has for
"ownership could not be taken" — so the installer does not abort under
`set -euo pipefail`:

```sh
if [[ -L "$lock" || ( -e "$lock" && ! -f "$lock" ) ]]; then
  warn "Refusing to use $lock: it is a symlink or not a regular file — leaving $file unchanged."
  ...
  return 0
fi
```

`-L` is the only test that sees a dangling link. Non-regular files are refused
too, not only links: a planted FIFO at the lock path makes `9>` block forever,
which **wedges** the installer rather than aborting it — a worse failure than
the one #1887 fixed, and one the mutation run reproduced (the suite hung until
its global timeout).

**What the fix deliberately does NOT change.** The identical `sudo chown` /
`sudo touch` pair on **`$file`** is left exactly as it is. Refusing a symlinked
`.env` would be a functional regression: operators do legitimately symlink an
env file into a shared or mounted location, and nothing in this window changed
that path. It is recorded as residual risk R1 instead. Narrowing a pre-existing
behavior that this window did not touch is outside this review's scope, and
"fail closed" does not license breaking a supported deployment to do it.

**Safe implementation note.** The guard closes the *planted-link* case, not a
same-instant swap between the test and the `sudo touch` — the shell cannot open
with `O_NOFOLLOW`. That residual is stated in the code comment rather than
papered over; planting still requires write access to the stack dir, so the race
is strictly harder than the condition the guard removes.

**Required tests (added).**
[`install_script_env_put_lock_symlink_test.go`](../../install_script_env_put_lock_symlink_test.go)

| Test | Kind | Asserts |
|---|---|---|
| `…_LockSymlink_TruncatesNothing` | negative / malformed input | a planted link to a victim file keeps its contents; **no sudo call** belongs on this path (writable stack dir) |
| `…_DanglingLockSymlink_IsNeverHandedToSudo` | privilege / boundary | the dangling-link path is never passed to `sudo`, and the target is not created |
| `…_LockFifo_DoesNotHang` | malformed input / availability | a FIFO at the lock path is refused, not opened |
| `…_RegularLockFileStillApplies` | **positive control** | the foreign-owned re-run the block exists to serve still applies the value and keeps unrelated lines |
| `…_ForeignOwnedStackDir_DoesNotAbortReRun` (existing, #1887) | regression | unchanged and still passing — the guard did not re-break what #1887 fixed |

The concurrency contract is covered by the two pre-existing
`…_Concurrent*` tests (lost update, duplicate, deadlock), both re-run and
passing: the guard sits before the lock is taken and does not alter the
transaction.

**Mutation evidence.** With the guard neutralized (`if false; then`), all three
hazard tests fail — truncation observed, the link observed being handed to
`sudo`, and the FIFO case reported as `WEDGED` after its 20 s budget — while the
positive control passes in **both** states, which is what shows the guard
refuses links rather than refusing the supported topology.

---

## Reviewed, no regression

**SEC-UISESS-DEMOTE-1 (#1883) — the roster ceiling cannot elevate, and cannot
lock out the compat case.** The new code is `if !rosterRole.HasRole(role) { role
= rosterRole }`. Replacement happens **only** when the roster role does *not*
dominate the cookie's, so the effective role is `min(cookie, roster)` over a
total order (`rolePriority` viewer<operator<admin) and is bounded above by the
roster in every branch — the roster is a ceiling, never a source, as the comment
claims. Three further questions were traced rather than assumed:

- *Does the pre-RBAC compat case still work?* Yes, and comparing the raw roster
  value would have broken it. `loadedRosterRole` keeps an empty persisted role
  **verbatim**, and `sessionRoleOrReject("")` resolves it to `RoleAdmin`;
  putting the roster value through the *same* resolver is what stops every
  legacy single-admin deployment being capped at viewer. `UIUserRole` returns
  the **clamped** `role` field, not `persistedRole`, so a downgrade-clamped
  record caps at viewer as it should.
- *Is the legacy single user locked out?* No. The pre-existing
  `cfg.UIUserExists(sess.Sub)` check already refuses any session whose subject
  is absent from the roster, so the new `!exists → uiSessionRefused` branch adds
  no new refusal; it only closes the gap between the two roster reads.
- *Is the ceiling applied everywhere a role is derived?* The only role
  resolvers are `resolveUISession` (used by `uiAuthMiddleware` and
  `apiAuthStatus`) and `classifyUISession` (used by `sseAuthStillValid`), and
  all three now go through it. `events.go:174` **discards** the capped role
  (`_, verdict :=`), which looks like a gap and is not: `apiEvents` gates on
  `RoleViewer`, viewer is the floor of the hierarchy, and the SSE payload is the
  same dashboard struct for every role — so a demotion cannot reduce a
  live stream below what it already required. `ui_mcp_tooltrust.go` uses the
  token-class half only, deliberately and by its own comment.

**`internal/realclientip` (#1892 / IM-007, ADR-0045) — the moved logic is the same
decision.** Compared the extracted package against the deleted root code
line by line: the empty-trust-set short-circuit, the "peer must itself be
trusted" gate, `Header.Values` joining **all** X-Forwarded-For field lines (the
Codex P1 spoof fix), the right-to-left walk, skipping malformed hops rather than
trusting them, returning `ip.String()` canonical form so two spellings cannot
fork the lockout key (review F2), and the all-hops-trusted fallback to the peer
are all preserved, in order, with the same comparisons. `SetTrustedProxies`
still validates every entry **before** taking the lock, so a bad entry mutates
nothing. Concurrency is unchanged (`sync.RWMutex`, published slice read under
`RLock` and replaced wholesale, never mutated in place).

The extraction's own risk is **divergence**, so that was checked directly: there
is exactly **one** `realclientip.Resolver` in the tree
(`realclientip.go:23`), no caller constructs a second one with an empty trust
set, and no copy of `parseIPOrCIDR` / `ipInNets` / `peerHost` survives in main.
`config_surfaces.go` was updated to name the new owner (`clientIPResolver`), so
the admin-durable persistence row still points at the real owner.

**The product-contracts gate (#1855) — a correctly built
`pull_request_target`.** This is the window's highest-leverage CI change and the
shape most often got wrong. It is right here: the **workflow and the checker are
taken from the base branch** (checked out at the workspace root), the PR tree is
checked out to `./pr` and only ever read, `./.github/actions/setup-go-cache` and
`go build ./cmd/contractcheck` both resolve against the **base** tree, and both
checkouts set `persist-credentials: false` with `permissions: contents: read`
(the `pull-requests: read` scope was dropped with the approver logic). Nothing
from `./pr` is built or executed — verified in the checker, not just in the
comment: `cmd/contractcheck/main.go` shells out only to a fixed `git` binary
with a fixed `registryPath` and a CI-supplied `-base HEAD^1`, and otherwise only
parses. A `.gitattributes` or `diff.external` in the PR tree cannot hijack those
`git` calls, because both require git **config**, which the PR does not control.
`timeout-minutes: 10` bounds a parsing DoS.

The retired **approval** control is an explicit owner decision, recorded in the
commit as such, and the PR **reverted its own CODEOWNERS additions** — the file
is identical to main, so no pre-existing review control was weakened. The gate is
self-certifying by design (a weakening passes once the same PR adds an
`amended`/`retired` record); recorded as R3, not as a finding, because the
posture before the gate existed was *nothing*, which is strictly weaker.

**CHAOS-119 panic guards (#1890) — the fail-closed direction was chosen each
time.** The 2026-11-13 review established the rule that matters: a guard wrapped
around a section that releases a mutex with a **trailing** `Unlock` converts a
loud crash into a silent permanent lock wedge, which is a regression, not a fix.
Each new guard was checked against it.

- `Refresher.RunTicker` now wraps the round in `runGuarded`. `Refresh()` takes
  its single-flight flag through `begin()` and releases it with **`defer
  r.end()`**, so a panic in `refreshFromSource` cannot leave `inflight` latched;
  `Meta`, `Staleness` and `begin` all use `defer`. The remaining trailing
  `Unlock`s (`end`, `recordAttempt`, `recordError`, `recordSuccess`) guard only
  field assignments. The loop also has **no production caller** today, so the
  guard changes no current behavior and removes a trap.
- The MCP telemetry **shutdown** drain is the subtle one, and the per-stage
  choice is correct. A single guard around the whole sequence would have let a
  fault in the force-flush or in one partition's drain skip `mgr.Close()` — the
  durability-critical step. Each stage is guarded separately, `closeErr` is
  **never** reported as clean when a drain panicked, and `done <- closeErr` runs
  on every path, so a panicking stage cannot leave the shutdown hook waiting out
  its whole budget. The CHAOS-105 "don't recover the whole worker" objection
  genuinely does not apply: this is a one-shot terminating sequence, not a loop
  that must keep ticking.
- `retryCPAddrPublish` keeps its worker-level recover deliberately (its exit
  contract is to clear `retrying` so a later failure can start a fresh loop) and
  only adds `recordCrash`. `retryLeadershipResume` and the SaaS feed tick are
  reporting-only additions over containment that already existed.

**The two diagnostics rows (#1886 / #1896) — disclosure was minimized
deliberately.** Both rows are readable by `viewer`, and both are written as
**fixed strings**: the OTLP row names the failing signal only and never the
endpoint (which may embed a token), the auth header or the raw error text; the
ClamAV row carries a counter but leaves the probe error — which names the
daemon's internal address — on the role-gated Security Scanning panel. Neither
changes scanning, readiness, push, retry or fail-open behavior. Both are
appended to `buildOperatorContract`, whose route keeps its existing
handler-level `requireRole`.

The ClamAV row's `strings.HasPrefix(ClamAVStatus(), "unreachable")` is the only
textual coupling of its kind in the tree (every other consumer collapses
non-`connected`/non-`disabled` to unreachable), so it was checked for a
fail-silent gap. It does not have one worth a finding: the value space is
`disabled` / `connected` / `unreachable: …` / `clamStatusUnknown`, the row
correctly skips the first two, and the `unknown` state — which the row does
*not* fire on — is bounded by `clamStatusProbeBudget` for the shipped client and
already **fails `/ready`**. The coupling is pinned behaviorally, not by a
literal: `TestClamAVScanDiagnostics_UnreachableDaemon` drives a real `Scanner`
at a real dead address, so renaming the prefix in `internal/secscan` fails the
test.

**The Fedora dnf5 repo registration (#1897) — package-source trust is
unchanged.** The branch is selected on `dnf --version` output and calls
`config-manager addrepo --overwrite --from-repofile=<URL>` instead of the
removed `--add-repo <URL>`. The URL is the same pinned
`https://download.docker.com/linux/fedora/docker-ce.repo` over **HTTPS**, and
the repofile it installs carries Docker's own `gpgcheck=1` and key URL, so
package signature verification is unchanged — this swaps the *subcommand*, not
the trust root. `--overwrite` can replace an operator's hand-edited
`docker-ce.repo`, which is a configuration-clobber risk rather than a trust one
and is what makes a partial-install re-run succeed. The dnf4 path is untouched.

**The enrollment alert detail (#1889).** `sanitizeLog` is applied to the
client-supplied node ID **before** it is interpolated, and the sanitized value
is what reaches `logger.Printf`, the audit record and the webhook body — the
right order, since the detail has three sinks and only one of them is the log.
Dedup cardinality is bounded (see *Method*).

**Test changes were checked for weakening, and none was weakened.** The window's
test diffs are terminology renames (`enrolment` → `enrollment`), one isolation
fix (`resetSyslogHealthForTest` in `diagnostics_test.go`, which correctly takes
ownership of a process-lifetime precondition instead of inheriting it from
whatever ran earlier under `-shuffle`), and the new `seedRosterRole` helper that
seeds the roster at the role a test asserts — which the new ceiling *requires*,
exactly as a real login would. No assertion, negative control or refusal case
was removed; `ui_role_failclosed_test.go` still asserts every refusal it did at
`feb11e8`.

Reviewed and unchanged: `proxy.go` and the proxy forwarding path (this window
adds only `proxy_http_readerfrom_test.go` and a bench test — no production proxy
change), `enrollment.go`, `internal/alerts`, `internal/secscan`,
`internal/otlp`, `store.go` (one additive accessor), `ui_middleware.go`,
`ui_auth.go`, `events.go`, `crashguard.go`, `internal/contracts`,
`.github/CODEOWNERS` (byte-identical to main), and the window's documentation
changes.

---

## Residual risk

**R1 — the same link-following pattern on `$file` itself is pre-existing and
left in place.** `env_put`'s first block does `sudo chown` / `sudo touch` on
`$file`, following links exactly as the lock block did. It is **not** fixed
here: refusing a symlinked `.env` would break operators who legitimately symlink
it, and this window did not touch that path. Its creation branch is also
effectively dead after a first install (`.env` exists). Worth a deliberate
decision in its own change — either an `O_NOFOLLOW`-capable helper or a
documented refusal with a migration note — not a silent narrowing here.

**R2 — `env_put`'s in-place rewrite is not atomic.** When the stack dir is
unwritable, #1887 stages in `$TMPDIR` and does `cat "$tmp" > "$file"`, which
replaces the `mv` rename. An interrupted or `ENOSPC` write now leaves a
**partial `.env`** where the rename left either the old file or the new one.
`.env` holds the stack's secrets and feature switches, so a truncated one is a
potential availability-and-posture event on the next `docker compose up`. The
trade was deliberate (the rename is impossible without write access to the
directory) and the previous behavior in this case was to abort the whole
installer, so it is not a regression — but the window has traded atomicity for
completion, and that is worth stating. The staged copy itself is mode 600 and
removed after use.

**R3 — the contracts gate is self-certifying.** A contract weakening passes once
the *same* pull request carries an `amended`/`retired` record with a reason.
That is the owner's explicit decision (#1855) and it is strictly stronger than
the nothing that preceded it, but it means the gate detects *unrecorded*
weakening only. Nothing in it prevents an author — human or agent — from
weakening a contract and recording it in the same change.

**R4 — `EnrollRequest.NodeID` has no length or charset bound.** A token with an
empty `NodePrefix` lets its holder choose any node ID, and that value now flows
into an alert detail, an audit record and a webhook body. Reaching the
dropped-record row additionally requires the ID to match a dropped record, so
this window's change does not widen it, and the token is single-use — but the
underlying absence of a bound is pre-existing and unrelated to the drop set.

**R5 — the link guard is not race-free.** `[[ -L "$lock" ]]` followed by
`sudo touch` is a TOCTOU window the shell cannot close (`O_NOFOLLOW` is not
reachable from a `[[ ]]` test plus a `sudo` call). Planting still requires write
access to the stack dir, so the race is strictly harder to win than the
persistent-link case the guard removes. Stated in the code comment.

---

## Verification

Run at this revision with the pinned toolchain. `go env GOVERSION` =
`go1.27.4`, `GOTOOLCHAIN` = `auto`, matching `go.mod`'s `toolchain go1.27.4`.

| Check | Result |
|---|---|
| `bash -n scripts/install.sh` | pass |
| `gofmt -l` (Go tree) | clean |
| `go vet ./...` | pass |
| `go mod tidy -diff` | clean |
| `CGO_ENABLED=0 go build -ldflags="-s -w"` release build | pass |
| `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build` cross-build | pass |
| `python3 docs/agent-context/check.py` | pass, exit 0 (static integrity only; client behavior not tested) |
| Finding-A reproducer **before** the fix | **fails** — created a file at an arbitrary path through the planted link via `sudo touch` |
| `go test -run 'TestInstallScript_EnvPut' .` after the fix | pass, 10/10 (4 new + 6 pre-existing, incl. both concurrency tests) |
| Mutation: guard neutralized (`if false; then`) | `…_LockSymlink_TruncatesNothing` **fails**, `…_DanglingLockSymlink_IsNeverHandedToSudo` **fails**, `…_LockFifo_DoesNotHang` **fails** (`WEDGED` after 20 s); `…_RegularLockFileStillApplies` **passes** in both states |
| `golangci-lint` v2.15.0, `--new-from-rev origin/main` (the gate's own command) | **`0 issues.`** — after fixing one real `nestif` finding this review introduced in its own test |
| `golangci-lint` v2.15.0, full-tree | 174 issues, all pre-existing — the **same total** the 2026-11-13 review recorded, and **none** in this review's new file |
| `TEST_SEED=20260421 go test -count=2 -shuffle=on -timeout=25m .` (root package, Deep determinism command scoped to the changed package) | **pass** — `ok github.com/KidCarmi/Culvert 995.392s`, exit 0 |
| `go run ./cmd/contractcheck impact -base origin/main` | `No contract code paths are touched by this change.` |

**Mutation-check note — the first harness proved nothing.** The initial
reproduction modelled `sudo` with a stub, and under `setpriv` that stub runs
with the test's own **dropped** privileges, so it cannot perform the root action
whose absence the test claimed to assert. With the fix reverted, one of the two
hazard tests still passed, and the other failed only on its warning-message
assertion. The tests were restructured to assert what is real at the privilege
the test actually has: the **truncation** half is fully reproducible
unprivileged (the `9>` redirection needs no sudo at all, which is also why the
finding does not depend on the foreign-owned topology), and the **creation**
half asserts on what `env_put` *hands to sudo*, recorded by the stub, rather
than on a root-owned file the harness cannot create. Recorded because the weaker
harness is the easy one to write and would have pinned nothing — the same
failure mode the 2026-11-13 review recorded for a `%q`-satisfied assertion.

**Harness note.** `exec.CommandContext` kills `bash` but not the **subshell**
`env_put` runs its transaction in, and a subshell wedged on `9>` outlives its
parent holding the inherited output pipes open — which blocks
`CombinedOutput` past the deadline, so the timeout would never be observed.
`cmd.WaitDelay` force-closes those pipes after the kill; without it, the FIFO
mutation case hung the entire package until the test binary's global timeout
panicked. The 20 s budget is pure headroom over a ~30 ms normal run.

**Lint scope note.** The full-tree run is read alongside the diff-scoped one
because `cyclop`, `funlen` and `gocognit` attribute a finding to a function's
**declaration** line, so `--new-from-rev` cannot see a function a change made
more complex. This change modifies **no** existing Go function — it adds one new
test file and a shell guard — so the diff-scoped run already covers every new
Go line. Lint was installed with
`GOTOOLCHAIN=go1.27.4 go install …/golangci-lint/v2/cmd/golangci-lint@v2.15.0`,
which is the step `docs/agent-context/conventions.md` records as the difference
between a working linter and the "local lint is unavailable" misdiagnosis.

**Not run.** `shellcheck` is not installed in this environment and is not a CI
gate for `scripts/install.sh`; the gate that exercises this file is
[`install-lifecycle-e2e.yml`](../../.github/workflows/install-lifecycle-e2e.yml),
which needs a real VM with Docker and **was not run here** — it is the check
that would exercise `env_put` end-to-end against a live stack, and it is the
most relevant gap in this review. Also not run: the frontend tree (untouched),
`cmd/culvert-maint` (untouched), the `benchgate` lane (no hot path changed), the
`internal/…` package suites (unchanged by this review's fix), and the
packaging/release-evidence workflows.

**Scope of these results.** These are focused and local checks at this
revision. They are **not** aggregate CI approval: the required
`✅ Fast PR Gate — APPROVED` and `✅ Deep PR Gate — APPROVED` checks, the sharded
race lanes with their completeness check and privileged regression, and the
merged coverage-floor artifact all run on the pull request. Readiness and
permission to merge remain separate decisions, and nothing in this review
authorises a merge, a deploy, a dependency change or any policy change.
