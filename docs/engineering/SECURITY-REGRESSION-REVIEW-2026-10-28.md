# Security Regression Review — 2026-10-28

**Scope.** `af32aa2…origin/main` — the 24 h since the 2026-10-27 review, 28
commits over 7 merged pull requests (#1739 #1740 #1741 #1742 #1743 #1744
#1745), 23 files, +3,175/−46. Five of the seven carry code:

| PR | Change | Security surface |
|---|---|---|
| **#1745** | CHAOS-102 — a pre-posture accept gate on the SOCKS5 listener | admission, startup ordering, proxy |
| **#1743** | The 2026-10-27 review's own R-1 fix — bound the CP's local revocation merge | sessions, cluster, persistence |
| **#1744** | `GET /api/logs` paging rewritten to allocate one page instead of every match | admin control plane, DoS |
| **#1742** | `env_file_value_set` accepts compose's `export `/indent forms; dotenv-resolve the reused log passphrase | secrets, crypto at rest |
| **#1739** | A diagnostics row for a faulted MCP gateway | information disclosure, RBAC |

#1740 and #1741 are documentation only.

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed 24 h ago?** Every finding is measured against the base
revision, not against an ideal.

**Method.** Each change read through its production callers, not its diff
hunks: the three admission globals traced to every consumer in the tree, the
revocation merge traced to `mergeUntrusted`'s `persisted` flag, the paging
helper traced to `parseLogQueryWindow`'s clamps, the installer's passphrase
resolution executed against real `.env` fixtures rather than reasoned about.
Every candidate finding was then put through a disproof pass, and the one that
survived got a **differential oracle**: the gate must fail on the broken shape
and pass on the shipped one.

---

## 1. Executive Summary

**No security regression was introduced in this window.** The one defect found
is a **gap in the new regression gate itself**, not in the shipped behaviour:
CHAOS-102 pins the *release* end of its posture gate by statement order but
pins the *arm* end only by presence, so a refactor that keeps the arm and moves
it below the bind reopens the window while leaving all ten of the new tests
green. That is fixed and gated here. One pre-existing missing-validation gap in
the installer became reachable for one more input shape; its net direction is
an improvement and it is reported, not changed.

| # | Finding | Severity | Status |
|---|---|---|---|
| **S-1** | CHAOS-102's arm-end wall accepts `armSOCKS5PostureGate` anywhere in `initSOCKS5`'s callee set. Moving it **below** `startSOCKS5` reopens the unfiltered-relay window and every existing CHAOS-102 test still passes | **LOW** (regression-gate gap guarding a HIGH behaviour) | **FIXED + gated** |
| **S-2** | The CA-passphrase reuse branch applies the charset guard but **not** `validate_passphrase_for_env_file`'s 12-character floor. #1742's dotenv resolution makes quoted short values reach `env_put` where the quotes previously got them rejected | LOW (pre-existing; **not** a regression — direction is plaintext CA key → encrypted) | Reported — owner decision |

Surfaces reviewed and found **clean**: the SOCKS5 posture gate's fail-closed
semantics and its arm/release ordering, the `socks5SourceDenied` extraction,
the Control Plane revocation bound fix (including the `Prov` clearing it newly
applies to the local merge), `/api/logs` paging bounds and wire shape, the MCP
diagnostics row, `env_file_value_set`'s unknown-verdict path, and the CI /
lint / toolchain / dependency surface — **no gate was weakened; no workflow,
`go.mod`, `go.sum`, `.golangci.yml`, `Makefile`, `Dockerfile` or
`docker-compose.yml` change exists in this window.**

---

## 2. Security Findings

### S-1 (LOW gate gap, HIGH behaviour) — the arm end of CHAOS-102's wall is not ordered

**Files.** `main.go:1113-1129` (`initSOCKS5`; arm at 1127, bind at 1128) ·
`socks5_posture_gate_chaos_test.go:287-343` (the two walls) ·
`socks5_posture_gate_chaos_test.go:375` (`callStatementIndexForTest`).

**What #1745 shipped.** `initSOCKS5` arms a gate immediately before
`startSOCKS5`, and `loadPersistentAdminState` releases it immediately after
`LoadAdminSettings`. `handleSOCKS5` checks it first and refuses. The reasoning
is correct and I could not fault the shipped behaviour: `startSOCKS5` returns
with the accept loop serving, the three globals `applyAdminSecurity` writes
(`ipf`, `rl`, `connLimiter`) are the only admission gates `handleSOCKS5` has,
and until that restore runs an unconfigured `IPFilter` admits every address.

**The gap.** The release end is pinned by **order**:

```go
if releaseAt < loadAt {   // socks5_posture_gate_chaos_test.go:339
        t.Fatalf("...the pre-posture gate is released at stmt %d, BEFORE LoadAdminSettings...")
}
```

The arm end is pinned only by **presence** — `calleeNames(initSocks)
["armSOCKS5PostureGate"]`. It has to be, because `callStatementIndexForTest`
returns the index of the enclosing *top-level* statement and both calls sit
inside the same `if s.socks5PortVal > 0` block, so it reports the **same index
for both** and cannot order them.

**Attack scenario.** Not an attacker action — a refactor. Any later change that
reads `initSOCKS5` as "arm the gate somewhere in here" and writes

```go
s.socks5Srv = startSOCKS5(s.socks5PortVal)
armSOCKS5PostureGate()
```

restores a pre-posture window. `startSOCKS5` blocks until the first `bind(2)`
resolves and returns with the loop accepting, so between its return and the arm
a SOCKS5 client is admitted **from any source IP, unrate-limited, uncapped and
relayed to an arbitrary TCP destination** — the exact condition CHAOS-102
exists to close, on the exact code path it guards.

- **Preconditions.** `socks5_port > 0`; a connection landing in the window.
- **Exploitability.** Not directly reachable: it requires the refactor first.
  Once present, the window is narrower than the pre-CHAOS-102 one (one
  statement, not `loadPersistentAdminState`'s whole I/O sequence) but is still
  a real accept window on a listener with no other admission control, and it is
  widened by the same slow/contended `/data` faults the register already tracks.
- **Likelihood.** Moderate over time. This is a 188-line file whose own prose
  says the arm "is one line, next to the only statement in the tree that
  creates the window" — a one-line invariant with no gate is the kind that
  moves.
- **Impact.** Unauthenticated, unfiltered TCP relay through the appliance for
  the duration of the window. **Affected assets:** the SOCKS5 data plane, the
  operator's GUI-built IP allowlist, the per-IP rate limit and connection cap.
- **CWE.** CWE-696 (Incorrect Behavior Order) · CWE-1188 (Insecure Default
  Initialization of a Resource) · CWE-362 (Race Condition). **OWASP:** A01:2021
  Broken Access Control; A05:2021 Security Misconfiguration.
- **Severity.** Gate gap LOW; the behaviour it fails to prevent is HIGH.
- **Regression risk of the fix:** none — test-only, no production file touched.

**Proof the gap is real (differential oracle).** Inverting the two lines in
`main.go` and running the whole CHAOS-102 suite:

```
--- FAIL: TestCHAOS102_Wall_TheArmPrecedesTheBind
    CHAOS-102 regression: initSOCKS5 arms the pre-posture gate at offset 58033,
    AFTER the startSOCKS5 bind at offset 58002 ...
```

and **every one of the ten pre-existing CHAOS-102 tests passed on that same
broken tree** — including both walls and the negative controls. `main.go` was
restored byte-for-byte afterwards (`git diff --quiet main.go`).

**Fix shipped.** `TestCHAOS102_Wall_TheArmPrecedesTheBind` compares `token.Pos`
rather than statement indices, via a new `callPosForTest` helper, and fails
when the arm follows the bind. The arm-absent shapes (the pre-fix boot and the
reorder remedy) are deliberately left to the callee-set wall that already owns
them, so the two walls do not overlap.
`TestCHAOS102_Wall_TheArmPrecedesTheBindNegativeControls` proves the new wall
can fail, on two synthetic `initSOCKS5` bodies, and additionally asserts the
premise — that `callStatementIndexForTest` gives the arm and the bind the same
index — so the wall self-reports if a future refactor separates them and makes
it redundant.

---

### S-2 (LOW, pre-existing) — the reused CA passphrase skips the length floor

**Files.** `scripts/install.sh:1801-1836` (the CA-reuse branch of
`setup_at_rest_encryption`) · `scripts/install.sh` `validate_passphrase_for_env_file`.

Every other path that writes a passphrase into `.env` — operator-typed,
host-env-supplied, auto-generated — calls
`validate_passphrase_for_env_file`, which **errors** below 12 characters
because the value is PBKDF2-SHA256'd (600 k) straight into the AES-256-GCM key
protecting the SSL-inspection Root CA private key. The reuse branch applies
only the inline charset guard, with no length check.

#1742 added a dotenv resolution step so the charset guard judges the
passphrase rather than its `.env` syntax. That is correct and necessary — it is
what makes a quoted operator passphrase usable at all — but it also means a
**quoted** short value now reaches `env_put`, where the quote characters
previously got it rejected. Measured against real fixtures:

| `.env` line | pre-#1742 | post-#1742 |
|---|---|---|
| `CULVERT_LOG_PASSPHRASE="ab"` | refused (charset) → CA key **unencrypted** | **persisted**, len 2 |
| `CULVERT_LOG_PASSPHRASE=ab` | **persisted**, len 2 | **persisted**, len 2 |
| `export CULVERT_LOG_PASSPHRASE="abcdef123456"` | refused (charset) → CA key **unencrypted** | persisted, len 12 |

**Why this is not a regression.** Row 2 shows the missing floor is pre-existing
and unchanged — an unquoted short passphrase was already persisted verbatim.
For the quoted rows the change moves the CA key from **plaintext on disk** to
AES-256-GCM under a weak passphrase, which is strictly better; and row 3 is the
operator-intended outcome the PR exists to deliver.

- **Attack scenario.** Offline brute-force of `ca.key.enc` after an attacker
  obtains the data volume (backup, snapshot, discarded disk). A short
  passphrase is recoverable regardless of the iteration count; the recovered
  CA key permits transparent TLS interception of every client that trusts it.
- **Preconditions.** Operator sets a short `CULVERT_LOG_PASSPHRASE` by hand in
  `.env`; a fresh deployment with no CA passphrase; attacker gets the volume.
- **Exploitability / likelihood.** Low — requires both operator error and
  volume compromise, and the operator's own logs are already encrypted under
  the same weak secret.
- **Impact.** Compromise of the SSL-inspection Root CA private key.
  **Affected assets:** the CA key, every saved request log.
- **CWE.** CWE-521 (Weak Password Requirements) · CWE-311 (Missing Encryption
  of Sensitive Data, on the pre-#1742 refusal path). **OWASP:** A02:2021
  Cryptographic Failures.
- **Recommended fix — deliberately NOT applied here.** Calling
  `validate_passphrase_for_env_file` in this branch would turn an operator's
  own short `.env` value into an **aborted install**, and skipping the write
  instead returns the CA key to plaintext — both worse than the status quo. The
  safe implementation is to keep encrypting and add a `warn` when the reused
  value is shorter than 12 characters, naming the variable and never the value,
  so the operator is told the shared key is weak. That is a posture decision
  for the owner, and the review's own rule is not to change security behaviour
  unilaterally.
- **Required tests if adopted.** Positive (≥12 reused, no warning, written);
  negative (<12 reused, warning emitted, still written); boundary (exactly 12,
  exactly 11); malformed (quoted, `export `-prefixed, CRLF, trailing comment —
  the shapes #1742's own Go gate already enumerates); and the existing
  assertion that no passphrase **value** ever reaches stdout or stderr.
- **Secret-exposure check (clean).** Every branch here names the variable, not
  the value; the inline guard pipes through `printf '%s' | grep -q` with no
  echo. The reuse guard lacks `grep -z`, which
  `validate_passphrase_for_env_file` carries to catch an embedded newline — not
  reachable here, because the value comes from `cut` on a single `grep` line.

---

## 3. Reviewed and Found Safe

**CHAOS-102, the shipped behaviour (#1745).** Fail-closed in the right
direction and correctly scoped.

- `handleSOCKS5` checks the gate **before** `connLimiter.Acquire`, so a refused
  connection consumes no slot and no rate-limit token, and the refusal does not
  depend on any of the state it compensates for.
- The zero value is "not armed ⇒ open". I probed this as a candidate fail-open
  and it is not one: the only populations with an unarmed gate are
  `socks5_port: 0` (no listener exists) and tests that never run `main`. There
  is no ordering in which the socket exists and the gate is unarmed —
  `armSOCKS5PostureGate()` precedes `startSOCKS5` inside the port guard, and
  S-1 is now what keeps it there.
- The release is unconditional on `LoadAdminSettings`' **outcome**. Correct:
  the three early returns (absent / unreadable / quarantined-corrupt) already
  leave the compiled default posture for the life of the process and are
  surfaced by a log line, the `state_file_corrupt` alert and a `/readyz` row.
  Holding the listener closed for them would be a new posture, not the closure
  of a race.
- Between the arm and the release the process either reaches the release or
  dies (`logFatalf`/panic): there is no path that leaves the gate armed with a
  live listener, so the fail-closed state cannot become a permanent outage.
- **Scope claim verified independently.** `ipf.Allowed` / `rl.AllowAuto` /
  `connLimiter` are consumed as gates in exactly two places tree-wide —
  `proxy.go:1551-1567` and `socks5.go:428-471`. The proxy's listener is opened
  by `runProxyUntilShutdown`, the last statement of `main`; `startAdminUI` and
  every MCP init run after `initPersistentAdminState`. The one other listener
  that binds **before** the posture restore is the Control Plane's gRPC
  listener (`initCluster`, `cp_grpc_bind.go`) — it consumes none of the three
  and is gated by mTLS plus `verifyNode`, so it has no analogous window. No
  third pre-posture listener exists.
- `socks5SourceDenied` is a faithful extraction: same order (IP filter, then
  rate limit), same position after the connection limit, same
  `IP_BLOCKED`/`RATE_LIMITED` request-history actions, same close-without-reply.
  The order matters because `rl.AllowAuto` **counts**, and it is preserved.
- Log-flood containment follows the CHAOS-54 precedent: one line per boot, the
  magnitude in `culvert_socks5_posture_refused_total`.
- Test hygiene: every test resets the gate and registers
  `t.Cleanup(resetSOCKS5PostureGateForTest)`.

**The R-1 revocation bound fix (#1743).** Verified, including the one thing the
fix changes beyond the bound.

- `Update` now returns `kept` and both consumers take it, so
  `maxRevocationsPerNode` governs what the CP **persists and enforces** as well
  as what it broadcasts. This closes exactly the fail-open R-1 described.
- **`Prov` is now cleared on the entries handed to the CP's own merge**, where
  previously `req.Entries` carried it. I traced this as a candidate new
  regression and it is inert: `mergeAndPersistRevocations` →
  `mergeClusterRevocations` → `MergeRevocations` → `mergeUntrusted(entries,
  **false**)`, and `Prov` is read only under `if persisted &&
  validProvenance(e)`. Gossip never takes that branch, so clearing it changes
  no admission decision. It cannot fail **open** either, since the provenance
  branch is the one that *bypasses* the untrusted bounds.
- No aliasing hazard: `kept` is handed out while also stored in
  `a.perNode[nodeID]`, but a later `Update` replaces the map value with a fresh
  slice rather than mutating the array, and `mergeUntrusted` only reads
  `Token`/`Expiry`/`User`. Both readers are read-only, so there is no race.
- `session_provider_bounds.go`'s correction is accurate: `ExportRevocations`
  and `exportPersisted` do now walk `r.users` onto the wire and onto disk, so
  the retired containment argument is correctly retired rather than left to
  read as reassurance.

**`/api/logs` paging (#1744).** `requireRole(w, r, RoleViewer)` is intact and
checked before any work. The rewrite is memory-safe and wire-compatible:

- Every current caller's `limit` arrives from `parseLogQueryWindow`, which
  admits only `v > 0` and clamps to `apiLogsMaxLimit` (5000), and `offset` only
  `v >= 0`. The allocation is reached only inside `if limit <= apiLogsMaxLimit`,
  so the CWE-770 bound dominates it — the shape CodeQL requires, as the comment
  records.
- `min(pageLimit, len(all))` with a `> 0` guard means a negative or zero
  future `limit` reserves nothing instead of panicking in `make`. The
  pre-change code would have **panicked** on a negative offset
  (`filtered[negative:…]`); the new code cannot. Strictly more robust.
- Worst-case reservation is one allocation of ≤5000×352 B ≈ 1.76 MB, bounded by
  the snapshot the caller already holds — no amplification versus base, which
  grew to the match count on the same input.
- Pagination arithmetic is equivalent: `total >= offset && len(page) <
  pageLimit` selects the half-open window `[offset, offset+limit)` over matches
  in the same newest-first order, and `total` is still the exact full count.
  The `"logs": null` shape for an empty or out-of-range page is preserved.
- The backing array of the cached snapshot is never mutated.

**MCP diagnostics row (#1739).** Report-only and correctly redacted.
`mcpHealthState()` returns a value type, so the new call cannot nil-deref the
`RoleViewer`-readable `/api/diagnostics` handler into a DoS. The message is a
**fixed string**: `snap.Reason` — which can name a configuration fault — is
deliberately excluded and left on the MCP panels. The row also lands in support
bundles (`support_collectors.go:81`), where secret-omission matters, and
carries nothing operator-supplied.

**`env_file_value_set` (#1742).** The predicate's three-way contract is intact:
`[[ -r "$file" ]] || return 2` still runs first, so "could not look" stays
distinguishable from "no entry" — the distinction
`persist_host_env_session_secret` needs so it cannot overwrite a signing key it
failed to read. `|| true` on the new command substitution keeps a no-match from
aborting under `set -euo pipefail`, the full `grep | tail` consumes its input so
no producer is cut off by SIGPIPE, and the final `grep -q` reads a here-string.
Judging only the **last** assignment matches compose's own last-wins
resolution, so a non-empty `export VAR=x` followed by `VAR=` now correctly
reads as *empty* — a fail-closed correction. `${var}` is interpolated into the
regex, but every call site passes an in-tree literal, so there is no injection
reachable from configuration or input.

**Delivery surface.** No change to `.github/`, `.golangci.yml`, `Makefile`,
`go.mod`, `go.sum`, `Dockerfile` or `docker-compose.yml` in this window. No
gate weakened, no `GOTOOLCHAIN` override, no suppression added. The
`docs/OPERATIONS.md` edit corrects a non-existent `--data-dir` flag to
`CULVERT_DATA_DIR` and has no security effect.

---

## 4. Verification

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./...` | pass |
| `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...` | pass |
| `go mod tidy -diff` | clean |
| `go test -count=1 -timeout 35m .` (root, full) | **pass**, 561.7 s |
| `go test -count=1 ./internal/session/...` | pass |
| `go test -run 'TestCHAOS102' -v .` | pass, 12/12 |
| `go test -run 'SOCKS5Posture\|LogPage\|FilterLogPage\|EnvFileValueSet\|RevocationCPMerge\|MCPGateway' .` | pass |
| `golangci-lint run --new-from-rev origin/main` (gate command, pinned v2.15.0 built with go1.27.3) | **0 issues** |
| `python3 docs/agent-context/check.py` | pass |
| `gofmt -l socks5_posture_gate_chaos_test.go` | clean |
| **S-1 differential oracle** | new wall **FAILS** on the inverted `initSOCKS5`; **all 10** pre-existing CHAOS-102 tests **PASS** on that same broken tree. `main.go` restored byte-for-byte (`git diff --quiet`) |
| Installer resolution probe | executed against real `.env` fixtures; the S-2 table is measured, not reasoned |

A full-tree `golangci-lint` comparison against the base was **not** run and is
not needed here: `cyclop`/`funlen`/`gocognit` attribute to a function's
declaration line, this change adds only new declarations (which
`--new-from-rev` does see) and makes no existing function more complex, and
`.golangci.yml` exempts `_test.go` from `funlen`, `dupl` and `cyclop` anyway.

**Operational note, not a finding.** The first full-suite run reported
`FAIL … 600.163s` — `go test`'s **default 10-minute timeout**, not a test
failure, hit while the lint gate was competing for CPU in the same container.
Uncontended the suite needs 561.7 s, which is under the default by ~6 %. Any
runner that shares CPU with another job will flip this to a timeout; the margin
is thin enough to be worth knowing.

**Not run / not proven here:** CodeQL, gosec, `-race`, the hosted required
gates, the frontend npm tree, `cmd/culvert-maint`, the `benchgate` lane and the
coverage-floor contract. A passing local selection is **not** a passing merge
gate.

---

## 5. Residual Risk

1. **S-2 stays open by decision.** The 12-character floor is still absent from
   the reuse branch. Closing it safely is a `warn`, not a refusal — see the
   recommended fix.
2. **S-1 pins order, not reachability.** The new wall proves the arm precedes
   the bind *in `initSOCKS5`*. If a future change moves the bind out of that
   function, both walls fail loudly with "re-derive CHAOS-102", which is the
   intended outcome — but neither wall can prove the arm precedes the bind
   across a function boundary.
3. **CHAOS-102 does not cover "the restore ran and failed."** By design: the
   quarantine posture leaves compiled defaults for the process's life, and on
   that path SOCKS5 serves under those defaults after the release. Pre-existing
   and surfaced three ways, but it means a corrupt admin-state file still
   yields an unfiltered SOCKS5 listener — the gate closes the race, not the
   decision.
4. **The R-1 cap bounds volume, not entitlement.** 4096 durable gossiped
   revocations per enrolled node remains; the 2026-10-27 review's R-2 (a peer
   may revoke any account) and R-3 (delete-then-recreate lockout) are still
   open owner decisions.
5. **`/api/logs` over-allocates on a narrow filter.** A 5000-limit query
   matching three rows reserves the full page. Stated as a trade-off in the
   code, bounded, `RoleViewer`-gated — not a defect.
