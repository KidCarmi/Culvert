# Security Regression Review — 2026-11-14

**Scope.** `2644508…de0b6d1` (`origin/main`) — the window since the 2026-11-13
review, 9 merged pull requests (#1884 #1885 #1886 #1887 #1888 #1889 #1890 #1891
#1892), 37 files, +2,768/−169.

| PRs | Change | Security surface |
|---|---|---|
| **#1892** | `refactor`: the trusted-proxy set and the X-Forwarded-For walk move out of `realclientip.go` into an instance-owned `internal/realclientip.Resolver` (IM-007, ADR-0045) | **the RISK-019 spoofing gate** — every admin-UI per-IP decision: login lockout, admin-API rate limit, UI IP allowlist, audit attribution |
| **#1886** | `fix(install)`: `env_put` takes `.env.lock` via sudo and stages in `$TMPDIR` when the stack dir is not writable, so a re-run in a root-owned `/srv/culvert` no longer aborts | **at-rest encryption provisioning** — `CULVERT_CA_PASSPHRASE`, `CULVERT_LOG_PASSPHRASE`, `CULVERT_SESSION_SECRET`; unsafe file writes; fail-closed installer |
| **#1887** | CHAOS-119: the telemetry shutdown drain gets three per-stage panic guards; five contained background rounds start reporting into the crash plane; `maxCrashLabels` 32 → 128 | **unsafe panic recovery; shutdown/drain durability ownership; crash-evidence suppression** |
| **#1888** | `feat(diagnostics)`: an operator-contract WARN row when ClamAV is configured but unreachable | **antivirus fail-open visibility; diagnostics RBAC and disclosure** |
| **#1885** | `docs(cluster)`: the cluster state file recovery runbook | operator remediation of a trust-store file (no runtime behavior) |
| **#1889 / #1890** | `docs(cluster)` ordering correction; `test(diagnostics)` syslog-health isolation | test determinism, operator remediation accuracy |
| **#1891 / #1884** | `test(bench)` corrects a 32 KiB benchmark artifact and pins `ResponseWriter` implementing `io.ReaderFrom`; terminology restoration in operator text | measurement and operator text only |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed at `2644508`?** Every verdict below is measured against
that revision, not against an ideal.

**Method.** Two changes in this window move a security control's *owner* or its
*failure mode* while claiming the decision is unchanged, and those took the
weight. The finding below was reproduced by executing the real shell function
from `scripts/install.sh` at both revisions — before the change and after —
before any fix was written, and the fix was mutation-checked twice.

**One finding — Medium, newly introduced in this window, fixed here.** No
security regression in the client-IP resolver extraction, the panic-guard and
crash-reporting work, the ClamAV diagnostics row, the documentation or the
test-only changes. One pre-existing weakness re-stated because this window
extends it (F2), and four residual risks recorded.

---

## F1 — `env_put`'s new degrade silently disables encryption at rest (Medium, FIXED)

**Affected contract.** `scripts/install.sh` must never start the stack with an
at-rest secret the operator supplied or the script generated missing from
`.env`. The file states the consequence itself, twice: a
`CULVERT_CA_PASSPHRASE` that never reaches `.env` means "docker compose resolves
it to empty and the proxy persists its Root CA private key UNENCRYPTED", and the
established posture for that is `error()` — a hard exit — not a warning. Every
other way the value could be dropped already fails closed: under the 12-character
floor, a charset compose would re-interpolate, a degraded `openssl` generator.

**What changed.** #1886 fixed a real availability bug: `env_put` opened
`"$file.lock"` with the invoking user's privileges, so a re-run in a stack dir a
first `sudo`/cloud-init install left root-owned died on
`env_put CULVERT_INSTALL_CHANNEL …` under `set -euo pipefail`. The fix takes the
lock via sudo and, when sudo cannot, **degrades: `warn` + `return 0`.**

That degrade is right for a channel name, a catalog URL or a GID. It is applied
to the three at-rest secrets as well, because `env_put` is one function and no
caller checks its status. The direction of the change is what makes it a
regression rather than an inherited weakness: in this exact state the previous
revision **aborted the installer**, so the stack never started with encryption
silently off.

**Attack scenario / failure scenario.** Not attacker-driven; a
misconfiguration-driven silent downgrade.

1. A first install runs as root (cloud-init, or `sudo bash install.sh`), so
   `sudo chown "$(id -un)" "$INSTALL_DIR"` at `scripts/install.sh:534` leaves
   `/srv/culvert` **root-owned**. That chown runs only in the provisioning
   branch; a re-run takes the `Culvert deployment already exists` branch and the
   directory ownership is never revisited.
2. An operator re-runs the installer as an unprivileged user whose sudo is
   denied or unavailable for these paths — or runs a first install into a
   directory it does not own.
3. `env_put` cannot create `.env.lock` in a directory it cannot write, sudo
   cannot take it, so it warns and **returns 0**.
4. `setup_at_rest_encryption` reads that as success. It then prints
   `IMPORTANT — SAVE YOUR ENCRYPTION PASSPHRASE … Stored in: $envfile
   (chmod 600)` — or, on the host-env branch, `Encryption passphrase already
   configured — keeping existing values.`
5. `docker compose up` resolves `${CULVERT_CA_PASSPHRASE:-}` and
   `${CULVERT_LOG_PASSPHRASE:-}` to **empty**. The SSL-inspection Root CA
   private key and saved request logs are written to the data volume
   **unencrypted**, and `CULVERT_SESSION_SECRET` falls back to a random
   per-process key (`session.InitRandomKey`), so no node shares a signing key.

**Preconditions.** A stack directory the invoking user cannot write to, and sudo
unable to take `.env.lock`. No attacker position, no network access, no
credentials.

**Exploitability / likelihood.** Not an exploit; a provisioning path an operator
reaches by following the documented sudo/cloud-init install and re-running the
script. Likelihood low-to-moderate, and **silent**: the operator is told
encryption is on.

**Impact.** The CA private key is the highest-value secret this appliance holds
— it signs every intercepted TLS connection — and it is the one secret a later
re-run cannot re-encrypt in place (`setup_at_rest_encryption` deliberately
leaves an existing CA bundle alone). Anyone who later reads the data volume,
a backup or a snapshot gets a usable MITM signing key. Saved request logs lose
confidentiality at rest. A missing session secret additionally breaks shared
session validation across nodes.

**Evidence (executed, not inferred).** The real `env_put` extracted from each
revision, run as uid 65534 against a 0755 root-owned stack dir with no `.env`
and `sudo` stubbed to fail:

- at `2644508` (before): `.env.lock: Permission denied`, **exit 1** — the
  installer aborts and never reaches `docker compose up`.
- at `de0b6d1` (after): two `WARN` lines, **`env_put` returns 0**, `NO .env WAS
  CREATED` — the installer continues.

**Fix (shipped here).** `env_put` keeps its degrade contract unchanged — the
availability fix #1886 bought is preserved. A new `env_put_required VAR VALUE
FILE` wrapper calls it and then verifies, through the shared
`env_file_value_set` predicate every caller here already trusts for "is this
configured", that the value actually landed; if it did not, `error()` exits with
the variable named and the remediation stated. The six secret call sites
(`CULVERT_SESSION_SECRET`, and `CULVERT_LOG_PASSPHRASE` /
`CULVERT_CA_PASSPHRASE` on each of their branches) go through the wrapper. The
non-secret call sites (`CULVERT_INSTALL_CHANNEL`,
`CULVERT_RELEASE_CATALOG_URL`, `CULVERT_MAINT_GID`,
`CULVERT_RELEASE_PROXY_REPO`) keep the degrade.

Only a value that genuinely did not land can now abort, so the normal path has
**no new failure mode**, and the misleading "Stored in: …" and "already
configured" lines become reachable only when the write actually took effect.

**Files.** `scripts/install.sh` (`env_put_required`, 6 call sites),
`install_script_env_put_required_test.go` (new),
plus the `installEnvPutFunctions` harness helper adopted by the seven existing
secret-path harnesses so they run the same three real functions install.sh does.

**CWE.** CWE-311 (missing encryption of sensitive data) via CWE-636 (failure to
fail closed); CWE-392 (missing report of error condition).
**OWASP.** A02:2021 Cryptographic Failures (A09:2021 for the false report).
**Severity.** Medium. **Regression risk of the fix.** Low — additive
verification, no change to a successful write.

---

## F2 — the sudo take-ownership pattern follows symlinks (Low, NOT changed; owner decision)

`env_put` takes `.env` — and, as of #1886, `.env.lock` — with
`sudo chown "$(id -un)" "$path"` and, when the file does not exist,
`sudo touch "$path" && sudo chown …`. Neither is symlink-safe: `chown` without
`-h` follows the link, and `touch` creates the **target**.

The `! -w "$dir"` branch is only taken when the invoking user cannot write the
stack directory — but "the installer cannot write it" is not "nobody can". A
group-writable stack dir (e.g. `0775 root:deploy` with the installing admin not
in `deploy`) lets a `deploy` member pre-plant `.env.lock` as a symlink; the next
re-run then runs `sudo touch`/`sudo chown` on the link target as root.

Recorded rather than changed: the identical two lines have governed `.env`
since before this window and are an established, reviewed pattern, and whether
a group-writable stack dir is a supported deployment is the owner's call. A
narrow fix is available and fail-closed — refuse when `[[ -L "$path" ]]`, and
use `sudo install -m 600 -o "$(id -un)" /dev/null "$path"` instead of
`touch`+`chown` — and should cover both paths together, not the lock alone.
**CWE-59 / CWE-367. OWASP A04:2021. Low** (contrived precondition, local
attacker position required).

---

## Verdicts on the rest of the window

**#1892 — `internal/realclientip` extraction. No regression.** This is the RISK-019
spoofing gate: `realClientIP` must return the direct peer unless that peer is
itself a configured trusted proxy, and only then walk X-Forwarded-For
right-to-left for the rightmost untrusted hop. Compared line by line against
`2644508:realclientip.go`, the moved body is **unchanged**, including the four
properties that carry the security argument: the `len(trusted) == 0` early
return (no trusted proxies → XFF never honored), the
`peerIP == nil || !ipInNets(...)` gate (a direct attacker cannot forge a
victim's IP), `Header.Values` + comma-join of **all** XFF field lines (the Codex
P1 spoof through a second field line stays closed), and the canonical
`ip.String()` return so `::ffff:1.2.3.4` and `1.2.3.4` cannot fork a lockout or
rate-limit key. `SetTrustedProxies` still validates every entry before mutating
anything, so a bad CIDR cannot clear the set. The two package globals became
fields on one `main`-owned instance; the zero value trusts nothing, which is the
same safe default the old `nil` slice gave. No caller changed (the three wrapper
names are preserved), `realclientip_test.go` is untouched and passes through the
wrappers, and a grep confirms no root file still references the removed
`trustedProxyNets`, `ipInNets`, `peerHost` or `parseIPOrCIDR`, so nothing reads
a stale copy of the trust set. `config_surfaces.go` re-points the surface owner
to `clientIPResolver`, keeping the admin-durable, not-cluster-synced record
accurate.

**#1887 — CHAOS-119 crash reporting and the telemetry drain. No regression;
posture improves.** The shutdown drain was `go`-detached and unguarded while
calling the same `exportStep` the periodic loop has guarded since CHAOS-118, so
a panic there was process-fatal from shutdown order 66 and **skipped** orders
67..140 — including the audit-log close. The replacement is per-stage, and the
two properties that could have made a panic guard a regression were both
checked: `mgr.Close()` (the durability-critical final flush and spool release)
runs even when the force-flush or a partition drain dies, and `done` is answered
on **every** path, so a dead stage cannot consume the shutdown budget the hook
exists to honour. A drain that panicked is reported as an error rather than
logged as a clean shutdown. The CHAOS-105 "whole-worker recover becomes a silent
stall" objection does not apply to a one-shot terminating sequence. The five
newly reporting recovers keep their existing containment, log lines and
outcomes; `recordCrash` holds only its own sinks (`crashByComponent`,
`lastCrashMu`, the audit ring) and is itself re-panic-proof, so adding it inside
an existing deferred recover introduces no lock-order or deadlock path at those
call sites. `maxCrashLabels` 32 → 128 **restores** evidence rather than
weakening a bound: past the cap `crashThrottleAllow` fails closed and suppresses
the record, log line and audit entry outright, and slots are first-crash-wins
and never pruned, so 32 slots against 62 fixed labels silently discarded exactly
the rare high-severity background crashes. The cap still fails closed, it is
still a fixed-cardinality bound (no call site derives a component from request
data), and 128 entries is not a memory concern.

**#1888 — the ClamAV diagnostics row. No regression.** Report-only, and
correctly so for a viewer-readable surface: the message is a **fixed** string
plus an integer counter, so the probe error — which names the daemon's internal
address — stays on the role-gated Security Scanning panel and is not widened to
the viewer role. The row reads the same `ClamAVStatus()` observation `/health`
and `/ready` already make (cached, with one coalesced bounded probe on a stale
observation), so it adds no new unauthenticated reachability and no per-request
outbound probe. It contributes nothing when scanning is off, when ClamAV is
answering, before the first observation lands, or when body scanning is
delegated — so it cannot mask a different failure. It changes no scanning,
readiness or fail-open decision; it only makes an existing fail-open visible on
the page an operator reads to ask "is this node protected the way I configured
it".

**#1885 / #1889 — cluster state recovery runbook. No regression.** Operator
remediation for `cluster.json`. Scanned for the shapes that would matter in a
recovery document: it recommends no permission widening, no
verification/TLS/auth disable, no `0.0.0.0` bind and no break-glass beyond
stopping the node before restoring the file and fixing the leader first on HA —
which is the safe ordering, not a weakening.

**#1890 / #1891 / #1884 — tests, benchmark and operator text. No regression.**
`TestApiDiagnostics_SyslogFeedOK` now owns the process-lifetime syslog health
precondition it previously inherited, registering reset at start **and** in
cleanup, which is the shared-global discipline the conventions require. The
benchmark correction and the new `io.ReaderFrom` pin are test-only; no
production file is touched. The terminology restoration is comments, operator
strings and test names; it was checked against the one place in this window
where it could have mattered — a merge landing after #1879's dedup fix could
have reverted `recordDroppedNodeReenrollment`'s detail to the constant string
that made the alert dedup key shared across nodes. It did not: the detail on
`de0b6d1` still carries the sanitized node ID, so the per-node dedup property
the 2026-11-13 review shipped survived the merge.

---

## Residual risk

1. **`.env` secrets transit `$TMPDIR` on the new in-place path (Low).** When the
   stack dir is not writable, `env_put` stages the filtered `.env` — every
   secret it holds — via `mktemp` (mode 600) in the default temp dir and
   `rm -f`s it. `env_put` installs no `trap`, so an interrupted install (SIGINT
   at the wrong microsecond) can leave that copy in `/tmp` indefinitely, outside
   the stack dir an operator thinks of as holding the secrets. Mode 600 keeps it
   confidential against other unprivileged users. Not changed in this window.
2. **The in-place rewrite is not atomic (Low).** `cat "$tmp" > "$file"`
   truncates then rewrites, where the writable path does an atomic `mv`. The
   `flock` serializes `env_put` against `env_put`, not against a reader, so a
   concurrent reader of `.env` could observe a truncated file. Install-time
   only, microsecond window, and the previous behavior on this path was a hard
   abort. Recorded; a `mktemp` inside the dir is impossible there by
   construction.
3. **`mktemp` is unguarded on the in-place path (Low).** The writable branch
   falls back to `"${file}.tmp.$$"`; the new branch does not, so a failing
   `mktemp` (unwritable/full `$TMPDIR`) aborts the subshell under `set -e` —
   loud, not silent, so the posture is acceptable, but it is the abort #1886 set
   out to remove, now on a different trigger.
4. **F2 above** is unresolved pending the owner's decision on whether a
   group-writable stack directory is supported.

---

## Verification

Run at `de0b6d1` plus this change:

- `bash -n scripts/install.sh` — clean. `shellcheck` is not installed in this
  container; not run.
- `go build ./...` — clean.
- `go test -run 'TestInstallScript' -count=1 .` — green (the whole
  install-script family, 30+ tests, including the seven existing secret-path
  harnesses adopted to `installEnvPutFunctions`).
- `go test ./...` — see the PR body for the full-module result at this SHA.
- `golangci-lint run --timeout=10m --new-from-rev origin/main` with the gate's
  own pinned **v2.15.0 built on the `go.mod` `go1.27.4` toolchain** —
  **0 issues**. The container's own `golangci-lint` is not used (it refuses this
  module's language version).
- Full-tree `golangci-lint run ./...` — **174 issues**, the same total CHAOS-119
  (#1887) recorded at both base and head in this window, so **zero net new**.
  Run because `cyclop`, `funlen` and `gocognit` attribute to a function's
  declaration line and `--new-from-rev` cannot see them.
- **Mutation-checked twice.** (a) Reverting the six call sites to the bare
  `env_put` is caught by
  `TestInstallScript_EverySecretIsWrittenThroughEnvPutRequired`. (b) Neutering
  the wrapper's verification (`|| rc=$?` → `|| rc=0`) is caught by
  `TestInstallScript_EnvPutRequired_UnpersistedSecretFailsClosed` **and**
  `…_EmptyResolvingValueFailsClosed`. The tree is green again after each revert.
- The F1 failure scenario was **executed at both revisions** before the fix was
  written (results quoted above), not inferred from the diff.

## Required tests (shipped)

| Kind | Test |
|---|---|
| Regression / negative | `TestInstallScript_EnvPutRequired_UnpersistedSecretFailsClosed` — unwritable stack dir, no `.env`, sudo denied: must exit non-zero, must not reach past the secret, must name the variable |
| Positive | `TestInstallScript_EnvPutRequired_PersistsAndReplaces` — writable dir: value replaced not duplicated, unrelated lines survive, exit 0 |
| Regression (the other direction) | `TestInstallScript_EnvPutRequired_ForeignOwnedStackDirStillPersists` — the #1886 scenario where sudo *can* take the files: the in-place rewrite lands, the non-secret `env_put` still degrades, no staging file left behind. Proves the fix does not reintroduce the abort #1886 removed |
| Boundary / malformed input | `TestInstallScript_EnvPutRequired_EmptyResolvingValueFailsClosed` — a value `env_put` writes but compose resolves empty must not pass as persisted |
| Invariant from source | `TestInstallScript_EverySecretIsWrittenThroughEnvPutRequired` — no secret is written through the degrading `env_put`, with a negative control asserting the gate still reads real call sites |

Concurrency and authentication/authorization tests are not applicable: the
change is to a provisioning script with no concurrent writer beyond the `flock`
the existing `TestInstallScript_EnvPut_*` family already covers, and no
authentication or authorization decision is touched.
