# Security review — a retained-path sink the sweep that bounded them missed, a revocation drop Diagnostics called healthy, and a CWE-117 rule applied to three of four sinks

**Date:** 2026-10-26
**Reviewer role:** Security Regression Engineer (scheduled run)
**Base reviewed:** `a27cffb` (the revision the 2026-10-24 review closed on)
**Head reviewed:** `648e145` (`origin/main` at the time of the run)
**Branch:** `claude/epic-bardeen-l09e55`

**Window size.** 102 pull requests merged into `main` between those two
revisions — 42 non-test Go files, ~2 953 insertions / ~297 deletions, plus
workflow, legacy-UI and documentation changes. Reviewed across five slices
(four delegated with bounded file lists and explicit regression classes, one
taken directly), with every reported finding re-verified against primary
evidence before any code changed.

**Three findings, all three fixed here.** None is an authentication or
authorization bypass; this window contains no such regression, and the review
says so plainly in §6. All three are in the same family: a *control that works*
whose *evidence surface* does not — an unbounded value in a forensic sink, a
drop the health row did not count, and a log-injection barrier applied at three
sinks out of four. That family is the one this register keeps recording, because
it is the one that survives review: the protection is there, so the diff reads
correct, and only the operator's view of it is wrong.

---

## 1. Executive summary

| # | Finding | Severity | Introduced by | Status |
|---|---|---|---|---|
| F1 | A sixth process-log sink retains the **decrypted inner request path** unbounded, after CHAOS-92 bounded the other five — and the value is unbounded *on the wire*, unlike the five that were fixed | **Medium** | Pre-existing sink; the incomplete enumeration and its gate are this window's (CHAOS-92, #1715) | Fixed |
| F2 | `/api/diagnostics` reports "session revocation healthy … no drops" while a legitimate remote revocation was dropped, in a configuration the product supports at its documented maximum | **Low** | This window (CHAOS-73 revocation bounds) | Fixed |
| F3 | Peer-supplied `cp_addresses` reach the Data Plane process log unsanitized at four sinks, in the same file whose new code declares that value untrusted | **Low** | Sinks pre-existing; the stated contract they violate is this window's | Fixed |

Plus one repository-hygiene item fixed in passing (§5) and five sub-threshold
observations recorded, not fixed (§7).

**What the window did well, stated first, because it is most of the diff.**
This window is dominated by correct fail-closed hardening, and each piece was
confirmed rather than assumed:

- **CHAOS-73 closed a real unauthenticated write primitive.**
  `/api/auth/logout` is public by design, and it used to insert whatever cookie
  it was handed into the process-wide revocation list — key bytes, key length
  and expiry all chosen by the caller — then persist and gossip it fleet-wide.
  `RevokeVerified` now checks the HMAC *first*, before any decode, map insert or
  disk write, and before the expiry, so a genuinely expired cookie still logs
  out while an unsigned one writes nothing. The refusal is deliberately
  invisible to the caller (still 200, cookie still cleared), which is why the
  counter F2 is about exists at all. Verified that eviction and admission now
  route through one expiry oracle (`revocationExpired`), so no entry can be
  dropped while a cookie it revokes still verifies, and that the MAC-pooling
  refactor is byte-identical and still constant-time (length-checked before any
  byte comparison, pinned by a differential test and a fuzz target).
- **BKP-1 closed a backup fail-open.** `loadAndMaybeDecrypt` chose its envelope
  by magic sniff and consulted the configured passphrase only in the encrypted
  branch, so anyone able to write into the backup directory substituted a
  hand-built plaintext tarball — and nothing else fired, because the manifest is
  self-referential: `validateFileChecksumsAndModes` hashes the attacker's bytes
  against the attacker's manifest. A substituted `data/ui_users.json` installed
  an attacker-authored admin roster. A plaintext archive is now refused when a
  passphrase is configured, and the legitimate no-passphrase restore is
  unaffected (verified: `passphrase_ref` is genuinely optional, and the
  unencrypted templates set the env var to an explicit empty).
- **BKP-2/BKP-4 removed a planted-symlink write.** `os.Create(outPath+".tmp")`
  became `os.CreateTemp` + `Chmod(0600)` before any archive byte is written, so
  the fixed, predictable name that `os.Create` would have followed to an
  attacker's link — carrying `cluster-ca.key` with it — is gone.
- **SEC-TUNHOST-2 closed a genuine inspected-tunnel pin bypass.** The inner-host
  pin compared a *repaired* authority while the origin received an *unrepaired*
  one. `allowed.example.com:0/x`, `:443?x` and `:@blocked.example.com` all
  reduced to the authorized host and pinned, while `Request.write` found the
  `/`, `?` or `@`, zeroed the Host and emitted a literal `Host: ` — the exact
  state the empty-inner-host branch refuses. Mixed-case U-labels pinned under a
  different A-label for the same reason. Confirmed both wire legs (H1
  `Request.write`, H2 `encodeHeaders`) now apply the same two predicates the pin
  does, and that the new gate is strictly narrowing — every accept is a subset
  of the old accepts.
- **CHAOS-84 fixed a whole class of clock-step latches.** Seven rate-limit and
  health gates compared `now-prev < interval` on the wall clock, so a backward
  step silenced them for the duration of the step; they now compare magnitude,
  or measure on the monotonic clock (`monotime.go`). Verified every monotonic
  call site is process-local, never persisted or gossiped, and that the
  `0 = never stamped` sentinel survives. Direction of change is strictly toward
  *more* reporting, never less — including `recordCrash`, which previously
  returned before logging.
- **SEC-POLICYACTION-1's diagnostics half.** `file_profile_resolution` still
  compared the raw action after the request path moved to
  `canonicalPolicyAction`, so it reported `ok` for exactly the rules
  (`"allow"`, `"ALLOW"`, empty) whose dangling file profile was blocking every
  file-bearing transaction fail-closed. Enforcement was correct throughout; only
  the row that explains it to an administrator was blind.
- **SEC-DIAG-ACCESSCIDR-1** made the admin-UI allowlist posture admin-only, with
  a fail-closed fallback for a hand-assembled contract, and both renderings
  built from one read of the rejection state so they cannot disagree.

---

## 2. F1 — the sixth retained-path sink (Medium)

### Affected contract

`roadmap/CHAOS-ENGINEERING-REVIEW.md` §53 (CHAOS-92), register row **PX-22**.
Its §53.1 claim: `r.URL.Path` reaches "the process log (5 sites), a buffered
HTML response body (5 sites) and the request-log `URI` field (4 sites)", and
§53.5's structural claim: the clamp sits at each chokepoint so "one edit bounds
all present and future sinks", pinned by a source gate.

### The defect

The process-log enumeration is short by one. `emitFileBlock`
(`proxy_tunnel.go:1255`) calls `fileblock.LogBlock`
(`internal/fileblock/fileblock.go:425`), which writes

```
FILE_BLOCKED (tunnel %s) -> %q%q (ext=%q)
```

with the client-chosen path as the second `%q`. Six call sites reach it: four
pass `req.URL.Path` straight from the decrypted inner request (global
extension, policy profile, content type, content disposition), one passes an
origin-supplied `Content-Disposition` filename, and `inspectMagicBlock`
forwards the path for the magic-byte and polyglot blocks.

**The sweep's source gate could not see it.**
`TestChaos92_DefectEveryRetainingSinkGoesThroughTheClamp` matches lines
carrying **both** `sanitizeLog(` and `URL.Path`. This sink sanitizes in the
*callee* — `obs.Sanitize`, the deliberately independent internal twin of
`sanitizeLog` (ADR-0003) — so its call sites carry no `sanitizeLog(` token and
the gate never examined them. The gate certifies the sinks the author already
enumerated; the enumeration, not the gate, was the load-bearing step. §53.10
anticipated "a new sink that retains the path by some other route" and named
CDR-PATH-1 as that shape. This was not a new sink. It was an old one, missed.

### Measured evidence

Through `emitFileBlock`, each figure verified to **fail** against the pre-fix
tree:

| path bytes | fill | process log | log ÷ path |
|-----------:|:----:|------------:|-----------:|
| 1 048 576 | `A` | 1 048 646 | 1.0x |
| 1 048 576 | `\x00` | 1 048 647 | 1.0x |
| 1 048 576 | `\xff` | **4 194 375** | **4.0x** |

`obs.Sanitize` folds bytes `< 0x20` and `0x7F` to `_`, so a control-byte fill
costs 1x — but `0xFF` is not a control byte, and `%q` renders each one as the
4-character `\xff`. The multiplier is the client's to choose, exactly as it is
for the block page.

**It is worse per request than the five sinks that were fixed.** Those are fed
by a path net/http caps at `MaxHeaderBytes + 4096` (§53.3's ~1 MiB). This one is
fed by `http.ReadRequest` on the decrypted stream, which is
`readRequestLimit(b, math.MaxInt64)` over a `textproto.ReadLine()` with
`lim = -1` — verified in the pinned `go1.27.3` source. There is **no bound on
the inner request line at all**.

### Attack scenario

An inspected destination is allowed by policy with SSL inspection enabled —
the product's flagship configuration, and the precondition CHAOS-69 named for
the inner path. A client on the network requests
`https://allowed.example.com/<N bytes of 0xFF>.exe` inside the tunnel. `.exe`
is in the shipped `fileblock.DefaultBlockedExts`, so the file-block branch
fires with no operator configuration. The block is correct and the client is
refused — and the appliance writes `4N` bytes into a `fileutil.RotatingFile`
capped at 50 MB keeping **one** archive. Every write *succeeds*, so the logsink
backpressure counter, `storageDegraded()` and `storage_write_failed` all stay
green while ~100 MB of forensic record — including the lines describing the
flood — rotates away. That is the CHAOS-63 evidence-destruction defect
(CWE-778, OWASP A09:2021), reached on each request at a cost of one wire byte
per four retained.

**Exploitability:** trivial once inspection is on; no authentication, no
operator opt-in beyond the inspection profile. **Likelihood:** moderate —
requires reaching an inspected destination. **Impact:** destruction of the
forensic record while every health surface reports healthy. **Affected
assets:** the process log as evidence; node memory and disk write bandwidth.

### Fix

`emitFileBlock` clamps `urlPath` with the sweep's own `boundRetainedPath`,
**inside** the `fileblock.LogBlock` argument so the sanitiser's scan and its
copy are bounded too — the rule the other five sites follow. It is package
main's only route into `LogBlock`, so one edit bounds all six call sites.

**Enforcement and the client-visible response are untouched, and that
separation is the point.** `fileBlocker.CheckPath`, `FileProfileBlocked` and
every matcher ran on the whole value at the call site *before* the emitter, and
`BlockMessage` derives the 403 body from `ext` and `source` only. Clamping a
matcher input would be fail-**open**: truncating the end of a path removes the
extension a file-block rule matches on.

Not done: no bound on the inner request line itself. That is a
`MaxHeaderBytes`-shaped product decision (PATH-REFUSAL-1), and for the inspect
loop it would mean replacing `http.ReadRequest` rather than setting a server
option. Recorded, not taken.

### Required tests (all added; all verified failing without the fix)

| Gate | Proves |
|------|--------|
| `DefectTunnelFileBlockLogStaysBounded` | one inspected request cannot choose the log volume; the line says it was truncated; the counter moves |
| `DefectTunnelFileBlockClampIsTheChokepointNotTheCallSites` | **source gate**: `fileblock.LogBlock`/`BlockConn` are reachable from package main only through `emitFileBlock`, which clamps inside the argument |
| `ControlTunnelFileBlockEnforcementStillSeesTheWholePath` | the load-bearing control — a 1 MiB `.exe` path still matches with `ext=".exe"` |
| `ControlTunnelFileBlockResponseIsUnchanged` | the 403 bytes are byte-identical at 16 B and 1 MiB |
| `ControlTunnelFileBlockRetainsOrdinaryValuesVerbatim` | ordinary traffic verbatim, unmarked, counter unmoved |
| `ControlTunnelFileBlockBoundIsInclusive` | the boundary through the emitter, not only through the helper |
| `ControlTunnelFileBlockHandlesMalformedValues` | 2/3/4-byte runes straddling the cut at four offsets each, plus `\xff`/`\x00`/`\n`/`\x7f` fills: no panic, no manufactured invalid UTF-8, CWE-117 barrier intact |
| `ControlTunnelFileBlockIsConcurrencySafe` | 32 concurrent emissions, exact counter, clean under `-race` |

Authentication and authorization gates do not apply to this sink: it is on the
unauthenticated data plane and no identity decision passes through it.

Recorded in the register as **CHAOS-92e**, §53.11, with §53.1, §53.5, §53.7 and
§53.10 corrected to match.

---

## 3. F2 — a dropped revocation reported as healthy (Low)

### Affected contract

`checkSessionRevocation` (`session_revocation_bounds.go:246`), whose own doc
comment states what it is for: "a dropped entry means a session an operator
deliberately killed may still authenticate, here or on another node."

### The defect

`admitUntrustedLocked` (`internal/session/revocation_bounds.go:323`) charges
three refusals: `RevokeOversize`, `RevokeFarFuture`, `RevokeCapacity`. The row
summed the first and third. With only far-future refusals it took the `diagOK`
branch and printed `session revocation healthy (… no refusals, no drops)`. The
counter exists, is incremented, and is on the Prometheus surface — it simply
never reached the authenticated row that exists to report it.

### Why a legitimate entry lands there

The bound is `now + MaxSessionLifetime + revocationExpirySkew`.
`MaxSessionLifetime` is exactly `7 * 24h` (`internal/session/session.go:473`),
`revocationExpirySkew` is `time.Hour`, and `POST /api/session-timeout` admits
`hours` 1–168 (`ui_config.go:1764`) — 168h *is* 7 days. So at the maximum
**supported, documented** TTL the entire inter-node clock-skew budget is one
hour.

### Attack scenario — no attacker required

A cluster runs `session_timeout: 168h`. Node A's clock drifts more than an hour
ahead of node B (NTP outage, VM clock drift). An operator revokes a compromised
administrator on A; A's entry carries `expiry = A_now + 7d`. B receives it by
gossip, finds `exp.After(B_now + 7d + 1h)`, refuses it, and charges only
`farFuture`. The revoked cookie keeps authenticating on B for the remainder of
its seven-day life — it still verifies, and `IsRevoked` finds nothing — and B's
`/api/diagnostics` affirmatively reports revocation healthy. The same gap hid
the hostile case the bound was written for: a peer pinning entries the sweeper
cannot reclaim, to fill `MaxRevocationEntries`.

**Exploitability:** not directly attacker-triggerable; this is a
misreporting / fail-open-signalling defect, not a bypass primitive.
**Likelihood:** low but entirely non-adversarial — it needs a configuration the
product offers and a clock problem every cluster eventually has. **Impact:** a
revocation an operator believes took effect did not, and the surface that
should say so says the opposite. **CWE-778**, with the underlying drop
**CWE-613**. **OWASP A09:2021.**

### Fix

Add the term that already existed, and make the row actionable:

- `RevokeFarFuture` is now summed into `dropped`, with a comment binding any
  future `RevokeReason` to the same sum.
- The message names the expiry bound among the causes, so a far-future drop is
  distinguishable from an over-long key or a full cap.
- The operator action names **clock skew as the benign cause to check first**,
  which is this file's own rule (`TestChaos73_RefusalSurfaceDoesNotAssertProbing`
  exists because an earlier surface accused the operator of being attacked after
  their own key rotation).

**The bound itself is unchanged.** Widening `revocationExpirySkew` is a
security-behavior change — it would admit entries a hostile peer can pin for
longer — so it is recorded as an owner decision in §7, not taken here.

### Required tests (added; all verified failing without the fix)

`TestChaos73_DefectFarFutureDropReachesTheContractRow` drives the real gossip
path, so it measures the sum the row computes rather than a counter poked
directly. `TestChaos73_DefectEveryUntrustedDropReachesTheContractRow` is the
structural half: the row's count must equal the sum of every refusal
`admitUntrustedLocked` charges plus the Control Plane's drop, which also proves
no term is double-counted and that an already-expired gossip entry is *not*
charged (so the row cannot inflate on ordinary expiry).
`TestChaos73_DropSurfaceNamesTheBenignCause` applies the accusation rule.
`TestChaos73_ControlCleanStateStillReportsHealthy` is the negative control: the
widened sum must not make an untouched node warn.

---

## 4. F3 — the CWE-117 rule applied at three sinks out of four (Low)

### Affected contract

`docs/agent-context/conventions.md`: untrusted log values are wrapped with
`sanitizeLog` and printed with `%q`, with the barrier inline so CodeQL
recognises it.

### The defect

`applyAddressesLocked` (`controlplane_client.go:1119`) adopts the CP config
snapshot's `cp_addresses` verbatim into `c.addrs`, and the line this window
added right beside it says so explicitly: "Both lists are peer-supplied —
`addrs` arrives verbatim in the CP's config snapshot — so they are untrusted log
values under the CWE-117 rule." Four older sinks in the same file printed an
address from that same list with a bare `%s`: `connect`'s insecure-mode and
connected lines, and `failover`'s two. `validateConfigSnapshot` count-caps
`cp_addresses` at 100 and never validates an entry as `host:port`, so a newline
inside one forges records.

### Attack scenario

A compromised Control Plane — or a MITM where `--cluster-insecure` is set —
publishes `cp_addresses: ["a:1\nControlPlane: <forged line>"]`. Every Data Plane
that polls the snapshot writes forged records into its process log and into
every downstream syslog/OTLP consumer. Such a Control Plane already dictates the
Data Plane's policy, so the marginal impact is log integrity only — hence Low.
But the contrast inside one file is the kind of inconsistency that rots, and
CodeQL enforces the rule.

### Fix

All four sinks use `sanitizeLog` with `%q`; the failover line sanitizes the
wrapped error too, since `connect`'s `"gRPC dial %s"` carries the same address.
Pinned by `TestCWE117_CPAddressLogSinksAreSanitized`, a source gate that fails
if any `logger.Printf` in that file prints `addr`/`nextAddr` without the
barrier, and fails *loudly* if the pattern drifts to nothing.

Not done: rejecting non-`host:port` or over-long `cp_addresses` entries in
`validateConfigSnapshot`. That changes what a snapshot admits — a
compatibility and availability decision for the cluster owner — and is recorded
in §7 instead.

---

## 5. Repository hygiene fixed in passing

`.github/scripts/__pycache__/security-exceptions.cpython-311.pyc`, 8 105 bytes
of compiled Python, was committed by accident in `ef95780` (a test-anchoring
commit in the CHAOS-92 sweep). The follow-up `36efd12` added `__pycache__/` and
`*.pyc` to `.gitignore` with the note "Generated, never committed" and the
claim that no `.pyc` is tracked anywhere — but `.gitignore` does not govern a
tracked path, so the rule was inert for the one file it was written for
(`git check-ignore` skips tracked files, which is how this was confirmed).

Exploitability is nil in practice and was checked rather than assumed: the
header's flag word is `00000000`, i.e. timestamp-based, not a PEP 552
`unchecked_hash` pyc, and git sets checkout mtimes to checkout time, so CPython
invalidates and regenerates it. The file is removed from the index, which makes
the sibling commit's statement true. Nothing references it; CI invokes the
`.py` directly.

---

## 6. Regression analysis

**No authentication or authorization regression exists in this window.** That
is a positive finding, checked rather than assumed:

- Every `requireRole` gate in `ui_auth.go` is untouched; the file's only change
  is the `apiAuthLogout` body. `/api/auth/logout` is public *by design*, and it
  needs no CSRF token: `ps_ui_session` is `SameSite=Strict` and `ps_session` is
  `SameSite=Lax`, so a cross-site POST carries neither cookie.
- `/api/stats` — which gained two counters this window — still gates on
  `requireRole(w, r, RoleViewer)`, and the new fields are integers rendered
  through `textContent`.
- Audience separation is intact: `classifyUISession` still requires
  `sess.Provider == uiSessionProvider` plus `cfg.UIUserExists(sess.Sub)` before
  any role is assigned.
- Every Control Plane RPC that gained a field or a bound still gates on
  `verifyNode` → `verifyNodeCert`, which requires the peer certificate serial
  to equal the *claimed* node's enrolled serial plus a revocation check, so the
  new `AuditClusterPushDrops` field cannot be spoofed across nodes.
- mTLS is unchanged: the new redial path in `applyAddressesLocked` goes through
  the same `connect()`, so it cannot downgrade the transport.

**No fail-closed → fail-open regression exists.** Every change in that family
moves the other way (CHAOS-73, BKP-1, SEC-POLICYACTION-1's diagnostics half,
CHAOS-84's seven clock gates, the upstream circuit breaker's half-open
re-anchor, `cdrUnavailableOutcome`). The three findings above are all
*evidence* regressions, not control regressions — which is precisely why they
pass a diff read.

**Policy engine.** The one-allocation rulebase publication was checked for the
two ways it could have gone wrong and did not: the permutation is identical
(same comparator over the same input sequence, with `Priority` preserved by the
clone), and `copyPolicyRuleForPublication` is the same deep-copy helper the
previous `clonePolicyRuleForPublication` wrapped, so no nested slice or map is
now shared with a live rule. The contiguous backing array is not retained by a
single rule pointer either, because `PolicyMatch` carries its own
`ruleSnapshot`. Default-deny behaviour is unchanged.

**Backward/wire compatibility.** The revocation `Prov` field is `omitempty` and
never emitted by `ExportRevocations`, so a pre-window peer round-trips cleanly;
`provenanceDomain` ends in `\x00`, which no base64url payload can contain, so a
provenance value can never function as a cookie signature. The CDR sidecar wire
contract is untouched — verified that `cdrRequestContext.URL` never leaves the
process except through `cdrFilenameFromURL`, so CDR-PATH-1's recorded scope is
complete and needs no second row.

**Dependencies.** Upgrades only, no downgrades, no new direct modules
(`kin-openapi` 0.151→0.152, etcd 3.7.2→3.7.3). All workflow changes are
pinned-action version bumps apart from one correct addition of
`./internal/session` to the `benchgate` job — a new gate package added to the
job that runs it, which is the rule `verification.md` states.

**Legacy UI.** No new `innerHTML`. The logging posture tile moved from an
else-if chain to collecting every concurrent warning, which is an improvement
(it previously masked all but the first), and renders through `textContent`
plus a `title` property assignment.

---

## 7. Sub-threshold observations (recorded, not fixed here)

1. **`revocationExpirySkew` leaves no skew budget at the maximum supported TTL
   (owner decision).** One hour of tolerance against a 168-hour TTL that the
   API explicitly admits. Raising it admits entries a hostile peer can pin for
   longer, so it is a deliberate trade and not a reviewer's call; F2 at least
   makes the consequence visible. The alternative — clamping an untrusted
   expiry down to the bound instead of dropping the entry — would retain a
   *shorter* revocation than the issuer intended, which is its own fail-open.
2. **`cp_addresses` entries are never validated as `host:port` and have no
   per-entry length bound** (`controlplane_snapshot.go`), so `c.addrs` retains
   unbounded peer-supplied strings. F3 bounds the *log* consequence; validating
   the snapshot field changes what a cluster admits and belongs to the cluster
   owner.
3. **The Control Plane's cluster audit ring is bounded by entry count (5 000),
   not bytes**, while `audit.Entry`'s `Detail`/`Before`/`After` are unbounded
   and the inbound frame budget is 16 MiB. A compromised *enrolled* node can
   grow retained CP memory far past any intended bound — the same DP→CP
   direction CHAOS-73 just bounded for revocations, left unbounded for audit.
   Pre-existing, out of window; worth a byte budget.
4. **`maxRevocationsPerNode` (4 096) is 16x tighter than the data-plane
   `MaxRevocationEntries` (65 536)**, so a node holding more than 4 096 live
   revocations has the surplus dropped at the Control Plane and never fanned to
   peers. The drop *is* counted and does reach the row F2 fixes, so it is now
   fully surfaced — but two caps an order of magnitude apart deserve a
   deliberate decision.
5. **Crash-orphaned partial plaintext backup archives now accumulate.** The
   `os.CreateTemp` fix (§1's BKP-2) means a SIGKILL mid-backup leaves a
   `.culvert-backup-<random>` file rather than reusing one fixed `.tmp` name,
   and nothing sweeps them (`--cleanup-restore-leftovers` targets the data dir).
   They appear in `--list-backups` with `encrypted:false`, since
   `runListBackups` has no dot-prefix filter, but cannot be restored through the
   agent (the filename validator rejects a leading dot). Mode 0600, same
   directory and same secret class as the real archive — operator-visible noise
   and disk hygiene (CWE-459), not new exposure. Smallest fix is a dot-prefix
   skip in `runListBackups`; not worth a code change on security grounds alone.
6. **Two documentation inaccuracies, no code impact.** `inspect_host_pin.go`
   says "Both are fixed" of two mixed-case examples, but only
   `BÜCHER.example.com` is refused — `Bücher.example.com` still pins, correctly,
   because its A-label is an ASCII case variant of the authorized one (the
   test table states this, and the later bullet scopes it right).
   `backup.go`'s comment says `os.CreateTemp`'s 0600 "is still filtered through
   the umask"; umask can only clear bits, so `CreateTemp` alone could never have
   published wider — the explicit `Chmod` is belt-and-braces. Neither changes
   behaviour.
7. **No warning when both rate-limit keys are set and disagree.**
   `rate_limit: 1000` plus `rate_limit_rpm: 0` silently disables per-IP rate
   limiting. This is the documented, reviewed precedence from #1504 and requires
   an admin to author that pair, so it is not a reachable attacker path and not
   a changed default (absent-key default is `0`/off, as before). One
   `logger.Printf` on disagreement would be the improvement. Verified that
   `fc.validate()` runs *before* `reconcileDeprecatedRateLimitKey`, so no
   negative value can slip through reconciliation on either key.

---

## 8. Scope NOT reviewed — read this before treating the window as closed

- **`logstore` and the request-log entry type.** F1 bounds what reaches
  `logstore.Entry.URI` through `policyLogURI` and `emitFileBlock`, but the
  entry type's own fields and the redaction pipeline were read only where a
  slice's contract touched them.
- **Frontend bundles.** `frontend/dist/*` was not verified to be reproducible
  from `frontend/src` at this revision. A tampered or stale `dist` is a
  supply-chain and XSS surface source review does not cover.
- **The 2026-10-24 review's own unreviewed backlog**, and everything before
  `266e684`, which no run in this role has reached.
- **Non-Go, non-workflow changes** beyond `static/index.html` and the
  documentation touched by the findings.
- **Hosted gates.** Everything in §9 is a local, focused result for this
  working tree. No aggregate CI run, no golangci-lint (see §9), no CodeQL, no
  DAST. A passing local check is not a passing merge gate.

---

## 9. Verification performed

Toolchain `go1.27.3` (from `go.mod`'s `toolchain` line; `go env GOVERSION`
confirms), on this working tree.

| Check | Result |
|---|---|
| `go build ./...` / `CGO_ENABLED=0 go build -ldflags="-s -w"` | clean |
| `go vet ./...` | clean |
| `go mod tidy -diff` | empty |
| `gofmt -l` (changed files) | clean |
| `go test -race -count=1 -run 'TestChaos92_\|TestC5_\|TestH1BlockResponder\|TestCharacterize_\|TestChaos69\|TestScanBlockConn\|TestTestFileReadsAreCWDIndependent' .` | ok — 66 tests |
| `go test -count=1 -run 'TestChaos73_\|TestCWE117_CPAddress\|TestChaos92_' .` | ok |
| `python3 docs/agent-context/check.py` | ok |
| `golangci-lint run --new-from-rev=origin/main` | **BLOCKED — not run.** The installed binary is v2.5.0 built with go1.25.1; CI pins v2.15.0 and this tree compiles with go1.27.3. The old binary panics inside `go/types` loading these sources. Reported rather than worked around; no gate was weakened to obtain a pass. |
| `go test -race -count=1 -timeout=40m .` (full root package) | 2 305 s; fails only the nine recorded TEST-DNS-1 cases |
| `TEST_SEED=20260421 go test -count=1 -timeout=30m .` (full root package, enumerating) | **exactly 9 failures**, all `TestIdPRegistry_*`/`TestAPIIdP*`, each `idp oidc issuer: URL must be https:// and must not point to a private address` |
| The same nine, run on `origin/main` in a clean worktree | **all nine fail identically** — verified pre-existing and environmental, not inherited from prose |

The nine are the register's **TEST-DNS-1** row (§53.8): `validateExternalURL`'s
fail-closed DNS check is working correctly, and the IdP fixtures chose
`example.com` on the assumption that a resolver answers for it. `getent hosts
example.com` returns nothing in this sandbox, so the precondition holds here.
None of the nine touches any contract these commits change (IdP/OIDC
persistence and redaction, versus the proxy data path, the revocation
diagnostics row and the Control Plane address log).

**Negative controls — every fix verified to fail without itself:**

- **F1:** reverting the one-line clamp makes seven of the eight gates fail,
  printing the measured numbers (1 048 646 log bytes for the `A` fill,
  4 194 375 for `\xff`), and the source gate prints the unclamped
  `emitFileBlock` body.
- **F2:** removing the `RevokeFarFuture` term makes
  `DefectFarFutureDropReachesTheContractRow` fail with the literal pre-fix text
  `session revocation healthy (0 entries tracked, no refusals, no drops)`;
  reverting the message changes makes `DropSurfaceNamesTheBenignCause` fail;
  `DefectEveryUntrustedDropReachesTheContractRow` fails with a count of 1
  against an expected 2.
- **F3:** reverting two of the four sanitizations makes the source gate fail
  and name both lines.
- **§5:** `git check-ignore` reports no rule for the tracked `.pyc`, which is
  how the inert-`.gitignore` claim was established.

**Method note.** Four slices were delegated with bounded file lists and explicit
regression classes (backup/restore crypto; control plane and cluster;
sessions, revocation and admin auth; scanners, request logging, PAC, OCSP,
upstream, config and the inner-host pin); the proxy data path, policy
publication, diagnostics, legacy UI, CI and dependencies were taken directly.
Every finding acted on was re-verified against primary evidence before any code
changed — which is how F2's trigger was established as non-adversarial
(`MaxSessionLifetime`, `revocationExpirySkew` and the `hours must be 1–168`
validator each read at the revision rather than taken from a summary), how F3's
contrast was confirmed (both the sanitized and the bare sinks read in place),
and how F1's magnitude claim was settled (`readRequestLimit(b, math.MaxInt64)`
and `readLineSlice(-1)` read in the pinned stdlib source, not recalled). Two
reported items were checked and *not* acted on: the cluster-CA working-directory
hypothesis, which does not hold — the change is strictly narrower than the
behaviour it replaced — and a `revocationExpirySkew` widening, which is a
security-behaviour change reserved for the owner.

---

## 10. Residual risk

- **The inner request line is still unbounded on the wire.** F1 removes the
  retention amplification, leaving one copy of the path in the request object —
  the cost of any header. Bounding admission is PATH-REFUSAL-1, and on the
  inspect path it means replacing `http.ReadRequest`, not setting
  `MaxHeaderBytes`.
- **CDR-PATH-1 remains the open egress sink** for the request path and is
  unaffected by F1's clamp; its recorded scope was re-verified as complete.
- **Source gates are textual.** They now fail on an unbounded
  `sanitizeLog(…URL.Path)` site, a direct `blockpage.Serve` call, a direct
  `fileblock.LogBlock`/`BlockConn` call, and an unsanitized CP-address sink —
  the four shapes known to reintroduce these defects. A sink that retains a
  value by some other route still would not trip them. F1 is the evidence that
  the enumeration, not the gate, is the step that fails.
- **F2 reports the drop; it does not prevent it.** A cluster at
  `session_timeout: 168h` with more than an hour of skew still drops legitimate
  remote revocations. It now warns, names clock skew first, and tells the
  operator to invalidate every session at once if they cannot wait — but the
  bound is unchanged pending the owner decision in §7.
- **Nothing here was run against a hosted gate.** golangci-lint is blocked in
  this environment for the reason recorded in §9, and CodeQL, DAST and the
  aggregate Fast/Deep gates have not run on these commits at the time of
  writing.
