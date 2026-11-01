# Security Regression Review — 2026-11-01

**Scope.** `8138243…3c5fab1` (`origin/main`) — the 24 h since the 2026-10-31
review, 8 merged pull requests (#1771 #1772 #1773 #1774 #1775 #1776 #1777
#1778), 31 files, +3,753/−154. Twelve production Go files changed, ten test
files, the install script, the legacy GUI, the CHANGELOG and six roadmap /
design documents.

| PR | Change | Security surface |
|---|---|---|
| **#1771 / #1773 / #1777 / #1776** | CHAOS-107 — the scan verdict cache is reconciled against the ClamAV signature set it was computed under, a flush advances a cache generation, and a verdict begun before a flush is refused publication | scanning, cache integrity, TOCTOU, policy enforcement, observability |
| **#1776** | `security_scan.go` — the CHAOS-106 call-site wall DISCOVERS its inputs (`go/ast` over every non-test file) instead of checking a hard-coded three-file list; the S-1 fix from the 2026-10-31 review | gate integrity, scanning, request/response processing |
| **#1775 / #1774** | `proxy_sslinner_line.go` — the per-inner-request `SSL_INNER` line is rendered by appends into a pooled carrier instead of `logger.Printf` with six verbs | logging, CWE-117 barrier, proxy hot path, observability contract |
| **#1772** | An unreadable `admin_settings.json` is surfaced in the authenticated diagnostics and alerted, not only logged | diagnostics, information disclosure, RBAC, configuration integrity |
| **#1778 / #1772** | `scripts/install.sh` — `env_put` no longer deletes `.env` lines holding non-UTF-8 bytes; CHAOS-79 write-failure gate test tightened | deployment, configuration durability |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed 24 h ago?** Every finding is measured against
`8138243`, not against an ideal.

**Method.** The CHAOS-107 generation fence was traced through *every* writer of
the verdict cache rather than through its diff hunks — `publishVerdict`,
`cacheTimeoutCooldown` and the `CacheSet` accessor — because a fence that
covers two of three publication paths is not a fence; and `SetIfGeneration`'s
TTL was compared against the `Set` it replaced (`SetTTL(…, 0)` → `c.ttl`) so the
fence could not have silently lengthened a cached clean. `ClamAVVersion`'s
conversion from `defer ss.mu.Unlock()` to three hand-placed unlocks was read on
every return path, since a missed unlock on the scan path is a node-wide hang.
The `SSL_INNER` rewrite was accepted only against its in-tree differential
oracle (a frozen copy of the deleted format string), and the pooled carrier's
hand-back was checked against what `log.Logger.Output` and
`internal/logsink.Writer.Write` actually do with the bytes they are handed
(both copy — verified in source, not taken from the doc comment). The
`admin_settings` read-failure path was read for the ENOENT case, for the
viewer-role path-free contract, and for the record-precedence collision with
`noteResidualQuarantine`, which runs on the same kind twenty lines earlier.

Four hypotheses were formed against the window's own claims and **disproved**:
that the CHAOS-107 fence leaves the remote-sidecar adoption path unfenced (no
production caller of `CacheSet` exists; the doc comment claiming one is stale);
that the hand-unlocked `ClamAVVersion` leaks `ss.mu` on the error path (all
three paths unlock); that the pooled `SSL_INNER` carrier can carry one
request's line into another's (`*bp = b` precedes the cap guard, the slice is
re-sliced to `[:0]` on every Get, and both downstream sinks copy); and that
`noteStateFileUnreadable` fires on a first-run node with no settings file
(`os.IsNotExist` returns first, two branches earlier).

The one finding that survived was **proved in both directions** against the
merged revision: the probe it bans passes the wall as merged and fails the wall
as fixed, naming the offending line.

---

## 1. Executive Summary

**No security regression was introduced in this window.** The two
security-relevant changes both move the posture forward in the direction their
own documentation claims, verified against production callers rather than
taken on trust:

- **CHAOS-107** closes a real, exploitable staleness window: a verdict cached
  under last week's ClamAV definitions was served, by exact content hash, to
  every user on the node for the remainder of `CacheTTL` after `freshclam`
  landed the signature that would have caught it. The generation fence is
  complete over every production writer of the cache, is conservative in the
  only direction that matters (it refuses verdicts rather than admitting
  them), and correctly refuses to flush on a *failed* `VERSION` query, which
  would otherwise hand any daemon blip a free node-wide cache wipe.
- **The `SSL_INNER` rewrite** keeps the CWE-117 barrier on every operand and is
  byte-identical to the format string it replaces, which is the acceptance
  condition that matters: these lines are the edge-case lab's interception
  witness and are parsed by SIEM forwarders.

The review found **one weakness in gate integrity**, in the structural wall
that this window rewrote. The rewritten wall requires every
`decompressForScan` call site to "bind both results, name the refusal rather
than `_`, and branch on that name" — but it searches for that branch across
the **whole file**, and `bomb` is the name every conforming site in the tree
already uses. So the first conforming site in a file vouches for every later
site in it: a second response path added to `proxy_tunnel.go`, `proxy_http.go`
or `cdr_proxy.go` that binds `bomb` and never branches on it passes the wall,
and the wall reports a clean gate while the bypass it exists to ban is live.

This is **not a posture regression** — the pre-window wall's
`strings.Contains(src, "if bomb {")` was blind on the same axis — but it is the
hole the rewrite was the moment to close, in the same gate and the same family
as the finding fixed 24 h ago, and it sits in the files a fourth response leg
is most likely to be added to. It is fixed here, and the fix is proved against
a probe the merged wall accepts.

| # | Finding | Severity | Status |
|---|---|---|---|
| **S-1** | The CHAOS-106 call-site wall enforces its branch rule file-wide, so a second `decompressForScan` site in a file that already branches on the same identifier passes unseen. Proved in both directions | **LOW** security / **MEDIUM** gate integrity (latent — no such caller exists; not a regression, the prior wall shared the blindness) | **FIXED + proved + negative control** |

---

## 2. Security Findings

### S-1 (LOW security / MEDIUM gate integrity) — the rewritten CHAOS-106 call-site wall lets the first compliant call site in a file vouch for every later one

**Affected contract.** `decompressForScan` (`security_scan.go`) returns
`(nil, true)` when a declared `Content-Encoding` claims an expansion past the
ratio allowance. The bound is a defense only if **every** caller fails closed
on that second value; the compiler forces the value to be received, not
consulted. `TestCHAOS106_EveryDecompressCallSiteConsultsTheRefusal`
(`chaos106_decompress_failclosed_test.go`) is the sole gate that enforces the
consultation.

**The defect.** `chaos106CallSiteViolations` classified each call site by
asking `chaos106BranchesOn(f, id.Name)` — whether *any* `if` condition **in the
file** tests the bound identifier. All three live sites bind the refusal to
`bomb`, and all three files therefore already contain `if bomb {`. A second
site in any of those files that binds `bomb` and never branches on it is
classified **conforming**.

Evidence, against the merged wall at `3c5fab1`, on a fixture holding one
compliant site and one bypass, both naming `bomb`:

```
sites=2 violations=[]
```

Two call sites found, zero violations reported — a clean gate over a live
bypass.

**Attack scenario.** An engineer adds the fourth response path the CHANGELOG
itself names as the expected next one (an H3 leg, a second CDR stage, a
request-direction scan) to `proxy_tunnel.go` — the file that already carries
`if bomb {` for the H1 inspection path, and the natural home for an H1-side
second stage. The new code buffers a response, calls
`scanBody2, bomb := decompressForScan(body, ce)`, and omits the refusal
branch. CI is green: the wall finds the call site, finds `bomb` bound by name,
finds `if bomb {` elsewhere in the file, and reports a conforming gate. On that
path the scanners are then handed the **compressed** bytes.

**Preconditions.** A new or extended `decompressForScan` call site in a file
that already holds a conforming one, binding the same identifier, with no
branch of its own. No attacker action is needed to create the condition — it is
created by a routine code change — and none of the repository's other gates
covers it.

**Exploitability (once the condition exists).** High and attacker-chosen. The
origin controls the `Content-Encoding` header and the compressed payload, so it
chooses the expansion ratio. A payload declaring an expansion past the bound
causes the refusal to be raised and dropped; the path then scans the compressed
stream, in which ClamAV signatures, YARA rules, the archive-magic check and the
Content-Type/magic-byte polyglot check all fail to match simultaneously.
Content is delivered to the client unscanned, with no block, no counter and no
log line — indistinguishable from a clean verdict.

**Likelihood of the precondition.** Moderate. It is exactly the change the
window's own CHANGELOG anticipates, in the three files the gate already
watches, and the identifier collision is not a coincidence: `bomb` is the
house name for this value, so a copied-and-adapted call site inherits it.

**Impact.** Complete scanner bypass on the affected response path:
malware/polyglot delivery through an inspecting gateway, which is the
product's primary control. **Affected assets:** inspected HTTP and
decrypted-tunnel response bodies; every downstream client on the node.

**Regression risk.** Latent, not live: no such call site exists at
`3c5fab1`, verified by the fixed wall over every non-test file in package
main. The risk is that the gate reports success at the moment it should fail.

**CWE / OWASP.** CWE-693 Protection Mechanism Failure (the gate), reaching
CWE-1025 / CWE-184 Incomplete List of Disallowed Inputs on the production
path it guards; OWASP A04:2021 Insecure Design, with the guarded defect under
A05:2021 Security Misconfiguration. Security severity: **LOW** today (latent),
**gate integrity MEDIUM** — a silent gate is worse than no gate, because it is
read as evidence.

**Fix (shipped here).** The branch is scoped to the **function** that holds the
call, not to the file. `chaos106CallSiteViolations` now walks each
`*ast.FuncDecl` body as its own scope and hands every nested `*ast.FuncLit` its
own scope, so a refusal bound inside a closure cannot be excused by an `if` on
the same name in the enclosing function — a different variable.
`chaos106BranchesOn` takes that scope instead of the `*ast.File`. A call site
in no function at all (a package-level `var` initializer) is classified by
neither branch and reaches the counting pass as a violation, which is correct:
nothing there can fail closed.

Kept deliberately permissive inside the scope (`if bomb`, `if bomb || x`, and a
branch inside a closure defined in the same function all count), because the
only thing that reopens the bypass is the branch's **absence**. The three live
sites are unaffected — each binds and branches inside one function body — which
the wall itself confirms by still passing over the real tree.

**Safe implementation note.** The fix is test-only. No production behavior
moves, the `chaos106RefusalFloor` anchor is unchanged, and the wall remains
`go/ast`-based rather than textual.

**Required tests (shipped).**

- `TestCHAOS106_CallSiteWallScopesTheBranchToItsOwnFunction` — the negative
  control for this exact shape: two sites in one file binding the same name,
  only the first failing closed. It asserts **both** directions — the bypass is
  reported, *and* its compliant neighbour is not — and asserts the reported
  `file:line` is the bypass, because a wall that counted the right number of
  violations while naming the wrong line would send the next editor to correct
  working code.
- `TestCHAOS106_CallSiteWallRejectsADiscardedRefusal` (pre-existing, unchanged)
  — the four banned shapes and the over-strictness control still pass.
- `TestCHAOS106_EveryDecompressCallSiteConsultsTheRefusal` (pre-existing) —
  passes over the real tree with the stricter rule, which is the no-false-
  positive control.

**Proved in both directions.** Same fixture, two walls. The wall as merged
reports `sites=2 violations=[]`. The wall as fixed reports one violation:

```
chaos106probe.go:12:16: binds the refusal to bomb but no `if` in the function
that holds the call branches on it, so nothing fails closed
```

---

## 3. Regression Analysis — surfaces reviewed and found clean

### 3.1 CHAOS-107 — the verdict-cache generation fence

- **Fence completeness.** Every production writer of the hash cache was
  enumerated, not just the one the diff touches.
  `publishVerdict` (all three verdicts: ClamAV block, YARA block, clean) now
  routes through `SetIfGeneration`. `cacheTimeoutCooldown` still uses
  `SetTTLUnless` and is deliberately outside the fence: it writes a **block**
  under a 30 s cooldown and under a tighten-only predicate, so it can only
  refuse content, never admit it. `Scanner.CacheSet` — whose doc comment claims
  "remote-scan result adoption" — has **no production caller**; the claim is
  stale. So no production path can publish a verdict past the fence.
- **No silent TTL extension.** `SetIfGeneration` writes
  `time.Now().Add(c.ttl)`; the `Set` it replaced is `SetTTL(hash, r, 0)`, and
  `SetTTL` substitutes `c.ttl` for a non-positive TTL. Identical lifetime. A
  fence that had quietly moved a cached clean onto the default TTL would have
  been a regression wearing a fix's doc comment.
- **Atomicity.** The generation compare and the store are inside the single
  `c.mu.Lock()` that `Invalidate` also takes, so no flush can fall between
  them. `gen` is an `atomic.Uint64` only so `Generation()` stays off the lock at
  scan start; every write is under `mu`.
- **Direction of error.** The epoch is captured *before* either engine runs, so
  a flush landing between the ClamAV and YARA legs is seen. The fence can only
  **discard** a verdict (the next request re-scans); it never admits one, and it
  never changes the current request's result. Observation lag between
  `freshclam` landing a signature and the node noticing it therefore produces
  conservative refusals, not stale cleans.
- **Fail-open check on the observer.** A failed `VERSION` query does not flush.
  Traced and agreed with: flushing on observer faults would let one daemon blip
  wipe the cache node-wide and send every subsequent body to the daemon that
  just failed to answer — the self-sustaining saturation `scanBodyInner`'s
  cancellation exists to prevent (CHAOS-52/53). The dark window cannot
  accumulate *new* false cleans either, because the pre-existing `clamDark`
  branch already refuses to cache a clean computed while ClamAV was unreachable.
- **Lock discipline.** `ClamAVVersion` lost its `defer ss.mu.Unlock()`. All
  three return paths were read: the `clam == nil` and cache-hit paths unlock
  before returning, the error path unlocks before `return`, and the success path
  unlocks before `rec.apply`. `rec.apply` deliberately runs outside `ss.mu`,
  which keeps the scanner lock off the hash cache's lock-ordering graph. No
  path can leave `ss.mu` held.
- **Re-baselining.** `Init` clears both `sigGen` and `sigGenKnown` alongside the
  version cache, so a reconfigured daemon re-baselines instead of being compared
  against the previous daemon's counter. An unidentifiable reply (`gen == ""`)
  is not recorded at all, so it neither flushes now nor manufactures a change
  later.

### 3.2 The signature-generation poller (`scan_signature_watch.go`)

Parented to the lifecycle context, so it exits on shutdown. `runGuarded` wraps
the **round**, not the goroutine, so a transient fault costs one interval
instead of silently disarming the observer for the process lifetime — which
would have reintroduced the exact window with the dashboard still green.
`globalSecScanner` is initialised at package scope (`secscan.New`), never nil,
so the unguarded `ss.mu.RLock()` in `ClamAVVersion` cannot be reached on a nil
receiver; the panic guard is a backstop, not the primary argument. The poll
interval (5 min) is deliberately shorter than the `VERSION` cache (10 min), so
a tick inside the previous window is free.

### 3.3 The `SSL_INNER` emitter (`proxy_sslinner_line.go`)

- **CWE-117 barrier preserved and relocated, not removed.** `clientIP`,
  `method`, `hostOnly` and `path` all pass through `sanitizeLog` at the single
  point each reaches the line, inside the emitter, before the sink — the same
  place the `Printf` form had it. `path` keeps its `boundRetainedPath` bound.
  The profile name keeps `%q` semantics through `appendQuotedForLog`, which is
  pre-existing and already proved equal to `strconv.AppendQuote` by
  `proxy_policylog_test.go`. The filter token reaches the buffer bare because it
  is one of two compile-time constants, which is what the replaced `%s` did.
- **Byte-identity.** Accepted only against the in-tree differential oracle:
  `sslInnerLineLegacy` is a frozen verbatim copy of the removed format string
  and argument list, and `TestSSLInnerLine_RenderIsByteIdentical` renders every
  branch both ways and requires the bytes to match, with each awkward value
  (control bytes, non-ASCII, quote, backslash) driven through every operand
  position. This matters beyond aesthetics: `EDGE-CASE-LAB-ARCHITECTURE.md`
  reads `SSL_INNER` as the MITM witness, and SIEM forwarders parse it.
- **No cross-request content leak through the pooled carrier.** Checked rather
  than assumed: the carrier is re-sliced to `[:0]` on every acquisition;
  `logger.Printf` has returned before the buffer is handed back;
  `log.Logger.Output` appends the formatted bytes into its own reused `l.buf`
  before calling the destination `Write`; and `internal/logsink.Writer.Write`
  copies into its own pooled carrier before queueing
  (`*bp = append((*bp)[:0], p...)`, `internal/logsink/logsink.go:142`). An
  oversize carrier is dropped rather than pooled, so one 2 KiB path cannot make
  every carrier permanently that large.
- **H1/H2 parity is now structural.** Both transports call one emitter, so the
  two lines cannot drift apart by hand — a parity improvement, not a regression.
- **Call depth.** `Printf` fixes its own depth, so under `Lshortfile` the line
  would attribute to the emitter rather than the caller. Inert in the shipped
  configuration (`setupLogger` uses `LstdFlags` only); recorded in the file.

### 3.4 Unreadable `admin_settings.json` in diagnostics

- **Viewer-role path-free contract upheld.** The `state_file_admin_settings`
  row carries no path and no filesystem layout, matching
  `checkStateFileIntegrity`'s documented contract for the viewer-role
  `/api/diagnostics`. The full detail, path included, stays in the process log
  and the `state_file_corrupt` alert payload — which is the pre-existing split
  (`quarantineCorruptStateFile` does exactly the same), not a new disclosure.
- **No first-run false positive.** `os.IsNotExist(err)` returns two branches
  earlier, so a node with no settings file yet does not get a `diagFail` row
  claiming its GUI-saved settings are not in effect.
- **`/ready` gating unchanged.** `noteStateFileUnreadable` writes only
  `stateCorruptionRecordByKind`, never `stateCorruptionByKind`, so the
  unauthenticated readiness probe and its strict gating are untouched — which
  is what keeps a permissions problem from taking a node out of a load-balancer
  pool.
- **Record precedence traced.** `noteResidualQuarantine("admin_settings", path)`
  runs ~20 lines earlier on the same kind, and `noteStateFileUnreadable`
  assigns unconditionally, so it can overwrite a same-boot `Residual` record.
  Benign and not a defect: `ReadFailed` is matched first in
  `checkStateFileIntegrity`, so the same row would be rendered either way; the
  residual alert has already fired; `stateCorruptionByKind` retains the
  residual detail for `/ready`; and the only field lost (`ResidualCount`) is not
  rendered for a `ReadFailed` row. The reverse order cannot occur.
- **The file is never moved or modified**, preserving the documented
  read-error posture (a rename needs only directory permissions and could move a
  healthy file aside on a transient blip).

### 3.5 `secScanStatusMapRemote` extraction

Behavior-identical to the inlined branch, hunk for hunk: the three
node-identity keys are still re-asserted after the sidecar's `/status` is
merged, `redactURLUserinfo` is still applied to every exposure of the
configured URL, the unreachable branch still reports only the **bounded**
`ProbeFailureReason` class rather than the raw error (which can carry
userinfo onto a viewer surface), and `stat_decompress_bombs` is still
overridden with this process's counter. The new `stat_scan_sigdb_invalidations`
key is **not** overridden in the remote branch; traced and correct — the
sidecar runs the same binary in local mode, so its `/status` carries its own
value, and in remote mode the sidecar is where ClamAV and its definitions live,
making the far end's counter the meaningful one (unlike the CHAOS-106 refusal,
which happens locally). Recorded as residual risk only for the mixed-version
case.

### 3.6 `scripts/install.sh` — `env_put`

`LC_ALL=C grep -avE` is strictly **less** destructive than the form it
replaces: under a UTF-8 locale, GNU grep classified a `.env` holding invalid
UTF-8 as binary and omitted the line from `-v` output, silently deleting a
hand-edited operator line — including, potentially, a security-relevant
setting. Byte-wise matching in the C locale still matches the ASCII
`^VAR=` prefix, so no line that was previously removed is now retained, and
`-a` only changes grep's binary handling, not the filter. The atomic
`mktemp`/`mv` and the `rc` guard against truncation are unchanged.

### 3.7 Test and global-state hygiene

The new test files restore what they mutate: `proxy_sslinner_line_test.go`
restores `logger` on every path (`defer`/`t.Cleanup`);
`proxy_path_bounds_test.go` uses `setupProxyTest`, registers
`snapshotPolicyStoreForTest`, restores `fileBlocker`, and — correctly —
restores the default policy action **together with** the rules, which is the
pairing `conventions.md` requires;
`admin_settings_corruption_test.go` registers `rewriter.Snapshot()` cleanup.
No new test asserts on audit-ring length deltas.

---

## 4. Residual Risk

1. **The wall still cannot see an indirect call of the seam.**
   `chaos106IsDecompressCall` matches a direct `*ast.Ident` call, so
   `f := decompressForScan; f(body, ce)` is neither counted nor checked.
   Contrived, and no such shape exists; closing it needs type information
   (`go/types`) rather than a syntax walk. Reported, not taken.
2. **Alternating signature identity re-flushes the cache.** `clamAddr` may be a
   TCP address; several `clamd` replicas behind one VIP, mid-`freshclam`
   rollout, can answer `VERSION` with different `DBVersion` values, flushing the
   verdict cache on each differing observation (at most once per ~5 min). The
   consequence is a cold cache and elevated scan load, which fails **closed**
   (`stat_scan_timeout`), so it is availability pressure, not a bypass — but it
   is worth a bound if clustered `clamd` becomes a supported topology.
3. **The stated alert condition is manual.**
   `culvert_scan_sigdb_invalidations_total` staying at zero while the reported
   signature counter advances is, by the change's own documentation, the alert
   condition — but there is no `OperatorContractCheck` row that performs that
   comparison, and `stat_scan_sigdb_invalidations` has no `setMetric` tile on
   the legacy Security panel (every neighbouring scan counter does:
   `static/index.html:9925–9936`). A GUI-only operator cannot see the counter at
   all, and no automated surface performs the comparison. Observability gap, not
   a posture regression, and the CHANGELOG scopes the claim honestly to the
   status JSON, Prometheus and the support bundle.
4. **Mixed-version sidecar.** In remote mode `stat_scan_sigdb_invalidations`
   arrives only via the blind merge of the sidecar's `/status`, so a sidecar
   older than this window reports no value and the panel reads zero — which is
   indistinguishable from "never adopted new definitions", the alarm shape.
5. **`Scanner.CacheSet`'s doc comment is stale.** It claims "remote-scan result
   adoption"; there is no production caller. Harmless today, but it is the
   sentence a future editor would rely on to add an **unfenced** publication
   path. Worth correcting at the next touch of that file.
6. **Detection latency is bounded by the `VERSION` cache**, not by the poller:
   worst case ≈ one 10 min `VERSION` window plus one 5 min tick. Accepted and
   documented; the window it replaces was up to the full `CacheTTL` (1 h
   default, unclamped).

---

## 5. Verification

Run at `3c5fab1` plus the S-1 fix, with the `go.mod` toolchain (`go1.27.3`),
not the container default.

| Check | Result |
|---|---|
| `go test ./internal/hashcache/ ./internal/secscan/` | PASS (`ok` 0.21 s / 15.65 s) |
| `go test -run 'TestCHAOS106' -count=1 .` | PASS — including `EveryDecompressCallSiteConsultsTheRefusal` over the real tree with the stricter rule (the no-false-positive control), the five pre-existing banned/permitted shapes, and the new function-scope control |
| `go test -run 'TestSSLInnerLine' -count=1 -v .` | PASS — byte-identity, awkward-value-in-every-position, pooled-carrier-not-leaked, oversize-carrier-not-pooled, concurrent-emitters-do-not-interleave, one-line, typical-line-fits-capacity |
| S-1 both-directions proof | merged wall on the fixture: `sites=2 violations=[]`; fixed wall: 1 violation at `chaos106probe.go:12:16` |
| `gofmt -l .` | clean |
| `go vet .` | clean |
| `go test -count=1 .` (full root package, 474 s) | PASS (`ok … 474.059s`) |
| `golangci-lint run --new-from-rev origin/main` (the gate's own command) and a full-tree pass, v2.15.0 built with the `go.mod` toolchain | `0 issues.` / baseline unchanged — see §5.1 |

### 5.1 Gate results

**`golangci-lint` v2.15.0**, installed with the `go.mod` toolchain
(`GOTOOLCHAIN=go1.27.3 go install …@v2.15.0`), which is the version
`.github/workflows/pr-fast-gate.yml` pins — not the container's, which is older
than this module's language version.

- The gate's own command, `run --timeout=10m --new-from-rev origin/main`:
  **`0 issues.`**
- Full-tree pass, `run --timeout=35m ./...`: **174 issues, exit 1** — the
  repository's pre-existing baseline (bodyclose 3, cyclop 24, dupl 4, errcheck
  8, funlen 8, gocognit 24, gocritic 40, gosec 15, nestif 8, noctx 17,
  staticcheck 14, unconvert 2, unparam 7). The full-tree pass is run because
  `cyclop`, `funlen` and `gocognit` attribute to a function's DECLARATION line,
  so `--new-from-rev` cannot see a function made more complex — and this change
  did make `chaos106CallSiteViolations` more complex, adding a recursive
  closure. The measurement is unchanged against the base by construction:
  **zero** of the 174 findings name
  `chaos106_decompress_failclosed_test.go`, the only Go file this change
  touches, and none of the four `dupl` findings (the only cross-file linter
  enabled) names it on either side. `gocognit` and `nestif` are NOT among the
  `_test.go` exemptions in `.golangci.yml`, so the new nesting was held to the
  full bar and cleared it.

**`python3 docs/agent-context/check.py`**: exit 0 (static integrity; 486
navigation links, 117 declared route edges). Run because this change adds a
file under `docs/`, which is what the Fast PR Gate's `docs-guidance` job keys
on.

**Not run, and why.** CodeQL — not runnable locally; the `SSL_INNER` rewrite
moves the `sanitizeLog` barrier into the emitter and hands `logger.Printf` a
`[]byte` via `%s`, so the hosted CodeQL run is the authority on whether the
CWE-117 barrier is still traced. Nothing in this review's own change touches
that path. The full aggregate CI for the exact SHA is the hosted gate's to
report; a passing local check is not a passing merge gate.

---

## 6. Files

- `chaos106_decompress_failclosed_test.go` — S-1 fix: function-scoped branch
  check in `chaos106CallSiteViolations`, `chaos106BranchesOn` takes a scope
  instead of the file, plus
  `TestCHAOS106_CallSiteWallScopesTheBranchToItsOwnFunction`.
- `docs/engineering/SECURITY-REGRESSION-REVIEW-2026-11-01.md` — this review.
- `CHANGELOG.md` — the S-1 entry under Unreleased / Security.

No production file is touched by this review's own change.

---

## 7. Required Tests

Shipped with the fix:

- **Negative control / regression:**
  `TestCHAOS106_CallSiteWallScopesTheBranchToItsOwnFunction` — the
  same-name-different-function bypass is reported, by `file:line`.
- **Positive control:** the compliant site beside it is not reported, and
  `TestCHAOS106_EveryDecompressCallSiteConsultsTheRefusal` still passes over
  the real tree (no false positives on the three live sites).
- **Boundary / malformed input:** the five pre-existing fixture shapes
  (conforming, discarded, bound-but-never-branched, single-value,
  inlined-into-another-call) are unchanged and still pass.

Still owed, in the owners named in §4 rather than here:

- A bound (or an explicit non-support statement) for repeated flushes driven by
  an alternating `VERSION` identity across `clamd` replicas (§4.2).
- A legacy-GUI tile for `stat_scan_sigdb_invalidations`, and an
  `OperatorContractCheck` that performs the "invalidations flat while the
  signature counter advances" comparison the counter's own documentation names
  as the alert condition (§4.3), including the mixed-version sidecar case
  (§4.4).
