# Security Regression Review — 2026-10-31

**Scope.** `a10b553…8138243` (`origin/main`) — the 24 h since the 2026-10-30
review, 9 merged pull requests (#1762 #1763 #1764 #1765 #1766 #1767 #1768
#1769 #1770), 65 files, +5,822/−147. Twenty-three production Go files changed,
twenty-three test files, the rest API contract, GUI, roadmap and operator
documentation.

| PR | Change | Security surface |
|---|---|---|
| **#1763 / #1767 / #1770** | CHAOS-106 — the scan-path expansion is bounded against the compressed bytes the origin actually transferred, a disproportionate expansion is **refused** (fail-closed) on all four response paths, and the ratio becomes an audited admin setting in `[16,256]` | scanning, DoS/memory, proxy, request/response processing, admin control plane, persistence, audit |
| **#1769** | `storeguard.OpenBadger` — a badger open that RETURNS an incomplete store keeps its poison marker instead of clearing it, so the next open quarantines before badger reads the directory | persistence, durability, crash-loop integrity |
| **#1768** | `SEC-KSROSTER-1` — the no-verifier kill-switch row is redacted below admin and its refusal claim scoped | authorization, information disclosure, RBAC, diagnostics |
| **#1765** | `internal/alpnpeek` — the ClientHello ALPN parser extracted from package main (ADR-0042) | TLS, proxy protocol negotiation, parser attack surface |
| **#1766** | A `cluster_ratelimit_freshness` operator-contract row for a stale CP broadcast | rate limiting, observability |
| **#1762 / #1764** | A per-worker category-group benchmark result; a category-group `catSet` hoist | CI gate, policy hot path |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed 24 h ago?** Every finding is measured against
`a10b553`, not against an ideal.

**Method.** The expansion bound was read through all four of its production
callers rather than through its diff hunks, and each caller's refusal branch
compared line by line against the scanner-verdict branch it claims to be
indistinguishable from (body ownership, counters, request-log status, block
emission, return value the caller breaks on). `readCapped` was traced for the
zero-length-read and no-progress cases that its predecessor
`io.ReadAll(io.LimitReader(...))` could not reach. The ALPN move was diffed
with rename detection to prove the bounds-checked parser and its fuzz target
survived byte-for-byte. The kill-switch redaction was traced from every
production `buildOperatorContract()` call site, not only the two the new test
drives. The `OpenBadger` manifest argument was checked for the store-leak case
on each of its three refusal paths.

Three hypotheses were formed against the window's own claims and **disproved**:
that the `adminSettingsPath == ""` branch skips the ratio PUT's `ifRevision`
fence and its audit `prev` capture (it does not — `precondition` runs before
that branch, inside `adminSettingsMu`); that `checkClusterRateLimitFreshness`
can nil-dereference its limiter (`rl` is `admission.go`'s package-level
`newRateLimiter()`, never nil); and that a `RecoveryTrigger` consumer in main
switches on the trigger set and would mis-render the new
`TriggerIncompleteOpen` value (no consumer switches on it).

The one finding that survived was **proved in both directions** against the
merged revision: the probe it bans passes the wall as merged and fails the
wall as fixed.

---

## 1. Executive Summary

**No security regression was introduced in this window.** The three
security-relevant changes all move the posture forward, and each fails closed
in the direction its own doc comment claims. That was verified against the
production callers, not taken on trust.

The review found **one confirmed regression in gate integrity**, introduced by
CHAOS-106 itself: the structural wall that is the sole guarantee every
`decompressForScan` caller fails closed enumerates a **hard-coded list of the
three files that call it today**, so the exact bypass it exists to ban —
a new response path that binds the refusal to `_` — passes it unseen in any
new file. It is latent (no such caller exists), but it is the one gate
standing between a future call site and a scanner bypass whose ratio the
attacker chooses. It is fixed here, and the fix is proved against a probe the
merged wall accepts.

Two documentation defects introduced by the same PR are fixed with it. One is
not cosmetic in kind: `scanInspectBody`'s **fail-closed outcome contract** —
the `scanBlocked` / `scanReadError` distinction whose conflation once turned
an on-path origin reset into a cacheable empty 200 on the H2 path — was
detached from its function by the complexity extraction and now documents
`inspectMagicStage` instead, leaving the function that owns the contract
undocumented.

| # | Finding | Severity | Status |
|---|---|---|---|
| **S-1** | `TestCHAOS106_EveryDecompressCallSiteConsultsTheRefusal` checks a hard-coded four-file list, so a `decompressForScan` call site in any NEW file that discards the refusal passes the wall. Proved in both directions | **LOW** security / **MEDIUM** gate integrity (introduced this window; latent — no live bypass) | **FIXED + proved + negative controls** |
| **S-2** | `scanInspectBody`'s outcome contract doc comment, including the `scanReadError` fail-closed rule, is attached to `inspectMagicStage`; the function that owns the contract has no doc comment | **INFORMATIONAL** (introduced this window; misleading security documentation) | **FIXED** |
| **S-3** | The rationale for not probing past the flat ceiling in `expandForScan` is a truncated sentence, so the reason the flat path must not take the probe is unreadable at the only place a future editor will look | **INFORMATIONAL** (introduced this window) | **FIXED** |

Surfaces reviewed and found **clean** are enumerated in §3.

---

## 2. Security Findings

### S-1 (LOW security / MEDIUM gate integrity, introduced this window) — the CHAOS-106 call-site wall cannot see the call site nobody has written yet

**Fixed, proved and given negative controls in this change.**

CHAOS-106's whole value rests on one property: `DecompressForScan` returns
`(nil, true)` when the ratio allowance refuses an expansion, and **every**
caller must fail closed on that second value. The owner states it as the
contract ([internal/secscan/secscan.go](../../internal/secscan/secscan.go)):

> `bomb` reports that the ratio allowance was exceeded … the caller must
> refuse the response (fail closed) and `out` is nil.

A caller that ignored it would scan the **compressed** bytes instead — and
since the origin picks the ratio, the attacker would be choosing the value
that silences ClamAV, YARA, the archive-magic check and the polyglot check at
once. The authors saw exactly this and wrote a structural gate for it, because
the compiler forces the value to be *received* but not *consulted*
([chaos106_decompress_failclosed_test.go](../../chaos106_decompress_failclosed_test.go)):

```go
callers := map[string]string{
	"proxy_tunnel.go": "scanBody, bomb := decompressForScan(",
	"proxy_http.go":   "scanData, bomb := decompressForScan(",
	"cdr_proxy.go":    "newScan, bomb := decompressForScan(",
}
…
for _, file := range []string{"proxy_tunnel.go", "proxy_http.go", "cdr_proxy.go", "security_scan.go"} {
	src := chaos106Source(t, file)
	if strings.Contains(src, ", _ := decompressForScan(") || … {
```

Both halves read **only the files named in the literal**. The wall therefore
proves a property of three files, while the property it is written to defend
is a property of the package. A fourth response path — an H3 leg, a second CDR
stage, a request-direction scan, any of which lands in a new file in this
package — never enters either list, so the gate reports a clean pass for the
precise shape it bans.

**Attack scenario.** An inspected response path is added in a new file (the
repository adds response-path files routinely; `proxy_tunnel_h2.go` is one).
Its author writes `scanData, _ := decompressForScan(buffered, ce)` — the
natural shape for anyone who has not read CHAOS-106, and the shape the old
single-return signature had. Review, `go build`, `go vet`, the behavioural
CHAOS-106 tests (which drive `scanInspectBody` and `scanHTTPResponseBody`
only) and this wall all pass. From then on, any origin reachable on that path
serves a response declaring `Content-Encoding: gzip` whose expansion exceeds
the ratio allowance; `DecompressForScan` returns `nil`, the caller scans the
~20 KiB of compressed bytes, no signature matches, the content is forwarded,
`statScanDecompressBombs` never increments, and the operator contract, the
Prometheus counter and the Security panel tile all read zero. The scanners
were not slow or saturated — they were handed the wrong bytes.

**Preconditions.** A new `decompressForScan` call site in a file not named in
the wall's literals. No attacker precondition beyond controlling the response
body on that path (a malicious origin, a compromised one, or an on-path
injector inside a non-inspected leg).

**Exploitability.** Trivial once the precondition exists — it is the normal
decompression-bomb shape, already captured as a fixture
(`chaos106Bomb`). **Likelihood** of the precondition: moderate; this is an
actively developed proxy with four response paths added over its history, and
the diff that creates it looks correct to a reviewer who does not know the
seam returns two values. **Impact:** full malware/CDR/DPI inspection bypass on
the affected path, silently, with every operator signal reading clean.
**Affected assets:** all clients behind the gateway on that path, and the
inspection posture the product is sold on.

**CWE.** CWE-1104 (use of unmaintained/insufficiently verified third-party
guard — here, a guard whose verification does not cover its own scope);
contributing to CWE-693 (protection mechanism failure) and the bypass it would
enable, CWE-20 / CWE-409 (improper handling of highly compressed data).
**OWASP.** A04:2021 Insecure Design (the control's verification is narrower
than the control), with A08:2021 as the consequence class.
**Security severity:** LOW today (latent, no live bypass). **Gate-integrity
severity:** MEDIUM. **Regression risk of the fix:** none to runtime — the
change is test-only.

**Safe implementation.** The wall now **discovers** its inputs instead of
listing them: it reads every non-test `.go` file in the package directory
(anchored to `pkgSourceDir()`, as `static_read_wall_test.go` requires of every
structural wall), parses each with `go/ast`, and for every call of the
`decompressForScan` seam requires that the call

1. is the sole right-hand side of a **two-value** assignment,
2. binds the second result to a **named** identifier (not `_`), and
3. that identifier appears in an **`if` condition** somewhere in the same file.

Anything else — a single-value assignment, a `_`, a bound-but-never-branched
value, or the call inlined into another expression — is reported with its
file:line. Because discovery can also fail silently (a renamed seam finds
nothing and "passes"), `chaos106RefusalFloor` asserts the three known files
each still hold at least one conforming call site, so a wall that stops
matching fails instead of reporting success. The condition shape is checked
permissively (`if bomb`, `if bomb || x`) and its **absence** strictly, which
is the only shape that reopens the bypass.

**Proved, not assumed.** A probe file carrying the banned shape was added to
the package:

```go
// zz_chaos106_wall_probe.go
func zzChaos106ProbePath(body []byte, ce string) []byte {
	scan, _ := decompressForScan(body, ce)
	return scan
}
```

* Against the wall **as merged at `8138243`**: `ok github.com/KidCarmi/Culvert` — the bypass passes.
* Against the wall **as fixed here**: `FAIL … zz_chaos106_wall_probe.go:5:13: discards the decompression refusal; a dropped refusal turns the CHAOS-106 expansion bound into a scanner bypass, with the attacker choosing the ratio that silences the scanners`.

The probe was removed afterwards; the working tree carries no such file.

### S-2 (INFORMATIONAL, introduced this window) — the fail-closed outcome contract documents the wrong function

`scanInspectBody` carries the contract that decides how an inspected exchange
terminates, and one clause of it is load-bearing enough to name its own
incident ([proxy_tunnel.go](../../proxy_tunnel.go)):

> `scanReadError`: … NOTHING was written to the client, so the caller MUST
> fail the exchange … never let this surface as a clean, empty success.
> Conflating it with `scanBlocked` produced a silent empty 200 on the H2 path
> (an on-path origin reset became a cacheable success); keeping it distinct is
> the fail-closed contract.

PR #1770 extracted `inspectMagicStage` to bring `scanInspectBody` back under
the cyclop threshold, and inserted the new function **between that comment
block and the declaration it documented**, appending its own description to
the end of the block. The result compiles and behaves identically, and is
wrong in the only way a doc comment can be: `go doc scanInspectBody` now
returns nothing, and `go doc inspectMagicStage` returns the three-outcome
contract of a function that returns `bool`. The next editor of the H1/H2
termination path — the exact reader this paragraph was written for after the
empty-200 incident — is the one who loses it.

Fixed by moving the block back above `func scanInspectBody`, leaving
`inspectMagicStage` with its own comment. No code change.

### S-3 (INFORMATIONAL, introduced this window) — the flat-ceiling rationale is a truncated sentence

`expandForScan`'s flat-ceiling branch must **not** take the `limit+1` probe the
ratio branch takes, and the comment explaining why breaks mid-clause
([internal/secscan/secscan.go](../../internal/secscan/secscan.go) as merged):

> … the pre-CHAOS-106 `io.LimitReader` never asked the decompressor for a byte
> past the ceiling, so a stream that is corrupt only AFTER it returned the
> decoded prefix. Probing would reach that corruption and drop the expansion
> back to the compressed bytes.

The sentence has no predicate, so the actual rule — a stream corrupt only past
the ceiling still yielded a scannable prefix, and probing one byte further
turns that prefix into a read error and therefore into a **compressed-byte**
scan, i.e. strictly less inspection than before CHAOS-106 — is not recoverable
from the text. An editor who "simplified" the two branches into one probe would
be making the scanner see less, with the only warning against it unreadable.
Repaired to state the rule in full. No code change.

---

## 3. Regression Analysis — surfaces reviewed and found clean

**CHAOS-106 refusal, all four production call sites.** Each refusal branch was
compared against the scanner-verdict branch beside it:

* `scanInspectBody` ([proxy_tunnel.go](../../proxy_tunnel.go)) — `origBody.Close()`, `statBlocked`, `recordInspectBlock(…, "SCAN_BLOCKED", "decompress", …)`, `scanBlockConn`, returns `scanBlocked`. Identical ownership to `inspectMagicBlock`; `statFileBlocked` correctly **not** bumped (this is not a file-type block), matching the `SCAN_BLOCKED` branch below it. Covers the H1 and native-H2 inspect legs, since `proxy_tunnel_h2.go` reaches the scanner only through this function.
* `scanHTTPResponseBody` ([proxy_http.go](../../proxy_http.go)) — `statBlocked`, `recordRequestAuthURI(… "SCAN_BLOCKED" …)`, `scanBlock`, `return true, nil`. Body closing is the caller's, as in every other block branch on that path; verified the bomb branch adds no close the siblings do not make.
* `runCDRStage` ([cdr_proxy.go](../../cdr_proxy.go)) — routes through `cdrEmitStageBlock`, which returns `cdrStageDecision{blocked: true}`, so the caller closes `origBody` and stops serving. `statCDRBytesOut` is now incremented **after** the check, so a refused replacement is not accounted as delivered (#1767); `cdr_swap_bytes_out_test.go` pins both directions.
* The seam itself ([security_scan.go](../../security_scan.go)) — `var decompressForScan = secscan.DecompressForScan`; no other production reference to `DecompressForScan` exists in the tree.

**The bound's arithmetic and reads.** `expandForScan` loads the ratio **once**
and computes its ceiling and its refusal against that same value via
`expandBoundAt`, so an administrator changing the setting mid-read cannot
produce a refusal measured against a ceiling that was never applied.
`int64(n) * ratio` cannot overflow: `n` is the buffered scan window
(`maxScanBufferBytes`, 5 MiB by default) and `ratio ≤ 256`. The refusal
predicate is an **observation** (`len(buf) > limit` after a `limit+1` read),
not an inference from `len == limit`, so a body of exactly the allowance is
not false-positived. A read error arriving with `len(buf) > limit` is still
treated as a refusal — fail closed — rather than falling back to the
compressed bytes.

**`readCapped` versus its predecessor.** Behaviour at the flat ceiling is
equivalent to `io.ReadAll(io.LimitReader(r, limit))`: the prefix is returned
with a nil error. The clamped final grow cannot produce a zero-length `Read`
(the loop condition `len(buf) < limit` is checked before the grow, and
`min(cap*2, limit) > cap` whenever `cap < limit`), so the no-progress path is
reachable only from a reader that genuinely returns `(0, nil)` — which the
`maxEmptyReads` counter bounds, as `io.ReadAll` does for `bufio`. The zstd arm
resets the pooled decoder to `nil` before returning it, so the refused buffer
is not pinned by a decoder sitting in the pool.

**The expansion bound as an operator setting.** `secscan` owns validation
(`[16,256]`), and `SetDecompressRatioLimit` **keeps the current bound** on
refusal, so no path can widen it with a bad value. The PUT is
`requireRole(…, RoleAdmin)` at the handler, the GET `RoleViewer`, matching
`uiRoutes`, `api/route-classification.yaml` and the OpenAPI
`x-culvert-permission` on both methods. Persist-before-apply: the durable file
records the target and `applyOnSuccess` installs it only after
`fileutil.AtomicWrite` lands, so a persist failure is a truthful 500 with the
running bound untouched (`TestScanDecompressSetting_PersistFailureLeavesTheBoundUnchanged`).
The `ifRevision` fence **and** the audit's `prev` capture run inside
`adminSettingsMu` before the `adminSettingsPath == ""` branch, so the
no-persistence configuration cannot silently drop either — the hypothesis that
it could was formed and disproved. `auditEvent` precedes the response and
`saveConfigVersion` is deliberately **not** called, registered in
`config_surfaces.go` with its rollback exclusion ("rolling back could silently
re-raise the decompression-bomb ratio the admin chose to tighten") and covered
by `TestScanDecompressSetting_PUTAppliesAuditsAndCreatesNoConfigVersion` — the
`auth_password_change_no_versioning_test.go` class, correctly applied.
A hand-edited out-of-range value in the settings file is refused on load and
the **default** installed (`applyAdminScanDecompressRatio`), so a corrupt file
can never widen the bound; the default is recorded as `0`/absent, so an
untouched node keeps following the shipped value across upgrades instead of
pinning it. The log line after a relaxation prints the bound **read back from
`secscan`**, not the request value (#1770), keeping request-derived data out
of the application log (CWE-117). The GUI writes every value through
`textContent`, so no reflected markup reaches the panel.

**The relaxation is visible.** `relaxed` in the API payload, a
`scan_decompress_ratio` WARN row on the operator contract whenever the ratio
is above the default, a GUI warning banner, and a one-shot application log
line. The maximum (256) sits below every bomb ratio CHAOS-106 measured
(~408:1 and up), so the bound cannot be configured into a state where the
measured attack shape is admitted while the UI still shows the protection as
on — the property that makes a tunable fail-closed default safe to ship.

**`storeguard.OpenBadger`.** The manifest argument holds: the pre-open read is
the set badger is about to load, `db.Tables()` is read **before** the
confirming manifest re-read (so a table still listed after the open was still
in the levels at the first read, unless badger never loaded it), and the
in-place filter `missing := absent[:0]` is safe because it only ever writes at
or behind its read index. All three refusal paths close the store they are
refusing — unreadable manifest, unreadable re-read, and the incomplete-open
verdict — so `openWith` discarding the value leaks nothing. `InMemory` short-
circuits before the manifest read, correctly. No `badger.Open` call remains
outside this wrapper anywhere in the tree (production), and both store owners
pass `ErrIncompleteOpen` through unchanged — `logstore.OpenTTL` explicitly
ahead of its encryption-mismatch mapping, which would otherwise have swallowed
it into a purge recommendation. The marker semantics are the conservative
direction: `Abandon()` releases the flock and **keeps** the marker, so the
quarantine decision is made by the next open *before* badger touches the
directory, whether or not this process survives. `catdb`'s documented response
to a failed open — degrade to Layer-1 categorisation, never refuse to boot —
is unchanged, and no consumer in main switches on the trigger set, so the new
`TriggerIncompleteOpen` value cannot land in an unhandled branch.

**`SEC-KSROSTER-1`.** `redactContractForRole` replaces the
`auth_exempt_kill_switch` row with a rendering built from the **same** backend
read as the admin row, so the two cannot straddle a roster change; the
fallback for a hand-assembled contract is a fixed redacted row, not the admin
text, so the redactor fails closed by construction. Every production
`buildOperatorContract()` call site was traced: `apiDiagnostics` and
`apiHealthExplain` both go through `writeOperatorContract`, the single
redaction point, and the third — the support-bundle collector — is the
exception already stated in that helper's contract and enforced by
`TestWall_EveryOperatorContractRendererIsClassified` (see §4). The new
`currentKillSwitchBackend` classification was reclassified from `rosterProbe`
to `rosterInput` in the operator-contract wall, correctly: the no-verifier
state **is** roster role posture, not a boolean existence probe.
`AuthEnabled` and `IsConfigured` were added to `rosterAccessorMethods`,
closing last window's S-2. The role-redaction gate carries positive,
disclosure, over-redaction, fallback and non-mutation controls across both
endpoints.

**`internal/alpnpeek` (ADR-0042).** Diffed with rename detection: the parser
body, every bounds check, the cursor helpers and the `OffersH2` predicate are
byte-identical to `inspect_h2_alpn.go`; only the package clause, three
identifiers and the comment location changed. `peekClientALPN`'s fail-closed
fallback to `["http/1.1"]` on any short, oversized or malformed ClientHello is
unchanged, and `FuzzParseClientHelloALPN` moved with the code — a dropped fuzz
target would itself have been the regression. No stale reference to the old
identifiers remains.

**`cluster_ratelimit_freshness`.** Report-only, derived from the same
`ClusterFreshness()` verdict the Cluster page and the Prometheus gauge use, no
I/O, contributes nothing unless cluster limiting is armed **and** stale, and
carries no node, IP or address data. The nil-limiter hypothesis was disproved:
`rl` is `admission.go`'s package-level `newRateLimiter()`.

**Counters and exports.** `DecompressBombs` is reported beside the
fail-**closed** saturation plane and deliberately not folded into the
fail-**open** `stat_scan_skipped`; in remote (sidecar) mode the proxy's **own**
counter is the one reported, because the sidecar only ever receives
already-expanded bytes and its structural `0` previously reached the Security
panel while this node blocked every bomb (#1763). The support-bundle field is
classified `redact:"internal"`, consistent with the rest of `scanSection`.

**CI, dependency and gate surface — nothing weakened.** `git diff a10b553..8138243`
on `go.mod`, `go.sum`, `.golangci.yml`, `Makefile`, `Dockerfile` and
`.github/` is **empty**. No `GOTOOLCHAIN` override, no suppression added, no
test skipped or loosened: #1762 made a benchmark check its results per worker
instead of through a shared sink (a sharpened assertion), and every CHAOS-106
behavioural gate ships with its own negative control, so a change that refused
all compressed traffic would fail the positive assertion too.

---

## 4. Residual Risk

1. **The support bundle carries the unredacted operator contract.** The
   `diagnostics` collector embeds `buildOperatorContract()` without the role
   redaction, so the admin rendering of `auth_exempt_kill_switch` — and of
   `access_cidr_lists` and the roster durability row before it — is inside a
   bundle that **`RoleOperator` may download**. It is a *stated* exception in
   `writeOperatorContract`'s contract and structurally enforced as one, and it
   is gated twice by admin (creation is `RoleAdmin`, and release requires the
   `RoleAdmin` approval/mandatory-preview step) with the section classified
   `INTERNAL`, which operator may read. Pre-existing, not introduced this
   window, and not re-litigated here — recorded because `SEC-KSROSTER-1`'s own
   viewer text now makes the explicit promise "the cause and the remediation
   are shown to administrators only", which is true of the API and not of an
   approved bundle. If that promise is meant to hold end to end, the collector
   is where it would have to be made good.

2. **The ratio bound does not apply above ~1 MiB of compressed bytes.** Once
   `n × ratio ≥ MaxDecompressBytes` (64 MiB — i.e. from about 1 MiB compressed
   at the default 64) `expandBoundAt` returns the flat ceiling and the path
   reverts to truncate-and-scan with **no** refusal. That is deliberate and
   documented (content that transferred its bytes honestly keeps its
   pre-CHAOS-106 treatment), and it preserves proportionality in the attacker's
   direction, but it means the refusal is a bound on *cheap* expansions, not on
   all of them. Unchanged from the merged design; stated so it is not mistaken
   for universal coverage.

3. **The aggregate cross-stream expansion is still unbounded.** Per-response
   expansion is now proportional, but bounding the sum across concurrent
   inspected responses needs an admission gate on in-flight inspected bodies,
   which `h2MaxConcurrentStreams` is not. The authors record this themselves
   (CHAOS-106 §7) and the comment in `proxy_tunnel_h2.go` was corrected to stop
   claiming otherwise. Open by design, not a regression.

4. **The small-response floor admits very high ratios under 1 MiB.** Anything
   expanding to at most `DecompressFloorBytes` (1 MiB) is never refused by the
   ratio, so e.g. 1 KiB compressed → 900 KiB (≈900:1) is admitted. Intended —
   the ratio alone is unfair to small responses — and harmless at that
   magnitude, but it is the shape a tuned probe would use to measure where the
   bound starts.

5. **A CHAOS-106 refusal cannot be exempted per object.** Only a host exclusion
   relieves it; the SHA-256 scan-exclusion list is consulted after the
   expansion, so it cannot. Documented in the operator guide this window
   (#1769, `79d72c0`), and the host exclusion is a broader grant than an
   operator may want for one legitimate CSV export. Accepted trade, recorded.

---

## 5. Verification

Run at the working revision (`8138243` plus this change), with the `go.mod`
toolchain (`go1.27.3`):

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./internal/{secscan,storeguard,alpnpeek,catdb,logstore}/... .` | pass |
| `go test ./internal/secscan/... ./internal/storeguard/... ./internal/alpnpeek/... ./internal/catdb/... ./internal/logstore/...` | pass (5 packages) |
| `go test . -run 'Decompress\|CHAOS106\|KillSwitch\|OperatorContract\|Wall_\|ScanDecompress\|ClusterRateLimit\|ConfigSurface\|RouteMeta\|APIContract'` | pass |
| `go test . -run 'Scan\|Inspect\|CDR\|Decompress\|Magic\|Polyglot'` | pass |
| `go test . -run 'CHAOS106' -v` | pass, incl. the 5 new negative-control subtests |
| S-1 probe against the wall **as merged** | **pass** (the bypass is accepted — the gap) |
| S-1 probe against the wall **as fixed** | **fail**, with file:line (the gap is closed) |
| `python3 docs/agent-context/check.py` | pass (108 blocks, 486 navigation links, 117 route edges) |
| `golangci-lint run --new-from-rev origin/main` (gate's own command, pinned `v2.15.0` built with the `go.mod` toolchain) | **0 issues** |
| `golangci-lint run ./...` full tree | 175 issues, **all pre-existing** — none in any file this change touches |
| `git diff a10b553..8138243 -- go.mod go.sum .golangci.yml Makefile Dockerfile .github/` | empty |

Not run, and why: the hosted Fast PR Gate and the CodeQL query pack, which run
on the pull request for this SHA and have no local equivalent configured here —
a local pass is not a hosted pass; and the module-wide `go test ./...`
aggregate, in favour of the changed surfaces and their callers, since the only
production edits in this change are comments. The conventions' full-tree lint
comparison WAS run
(see the table) because `--new-from-rev` attributes `cyclop`, `funlen` and
`gocognit` to a function's declaration line and so cannot see a function made
more complex in place; the full tree reports the same 175 pre-existing issues
and none in `chaos106_decompress_failclosed_test.go`, `proxy_tunnel.go` or
`internal/secscan/secscan.go`.

## 6. Files

* [chaos106_decompress_failclosed_test.go](../../chaos106_decompress_failclosed_test.go) — S-1: the wall discovers every non-test file in the package and checks each `decompressForScan` call site with `go/ast`; `chaos106RefusalFloor` bans a vacuous pass; `TestCHAOS106_CallSiteWallRejectsADiscardedRefusal` is the wall's own negative control.
* [proxy_tunnel.go](../../proxy_tunnel.go) — S-2: `scanInspectBody`'s outcome contract moved back above its declaration. Comment only.
* [internal/secscan/secscan.go](../../internal/secscan/secscan.go) — S-3: the flat-ceiling no-probe rationale completed. Comment only.
* `docs/engineering/SECURITY-REGRESSION-REVIEW-2026-10-31.md` — this review.
* [CHANGELOG.md](../../CHANGELOG.md) — the `### Security` entry for S-1 (and S-2/S-3 with it).

## 7. Required Tests

Shipped with S-1:

* **Positive** — the conforming shape (`scan, bomb := …; if bomb { … }`) passes the checker.
* **Negative** — `, _ :=`, a single-value assignment, a bound-but-never-branched refusal, and the call inlined into another expression each fail it.
* **Regression (the finding itself)** — the discarding probe in a file the old literals never named fails the fixed wall and passed the merged one; both directions executed.
* **Boundary / vacuous-pass** — `chaos106RefusalFloor` fails the wall if any of the three known call sites stops existing, so a renamed seam cannot read as a clean gate.
* **Malformed input** — every discovered file is parsed, and a parse failure is `t.Fatalf`, not a skipped file.
* **Authorization / authentication** — unchanged by this change; the window's own
  `TestScanDecompressSetting_PUTRequiresAdmin` and
  `auth_killswitch_diag_role_redaction_test.go` (viewer and operator, both
  endpoints, with an over-redaction control) were reviewed and re-run rather
  than duplicated.
* **Concurrency** — not added: the checker is a pure function over parsed
  source with no shared state. The runtime concurrency contract CHAOS-106
  introduces (one ratio load per expansion) is pinned by
  `internal/secscan/decompress_ratio_setting_test.go`, which was reviewed and
  re-run.
