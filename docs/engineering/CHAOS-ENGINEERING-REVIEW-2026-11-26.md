# Chaos engineering review — 2026-11-26

Reviewer: Culvert Chaos Engineer (automated round). Base revision `a0aecf8`
(`origin/main`), clean worktree at branch point.
[CHAOS-ENGINEERING-REVIEW.md](../../roadmap/CHAOS-ENGINEERING-REVIEW.md) stays
the index; this is the dated record for the round it registers.

Id claimed: **CHAOS-129**, in a committed placeholder row as commit one
(`f87e212`), before any code, and checked against `origin/main` rather than the
working tree per the register's 2026-09-25 amendment. `CHAOS-126` was the
highest id anywhere on `origin/main` at `a0aecf8`; of the open pull requests
#2075 holds `CHAOS-127` and #2119 holds `CHAOS-128`, so this round took 129 and
did not move.

Scope: **the content-shape stage's precondition.** Archive magic bytes (F4) and
Content-Type/magic polyglots (F5) are the only two response blocks in this
product that decide from the FIRST BYTES of a body alone. The question this
round asked was not whether they are correct — their unit coverage is good —
but *what has to be true for them to run at all*.

It narrows no prior chaos row. `F4`/`F5` are carried in the feature inventory
as content blocks, and no round had asked after their precondition.

---

## 1. Executive summary

The answer was: **a malware scanner has to be configured.** Nothing in either
block needs one.

F5 compares the type it detects against the `Content-Type` the ORIGIN itself
sent — two header reads and a table lookup. F4 asks the operator's own file
profile whether the detected archive type is blocked. Neither consults a daemon,
a rule set or a feed, and the code says so: `inspectMagicStage` is documented as
the stage where "both decide from the first bytes of the decompressed body
alone, both emit through `inspectMagicBlock`, and both run before CDR and before
any scanner" (`proxy_tunnel.go:1645`).

**That documented independence was true of their ORDER and false of their
PRECONDITION.** Both legs reached them only from *inside* the scanner's
buffering branch, so the stage silently inherited a precondition it has no use
for:

| leg | enclosing gate | when it is false |
|---|---|---|
| plain HTTP (`scanHTTPResponseBody`) | `globalRemoteScanner.Enabled() \|\| globalSecScanner.BodyScanEnabled()` (`proxy_http.go:321`, returning at `:331`) | no sidecar, and no ClamAV address and no loaded YARA rules |
| SSL-inspect (`scanInspectBody`) | `bodyNeedsBuffering(ct)` (`proxy_tunnel.go:1629`) | the above, **and** DPI-on-text off |

`bodyNeedsBuffering` is false for *every* content type in that posture
(`security_scan.go:273-287`). Measured directly:

```
bodyNeedsBuffering("text/plain")               = false
bodyNeedsBuffering("application/octet-stream") = false
bodyNeedsBuffering("text/html")                = false
bodyNeedsBuffering("image/png")                = false
```

So on a gateway with scanning unconfigured — which `loadScanning`
(`scanning_startup.go:17-32`) produces by taking *neither* branch of its switch,
leaving `globalSecScanner.Init` uncalled and `enabled` false — **neither leg
evaluated either content-shape block.**

**CHAOS-129a (HIGH) — the polyglot block did not exist in the default posture.**
Measured on the production function, same bytes, same request, same process:

| scanner | fixture | outcome |
|---|---|---|
| none | `PK\x03\x04…` served as `Content-Type: text/plain` | **200, forwarded** |
| a ClamAV client that never matches | identical | **403 `POLYGLOT_BLOCKED`** |

The scanner in the second row inspected the body and found nothing. Its entire
contribution was to satisfy a gate. That is what makes this a defect rather than
a design: the control's availability was decided by a subsystem whose verdict it
never consults.

**CHAOS-129b (HIGH) — the archive block an operator explicitly configured was
silent in the same posture.** `IsBlockedArchive` (`filemagic.go:20`) fires only
when the detected extension, or `.zip` — which blanket-blocks every archive — is
in the file blocker. In the stock profile it cannot fire at all, so (a) is
really a measurement of F5. (b) is the F4 half: with `.zip` blocked and no
scanner, a ZIP served honestly as `application/zip` was forwarded. The operator
had turned archive blocking on, the admin UI showed it on, and it did nothing.

**CHAOS-129c (HIGH) — it flipped at RUNTIME, with no signal.**
`BodyScanEnabled` is `clam != nil || (yara != nil && yara.Loaded())`
(`internal/secscan/secscan.go:516-523`), and `Loaded()` resolves to
`len(rules) > 0` (`internal/yara/yara.go:242`, via `yaraRuleSetMatcher`,
`security_scan.go:66`). Deleting the last YARA rule through the admin API
(`globalYARA.DeleteRule`, `ui_security.go:1335`) therefore takes it false. On a
YARA-only node — no ClamAV address — **removing one malware rule turned both
content-shape blocks off, with no log line, no counter and no alert.** An
operator pruning a noisy signature has no reason to expect file-type and
polyglot blocking to leave with it, and nothing told them it had.

The direction of the dependency is the part worth keeping. A ClamAV daemon
**outage** correctly does *not* do this: `ss.clam` stays non-nil through a dead
daemon, so the stage survived the failure of the thing it never depended on —
and died of the *configuration* of it. The resilience was pointed at the wrong
event.

**CHAOS-129d (MED) — a third arm was silent with scanning fully configured.** A
response whose DECLARED `Content-Length` exceeds the scan window also returned
before the stage (`proxy_http.go:331`), so an origin could place a body outside
both content-shape blocks by declaring it large. The stage needs six bytes; the
declaration bought a pass on all of them.

All four are fixed. §10 records what is not.

**Why the fix does not buy parity with memory.** The gate existed to avoid
buffering bodies nothing would scan, and that concern is real — `CHAOS-115` was
precisely "a whole scan window per scan". The content-shape blocks do not need a
scan window: `filemagic.PrefixWindow()` is **6 bytes**, the longest offset-0
signature in the table, and `secscan.ReadScanBuffer` caps its Content-Length
pre-size by the limit it is handed (`internal/secscan/scanbuffer.go:64-66`), so
the shape-only path retains the prefix rather than a window. The one signature
outside it is ISO9660, whose `CD001` sits at sector 16 —
`filemagic.MaxWindow()` = 32 774 bytes — and reaching it on every response would
retain ~32 KiB per in-flight body to add one type. It is left to the
scanner-configured path and recorded as a residue (§10.1), not quietly claimed.
`filemagic.Detect` declines any signature longer than the data it is given, so a
short window cannot MISreport; only decline to match.

---

## 2. Failure scenarios

| # | Scenario | Pre-fix behavior | Expected | Post-fix |
|---|---|---|---|---|
| 1 | Gateway deployed with no ClamAV, no YARA, no sidecar; origin serves a PE/ZIP as `text/plain` over plain HTTP | Forwarded, 200 | Blocked on the type/content mismatch | `403 POLYGLOT_BLOCKED`; gate `TestCHAOS129_PlainHTTP_PolyglotBlockedWithNoScannerConfigured` |
| 2 | Same, over an SSL-inspected tunnel | `scanClean`, delivered | Blocked | `scanBlocked`, one emission through the responder choke point |
| 3 | Operator blocks `.zip`; no scanner; origin serves a ZIP | Forwarded, 200 — the configured control did nothing | `FILE_BLOCKED` | `FILE_BLOCKED (magic) … type=ZIP` |
| 4 | YARA-only node; operator deletes the last rule | Both content-shape blocks silently stop, fleet-wide | They are unaffected — they never used YARA | Unaffected; the stage no longer reads the scanner's state |
| 5 | ClamAV daemon goes down | Stage survives (`clam` stays non-nil) | Survives | Unchanged — correct before and after |
| 6 | Scanning configured; origin declares `Content-Length` past the scan window | Returned before the stage; neither block ran | Six bytes is all the stage needs | Blocked; gate `…_OversizedDeclarationStillShapeChecked` |
| 7 | Host on the admin scan-exclusion allowlist | Exempt | Exempt — the operator said so | Still exempt, on both legs, and now the ONLY case that leaves a response without a shape verdict |
| 8 | Origin resets the connection inside the first bytes of its body | Streamed whatever arrived | Fail closed, charge the parent | `502`, `upstreamReadErr` returned for the breaker attribution (CHAOS-11) |
| 9 | `Content-Encoding: gzip` on an `application/pdf` body | Full-window path decompressed, then decided | No false positive | Deferred to the full-window path; gate pins that a gzip-encoded PDF is NOT blocked |
| 10 | ISO9660 served as `text/plain`, no scanner | Not evaluated | Known gap, not a silent one | Still not detected on the prefix window; asserted as a residue, and asserted still caught on the full window |

---

## 3. Risk matrix

| Id | Finding | Sev | Likelihood | Blast radius | Evidence |
|---|---|---|---|---|---|
| 129a | Polyglot detection absent whenever no scanner is configured, on both legs | **H** | Default posture | Every proxied response, both legs | `proxy_http.go:321,331`; `proxy_tunnel.go:1629`; `security_scan.go:273-287`; measured 200 vs 403 |
| 129b | Operator-configured archive blocking silent in the same posture | **H** | Any node with archive blocking on and no scanner | Every archive download | `filemagic.go:20-38`; measured |
| 129c | Runtime flip: deleting the last YARA rule removes both blocks, unsignalled | **H** | One admin action on a YARA-only node | Fleet-wide, until a rule returns | `internal/secscan/secscan.go:516-523`; `ui_security.go:1335`; `security_scan.go:66` |
| 129d | A declared over-window length bypassed both blocks with scanning on | **M** | Origin-chosen | Per response | `proxy_http.go:331`; measured |
| 129e | The reassembly this fix adds strands the origin's `Close` if written with `io.NopCloser` | **M** | Introduced and caught inside this round | Upstream connection per clean pass | §11 |

Severity rationale: 129a–c are rated HIGH not because the blocks are the
product's strongest control — they are a shape heuristic, and a determined
attacker has better options — but because the *failure was invisible*. A control
that is off reads exactly like a control that found nothing: no counter moved,
no line was logged, and the admin surfaces that report scanning posture
(`support_collectors_posture_b.go:177`) report the scanner, which was the thing
that was honestly absent.

---

## 4. Recovery assessment

- **Automatic recovery: none was needed, and none existed.** This was not an
  outage; it was a control that was never armed. There is no transient to ride
  out and nothing self-heals, which is why it could sit unnoticed.
- **Manual recovery, pre-fix:** configure ClamAV or load any YARA rule. That is
  a remedy for the wrong problem — it arms the content-shape stage as a side
  effect of standing up an unrelated subsystem — and no document anywhere said
  to do it, because nobody knew it was load-bearing.
- **Post-fix:** the stage has no recovery path because it has no dependency. It
  reads two response headers and six body bytes. The only states that remove it
  are the admin host allowlist (deliberate, §2 scenario 7) and a declared
  `Content-Encoding` (deferred to the full-window path, §10.2).
- **Fail direction:** an origin read failure inside the window now fails CLOSED
  (502 on the plain-HTTP leg, `scanReadError` on the inspect leg, which tears the
  tunnel down rather than surfacing an empty 200). That follows CHAOS-17's
  contract, narrowed to this window.

---

## 5. Operational impact

- **Before:** an operator reading the admin UI saw file blocking on and archive
  magic detection described as a content control. Both were true of the
  configuration and false of the running system. The gap was unobservable from
  any surface — there is no "content-shape stage active" indicator, and there
  still isn't (§10.3).
- **The runtime flip is the operationally nastiest part.** It is reachable by a
  routine, reasonable, audited admin action (delete a YARA rule) whose audit
  entry records the rule deletion and cannot record the two unrelated controls
  that left with it. A post-incident reconstruction from the audit log would not
  show the connection.
- **After:** no new operator setting, no new alert, no new counter — see §7 for
  why each was refused. The change is invisible to a correctly-configured node
  and arms two controls on an under-configured one. `FILE_BLOCKED (magic)` and
  `POLYGLOT_BLOCKED` request-log statuses, their counters (`statFileBlocked`,
  `statBlocked`) and the block page are byte-identical to the ones the
  scanner-configured path already emitted, because both paths now go through one
  function (`httpMagicStage`).
- **New cost on the hot path:** one `IsHostExcluded` lookup per plain-HTTP
  response that previously skipped it, and a ≤6-byte read plus a
  `MultiReader` wrap per response on both legs. The scanner-configured path is
  untouched and still buffers its full window.

---

## 6. Security impact

- **The leg that lost the most is the cheaper one for an attacker.** Plain HTTP
  needs no CA, no inspection consent and no handshake. Both legs were affected
  equally here, so this is not a differential — but it is worth stating that the
  gating did not spare the easy path.
- **What the lost controls actually catch:** a renamed or disguised download
  whose declared type contradicts its bytes. F5's value is highest exactly where
  no scanner is deployed, because it is then the *only* thing looking at the
  body at all. The gating removed it precisely in the posture where it was the
  last line.
- **No attacker is required to trigger the runtime flip** — an administrator
  tidying rules is enough. One suffices, though: any party who can get a YARA
  rule removed, or a node provisioned without a ClamAV address, silently
  disables two content controls.
- **No new attack surface is added.** The stage reads six bytes it was already
  entitled to read and makes a decision from a static table. The one new
  rejection class — a 502 on an origin read failure inside the window — is a
  fail-closed outcome on a response that could not be delivered intact anyway.
- **One false-positive class was deliberately avoided rather than accepted:**
  judging COMPRESSED bytes would block a gzip-encoded PDF as "GZIP disguised as
  application/pdf", since the raw prefix is gzip magic and `application/pdf` is
  neither an accepted content type for GZIP nor web content exempted as
  HTTP-compressed (`internal/filemagic/filemagic.go`). Encoded bodies are
  therefore deferred to the full-window path, which decompresses first. The gate
  `…_EncodedBodyIsNotAFalsePositive` asserts the fixture really does look like a
  polyglot to the checker before asserting it is not blocked, so the test cannot
  pass by accident.

---

## 7. Shipped

1. **`internal/filemagic`: two DERIVED detection windows.** `PrefixWindow()`
   (longest offset-0 signature) and `MaxWindow()` (widest signature in the
   table), computed once at package init rather than written down, because
   `PrefixWindow` is read on the response path. A signature added at offset 0
   that is longer than the window its callers size a buffer from would otherwise
   compile, ship, and never match.
2. **`content_shape.go`: the stage, and one home for its bookkeeping.**
   `httpMagicStage` is the plain-HTTP sibling of `inspectMagicStage` and is now
   the single place the plain-HTTP F4/F5 counting, logging and block-page
   emission lives — called by both the full-window path and the new bounded one,
   so they cannot drift. The bookkeeping is unchanged from when it was inline.
3. **`scanHTTPContentShape` / `inspectContentShape`: the bounded path.** Both
   early-return arms on the plain-HTTP leg (`!scanActive`, and a declared length
   past the window) and the `!bodyNeedsBuffering` arm on the inspect leg now
   route here instead of returning. Read `PrefixWindow()` bytes, run the two
   blocks, reassemble.
4. **`shapeReassembledBody`: the origin's `Close` survives reassembly.** See
   §11 — this is the defect this round introduced and caught.
5. **The host-exclusion short-circuit was moved AHEAD of the scanner gate on the
   plain-HTTP leg**, so the admin allowlist still covers the stage now that the
   stage is reached with no scanner active. It is the one exemption that leaves a
   response without a shape verdict, on both legs, deliberately.

**Refused, with reasons:**

- **No operator setting.** A toggle for the content-shape stage would need admin
  API and UI parity (`docs/agent-context/conventions.md`), and would ship a
  switch whose only correct position is on: the stage costs six bytes and has no
  dependency to fail. The thing an operator configures is already there —
  F4 reads the file profile, F5 reads the origin's own header.
- **No new alert.** The stage has no failure mode of its own to alert on. A
  block is a block and already lands in the request log with its reason.
- **No new counter.** `statFileBlocked`/`statBlocked` already count both blocks,
  and routing both paths through `httpMagicStage` is what keeps that true.
- **No overflow signal on the bounded path.** `logScanLimitExceeded`'s counter
  and deduped `scan_skipped` alert mean "bytes were forwarded past the scan
  window". A six-byte window would fire that on essentially every response and
  destroy the signal. The nil callback is deliberate.
- **The scanner-configured full-window path was not re-plumbed** to use
  `shapeReassembledBody`. It still installs an `io.NopCloser`, which is the
  pre-existing asymmetry recorded in §10.4 — fixing it is a change to a path
  this round did not find a defect in, and it would move close counts that
  existing tests pin.
- **ISO9660 on the prefix window** — §10.1.

---

## 8. Required tests — shipped

`content_shape_chaos129_test.go` (12 gates) and
`internal/filemagic/window_chaos129_test.go` (2 gates).

| Gate | Property |
|---|---|
| `…_PlainHTTP_PolyglotBlockedWithNoScannerConfigured` | 129a, plain-HTTP leg. Asserts its own precondition (no scanner active) first |
| `…_Inspect_PolyglotBlockedWithNoScannerConfigured` | 129a, inspect leg; exactly one emission through the responder choke point |
| `…_PlainHTTP_ConfiguredArchiveBlockWasAlsoSilent` | 129b. Isolates F4 by serving the ZIP under an HONEST `application/zip`, so F5 has nothing to say and only F4 can block |
| `…_PlainHTTP_OversizedDeclarationStillShapeChecked` | 129d |
| `…_PlainHTTP_ExcludedHostIsStillExempt` | The deliberate exemption, not widened |
| `…_PlainHTTP_EncodedBodyIsNotAFalsePositive` | §6's false-positive class; asserts the fixture triggers the checker before asserting it is not blocked |
| `…_PlainHTTP_CleanBodyPassesIntact` | Negative control + byte-identical reassembly + the wrapper type |
| `…_PlainHTTP_BodyShorterThanTheWindowSurvives` | A 1-byte body is not a short read |
| `…_PlainHTTP_EmptyBodySurvives` | The degenerate case |
| `…_Inspect_CleanBodyPassesIntact` | Negative control on the leg where reassembly is NEW; origin body not closed by the stage, and closing the reassembled body DOES close the origin |
| `…_PlainHTTP_ShapeReadErrorFailsClosed` | 502 + `upstreamReadErr` for the breaker |
| `…_ISO9660_IsTheRecordedResidueOfThePrefixWindow` | Residue in both directions: not caught on the prefix window, still caught on the full one |
| `TestDetectionWindows_DeriveFromTable` | Both windows track the table; a hand-edited constant fails |
| `TestPrefixWindow_MatchesEveryOffsetZeroSignature` | Every offset-0 signature matches at exactly `PrefixWindow()` bytes; the offset-16-sector one does not |

Every positive assertion carries a negative control, because a change that
blocked all traffic — or corrupted every body it passed — would satisfy the
positive half alone.

---

## 9. Verification

Run on `claude/serene-cerf-fesvym` at the final tree.

- **Red before green.** With the two production call sites reverted and the
  tests unchanged, the four positive gates fail with the finding's own words
  (`a ZIP served as text/plain was forwarded with no scanner configured (status
  200)`; `an over-declared ZIP … was forwarded unshaped`; `a read error inside
  the shape window was not handled`; `outcome = 0, want scanBlocked`). The
  negative controls pass both ways, which is what makes them controls.
- `go test ./internal/...` — PASS, exit 0, no failures.
- `go test .` (root package, full) — see §9.1.
- `golangci-lint run --timeout=15m --new-from-rev origin/main` with the gate's
  own pin (`v2.15.0`, installed under the `go.mod` toolchain `go1.27.4`) —
  **0 issues.** Three `bodyclose` findings and one `noctx` finding in the new
  test file were fixed, not suppressed; `bodyclose` recognises only a literal
  `resp.Body.Close()`, so the deferred close is inline rather than behind a
  helper.
- `golangci-lint run --timeout=20m` full-tree — 174 pre-existing issues, **none
  in the new files and none naming `proxy_http.go` or `proxy_tunnel.go`**. This
  is the comparison `--new-from-rev` cannot make: `cyclop`, `funlen` and
  `gocognit` attribute to a function's DECLARATION line, and both functions this
  round edited kept theirs. `scanHTTPResponseBody` lost two branches (the two
  inline blocks became one call) and `scanInspectBody` is complexity-neutral (one
  `||` became two sequential `if`s), so neither moved toward a threshold.
- `gofmt -l` — clean on every touched file.

### 9.1 What the root suite caught

The first full root run **FAILED**, on a test this round did not write:

```
--- FAIL: TestRunInspectExchange_BodyClose/bodyCloseCountsPerOutcome
    inspect_exchange_test.go:300: delivered: resp.Body closed 0 times, want 1
```

That is finding 129e and §11. It was fixed and the suite re-run; the result of
the re-run is recorded in the pull request rather than asserted here, because a
hosted gate's verdict is not a local one's — see the closing note.

---

## 10. Residual risk

**10.1 ISO9660 is outside the prefix window, by decision.** Its signature sits
at 0x8001, so covering it on the shape-only path means retaining
`filemagic.MaxWindow()` = 32 774 bytes per in-flight response — 5 400× the
6-byte window — to add one type. It is left to the scanner-configured path,
which still buffers the full window and still catches it.
`TestCHAOS129_ISO9660_IsTheRecordedResidueOfThePrefixWindow` asserts both halves
so the gap cannot drift into an unnoticed claim: if a future change makes the
prefix window catch it, that gate fails and demands this section be updated.

**10.2 A declared `Content-Encoding` skips the shape-only path.** Six bytes
cannot be expanded, and judging the compressed bytes would create the
false-positive class in §6. So on a node with no scanner, an origin can keep a
body away from both content-shape blocks by serving it `Content-Encoding:
gzip` — which is a real evasion, bounded by the fact that the response must then
actually be a valid compressed stream for the client, and that compressing an
already-compressed archive or executable is the unusual case. Closing it
properly means a decompress-a-bounded-prefix primitive with its own expansion
allowance (the CHAOS-106 shape, one plane over) and is a round of its own.

**10.3 Neither control is observable as PRESENT.** This round removed the
dependency that made them disappear; it did not add a surface that says they are
there. An operator still cannot distinguish "the content-shape stage ran and
found nothing" from "the content-shape stage did not run", and that is exactly
the property whose absence let 129a–c sit unnoticed. The honest fix is a posture
field beside the scanner's own (`support_collectors_posture_b.go:113`) rather
than a counter, and it needs GUI parity.

**10.4 The scanner's full-window reassembly still installs an `io.NopCloser`**
(`proxy_http.go`, `proxy_tunnel.go`), so the origin's `Close` is stranded there
the way it briefly was here. In practice `net/http` auto-closes a body read to
EOF, so the leak needs a client that disconnects mid-response; it is pre-existing
and out of this round's finding, recorded so the asymmetry with
`shapeReassembledBody` is deliberate and visible rather than accidental.

**10.5 `IsBlockedArchive`'s `.zip`-implies-every-archive rule** (`filemagic.go:31`)
is unchanged and unexamined by this round. It means an operator who blocks `.zip`
also blocks GZIP, RAR, XZ, 7Z, BZIP2, Z-LZW, ZSTD and ISO. That may be intended;
it was not in scope.

---

## 11. The defect this round introduced, and what found it

Worth recording on method, because the fix was reviewed, measured and green on
its own 12 gates before this surfaced.

The reassembly on both new paths was first written the way the scanner's
full-window path writes it:

```go
resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), rest))
```

On the inspect leg that **strands the origin's `Close`**. The exchange seam
closes exactly the handle it is left with, so every clean pass through the new
stage leaked the upstream body and its connection. Nothing in the 12 gates saw
it: `TestCHAOS129_Inspect_CleanBodyPassesIntact` asserted the stage does *not*
close the origin body — which is correct, the caller owns that close — and had no
assertion that the caller could still REACH it. The pre-existing
`TestRunInspectExchange_BodyClose` caught it on the first full root run, because
its fixture carries no `Content-Type` and therefore lands in exactly the
`!bodyNeedsBuffering` arm this round rewired.

Two things follow. The narrow one: `shapeReassembledBody` preserves the origin's
closer, and both legs now gate on it — the inspect test asserts that closing the
reassembled body closes the origin, and the plain-HTTP test asserts the wrapper
type is the one installed. The general one: **a new path that inherits a
neighbouring path's idiom inherits its ownership assumptions too, and the test
written for the new path will tend to assert the property the author was
thinking about rather than the one the caller depends on.** The suite that
caught this was not the round's own.

---

A passing local check is not a passing hosted review or merge gate. Nothing in
this round authorises a policy, dependency, posture or deployment change beyond
the two call sites and the stage described above.
