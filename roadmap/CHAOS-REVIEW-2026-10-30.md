# Chaos engineering review — 2026-10-30

Reviewer: Culvert Chaos Engineer (automated round). Base revision `9eb4281`
(`main`), clean worktree. Scope: the **resource-exhaustion** rows of the
response-scan data plane, selected by working the open HIGH items of the
[2026-10-29 backlog](CHAOS-REVIEW-2026-10-29.md) §7 rather than re-sweeping
ground earlier rounds closed.

Recorded separately for the reason the previous two rounds were:
[CHAOS-ENGINEERING-REVIEW.md](CHAOS-ENGINEERING-REVIEW.md) stays the index.

Id claimed: **CHAOS-106** (the scan-path decompression amplifier). It was free
at `9eb4281`.

---

## 1. Executive summary

The last round picked up the CA and background-worker planes. The row it left
at the top of the list was `X-4` — "scan-path decompression expands a buffered
prefix to up to 64 MiB **before** any scanner admission gate, with no semaphore
or memory budget for the buffering stage" — carried as HIGH and delegated since
2026-10-13 without a measurement. This round measured it, and the measurement
is worse than the row's framing.

**CHAOS-106 (HIGH) — the only declared memory ceiling in the inspected
response path was wrong by ~23x, and a single client connection could reach
3.6 GiB of heap from 5 MiB of traffic.**

The shape is the inversion the last two rounds kept finding: the mechanism that
exists to make the pipeline *safe* is the one that made it dangerous. Here it
is the transparent decompression added so ClamAV/YARA/DPI signatures match
actual content rather than compressed bytes — a correctness fix (the "1.1 fix"
comment at both call sites) whose cost was never bounded against anything the
operator controls.

Three facts compose:

1. **The operator's per-response memory knob governs the wrong stage.**
   `readScanPrefix` buffers at most `maxScanBufferBytes()` — the max of the DPI
   scanner's cap and `Scanner.maxBytes`, default 5 MiB. That is the only
   per-response size control an operator has. `secscan.DecompressForScan` then
   expanded that prefix under a *flat* `MaxDecompressBytes = 64 MiB`, a
   constant with no relation to the window, the request, or anything
   configurable. A 1 MiB window and a 64 MiB window produced the same 64 MiB
   expansion.

2. **The expansion costs considerably more heap than it holds.**
   `io.ReadAll(io.LimitReader(r, MaxDecompressBytes))` grows by doubling and
   has no knowledge of the limit, so the predecessor array is still live when
   its successor is allocated, and the final grow runs *through* the ceiling.
   Measured across 32 concurrent expansions: **3.64 GiB peak heap for 2.00 GiB
   actually held**, with 5.05 GiB of allocation churn. Most of that 1.78x gap
   is the doubling ladder itself rather than the past-the-ceiling overshoot
   (which measures 1.004x of the final capacity at a ~1 MB ceiling) — so the
   leverage on it is the ceiling, not the loop. See §2.1.

3. **Nothing bounds the aggregate.** `internal/secscan` has a `scanInflight`
   gauge and `internal/yara` has a real counted, fail-closed in-flight **cap**
   — but no gate stands in front of the buffering/expansion stage, so N
   concurrent inspected responses multiply freely.

The result is a cost asymmetry of **408:1** on wire bytes, empirically
reproduced (§2.1): **160 KiB of gzip bought a 64 MiB expansion**, and 32 of
them — one inspected HTTP/2 connection at this repository's own
`h2MaxConcurrentStreams`, from **5.0 MiB of traffic** — reached 3.64 GiB peak.
An in-line security gateway that OOMs is a full-organization outage, and the
attacker needs nothing but a client that can reach an origin they control,
which is the proxy's entire purpose.

The most telling evidence is in the tree's own prose. `proxy_tunnel_h2.go`
states the ceiling explicitly — "the scan pipeline buffers up to
maxScanBufferBytes per in-flight response, so the per-connection scan-buffer
memory ceiling is maxScanBufferBytes × this" — and sizes
`h2MaxConcurrentStreams` at 32 *by that arithmetic*. With the expansion stage
counted, the real figure was `MaxDecompressBytes × 32` = 2 GiB, not 160 MiB.
The cap was chosen against a budget the pipeline did not honour.

**What this round changes, and what it deliberately does not.** The expansion
is now bounded against the bytes the origin actually transferred, and a
disproportionate expansion is **refused** (fail closed) rather than truncated
and forwarded. That removes the asymmetry — the part a chaos round can decide
on evidence. It does **not** lower the absolute 64 MiB per-response ceiling and
does **not** add an admission gate on concurrent inspected responses: both
change the detection envelope or the traffic posture of a security product, and
both are recorded in §7 as owner decisions with the measurements to decide on.

---

## 2. Failure scenarios

### 2.1 CHAOS-106 — decompression amplification in the inspected response path

| | |
|---|---|
| **Trigger** | Any client the proxy serves fetches a response from an origin it controls, carrying `Content-Encoding: gzip` (or `deflate`/`br`/`zstd`) over a body whose expansion ratio is disproportionate. No authentication is needed beyond whatever the proxy already requires of that client, and the three front-door limiters ship disabled. |
| **Current behavior (pre-fix)** | `readScanPrefix` buffers ≤ `maxScanBufferBytes()` (default 5 MiB). `DecompressForScan` expands it under a flat 64 MiB ceiling via `io.ReadAll(io.LimitReader(...))`. Both buffers stay live through the CDR stage, the DPI scan and `ScanBody`. |
| **Failure mode** | Heap exhaustion. Not a slow leak — a single HTTP/2 connection at `h2MaxConcurrentStreams` reaches it in one round trip per stream. |
| **Blast radius** | The process. Culvert is an in-line forward proxy and security gateway, so an OOM is a full loss of egress for every user behind it, plus the admin control plane, the cluster plane and the audit/log queues in the same binary. |
| **Expected behavior** | The response path's memory ceiling is a declared number the pipeline enforces, and it is a function of something the operator controls. |
| **Recovery (pre-fix)** | Process restart (container restart under Docker). Automatic in the sense that the supervisor restarts it; not automatic in the sense that the attacker can repeat it immediately at the same cost. |
| **Monitoring visibility (pre-fix)** | None specific. `scanInflight` is a gauge over body *scans*, not expansions, and it is structurally blind to the stage that allocates: the expansion happens **before** `ScanBody` is called. No counter, no log line, no alert, no health row. The node simply dies. |
| **Verification** | **Empirical**, measured on `9eb4281` before any change. See the table below. |

Measured with `DecompressForScan` driven directly at the pre-fix ceiling, one
goroutine per stream, 32 streams (`h2MaxConcurrentStreams`), holding each
result as the production path does through the scan:

| Quantity | Measured |
|---|---|
| Attacker wire bytes per response (gzip of 80 MiB of zeros, clipped to the ceiling) | **164,470 B (160.6 KiB)** |
| Expansion per response | **67,108,864 B (64.0 MiB)** |
| Cost asymmetry | **408:1** |
| Attacker wire bytes, 32 streams | **5.0 MiB** |
| Live decompressed bytes | **2048.0 MiB** |
| Peak `HeapAlloc` | **3642.3 MiB** |
| `TotalAlloc` delta | **5047.3 MiB** |
| Ceiling `proxy_tunnel_h2.go` declares (`maxScanBufferBytes × 32`, defaults) | 160 MiB |
| Overshoot of the declared ceiling | **~23x** |

The same measurement re-run against this round's tree, byte-identical input and
harness:

| Quantity | Pre-fix | Post-fix | Change |
|---|---|---|---|
| Per-response expansion allowance | 64.0 MiB (flat) | **10.0 MiB** (64 × 164,470 B) | proportional to what was sent |
| Responses refused | 0 / 32 | **32 / 32** | fail closed |
| Live decompressed bytes held | 2048.0 MiB | **0.0 MiB** | refused, so nothing is retained |
| Peak `HeapAlloc` | 3642.3 MiB | **289.6 MiB** | **12.6x lower** |
| `TotalAlloc` churn | 5047.3 MiB | **833.5 MiB** | **6.1x lower** |

Two things are worth separating in that 1.78x pre-fix gap between live
(2.00 GiB) and peak (3.56 GiB). The part `readCapped` removes outright is the
growth that runs *past* the ceiling, and honestly measured that is small:
`io.ReadAll` lands on 1.004x of a ~1.06 MB ceiling
(`TestCHAOS106_ReadCappedNeverAllocatesPastItsCeiling` logs both). The bulk of
the gap is the doubling ladder's own intermediates, which any incremental
expansion pays and which `readCapped` does not pretend to eliminate. What
actually moved the peak by 12.6x is the **ceiling** — the ratio allowance — not
the read loop. The read loop's contribution is that the ceiling it is handed is
now the ceiling it respects, which is a correctness property rather than a
measured win.

**Why a ratio bound, and why refusal rather than truncation.** The bound now in
`internal/secscan` is `min(MaxDecompressBytes, max(64 × compressedBytes,
1 MiB))`, and reaching the **ratio** half refuses the response while reaching
the flat half keeps the pre-existing truncate-and-scan behavior verbatim.

- *Proportionality is what restores the declared ceiling.* Tying the allowance
  to transferred bytes is what makes `proxy_tunnel_h2.go`'s arithmetic true
  again: an expansion can only be large if the origin actually sent a lot, and
  what the origin can send is already bounded by the scan window the operator
  set.
- *64 is several times above legitimate and several times below hostile.* Real
  web content gzips at roughly 3–10:1 (HTML/JS/CSS), 10–20:1 (JSON) and up to
  ~50:1 for highly repetitive XML or log text; decompression bombs sit at
  400–1000:1 (gzip of zeros is ~1030:1). The gates in §9 build fixtures from
  varying bytes and **assert the ratio each one actually achieved**, because the
  first draft of those controls used a repeating alphabet — which gzips at
  403:1 and would have "proved" the bound safe while hiding that it refused
  honest content.
- *The floor exists because the ratio alone is unfair to small responses,* where
  a few hundred bytes of framing legitimately expand far past 64x. Anything up
  to 16 KiB compressed gets the flat 1 MiB floor instead.
- *Refusal, not truncation.* Truncating at the allowance and scanning the prefix
  would forward the rest **uninspected** — and a 400:1 ratio is exactly what a
  padded archive hiding a payload produces, so the one shape that trips the
  bound is the one shape where the uninspected tail matters most. A response
  whose declared encoding expands past 64x what it transferred is itself
  hostile content on a security gateway. This is `AGENTS.md`'s "prefer fail
  closed" and the same direction CHAOS-53 took the sidecar's saturation path.
- *The flat ceiling is deliberately NOT given the refusal.* Content large
  enough for the allowance to reach 64 MiB transferred its bytes honestly;
  refusing it would be a traffic-posture change this round did not decide to
  make, so its prefix keeps being scanned exactly as before
  (`TestCHAOS106_FlatCeilingStillTruncatesAndIsNeverRefused`).

**Why the refusal needed caller plumbing.** A bound that the caller can ignore
is not a bound — it is a *bypass*: if `DecompressForScan` silently returned the
compressed bytes on refusal, an attacker would pick the ratio that makes every
scanner see gzip framing instead of content. So the function now reports the
refusal and all three call sites fail closed through the same emission a
scanner verdict uses, which is why `TestCHAOS106_EveryDecompressCallSiteConsultsTheRefusal`
is a source gate as well as a behavioural one: the compiler forces the second
return value to be *received*, not *consulted*.

---

## 3. Risk matrix — this round

| ID | Domain | Finding | Likelihood | Impact | Sev | Status |
|----|--------|---------|-----------|--------|-----|--------|
| CHAOS-106 | Data plane / scanning / memory | Scan-path expansion bounded by a flat 64 MiB unrelated to the operator's window: 408:1 cost asymmetry, 3.64 GiB peak from 5 MiB of wire bytes on one connection, no counter/log/alert | **High** — any client reaching an origin it controls; the proxy's own purpose | Process OOM = total loss of egress, control plane and cluster plane for everyone behind the gateway | **HIGH** | **FIXED** (asymmetry; see §7.1–7.2 for the ceiling and the aggregate) |
| CHAOS-106b | Data plane / memory | `io.ReadAll(io.LimitReader(…))` grows through a ceiling it cannot see, so the allocation is not the one the caller asked for (measured 1.004x of a ~1 MB ceiling; the larger 1.78x peak-over-live gap is doubling churn, addressed by the smaller ceiling rather than by the loop) | High (every expansion) | Small on its own; it is the correctness half of the bound | **LOW** | **FIXED** |
| CHAOS-106c | Observability | A refused/clipped expansion had no counter, log line or metric; `scanInflight` is structurally blind to the stage, which runs before `ScanBody` | High | The node dies with nothing said | **MED** | **FIXED** |
| CHAOS-106d | Documentation / contract | `proxy_tunnel_h2.go` states a per-connection memory ceiling the pipeline does not honour, and `h2MaxConcurrentStreams = 32` was sized by that arithmetic | — | A cap chosen against the wrong budget | **MED** | **FIXED** (comment corrected with the true arithmetic) |

### 3.1 Inherited rows this round re-classifies

| ID (2026-10-13) | Re-classification |
|---|---|
| `X-4` | **This round's CHAOS-106, PARTLY FIXED.** The row's premise is confirmed and now measured. Its *first* clause — expansion to 64 MiB before any admission gate — is addressed by making the bound proportional and the refusal fail-closed. Its *second* clause — "no semaphore or memory budget for the buffering stage, so N concurrent responses multiply freely" — **stands and is unaddressed**; it is §7.2. The row's CDR sub-clause (presize from a peer-reported size with the cap checked only after appending) was **not** re-examined this round and keeps its original status. |
| `X-5` | **Untouched, still MED.** Re-confirmed as still open at `9eb4281`: `internal/scanner` spawns one goroutine per `Scan` with no in-flight cap and abandons it on timeout, holding its `data` snapshot until `re.Match` returns. The twin cap in `internal/yara` (`yaraSaturationCheck`, `GetMaxInflight`, `GetOnSaturation`) is still the model to copy. Note the row's wording is now stale in one respect: the per-**pattern** goroutine it describes was hoisted to one per **scan**, so the leak is one abandoned goroutine per scan, not per pattern. |
| `X-2` | Unchanged from the 2026-10-29 re-classification. Its memory half — the stated `queueDepth × maxPooledLine` budget is not what the queue holds — remains open. It is the same *class* of defect as CHAOS-106: a declared ceiling that the code does not enforce. Two of the three such rows are now closed; this is the third. |

---

## 4. Recovery assessment

| | CHAOS-106 (pre-fix) | CHAOS-106 (post-fix) |
|---|---|---|
| Automatic recovery | Supervisor restart after OOM, repeatable by the attacker at 160 KiB per 64 MiB | **No failure to recover from** for the asymmetric case: the response is refused inside its own request, nothing else is affected |
| Manual recovery | None available — there is no knob that bounded the stage | Not required |
| Detection | None. The process dies; the log ends | `culvert_scan_decompress_bombs_total`, `stat_decompress_bombs` on the scan-status API, `decompress_bombs` in the support bundle, and one rate-limited WARN naming the class, the compressed size and the allowance |
| Data integrity | Unaffected by the OOM itself, but an OOM mid-write is the regime the storage rounds (CHAOS-50/§19) exist for | Unaffected |
| Residual | — | The 64 MiB absolute ceiling and the aggregate across concurrent responses: §7.1, §7.2 |

The refusal is **deterministic**, not probabilistic: the same response is
refused on every node and every retry, so an operator seeing the counter climb
is seeing content, not capacity — which is the distinction CHAOS-52 insisted on
and the reason this counter is not folded into `statScanSkipped`.

---

## 5. Operational impact

- **One new signal, no new configuration.** The bound is a package constant
  pair in `internal/secscan`, like `MaxDecompressBytes` beside it, so no
  operator setting is added and no GUI/API parity obligation is incurred. The
  refusal reaches the operator on every surface a scan counter already reaches:
  Prometheus (`culvert_scan_decompress_bombs_total`), the scan-status admin API
  (`stat_decompress_bombs`, reported beside the **saturation** plane because it
  is fail-closed, not beside the fail-open `stat_scan_skipped`), the support
  bundle's `sections/scan.json`, and a tile on the legacy Security panel beside
  "ClamAV at capacity" and "Late verdicts discarded".
- **Not done: the OpenAPI entry and the regenerated frontend client.**
  `SecurityScanStatus` is `additionalProperties: true` and documents only a
  curated subset of the keys the handler returns (`stat_scan_skipped`,
  `stat_clam_scan_error`, `yara_inflight` and others are already undocumented),
  so the new key is contract-legal. A documentation entry was drafted and then
  **withdrawn**: `api/openapi/openapi.json` is the input to
  `frontend/src/api/types.gen.ts`, which is committed generated output under a
  byte-comparison drift gate and carries the spec's SHA-256 in its header, and
  regenerating it requires the pinned Node 24.19.0 / npm 11.17.0 workspace this
  environment does not have. Hand-editing it is explicitly forbidden by the
  file's own header, and landing a spec change without the regen would fail the
  Fast Gate's `frontend` lane. The entry belongs in a follow-up run from the
  pinned toolchain; it is documentation, not signal, and nothing above depends
  on it.
- **The log line is rate-limited and the counter is not.** This fires once per
  refused response and an *attacker* sets that rate, so an ungated line would
  add `internal/logsink` producer latency to every proxied response exactly
  while the node is under attack — the CHAOS-54 shape, one subsystem over. The
  line carries the class and the exact running total; the magnitude lives in the
  counter.
- **A refusal is visible as a block, not as an error.** It routes through the
  same `SCAN_BLOCKED` request-log action and the same block responder as a
  scanner verdict, with `source=decompress` and a bounded reason, so existing
  dashboards and the alert store's dedup window both work unchanged.
- **Client-visible change.** A response whose declared encoding expands past
  64x the bytes it transferred now receives a 403 block page instead of being
  delivered. The negative controls in §9 exist because that is the one way this
  change could hurt: every realistic compression ratio must still pass, whole
  and byte-identical.
- No persisted file, no wire-format change, no new alert channel, no shutdown or
  startup ordering change.

---

## 6. Security impact

- **The direction is fail-closed, and the refusal is not optional.** The three
  production call sites (`scanInspectBody`, `scanHTTPResponseBody`,
  `runCDRStage`'s swap branch) each refuse the response. The alternative —
  returning compressed bytes to scan — would have converted the bound into a
  *scanner bypass* the attacker selects by choosing the ratio, which is why the
  structural gate forbids a discarded refusal.
- **No detection coverage is reduced for honest content.** Nothing in the
  legitimate range changes: `TestCHAOS106_LegitimateCompressionRatiosAreAdmittedWhole`
  pins incompressible, HTML-shaped and repetitive-JSON fixtures as
  byte-identical after expansion, each asserting the ratio it actually
  achieved. The flat 64 MiB ceiling's truncate-and-scan behavior is pinned
  unchanged.
- **Every pre-existing fallback keeps its exact posture.** An absent, unknown or
  malformed `Content-Encoding`, a truncated or corrupt stream, and an empty
  expansion all still hand back the original bytes with no refusal
  (`TestCHAOS106_PreExistingFallbacksAreUnchanged`) — refusing on a header typo
  would block traffic for a non-attack.
- **The zstd path drops its pooled reference before returning the decoder.**
  The pooled `zstd.Decoder` otherwise keeps a `bytes.Reader` over the
  compressed input, and on the refusal path that input is the only thing still
  pinning the buffer just refused; `Reset(nil)` before `Put` means a refusal
  does not leave the refused bytes reachable from the pool.
- The refusal log value is origin-supplied (`Content-Encoding`) and is
  sanitised through `obs.Sanitize` with `%q` even though it has already been
  matched against the known encoding set (CWE-117).

---

## 7. Suggested improvements (prioritized, NOT done here)

1. **Lower or derive the absolute per-response expansion ceiling (HIGH, owner
   decision).** `MaxDecompressBytes` is a flat 64 MiB, which is 12.8x the
   default 5 MiB scan window. After this round an attacker must transfer
   ≥1 MiB to reach it (vs 160 KiB before), but the ceiling itself is unchanged,
   so 32 streams × 64 MiB = 2 GiB is still reachable for ~32 MiB of traffic.
   Tying the ceiling to the operator's window — e.g. `k × Scanner.maxBytes`
   — would make the one declared number fully operator-controlled. It is listed
   here and not done because it **narrows the detection envelope** for
   legitimately large compressed objects, which is a product decision.
2. **An admission gate on concurrent inspected responses (HIGH, owner
   decision).** This is `X-4`'s unaddressed second clause and the only thing
   that bounds the **aggregate**. A byte budget charged for the *lifetime* of
   the expansion buffer (not merely the duration of the expansion, which
   completes in milliseconds and would bound nothing) needs the buffer's owner
   to release it, so it is caller-lifetime plumbing through
   `scanInspectBody`/`runCDRStage`, with a posture choice on refusal. The
   in-tree model for the posture is `internal/yara`'s
   `GetOnSaturation`/`FailClosed`; the model for the gauge is
   `secscan.ScanInflight`.
3. **`X-5` — cap the DPI scan's in-flight goroutines (MED).** Re-confirmed open
   this round. `internal/scanner.scan` spawns a worker per scan that is
   *abandoned* on timeout while still holding its `data` snapshot, so a
   saturated node accumulates uncounted, uncapped goroutines each pinning up to
   a full scan window. `internal/yara` solves exactly this, in this tree, with
   a counted fail-closed cap — the smallest remaining copy-an-existing-solution
   row in the exhaustion family.
4. **`X-2`'s memory half (HIGH).** Still open; same defect class as this round's
   (a declared ceiling the code does not enforce).
5. **`R-1` — the four DP→CP loops with no backoff (MED).** Still open, still
   needing a posture decision rather than a mechanical fix.
6. **A dedicated health/alert row for a lost CA overlap (MED).** Carried from
   the 2026-10-29 round §7.1, unchanged.

---

## 8. Suggested PR — what this round changes

One commit on `claude/serene-cerf-kk1orz`:

`fix(secscan): bound scan-path decompression against the bytes transferred (CHAOS-106)`

- `internal/secscan/secscan.go` — `DecompressForScan` reports a refusal;
  `expandBound` (the proportional allowance, its floor and the flat ceiling),
  `expandForScan` (refuse vs truncate), `readCapped` (growth clamped to the
  ceiling, no-progress bounded), `noteDecompressBomb` (exact counter + its own
  rate gate), `DecompressBombs()`, `CounterSnapshot.DecompressBombs`, and the
  zstd pooled-decoder dereference.
- `proxy_tunnel.go`, `proxy_http.go`, `cdr_proxy.go` — each call site fails
  closed through the emission a scanner verdict already uses.
- `security_scan.go` — the bounded `source`/`reason` literals, plus
  `stat_decompress_bombs` on the scan-status surface.
- `metrics.go`, `support_collectors_posture_b.go`, `static/index.html` — the
  Prometheus series, the support-bundle field and the legacy Security-panel
  tile.
- `proxy_tunnel_h2.go` — the per-connection memory-ceiling comment corrected
  with the true arithmetic and with what still bounds nothing (§7.2).
- `internal/secscan/decompress_ratio_chaos_test.go`,
  `chaos106_decompress_failclosed_test.go` — the gates in §9.
- `scanner_test.go`, `coverage_day3_test.go` — the four pre-existing
  `decompressForScan` tests updated for the reported refusal.
  `TestDecompressForScan_GzipBomb` now asserts the refusal rather than only the
  old truncation, which is the one pre-existing behavior this round
  deliberately changes.

---

## 9. Required tests — and what they pin

`internal/secscan/decompress_ratio_chaos_test.go` (white-box, beside the owner):

| Gate | Pins |
|---|---|
| `TestCHAOS106_DisproportionateExpansionIsRefused` | The reproduction. A ~1000:1 expansion is refused, hands back no bytes, counts exactly once, and its allowance is below the flat ceiling. **Verified to FAIL with the bound neutered.** |
| `TestCHAOS106_ExpandBound_ProportionalWithAFloorAndACeiling` | The bound's three regimes — floor, proportional, flat ceiling — and that the refusal is armed only in the first two. **Verified to FAIL pre-fix.** |
| `TestCHAOS106_LegitimateCompressionRatiosAreAdmittedWhole` | The control that matters most: incompressible, HTML-shaped, repetitive-JSON and small-repetitive fixtures all expand byte-identically, each asserting the ratio it actually achieved so a drifting fixture fails as a broken control instead of passing. |
| `TestCHAOS106_PreExistingFallbacksAreUnchanged` | Seven fallback paths (absent/unknown/malformed × four encodings) still return the original bytes with no refusal. |
| `TestCHAOS106_FlatCeilingStillTruncatesAndIsNeverRefused` | Honestly-transferred bytes keep the pre-CHAOS-106 truncate-and-scan behavior exactly, truncated to the ceiling. |
| `TestCHAOS106_ReadCappedNeverAllocatesPastItsCeiling` | The allocation half: the returned capacity never exceeds the ceiling, as a differential oracle against `io.ReadAll(io.LimitReader(...))` on the same input. The ceiling is deliberately not a power of two, because `io.ReadAll`'s growth happens to land exactly on one and the comparison would then pass for the wrong reason. It logs both capacities, and fails if the overshoot it documents ever disappears — a silently-equal oracle is a dead oracle. |
| `TestCHAOS106_ReadCappedBoundsANoProgressReader` | A `(0, nil)` reader cannot spin the response path. |
| `TestCHAOS106_RefusalLineHasItsOwnRateGate` | The line is gated, the first one always emits, and the gate is NOT shared with the ClamAV-error line (the storage_health.go rule). |
| `TestCHAOS106_CounterStaysExactWhileTheLineIsSuppressed` | The magnitude is never rate-limited with the line. |
| `TestCHAOS106_RefusalReachesTheCounterSnapshot` | The refusal reaches the snapshot package main exports, not only the package-local atomic. |

`chaos106_decompress_failclosed_test.go` (root — the cross-domain wiring):

| Gate | Pins |
|---|---|
| `TestCHAOS106_ScanInspectBody_RefusesADisproportionateExpansion` | The primary SWG path returns `scanBlocked`, emits exactly one block through the responder choke point, closes the origin body, and counts the refusal. **Verified to FAIL with the bound neutered.** |
| `TestCHAOS106_ScanHTTPResponseBody_RefusesADisproportionateExpansion` | The plain-HTTP path, on the chunked shape that skips every pre-check: handled, 403, no refused bytes in the block page, and `upstreamReadErr` nil — a refusal is this node's decision and must not charge the upstream breaker (CHAOS-11). **Verified to FAIL with the bound neutered.** |
| `TestCHAOS106_ScanInspectBody_StillDeliversOrdinaryGzip` / `..._ScanHTTPResponseBody_...` | The negative controls, one per path: ordinary gzip is `scanClean`/not handled and the reassembled body is byte-identical to the wire bytes. Without these, a change that refused *all* compressed traffic would pass the two gates above. |
| `TestCHAOS106_EveryDecompressCallSiteConsultsTheRefusal` | The structural wall: every call site binds the refusal AND branches on it, and no file discards it with `_`. Source-level for the reason `cp_grpc_bind_chaos_test.go`'s `logFatalf` ban is — a reintroduced caller that dropped the refusal would compile and pass every behavioural gate above, and silently reopen the bypass. Reads through `pkgSourceDir()`, never a bare relative path (`static_read_wall_test.go`). |

The fixtures are built so the refusal under test is unambiguous: the scan
window is set wide enough to buffer the whole compressed fixture, because a
window-truncated gzip stream fails to decompress at all and would take the
*fallback* path instead — proving nothing.

---

## 10. Verification performed

| Check | Result |
|---|---|
| Pre-fix empirical measurement at `9eb4281` (§2.1 table) | reproduced |
| `go build ./...` | pass |
| `gofmt -l` on every touched file | clean |
| `go vet ./...` | pass |
| `go test -run 'TestCHAOS106' -count=1 ./internal/secscan/ .` | pass (and verified FAILING in both packages with the ratio bound neutered to the pre-fix flat ceiling) |
| `go test -count=1 ./internal/secscan/` | pass |
| `go test -run 'Scan\|Decompress\|DPI\|CDR\|Inspect\|Magic\|Polyglot\|Clam\|YARA\|Metrics\|Support\|OTLP' -count=1 .` | pass |
| `golangci-lint run --new-from-rev origin/main` (the gate's own command, v2.15.0 installed with the `go.mod` toolchain) | see the PR body for the result at the pushed SHA |
| Full-tree `golangci-lint run`, compared against the same measurement on `origin/main` | see the PR body |
| `go test -race ./...` | see the PR body for the result at the pushed SHA |

A passing local check is not a passing hosted gate; the Fast PR Gate's sharded
`-race` run and CodeQL are authoritative.

---

## 11. Residual risk

- **The absolute per-response ceiling is unchanged.** 64 MiB is still reachable;
  it now costs ≥1 MiB of transferred bytes instead of 160 KiB. The aggregate
  across concurrent responses is therefore still unbounded, and §7.1/§7.2 are
  the two rows that would close it. The measured 12.6x peak reduction in §2.1 is
  the improvement **for the cheap attack**, which is the one an attacker would
  choose; it is not a bound on the expensive one. 32 streams × 64 MiB = 2 GiB
  remains reachable for roughly 32 MiB of sustained transfer, so this round
  raised the price by 6.4x rather than closing the door.
- **The ratio is a heuristic, and heuristics have a tail.** A legitimate object
  that genuinely compresses past 64:1 *and* transfers more than 16 KiB is
  refused. The measured legitimate range tops out around 50:1 for the most
  repetitive real content, and the floor covers small responses, but a
  pathological-but-honest object — a multi-megabyte archive of near-identical
  log files, say — is the shape that would hit it. The counter and the log line
  make that diagnosable in one grep rather than invisible, which is the
  mitigation available without a configuration surface.
- **Only the response path was swept.** Request-body expansion, the CDR
  sidecar's own presize path (`X-4`'s second half, untouched this round) and
  the feed/update/support archive extractors each have their own decompression
  and were not re-examined. `support_validate.go`, `restore.go`,
  `release_catalog_bundle.go` and `internal/feedsync` all decompress; none is on
  the unauthenticated request path, which is why they were not this round's
  scope, but none was verified either.
- **`X-5` remains open** and is the other half of the same exhaustion family: a
  refused expansion costs nothing, but an abandoned DPI scan still holds a full
  scan window for as long as `re.Match` runs.
- The backlog rows in §7 and in the
  [2026-10-13](CHAOS-REVIEW-2026-10-13.md) and
  [2026-10-29](CHAOS-REVIEW-2026-10-29.md) rounds that this round did not reach
  are unchanged and keep their original verification status. Nothing there was
  re-confirmed except where §3.1 says so.
