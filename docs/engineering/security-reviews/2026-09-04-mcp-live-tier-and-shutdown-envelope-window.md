# Security regression review — 2026-08-25 → 2026-09-04

**Window:** `9cf2878..0fa02c4` (the commits since the previous review closed at
`9cf2878`, `2026-08-25-mcp-overnight-hardening-run.md`).
**Scope:** every non-test production change in the window — 83 files, ~12,808
insertions / 267 deletions of Go, plus `docker-compose.yml`, `static/index.html`
and the release/CI actions touched in the same range.
**Method:** diff-scoped review prioritised by attacker reachability, then
empirical verification — the project's own invariant gates were executed, and
the one finding was reproduced by measurement, fixed, and mutation-verified
(the fix reverted and the new gates required to fail).

**Verdict: one regression found and fixed (SEC-SHUT-1, Medium). No
authentication, authorization, policy, TLS, crypto, or trust-boundary
regression was found.**

---

## 1. Executive summary

The window is dominated by the MCP Agent Security Gateway live/Canary tier
(ADR-0024/0034/0035) and the CHAOS-56 bounded-shutdown work. The MCP surface is
new code behind a disabled-by-default posture; the shutdown work is a
modification to an existing durability guarantee. Consistent with the general
rule that *changes to existing guards regress more often than new guarded code
does*, the single finding is in the shutdown work, not in the much larger MCP
delta.

`SEC-SHUT-1` is a bound that did not hold in the dimension it claimed. The
CHAOS-56 watchdog grace is documented — in `runtime_shutdown.go` and in
`CLAUDE.md` — as **one shared** overrun allowance per phase, and the
cross-artifact gate `TestChaos56_EnvelopeFitsTheContainerStopGrace` encodes that
as `Total + 2×grace = 51s` and checks it against `docker-compose.yml`'s
`stop_grace_period: 60s`. The implementation charged the grace **per hook**, so
the real worst case grew with the number of registered hooks. Measured on the
shipped constants: **59.2 s**, and **60.0 s** with one further durable closer —
i.e. the shipped tree sat **0.83 s** inside the SIGKILL threshold, and the gate
that exists to detect exactly this drift could not see it, because it validates
a formula rather than the behaviour.

Crossing the stop grace means SIGKILL skips `request-log-close`,
`audit-log-close` and `log-closer` — the durable compliance record, the audit
file descriptor, and the flush holding the lines that say why the process went
down — and leaves the community category store unclean, which is the torn
`MANIFEST` case CHAOS-50's boot-path quarantine exists to survive. That is the
precise loss the three-phase split and the flush reserve were built to prevent.

Fixed by clamping every hook's watchdog to a single per-phase ceiling. The
envelope is now flat in hook count (**51.0 s**, unchanged when a hook is added),
restoring ~9 s of margin.

## 2. Finding ledger

| ID | Severity | Finding | State |
|---|---|---|---|
| SEC-SHUT-1 | **Medium** | The shutdown watchdog grace was charged per hook, not per phase, so the worst-case sequence grew with hook count: 59.2 s measured against a documented 51 s and a 60 s container stop grace. One further durable closer crossed it, making SIGKILL skip the audit/request-log/log-sink flushes. | **Fixed** (this PR) |

No other finding rose to a reportable defect. §4 records what was reviewed and
why it is assessed as sound, as the review contract requires.

---

## 3. SEC-SHUT-1 — the shutdown envelope was not bounded in hook count

### Attack scenario

Not directly attacker-triggerable; it is a fault-activated loss of the audit
record, which matters because the audit log is the artifact an operator relies
on *after* an incident.

1. A storage fault stalls one or more shutdown hooks that cannot observe `ctx` —
   an `fsync` inside a durable close, a badger compaction, a `write(2)` into a
   wedged NFS mount. This is the exact fault class CHAOS-50, CHAOS-56 and the
   `storage_health.go` plane are built around, and it is reachable without an
   adversary.
2. The operator restarts the container (the ordinary remedy).
3. Each stalled hook extends the phase by a further full grace. With the shipped
   registry the sequence needs 59.2 s; the container kills it at 60 s.
4. SIGKILL lands mid-flush. The in-flight audit batch is lost (`internal/audit`
   documents the ring as holding only the newest 500 entries and being wiped on
   restart, so the JSONL file is the durable record), the request-log queue is
   not drained, and the category store closes unclean.

The adversarial version is indirect but worth stating: an attacker who can
induce storage pressure — the SOCKS5 accept-storm of CHAOS-54 wrote ~40 MB/s
into the process log — and who then causes or awaits a restart, degrades the
very record of what they did. Audit-trail destruction is the objective; the bug
supplies the mechanism.

### Preconditions

- Two or more shutdown hooks stalled in the same phase (one alone stays inside
  the envelope), or an ordinary future change adding a hook to any phase.
- A container/orchestrator stop grace at or near the shipped 60 s.

### Exploitability / likelihood

**Exploitability: Low** — no direct request path reaches it; it requires a
storage fault plus a restart. **Likelihood: Medium and rising** — it needed no
adversary at all, and the margin was 0.83 s, so ordinary maintenance (adding one
durable closer, a slower host, scheduler jitter under load) crossed it silently.
The gate designed to catch this could not, which is what makes it a regression
risk rather than a one-off.

### Impact / affected assets

- **Audit log (`internal/audit`)** — the durable compliance record; in-flight
  entries lost. Integrity/completeness of security evidence.
- **Request log (`internal/reqlog`)** — queue not drained.
- **Process log (`internal/logsink`)** — the flush holding the shutdown
  diagnosis is discarded, so the incident is also unexplained.
- **Community category store (`internal/catdb`)** — unclean badger close; the
  next boot may quarantine it.

### Root cause

`hookBudget` redistributes an abandoned hook's unused **slice** to the hooks
behind it, and the original reasoning concluded from that that the phase could
overrun by only one grace. But the grace is added **on top of** each hook's
deadline in `runShutdownHook` and is never charged against the phase's remaining
time, so only the slice is conserved — each stalled hook contributed a further
full grace. The overrun therefore scaled with hook count:

| stalled hooks | 1 | 2 | 3 | 6 | 9 | 10 |
|---|---|---|---|---|---|---|
| phase overrun (in graces), pre-fix | 1.01 | 1.01 | 1.41 | 2.39 | 3.37 | 3.70 |
| phase overrun (in graces), post-fix | 1.01 | 1.01 | 1.01 | 1.00 | 1.01 | 1.01 |

End to end on the shipped constants, every hook stalled:

| | pre-fix | post-fix |
|---|---|---|
| full sequence (6 flush hooks) | 59.166 s | 51.002 s |
| full sequence (7 flush hooks) | **60.016 s → SIGKILL** | 51.004 s |
| documented envelope (`Total + 2×grace`) | 51 s | 51 s |
| compose `stop_grace_period` | 60 s | 60 s |

### Fix

`RunAll` derives a single `phaseAbandonBy = phaseEnd + shutdownHookGrace` and
passes it to `runShutdownHook`, which clamps each hook's abandon instant to it.
The grace becomes what it is documented to be — the phase's, not the hook's.

Deliberately narrow, and in the safe direction:

- **The healthy path is untouched.** The clamp is only reachable once a phase has
  already overrun its deadline; with nothing stalled it is never evaluated.
- **Per-hook budgeting is unchanged.** `hookBudget` still reserves
  `shutdownHookMinSlice` for every hook behind, so the within-phase reserve that
  protects `audit-log-close` from a stalled `syslog-close` is intact. Only the
  overrun allowance is shared.
- **Every hook is still started.** The clamp bounds waiting, not execution; a
  stalled hook never causes the closers behind it to be skipped
  (`TestChaos56_SharedGraceStillRunsEveryHook`).
- **The unbounded shape is preserved.** With no phase deadline `phaseAbandonBy`
  is the zero value and the hook is waited for indefinitely, byte-identical to
  the pre-CHAOS-56 behaviour the un-budgeted tests rely on.
- **A completion already in hand is preferred over an expired timer.** The clamp
  makes an already-fired watchdog ordinary for hooks reached late in an
  overrunning phase, and Go picks uniformly among ready `select` cases, so a hook
  that had returned would otherwise be recorded abandoned about half the time.
  The residual is stated in the code: a hook whose goroutine has not yet been
  *scheduled* can still be recorded abandoned. That is left as-is — a scheduling
  floor is how the per-hook grace grew unbounded in the first place — and it errs
  toward reporting less durability than was achieved, which is the safe direction
  for an operator reading a shutdown log.

Note what was **not** done: neither `defaultShutdownBudget` nor
`stop_grace_period` was widened. Enlarging the envelope would have made the
symptom disappear while leaving the bound still uncomputable from the constants,
and every future hook would re-open it.

### Required tests (all shipped in `shutdown_envelope_test.go`)

| Test | Kind | Pins |
|---|---|---|
| `TestChaos56_PhaseGraceIsSharedNotPerHook` | Regression / boundary | A phase where every hook stalls finishes within deadline + one grace at 1/2/3/6/9/10 hooks |
| `TestChaos56_PhaseOverrunIsFlatInHookCount` | Regression (ratio) | Ten stalled hooks cost no more than 1.5× two — machine-independent, so it holds under `-race` on a shared runner |
| `TestChaos56_FullSequenceFitsTheStopGraceInHookCount` | Regression (end-to-end) | The real `runShutdownSequence` at shipped phase proportions stays inside `Total + 2×grace`, **and does not move when a durable closer is added** |
| `TestChaos56_SharedGraceStillRunsEveryHook` | **Control** | A degenerate "abandon everything" bound would pass the gates above while being worse than the defect; every durable closer must still be started |
| `TestChaos56_HealthyPhaseIsUnaffected` | **Control** / positive | No stall ⇒ no error, all hooks run, no added cost |
| `TestChaos56_UnboundedPhaseStillWaitsIndefinitely` | Negative / boundary | A zero `phaseAbandonBy` must not be read as "abandon immediately" — that would be a fail-open on durability dressed as a bound |

**Mutation-verified.** With the clamp reverted, the three regression gates fail
(6 hooks: 338 ms vs a 250 ms ceiling; ratio 2.35×; full sequence 1.188 s and
1.205 s vs a 1.05 s ceiling) while both controls still pass — so the gates
detect this defect specifically, not merely "something changed".

The pre-existing `TestChaos56_EnvelopeFitsTheContainerStopGrace` is left as it
is: its `Total + 2×grace` arithmetic is now a true statement about the
implementation rather than an assumption about it.

### CWE / OWASP / risk

- **CWE-459** Incomplete Cleanup (primary) · **CWE-778** Insufficient Logging
  (consequence: loss of the durable audit record)
- **OWASP A09:2021** Security Logging and Monitoring Failures
- **Security severity: Medium.** No confidentiality or authorization impact; the
  loss is of security *evidence* and of clean-shutdown durability, under a fault
  that is known-reachable.
- **Regression risk: High (pre-fix).** The failure was silent, the margin was
  sub-second, and the guard's own gate validated a formula instead of the
  behaviour — so the next hook registered would have crossed it with every test
  green. Post-fix the property is bounded in hook count and pinned by a gate
  that moves when the behaviour does.

---

## 4. Reviewed and assessed sound

Recorded explicitly, per the review contract, with the reason each is judged
safe rather than merely "no finding".

**MCP tool-trust, ADR-0034** (`internal/mcp/tooltrust/{store,tooltrust}.go`,
`mcp_tooltrust.go`, `ui_mcp_tooltrust.go`, ~2,700 lines). Four-eyes on
`live_execution` is enforced at the pending→active transition against canonical
authenticated principals (`sess.Sub`), not display strings, and fails closed for
an anonymous caller. Approve routes on the **stored** purpose, so a caller cannot
select which governance applies; `ApproveShadow` and `ApproveLive` each refuse
the other's purpose, and only the shadow path materialises `catalog.Usable`.
Trust is bound to an exact reviewed fingerprint plus a catalog/registry revision
(optimistic concurrency), and `verifyTarget` never re-targets. Commit order is
durable-before-effect with rollback on persist failure, and expiry is re-checked
after the durable write because the clock advances under it. RBAC is
viewer/operator/admin per method, matching `uiRoutes`. The custom
unpaired-surrogate scanner was hand-traced against escaped-backslash,
pair-boundary and truncation cases and is correct; it guards durable-state
tampering, which already presupposes filesystem access.

**MCP live/Canary tier** (`mcp_live_*.go`, `mcp_canary_*.go`,
`internal/mcp/{canary,rollout,execution}`). The disabled-by-default posture holds:
`mcp_execution_posture_test.go` and the `*_wall_test.go` gates pass. A nil
`LiveGate` in the composition input means *compose the real production gate*, not
*skip the gate* — the fail-safe direction — and the executor has exactly one
composition site. Zero values fail closed (`RiskUnknown`, `selectorSchema`
rejects a higher schema whole rather than under-matching). The Shadow Exit Review
attestation is admin-only, never synthesised at startup or from passing tests,
bound to `version+commit` so a build change invalidates it, atomically written
`0600`, and quarantined-and-treated-as-absent when corrupt. Note that the
project's own First Controlled Canary review already records 15 open blockers to
activation; those are pre-activation gaps, not reachable defects in the shipped
default posture, and are not restated here.

**`internal/fileblock`** — an existing data-path control, so reviewed closely.
The lock-free view is correct: every one of the five write sites
(`SetPath`/`Add`/`ReplaceAll`/`Remove`/`ClearAll`) republishes before releasing
the lock, pinned per mutator by test. A never-published view reads as *allow*,
which is identical to the prior zero-valued nil-map behaviour, so it is not a new
fail-open. The `CheckContentType` pre-filter is the load-bearing part: it is a
*purely negative* filter and every block is still decided by the unchanged
`mime.ParseMediaType` body. Its equivalence claim was verified against the actual
toolchain rather than taken from the comment — Go 1.26.6's `ParseMediaType`
computes `mediatype` as `strings.TrimSpace(strings.ToLower(base))` over
`base, _, _ := strings.Cut(v, ";")`, reproduced verbatim, and returns an error
otherwise. Rename-bypass prevention is intact; package tests pass.

**Admin API / RBAC.** New routes (`/api/mcp/tool-approvals`,
`/api/mcp/tool-approval-decision`, `/api/mcp/rollout/rehearse-rollback-authoritative`,
`/api/mcp/canary/shadow-exit-review`) all carry per-method `uiRoutes` metadata
matching their handler-level `requireRole`, preserving invariants #1, #2 and #6.
C1/C2/C4/D0 parity gates pass. The `sessionAdmin` change *improves* attribution
(Basic-auth actor instead of `"unknown"`); the context key is an unexported type
set only after `VerifyUIUser` succeeds, so it is not caller-influenced.

**Custom UI TLS upload** (`ui_tls_custom.go`, `ui_security.go`). Admin-only,
`MaxBytesReader`-bounded before parse, audited, validated via
`certMgr.ParseTLSPair` before persisting. Paths are fixed under `dataDir` (no
traversal); key `0600`, cert `0644`. The two-write torn-pair window is handled by
re-validating with `tls.LoadX509KeyPair` at startup and degrading to the
self-signed certificate rather than a fatal boot failure.

**Control plane** (`controlplane_server.go`). The change is the CHAOS-56 bounded
`GracefulStop`; no authentication, mTLS, or snapshot-redaction behaviour is
touched. Force-close is safe because an interrupted unary RPC is retried by the
caller's own sync loop.

**Catalog ingest / event validation.** `parseDiscovery` treats any non-string or
non-empty `nextCursor` conservatively as *not known-complete*, so an
omission-based withdrawal never fires against a possibly-partial page — the
fail-safe direction. A malicious server can suppress its own tools' withdrawal
this way, but it controls those tools regardless, so there is no privilege gain.
The event schema widening from one version to a set is guarded on the write path:
`validateShadowWriteOnly` requires new shadow events to be v2 with complete
evidence, so v1 acceptance is a read/recovery compatibility path and not a
downgrade.

**Admin SPA** (`static/index.html`). No XSS vector introduced. The MCP panels
build DOM through `mcpxEl`, which assigns `textContent`; the new UI-cert status
uses `el.textContent`. Third-party-controlled strings (MCP tool and server names)
therefore cannot reach an HTML sink on these paths.

**Log injection (CWE-117).** Every new `logger.Printf` interpolating a non-constant
was checked; the interpolated values are bounded enums (`mcperr.Reason`,
capability/mode strings), OS signals, or internal errors. No new unsanitised
user-controlled value reaches the log.

### Test evidence

`go build ./...` clean; `go vet .` clean; `gofmt` clean. All `internal/mcp`
package tests pass (25 subpackages). `internal/fileblock` passes. The invariant
gates — execution posture, policy-learn and live-production-deps walls,
C1/C2/C4/D0 route-metadata parity, config-surface parity — pass (92 assertions,
zero failures). The full shutdown suite, including all 15 pre-existing CHAOS-56
gates, passes with the fix in place.

---

## 5. Residual risk

- **The measured envelope is a worst case under a synthetic all-hooks-stalled
  fault.** It is now flat in hook count, but it is still a wall-clock bound: a
  host slow enough to inflate the phase budgets themselves is outside what any
  constant can pin. The end-to-end gate is scaled 1:50 to stay fast, so it pins
  the *shape* (flat in hook count), not the absolute production seconds.
- **`shutdownFlushBoundary` still governs which hooks get the reserve.** A hook
  registered below it that is durability-critical would not be protected. That
  ordering remains a review responsibility; no gate can infer intent from an
  order constant.
- **SD-5 remains open and untouched** — there is still no unclean-shutdown
  breadcrumb, the one signal a SIGKILL cannot destroy.
- **MCP live/Canary activation remains blocked** by the 15 blockers the project's
  own First Controlled Canary review records. Nothing in this review or PR
  changes that posture, and nothing here should be read as authorising Shadow,
  Canary or Production execution.
- **Scope honesty.** This was a diff-scoped review of one 10-day window, not a
  whole-product audit. The MCP live tier is ~12 k lines of new code reviewed
  against its own documented invariants and its own gates; depth there was
  prioritised by reachability, and the disabled-by-default posture is what makes
  that prioritisation defensible.
