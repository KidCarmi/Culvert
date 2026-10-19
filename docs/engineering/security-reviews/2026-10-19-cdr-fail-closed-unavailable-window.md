# Security review — the CDR unavailable fail-mode bypass, the category normalization hoist, HA epoch fencing and release-dispatch panic containment

**Date:** 2026-10-19
**Reviewer role:** Security Regression Engineer (scheduled run)
**Scope reviewed:** the five pull requests merged into `main` on 2026-10-19 with
security-relevant surface — **#1555** (`internal/urlcat` + `policy_hostcat.go`
host-normalization hoist), **#1611** (CDR circuit breaker / pool / proxy),
**#1605** (release-dispatch panic containment), **#1556** and **#1645** (HA
lease, intent gate, epoch commit, CP gRPC listener supervision, and the admin
and health surfaces they touch). Merge commits `d68bb6d`, `588e5c1`, `b1a21a7`,
`31b4c9d`, `266e684`.

**Scope NOT reviewed — read this before treating the window as closed.** 40
pull requests have merged since the `2026-10-11` review. This run deep-reviewed
the 5 above, chosen by security surface and recency; the other 35 have had no
review in this role. They are the next run's scope, and nothing here should be
read as a statement about them.

---

## 1. Executive summary

**One finding, and it is a real fail-closed bypass rather than a regression the
window introduced.** `cdr.fail_mode: closed` — the operator's instruction that a
document CDR could not scan must not reach the endpoint — was enforced for a
Sluice that *answers* with an error and not enforced when there was no Sluice to
ask. Both the proxy-side liveness gate and the picker inside `safeCDRSanitize`
returned an unconditional pass when no instance was available, so a fail-closed
deployment forwarded every inspected document **unsanitized** for as long as the
engine was down, while `/api/cdr/*` and the startup banner still reported CDR
enabled and fail-closed. The gap sat behind a circuit breaker that opens after 5
consecutive failures and stays open 30 s, which puts the switch within reach of
anything able to make Sluice fail that often. **Fixed in this change** (§6).

The finding is notable less for its depth than for how it hid: the in-code
contract asserted the correct behaviour at *both* sites ("the caller's fail_mode
then decides", "callers treat nil as skip CDR and apply fail_mode") and the
operator runbook assumed it too — `docs/OPERATIONS.md` §6 tells an operator to
switch to fail-open "to keep traffic flowing while you fix the engine", advice
that was a no-op because fail-closed already kept it flowing. Three independent
descriptions of the intended posture, no code implementing it, and no test
asserting it: the one existing test over this path pins the fail-OPEN case.

**The other four PRs are clean**, and two are net tightenings:

- **#1555** (policy host normalization) is a pure cost change. `normalizeHost`
  in package main *is* `hostutil.NormalizeHost` (`security.go:13`), so hoisting
  the canonicalization from the matcher to the caller applies the same function
  to the same input and only moves where. Every seeding site passes
  `normalizeHost` of the same host it passes raw — verified at
  `policy.go:1590`, `ui_policy.go:2779`, `cdrpolicy.go:491` and
  `authpolicy.go:584` (which seeds from its own `normHost()` memo of the same
  `ctx.Host`). The non-idempotence of `NormalizeHost` makes a wrong seed a
  silent matching change rather than a loud failure, which is why it matters
  that the equivalence is pinned by the repo's own named/randomized/fuzz
  oracle (`urlcat_matcheshost_norm_test.go`, `policy_hostcat_normhoist_test.go`)
  and not left to caller discipline.
- **#1611** (CDR breaker) is itself the fix for a fail-open wedge, and its new
  reservation algebra holds: `Release` is generation- and state-guarded
  (`cdr_breaker.go:422`) so a deferred release cannot undo a recorded outcome or
  free a slot of a budget other than its own, and `outcomeIsCurrentLocked`
  retires an outcome whose episode has moved, so a pre-trip RPC's late failure
  cannot reopen a recovered breaker.
- **#1605** (release dispatch) removes a fail-open: `respondPreApply` no longer
  answers `200 {"status":"ok"}` for `(nil, nil)` — the pair a panicking detached
  worker produced — and the recovered path writes `Terminal:
  FAILED_NEEDS_ATTN` with `Verified` at its zero value, so no recovered panic
  can mark an unverified release current. Authorization is unchanged and matches
  the route metadata (`RoleAdmin` dispatch/resume, `RoleViewer` status).
- **#1556 / #1645** (HA) strengthen the authority model. The new `gatedUnary`
  wrapper fails **closed by omission** — an RPC with no policy entry takes the
  gated branch (`controlplane_server.go:1171`) — and the staged → committed →
  exposed grant sequence means a staged grant confers no write authority, no
  certificate issuance and no advertised epoch. The new `cp_grpc` field on the
  unauthenticated proxy-port `/health` is a closed five-value enum
  (`cp_grpc_health.go:783`) carrying no address, node ID, attempt count or error
  text, and the node's CP-ness was already public on the same response via
  `cluster_ca`. The new `/metrics` series carry no labels at all.

---

## 2. Finding — `cdr.fail_mode: closed` not enforced when CDR is unavailable

| | |
|---|---|
| **Severity** | **High** |
| **CWE** | CWE-693 Protection Mechanism Failure; CWE-754 Improper Check for Unusual or Exceptional Conditions |
| **OWASP** | A04:2021 Insecure Design (fail-open on a security control's unavailability); A05:2021 Security Misconfiguration (configured posture not applied) |
| **Affected assets** | Every endpoint receiving a file through an SSL-inspected tunnel on a `fail_mode: closed` deployment |
| **Regression risk of the fix** | Low — fail-open deployments are byte-identical; only explicitly fail-closed deployments change, and they change toward what they configured |

### Attack scenario

**Preconditions.** CDR enabled with `cdr.fail_mode: closed` (or
`-cdr-fail-mode closed`); at least one Sluice instance enrolled; the attacker
can get documents to a user through the inspected proxy, which is the ordinary
web-download path.

1. The attacker sends, or induces a user to fetch, `FailureThreshold`
   documents of a class that makes the Sluice engine return `Status_ERROR` —
   a malformed container, a decompression bomb the engine refuses, anything
   the engine faults on. The default threshold is **5 consecutive failures**
   (`cdr_breaker.go:71`).
2. Those requests are themselves blocked (`cdrErrorOutcome` honours
   fail-closed), so the attacker's probing is invisible as a bypass — it
   looks like the control working.
3. On the fifth failure the instance's breaker opens for `ResetTimeout`,
   **30 s** by default. With one instance, or with every instance faulting on
   the same input class, the pool now has nothing available.
4. For the whole open window, `runCDRStage`'s liveness gate returned a pass
   and every inspected document — including the attacker's actual payload —
   was forwarded **unsanitized**, with no CDR verdict, no block, and no
   `fail_closed` counter movement.
5. Half-open admits exactly **one** probe per window. The attacker makes that
   probe fail and holds the window open indefinitely, so sustained traffic is
   scanned at a rate of one document per 30 s and passed otherwise.

Sluice does not have to be attacked at all for the same exposure: an ordinary
engine crash, an OOM, a container restart, a certificate-pinning mismatch, a
network partition, or an un-enrolled instance after a config rollback all
produce the identical "no instance available" state. The attacker-driven path
matters because it makes the window *reachable on demand* rather than only
coincident with an outage.

**Exploitability:** moderate — no credentials and no privileged position are
needed, but the attacker needs an input class that faults the engine, and the
window is time-bounded and loudly visible in metrics (`culvert_cdr_errors_total`,
`culvert_cdr_pool_breaker_state`) *if* someone is watching them.
**Likelihood:** high as an *outage* consequence, independent of any attacker.
**Impact:** complete loss of content disarm for the window, on a deployment that
explicitly configured the opposite. Malicious macros, embedded objects and
active content reach endpoints with no verdict recorded against them.

### Evidence (pre-fix)

- `cdr_proxy.go` `runCDRStage` — `if !cdrAnyInstanceAvailable() { return
  cdrStageDecision{body: body, scanBody: scanBody} }`: the pass does not consult
  `cfg.FailMode`, and `cdrStageDecision` has no way to express a refusal.
- `cdr_proxy.go` `safeCDRSanitize` — `if pooled == nil { return
  cdrPassSkipped("SKIPPED") }`, directly under a comment stating that the
  caller's `fail_mode` then decides. The caller does not.
- `cdr_pool.go` `cdrPickPooledReserved` doc — "callers treat nil as *skip CDR*
  and apply fail_mode."
- `cdr_proxy.go` `cdrErrorOutcome` was the **only** runtime consumer of
  `CDRFailOpen()` (`grep` over non-test Go: `cdr_ui.go:138` is a status field,
  `cdr_startup.go:62` is the startup banner string, `main.go:970` is a comment).
- `cdr_pool_test.go` `TestSafeCDRSanitize_BreakerOpenReturnsSkipped` pins this
  path with `CDRConfig{Enabled: true}` — fail-open. No test covered fail-closed
  here, which is why the three prose descriptions of the correct behaviour never
  met a counterexample.

---

## 3. Regression analysis

**Is this a regression of the reviewed window?** No. The unconditional pass
predates all five PRs. #1611 moved the liveness gate from `cdrActiveClient() ==
nil` to `!cdrAnyInstanceAvailable()`, which changed *which* conditions reach the
branch (correctly — that PR fixed a permanent half-open wedge) but not what the
branch does. It is reported because the role's mandate is broken fail-closed
behaviour, not only newly broken behaviour, and because #1611's own comments
show the authors reasoning about the fail-open impact of the wedge while
assuming fail-closed would have refused — the belief that keeps the gap alive.

**What the fix changes.** Only deployments with `fail_mode` explicitly
`closed` (case-folded, trimmed). For them, an unavailable engine becomes a
`CDR_BLOCKED` refusal with reason `cdr_unavailable` instead of a silent pass.
Fail-open deployments — the default, every unset config, and every explicit
`open` — take the same early return as before, touch the same counters (none),
and write the same log lines (none). A **disabled** CDR never blocks regardless
of `fail_mode`, because an empty pool is also what "off" looks like to the
picker; blocking there would deny every inspected document on a deployment that
never asked for CDR.

**Availability consequence, stated plainly.** On a fail-closed deployment a
Sluice outage now interrupts document delivery through inspected tunnels. That
is the posture `fail_mode: closed` requests and the behaviour the runbook
already assumed; the runbook's escape hatch (switch to fail-open while you fix
the engine) becomes meaningful rather than decorative. This is a deliberate
behaviour change to align implementation with configured intent, not a
posture change — and it is the direction the Implementation Rules require
("prefer fail closed").

---

## 4. Non-findings — recorded so the next run does not re-litigate them

1. **`SKIPPED_OVERSIZE` still passes unsanitized under fail-closed.** A file
   over the profile/config cap, and a Sluice-side `file_too_large`, are
   documented as explicitly *not* fail-mode events (`cdr_proxy.go`
   `cdrHandleCallError`). That is a reviewed decision about a file the engine
   cannot process at all, distinct from an engine that is not there. Left as is;
   the fix deliberately does not touch it.
2. **Role-less epoch floor** (`ha_fencing.go:106`) returns
   `max(leaseEpoch, committedEpoch)` rather than 0 with `role == ""`. Reachable
   only when a first `EnableAsLeader` committed epoch E and then lost the grant
   before exposure; no peer can hold E (the etcd `CreateRevision` epoch is
   cluster-unique) and the next real leader is at `>E`. Recorded owner decision
   on Codex P1 4302435329, in ADR-0005's implementation notes.
3. **A panic after apply writes `FAILED_NEEDS_ATTN` without firing
   `maybeAlert`** (`release_api.go:935`). The pre-#1605 behaviour was process
   death, so no working control got weaker; the crash counter always increments
   and §43 of the chaos review records the deferral.
4. **`DispatchService.contained()` swallows a panic from an audit sink**
   (`release_dispatch_service.go:316`), which would leave `internal/audit`'s
   non-deferred mutex held. No supported trigger — the critical section is a
   slice append and two reads — and the lock-without-defer shape predates the
   diff.
5. **`selfFence` (`ha_lease.go:400`) is now dead in production.** Hygiene only.

---

## 5. Files

| File | Change |
|---|---|
| `cdr_proxy.go` | `cdrUnavailableOutcome` / `cdrUnavailableFailsClosed` / `cdrUnavailableBlockReason`; both unavailable paths routed through them; `cdrEmitStageBlock` extracted from the `cdrBlock` branch so a refusal and a verdict block emit identically |
| `cdrstore.go` | `initCDRClient` publishes the config it is applying **before** returning the complete-pool-failure error, so a cold start that cannot reach Sluice does not read itself as disabled (Codex #1668 P1) |
| `cdr_pool.go` | `cdrPickPooledReserved` doc: nil means *cannot be scanned*, route it through `cdrUnavailableOutcome` — a bare pass there is the bypass |
| `cdr_metrics.go` | `culvert_cdr_fail_closed_total` HELP and the counter comment widened to cover unavailability, not only engine errors |
| `cdr_fail_closed_unavailable_test.go` | New — the suite in §7 |
| `docs/OPERATIONS.md` | §6 states the fail-closed refusal (reason, counter, log) and that a disabled CDR never blocks |
| `CHANGELOG.md` | `[Unreleased] → Security` entry |

## 6. Suggested fix (as implemented)

Both unavailable paths route through one decision point:

```go
func cdrUnavailableFailsClosed(cfg CDRConfig) bool {
	return cfg.Enabled && !cfg.CDRFailOpen()
}

func cdrUnavailableOutcome(cfg CDRConfig) *cdrRunResult {
	if !cdrUnavailableFailsClosed(cfg) {
		return cdrPassSkipped("SKIPPED")
	}
	atomic.AddInt64(&statCDRFailClosed, 1)
	return cdrBlockResult(cdrUnavailableBlockReason, nil, "", "", 0, false)
}
```

Safe-implementation properties:

- **Explicit validation over inference.** `cfg.Enabled` is checked, not assumed
  from pool emptiness, so "off" and "down" stay distinguishable.
- **The refusal takes no breaker reservation**, so it cannot strand a half-open
  probe — the CHAOS-72 failure mode this must not reintroduce.
- **One emission path.** `cdrEmitStageBlock` serves both the refusal and the
  verdict block, so an operator's request log, block page and `CDR_BLOCKED` line
  look the same whichever produced it, and the two cannot drift.
- **Hot path untouched.** The config read lives inside the unavailable branch;
  the scanning path keeps its single pre-existing `cdrActiveConfig()` read at
  the call site, so the fix adds no lock to a request that gets scanned.
- **Counter semantics preserved.** The fail-open pass still touches nothing.

## 7. Required tests (as implemented)

`cdr_fail_closed_unavailable_test.go`:

| Class | Test |
|---|---|
| Positive | `TestSafeCDRSanitize_AllBreakersOpenFailClosedBlocks`; `TestRunCDRStage_UnavailableFailClosedRefusesTheTunnel` (asserts the block page is written and `statCDRBlocked`/`statCDRFailClosed` move) |
| Negative | `TestSafeCDRSanitize_AllBreakersOpenFailOpenStillSkips`; `TestRunCDRStage_UnavailableFailOpenForwardsUnchanged` (original bytes through, no counter movement); `TestRunCDRStage_DisabledCDRNeverBlocks` |
| Positive control | `TestSafeCDRSanitize_FailClosedWithHealthyInstanceStillScans` — fail-closed must not refuse a document CDR *can* scan |
| Boundary / malformed input | `TestCDRUnavailableOutcome_AppliesFailMode` over every spelling `CDRFailOpen` folds — `closed`, `CLOSED`, `Closed`, `"  closed  "`, unset, `open` — and both enablement states |
| Regression | The pre-existing `TestSafeCDRSanitize_BreakerOpenReturnsSkipped` is left passing unchanged; it is the fail-open half of the contract |
| Concurrency | `TestCDRUnavailable_FailClosedIsRaceFreeAndLeavesTheBreakerAlone` — 24 concurrent requests under `-race`, all refused, breaker still open, `staleProbes` unchanged |
| Authentication / authorization | No new surface: the fix is in the proxy data path, adds no route and no handler. The adjacent admin surface (`apiCDRTest`) keeps its `requireRole(w, r, RoleAdmin)`, verified unchanged. |

## 8. Verification

- `go build ./...` — clean.
- `go vet ./...` — clean.
- `go test -race` on the CDR breaker/pool/proxy suites plus the new file — all
  pass, including the pre-existing fail-open test.
- `go test` on the whole root package at the final tree — see the pull request
  for the result at the exact SHA.
- `python3 docs/agent-context/check.py` — passes (no guidance path changed).
- **Not run:** `golangci-lint` and CodeQL. The sandbox's `golangci-lint` is
  2.5.0 built with Go 1.25 and panics loading this Go 1.26 module
  (`package requires newer Go version go1.26`); CI's pinned version is
  authoritative. `runCDRStage`'s cyclomatic complexity is 7 after the change
  (the `cdrBlock` branch moved out), well inside the cyclop threshold of 15.
- A passing local run is not a passing hosted review or merge gate.

## 8a. Post-review finding — the same bypass through a lost config (Codex #1668 P1)

Codex's review of the fix found a second route to the identical exposure, and it
is the more likely one in production. `initCDRClient` returned its "every
instance failed to dial, or none enrolled" error **before** the
`cdrActiveCfg = cfg` publish, so a total pool-construction failure left the
active config at its zero value — `Enabled: false`. Since
`initCDRInfrastructure` logs that error and continues by design
(`cdr_startup.go`: "CDR: initial client dial failed, CDR effectively
disabled"), an appliance configured enabled + `fail_mode: closed` that **booted
while Sluice was unreachable** read itself as disabled: `cdrUnavailableFailsClosed`
saw `Enabled` false, the unavailable path returned `SKIPPED`, and every
inspected document was forwarded unsanitized. The §2 fix alone would not have
covered it — the posture never reached the decision.

Verified at source before fixing: the early `return` precedes the publish, and
`setCDREnabledRuntime` (whose "truthful flag (unchanged on failure)" comment in
`cdr_ui.go` looked like a deliberate reliance on NOT publishing) only mutates
`Enabled` in place and never calls `initCDRClient`, so nothing depended on the
old ordering.

The failure path now publishes before returning the error. Two pre-existing
defects fall with it:

- `checkCDR` (`diagnostics.go`) reported a boot-time total dial failure as
  `"disabled"` with status **OK** — a broken appliance reading as healthy —
  instead of the `enabled-broken` / `diagFail` row that state is for.
- `propagateServerRotation` and the RenewCert poller both re-init with
  `initCDRClient(cdrActiveConfig())`. Handed a zero config, that takes
  `!cfg.Enabled` → `shutdownCDRClient()`, so the recovery paths **turned CDR
  off until restart** instead of retrying.

Breaker seeding is unaffected: `buildCDRPoolFromRegistry` has already returned
and built nothing, so the `cdr_breaker.go` rule that a breaker is seeded from
the config being applied and never from the published one still holds on this
path.

Pinned by `TestCDRUnavailable_FailClosedSurvivesPoolInitFailure` (and its
fail-open negative control), which drive the real `initCDRClient` failure.
Both were confirmed to **fail against the un-fixed `cdrstore.go`** and pass
against the fixed one, rather than being written to the fix.

## 9. Residual risk

1. **35 of the 40 pull requests merged since 2026-10-11 have not been reviewed
   in this role.** This is the largest residual item and the next run's scope.
2. **`SKIPPED_OVERSIZE` remains a documented pass** under fail-closed
   (non-finding 1). If the intent is that *nothing* unscanned reaches an
   endpoint on a fail-closed deployment, that is a separate, operator-visible
   decision — an oversize file would start being refused — and should be taken
   deliberately, not folded into this fix.
3. **The fix is enforced at the inspected-tunnel CDR stage only**, which is
   where CDR runs today (`runCDRStage` has one caller, `proxy_tunnel.go:1324`).
   A future CDR call site — a request-direction/upload path, an H2 stream path —
   must route its own unavailable case through `cdrUnavailableOutcome`. The
   `cdr_pool.go` doc now says so at the picker, which is the place a new caller
   will read.
4. **No alert fires on the refusal.** A fail-closed deployment losing CDR is
   visible as `culvert_cdr_fail_closed_total` rising and the existing
   `cdr_unavailable` alert on the error path, but a pool that is empty because
   no instance is enrolled produces no engine errors to alert on. The
   `enabled-broken` diagnostics state covers it for anyone looking at the page.
