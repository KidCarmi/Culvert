# Production Merge Review — Sensitive Pushes (Palo-Alto-style)

Review posture: a senior security-appliance reviewer deciding **go / no-go
to production**. Culvert is an inline security control (forward proxy,
TLS-inspecting, Zero-Trust policy). The bar is not "tests pass" — it is:
fail-closed under every failure mode, no silent weakening of a security
control, bounded blast radius, clean rollback, observable in production,
and an auditable trail for every security-relevant mutation. A "sensitive
push" is any change to the threat/verdict path, auth, the CA/TLS surface,
connection limits, or the audit trail.

Verdict scale: **MERGE** (ship to prod) · **MERGE w/ conditions** ·
**HOLD** (fixable, not yet) · **NO-MERGE** (reject as-is).

---

## #623 — Threat-feed domain allowlist consolidation  →  **MERGE (conditions met)**

**What it changes in the control path.** Adds a lookup-time mask: an
allowlisted host's *domain-level* threat-feed hit is suppressed, while its
*exact malicious-URL* hit is still enforced. Supersedes #614/#615.

**How I reviewed it (adversarially).** Three independent lenses
(correctness/concurrency, security boundary, ops/cluster) plus a lead pass.
The full record is in `OPEN-PR-REVIEW.md` and `MERGE-EXECUTION-PLAN.md`.

**The questions a Palo reviewer asks, and the answers:**

1. *Can the allowlist unblock a known-bad URL?* No. `CheckURL` matches the
   exact-URL map **before** the domain fallback and returns unconditionally;
   the mask is only on the domain fallback. Pinned by tests. **This is the
   load-bearing invariant and it holds.**
2. *Can anything but an admin write the allowlist?* No. Write paths are the
   admin-RBAC API (PUT, `requireRole(admin)` + route metadata) and the
   CP→DP config snapshot (ClusterSynced surface). **Feed content cannot
   inject an allowlist entry** — ingest no longer reads the allowlist. This
   is tighter than the pre-existing code.
3. *Does it fail closed?* Yes. Unparseable host → no mask (blocks). Persist
   failure → in-memory apply + HTTP 500 + a distinct
   `threatfeed.allowlist.update_unpersisted` audit action (no silent
   security-posture change). Feed disabled → early return. IDNA fail-open
   is admin-pattern-only and can only ever collide with the *same* string,
   never mask a different domain.
4. *Version skew / rollback — the real trap.* The first cut retained masked
   domains on disk and on the wire, which **changed the meaning** of the
   persisted `domains` map and the `ThreatFeedDomains` wire field without
   changing their shape — an older binary (rollback, or an un-upgraded DP in
   a rolling upgrade) has no lookup-time mask and would hard-block
   github.com / drive.google.com fleet-wide (these routinely appear in
   URLhaus). **Caught in review, fixed:** masked-domain retention is now
   in-memory only; the persisted key and wire field exclude allowlisted
   hosts, preserving legacy meaning. Verified against the actual old-code
   paths in both upgrade directions. This is the finding that would have
   caused a prod incident, and it is closed.
5. *Cluster consistency.* Allowlist full-clear now propagates as an explicit
   wipe (dropped `omitempty`, registry row `WireWipeCapable`, parity suite
   green) — a DP can no longer be left holding a stale fail-open mask. PUT
   publishes a snapshot so DPs converge within one poll (≤30s) rather than
   waiting for an unrelated admin action.
6. *Is the bypass observable?* Yes (added in this review):
   `culvert_threat_feed_allowlist_masked_total` + a status-API field count
   every real suppression. A security-control bypass that can't be seen is a
   prod anti-pattern; this one is now metered and alertable.
7. *Blast radius / rollback.* Touches threat-feed verdicts, persistence, and
   CP/DP sync. Rollback = revert the PR (one logical unit); **binary
   rollback after deploy is safe by construction** (legacy surfaces keep
   their meaning). Residual: in-memory masked intel is rebuilt by the next
   feed sync after a restart — acceptable, documented.

**Residual risks (accepted, not blocking):** (a) old-CP → new-DP: a
pre-#623 CP omits the allowlist field, so a new DP keeps its last allowlist
until the CP is upgraded — bounded by the upgrade window, standard for a
config-sync field; (b) duplicate IDNA pass on the dispatch hot path —
deliberately **not** fixed here (threading a pre-normalized host through the
secscan layer touches the RISK-013 strict-gate contract and does not belong
in a verdict-semantics PR); logged as a follow-up.

**Operator story.** `docs/operator/threat-feed-domain-allowlist.md` ships:
security boundary, the sharper non-inspected-CONNECT trust consequence
(allowlisting a host on an opaque CONNECT path trusts *all* traffic to it —
prefer SSL inspection for allowlisted hosts), the masked metric, and the
upgrade/rollback behavior.

**Evidence.** gofmt/vet/build clean; full `go test ./...` 50 pkgs / 0 FAIL
(re-run per commit); `-race` on the engine; isolated `-shuffle=on -count=2`
on the once-flaky test; all `TestConfigSurfaces_*` parity tests. On PR:
Deep Gate APPROVED, govulncheck green post-toolchain, Snyk/CodeQL clean;
only red is the advisory playwright driver-CDN 404 (repo-wide infra).

**Verdict: MERGE.** The one prod-incident-class defect (version-skew
poisoning) was found and fixed; the security boundary is proven, fail-closed,
observable, auditable, and rollback-safe. Condition already satisfied:
toolchain #624 is merged so the required govulncheck gate is green.
Ship after a human maintainer confirms the Phase-3 record — which is the
one thing a reviewer should never rubber-stamp on another reviewer's word.

---

## #622 — Chaos fixes (SOCKS5 conn-limit, OCSP outage TTL, CP version floor, CA visibility)  →  **MERGE w/ conditions**

**Control-path relevance:** high — touches OCSP revocation caching (TLS
trust), SOCKS5 resource limits (DoS), and CP config-version monotonicity
(does a config change reach DPs at all).

- *OCSP short-TTL:* an all-responders-unreachable verdict stays **fail-closed
  (revoked)** but expires in 2 min instead of 1 h. This does **not** weaken
  revocation — a confirmed-revoked cert keeps the full TTL; only outage
  recovery latency shrinks. Correct direction.
- *SOCKS5 conn-limit:* closes a real per-IP FD/goroutine DoS bypass; inert
  when the limiter is disabled (default). Good.
- *CP version floor:* fixes a HIGH — a CP restart silently suppressed all
  post-restart config sync. Durable floor + reseed. Correct.
- *CA load-failure visibility:* surfaces a silent fail-open of the primary
  inspection control. Correct.

**Conditions before merge:** (1) fix the 4 self-inflicted lint findings in
its own new test files (noctx / whyNoLint) — currently red; (2) merge **#581
first**, then rebase #622's `internal/ocsp` hunks over it (they touch the
same lines); (3) release-note the epoch-scale config-version rollback caveat
(a reverted CP needs DP restarts to resync). Also: salvage #610's unique
2026-07-07 review doc before closing #610. **Verdict: MERGE once the four
lint fixes land and #581 is sequenced ahead.** The fixes themselves are
prod-worthy and fail-closed.

---

## #612 — Policy engine precompute (Zero-Trust hot path)  →  **MERGE**

**Control-path relevance:** maximal — this is the default-deny evaluator on
every request. The rule for a hot-path perf change: behavior must be
**bit-identical** and every precompute must have an allocating fallback so
correctness never depends on the optimization.

- Verified: fail-closed on invalid CIDR / unparseable client IP / invalid
  tz; precompute populated under lock in `sortLocked` (every mutator funnels
  through it, incl. the DP `ReplaceAll` sync); nil precompute → allocating
  fallback. Two deliberate, documented deltas (log-once tz warning; invalid
  tz cached as UTC until restart) — neither changes a match decision.
- Hard alloc benchgates wired into the required perf lane guard against
  regression.

**Verdict: MERGE**, and it is the survivor of the #583/#605/#612 trio —
close those two after it lands. Condition: post-merge soak watching the
latency histogram + policy hit counters (standard for any hot-path change).

---

## #581 — OCSP fail-closed observability  →  **MERGE**

Additive counters on an already-viewer-readable API + a UI banner; the
fail-closed/revoked decision logic is byte-identical (increments only). No
new route, no RBAC change. Makes a top-MTTR fail-closed condition visible
from the GUI instead of via SSH+grep — the kind of observability a prod
reviewer *wants*. **Verdict: MERGE**, sequenced **before #622** (conflict-free
against main today; #622 rebases over it).

---

## #618 — default-auth-outcome route + DPI-bypass audit-action rename  →  **MERGE w/ conditions**

Touches the **audit trail** (sensitive) and an API route. Done correctly:
canonical route added with the legacy path kept as an alias (spec's
back-compat requirement honored), all admin-UI invariants updated (route
metadata both paths, C1/D0 locks, alias regression test), RBAC unchanged.
The one real-world consequence: external SIEM filters keyed on the old
`security.dpi_bypass` action string stop matching. **Condition: ship a
release note for the audit-action rename** (repo precedent exists for this
class). **Verdict: MERGE with the release note.**

---

## #503 — connlimit Release-while-disabled leak  →  **NO-MERGE as-is / REBUILD (must-fix bug)**

The *bug is real and live on main*: a per-IP counter leak that permanently
phantom-blocks a legitimate IP after an admin disable/enable cycle
(restart-only recovery) — a self-inflicted DoS. But the PR's diff targets the
pre-ADR-0002 file layout and its test uses unexported struct literals; it
**will not compile** against current main. **Verdict: NO-MERGE the branch;
REBUILD** the 3-line guard deletion in `internal/connlimit/connlimit.go` +
port the contract test. Land it **near #622**, which widens exposure to the
same leak via its new SOCKS5 Release path. This is a must-fix for a
DoS-hardened prod posture.

---

## #515 — auth kill-switch must not disable CR rules (no-backend Exempt)  →  **NO-MERGE as-is / REBUILD (security must-fix)**

The most security-sensitive item in the backlog. The *bug is live on main*:
engaging the Exempt kill switch — a control that is supposed to be strictly
*more* restrictive — actually **weakens** enforcement in a no-backend Exempt
deployment (scoped CredentialRequired rules stop challenging), violating the
frozen defaultAuthOutcome spec. A security control that fails *open* when
engaged is exactly what a Palo reviewer blocks a release on. The PR's branch
predates Slice 5 + DEBT-002/003 and won't compile. **Verdict: NO-MERGE the
branch; REBUILD** in `resolveRequestAuth` (capture pre-kill-switch effective
default; add the no-backend inert guard) with tests on `SetDefaultAuthOutcome`
proving red-before/green-after per the spec matrix. **Treat as a release
blocker until landed or explicitly risk-accepted.**

---

## Cross-cutting prod blockers (not a single PR)

1. **HA-lease test race** (`TestSelfFence_EntersStandbyResync`) — a live flake
   that non-deterministically reddens required gates. A flaky required gate
   means you cannot trust "green" as a merge signal. **Fix or quarantine
   before cutting a release.**
2. **Playwright driver-CDN 404** — the browser-level RBAC e2e is dark
   repo-wide (advisory, so it doesn't block, but it means admin-UI RBAC is
   unverified end-to-end in CI). Re-pin the driver.
3. **#619 F1** — merge-mode config import silently skips conflicting rules
   (log-only, response says ok). A silently-dropped *deny* leaves traffic
   flowing against admin intent. Unclaimed; should be tracked before a
   release that markets policy-as-config.

---

## Bottom line (what I would tell the release owner)

- **Ship now (sensitive, cleared):** #623, #612, #581 — fail-closed,
  observable, rollback-safe, adversarially reviewed.
- **Ship after named conditions:** #622 (own lint + sequence behind #581 +
  release note), #618 (release note).
- **Release blockers until rebuilt:** #503 (DoS) and #515 (auth fails open
  when the kill switch is engaged). Neither is mergeable as its current
  branch; both are live bugs on main.
- **Gate hygiene before tagging a release:** de-flake the HA-lease test and
  restore the playwright lane so "required checks green" is a trustworthy
  signal.

No MVP-hard blocker remains once #503/#515 are rebuilt (or consciously
risk-accepted) and the gate flake is quarantined. The threat-feed work
(#623) is production-ready.
