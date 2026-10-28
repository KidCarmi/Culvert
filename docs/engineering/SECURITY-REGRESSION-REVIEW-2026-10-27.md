# Security Regression Review — 2026-10-27

**Scope.** `origin/main...claude/epic-bardeen-mnyj0f` — 205 commits, 117 files,
+32,757/-590. The branch is itself a security-hardening sweep (CHAOS-68/70/73/
76/79/83/87/88, AU-2…AU-72, SEC-REVEXP-1, T-70): durable fleet-wide session
revocation, a shared revocation-expiry oracle, cluster sync byte budgets, an
identity-result cache package, IdP session cutoffs, portal-logout admission and
SIEM delivery accounting.

**Question asked.** Not "is the hardening good?" but the inverse: **did the
hardening introduce a security regression?** Every finding below is measured
against the base revision, not against an ideal.

**Method.** Four independent bounded audits (syslog/SIEM+alerts, cluster/control
plane/HA, identity cache+IdP, admin control plane+proxy+store), each required to
read production callers rather than diff hunks, plus a lead pass over the
revocation core. Every candidate finding was then put through a disproof pass
and, where it survived, a **differential oracle**: the gate must fail on the
pre-fix code and pass on the fixed code. Reasoning alone was not accepted as
evidence for any finding.

---

## 1. Executive Summary

**One confirmed, exploitable fail-open regression was found, fixed and gated.
Two design-level consequences of the branch's intended behaviour are reported
for the owner's decision and deliberately NOT changed. One load-bearing comment
that the branch itself falsified was corrected.**

The hardening work is, on the whole, unusually careful: the expiry oracle
(SEC-REVEXP-1), the MAC-first revocation admission (CHAOS-73), the provenance
MAC, the exact provider-id match (AU-70) and the `SessionsNotBefore` cutoff
(AU-65) are all correct and fail-closed, and I could not break the revocation
sync rotation. The one real defect is a classic second-consumer bug: a bound was
applied to one reader of a peer's push and not to the reader added beside it.

| # | Finding | Severity | Status |
|---|---|---|---|
| **R-1** | CP merges a peer's **unbounded** revocation push into its own session store, bypassing `maxRevocationsPerNode`; one request can saturate the global cap and make the CP refuse **honest** nodes' revocations | **HIGH** (fail-open) | **FIXED + gated** |
| **R-2** | A peer may inject an account revocation for **any username**, durably and fleet-wide; no entitlement check, no un-revoke path | MEDIUM | Reported — owner decision |
| **R-3** | Delete-then-recreate of an account locks the new account out until the old revocation expires (now durable + fleet-wide, was in-memory + single-node) | MEDIUM | Reported — owner decision |
| **R-4** | `session_provider_bounds.go` asserted the `users` map is "neither persisted nor gossiped"; CHAOS-68 in this same branch made it both, retiring the stated containment argument | LOW (doc) | **CORRECTED** |

Surfaces reviewed and found **clean**: syslog/SIEM delivery and drop
accounting, `internal/alerts` retry durability, the identity-result cache
(`internal/identcache`), LDAP/OIDC validation, admin RBAC and audit/config
versioning, `static/index.html` XSS, generated OpenAPI/TS artifacts, proxy
request handling, `store.go` persistence, and CI/lint/toolchain gates (no gate
was weakened; no workflow, `go.mod`, `.golangci.yml` or `Makefile` change).

---

## 2. Security Findings

### R-1 (HIGH, fail-open) — The Control Plane's own revocation merge bypassed the per-node cap

**Files.** `controlplane_server.go:403,428` (call site) · `controlplane.go:382`
(`revocationAggregator.Update`) · `internal/session/revocation_bounds.go:97,342`
(global cap and capacity refusal).

**What changed.** CHAOS-68 gave the CP's `SyncRevocations` handler a *second*
consumer of a Data Plane's pushed entries. On base the handler did one thing:

```go
globalRevAggregator.Update(req.NodeID, req.Entries)   // fan-out slot only
```

`Update` bounds that slice — `maxRevocationsPerNode` (4096), per-field length
limits, `Prov` cleared — and **drops the overflow with a counter**. Its own
comment states the intent: *"reaching it means a node is malfunctioning or
hostile."* But `Update` did not **return** the bounded set, and the branch added
a second consumer handed the **raw request**:

```go
mergeAndPersistRevocations(req.Entries, "ControlPlane")   // the CP's OWN sessionRevoked
```

So the per-node cap governed what the CP **broadcast** but not what it
**enforced and persisted locally**. The only remaining bound was the *global*
`MaxRevocationEntries` (65,536) — a budget shared by the entire fleet.

**Attack scenario.** The RPC accepts `maxClusterInboundMsgSize` = 16 MiB and a
minimal entry marshals to 33 bytes, so **one** request carries ~490,000 entries
against a 65,536 global cap — 7.5× saturation from a single call. Once
`r.tokens` is full, `admitUntrustedLocked` refuses every further untrusted entry
with `RevokeCapacity`. **A genuine logout performed on any other Data Plane is
then no longer honoured on the Control Plane** — precisely the fail-open
CHAOS-68 exists to close, reached from inside the fleet. The junk is written to
the revocations file and re-admitted on reload, so the condition survives
restart for up to `MaxSessionLifetime` (7 days).

**Preconditions.** One enrolled node's mTLS client cert and key (one compromised
DP). `verifyNode` is correctly enforced — this is not an unauthenticated path.

**Exploitability.** High once the precondition holds: a single well-formed RPC,
no race, no timing. **Likelihood.** Low-moderate (requires fleet foothold).
**Impact.** Cluster-wide session-revocation enforcement silently degrades to
"incomplete" on the node that hosts the admin UI; plus whole-file write
amplification (the file is rewritten per merge, entries up to 8,192 bytes).

**Affected assets.** Control-plane session integrity; the revocations file; the
`session_revocation` operator contract row.

**CWE-770** (allocation without limits) → **CWE-613** (insufficient session
expiration). **OWASP** A01:2021 Broken Access Control / A04:2021 Insecure Design.

**Regression risk.** Introduced by this branch — both the second consumer and
the `User` wire field are new; base never wrote a peer's entries into the CP's
own `sessionRevoked`.

**Fix applied (minimal, structural — not a second cap).** `Update` now returns
the set it retained, and the handler merges **that**:

```go
kept := globalRevAggregator.Update(req.NodeID, req.Entries)
...
mergeAndPersistRevocations(kept, "ControlPlane")
```

One bound now governs both consumers *structurally*, so a future third consumer
inherits it rather than having to remember the cap. `Update` already clears
`Prov` on `kept`, which the gossip merge ignores anyway, so nothing else moves.
Handing out `kept` is safe: a later `Update` for that node replaces the map value
with a freshly allocated slice rather than mutating this backing array, and
`MergeRevocations` only reads the entries it is given.

**Differential oracle (the evidence).** Pre-fix, the new gates fail exactly as
predicted:

```
--- FAIL: TestCPMergeBound_OnePeerPushCannotExceedThePerNodeCap
    the CP's own revocation list holds 8192 entries from one peer; the per-node cap is 4096
--- FAIL: TestCPMergeBound_AGreedyPeerCannotLockOutAnHonestNodesRevocation
    FAIL-OPEN: a genuine logout from another node is not honoured on the Control
    Plane because one peer's push had filled the global revocation cap
--- FAIL: TestCPMergeBound_Boundary/one_past_the_cap
--- FAIL: TestCPMergeBound_AccountEntriesAreBoundedToo
    the CP holds 8192 account revocations from one peer; the per-node cap is 4096
```

Post-fix all eight gates pass. The positive/authn/oversize/concurrency controls
pass on **both** revisions, which is what makes them controls rather than
restatements of the defect.

---

### R-2 (MEDIUM) — A peer may revoke any account, durably and fleet-wide

**Files.** `internal/session/session.go:477-501` (`mergeUntrusted`) ·
`internal/session/revocation_bounds.go:381` (`admitUntrustedUserLocked`) ·
`internal/session/session.go:1078` (`Decode`).

CHAOS-68 put `RevocationEntry.User` on the gossip wire. `admitUntrustedUserLocked`
validates length, far-future expiry and capacity — **nothing about whether that
account is the pushing node's to revoke**. `Decode` then rejects every cookie
whose `Sub` matches, for the admin UI *and* the proxy session. Confirmed by
probe: a single peer entry `{"token":"user:admin","user":"admin"}` makes
`IsUserRevoked("admin")` true.

Because `RevokeUser` also blocks **new** logins (the cookie is minted, then
rejected on the next request) and there is **no un-revoke path**, one compromised
DP can durably deny administrative access fleet-wide for up to 7 days — and the
CP admin UI is where the operator would de-enroll that very node. R-1's fix caps
the *volume* at 4096/node but a single targeted entry still lands.

**Why not fixed here.** Cross-node revocation propagation *is* the feature:
"account deleted on one node must be enforced everywhere" necessarily means a
peer's revocation is honoured. Adding a per-node entitlement model, or a
break-glass un-revoke, is an architectural change to the cluster trust model —
outside a regression review's mandate and explicitly against this task's rule
against changing security behaviour unless required. Note the direction: this is
over-revoking (**fail-closed**), an availability risk, not an auth bypass.

**Recommended fix (owner's call).** Either (a) scope an account revocation to
entries a node can justify, or (b) add an audited, admin-only clear so the
lockout is recoverable, or (c) accept and document it as within the enrolled-node
trust boundary. Also note the silence: no `auditEvent` and no counter
distinguishes "a peer revoked an account here".

**CWE-285** (improper authorization) / **CWE-613**. **OWASP** A01:2021.

---

### R-3 (MEDIUM) — Delete-then-recreate locks the new account out

**File.** `internal/session/session.go:275-281` (`RevokeUser`), `:1078` (`Decode`).

`RevokeUser` records `users[username] = now + TTL()` and nothing compares
`Session.Iat` against when the cut was made. So an operator who deletes account
`bob` and re-creates `bob` within the session TTL finds the new account unable to
hold a session: the fresh cookie is minted, then rejected. Confirmed by probe —
`Decode` returns `session: user revoked` for a brand-new cookie.

**This is a pre-existing semantic that the branch amplified**: on base the entry
was in-memory on one node and cleared by restart; CHAOS-68 made it **persisted
and gossiped**, so the lockout now survives restart and spreads to every node.
No attacker required — an ordinary operator workflow.

**Recommended fix.** The branch already built the right mechanism one map over:
`ProfileAdmitsSession` compares `Session.Iat` against a profile's
`SessionsNotBefore` (AU-65). The account dimension has no equivalent. A cookie
minted *after* the deletion instant necessarily authenticated against the current
roster, so admitting it is sound — but it needs a new wire field to carry the cut
instant (today's `Expiry` is `now+TTL`, not the revocation time) and it *loosens*
a security control. Not implemented unilaterally for that reason.

**Required tests if adopted.** A cookie minted before the cut stays refused
(negative); one minted after is admitted (positive); clock skew across nodes at
the one-second boundary; the field survives gossip and reload; an older binary
ignoring the field still fails closed.

**CWE-613**. **OWASP** A04:2021 Insecure Design.

---

### R-4 (LOW, documentation) — A retired containment argument read as reassurance

**File.** `session_provider_bounds.go:47-51` (corrected).

The comment stated the `users` map is *"still neither persisted nor gossiped
while the sibling `tokens` map in the same struct is both"*, and concluded AU-19
was therefore contained — *"bounded for the admin UI by `uiAuthMiddleware`'s
roster backstop and unreachable from the proxy cookie"*.

CHAOS-68, **in this same branch**, made the `users` map both persisted
(`exportPersisted`) and gossiped (`ExportRevocations`,
`ExportRevocationsByOrigin`), and put `User` on the wire. Both stated bounds are
therefore gone: it *is* reachable from the proxy cookie (R-2), and the roster
backstop is no bound on a re-created account (R-3). Per AGENTS.md — *flag
conflicts; do not change runtime behaviour to match stale prose* — the **prose
was corrected**, no behaviour changed. This mattered because the stale claim was
the stated reason the dimension was left open; a future reviewer would have
re-derived a containment that no longer exists.

---

## 3. Reviewed and Found Safe

Recorded so the negative result is auditable, not implied.

- **Revocation expiry oracle (SEC-REVEXP-1).** `revocationLive` is exactly
  `Decode`'s acceptance test (`now.Unix() <= exp.Unix()`); every eviction site
  routes through it (verified by enumerating all comparisons in the package — no
  second dialect survives). The change can only retain an entry longer, never
  drop one sooner. Correct, fail-closed direction.
- **Revocation sync byte budgeting (AU-50/AU-71).** Traced in full; **no
  starvation**. The priority prefix is hard-capped at half the budget, the
  rotating window always gets ≥ half, the cursor is a *key* (not an index) so
  entries arriving/expiring between ticks cannot push the resume point back, the
  ordering is total and map-iteration-independent, an oversized entry steps the
  cursor instead of jamming, and the cursor clears when the backlog drains.
  Nothing is removed from any list; both legs merge additively. The reply cursor
  is correctly **per requesting node**, and its key space is the verified
  enrolled-node set (`verifyNode` precedes it), so the map is bounded.
- **`ExportRevocationsByOrigin` capacity arithmetic.** `len(tokens)+len(users)
  -len(verified)` cannot go negative: `verified` is only ever written alongside
  `tokens` and deleted alongside it. Verified by enumerating all writes/deletes.
- **Portal logout admission (AU-54/AU-55).** Cross-site requests perform **zero
  mutation** and get a constant-HTML confirmation page (no interpolation, so no
  injection surface); cookie-bearing logouts are charged to the same per-client
  limiter `/api/` mutations use; over the limit **nothing** happens, rather than
  clearing a cookie whose revocation was skipped. `RevokeVerified` checks the MAC
  **first**, so an unauthenticated caller cannot plant or inflate a durable
  gossiped entry. The documented absent-`Sec-Fetch-Site` fail-open is a recorded
  availability trade-off (AU-55), not a defect.
- **Identity-result cache (`internal/identcache`, ADR-0041).** Behaviour-
  preserving against base. Keys are `cacheKey(...)` — length-framed HMAC-SHA256
  under a per-process random secret, so injective and credential-free (no
  plaintext password or token in any key). Each provider holds its **own** cache
  instance, so no cross-provider key confusion. `Get` evicts on expiry and never
  serves a stale hit. The `client` argument is **attribution only** and never
  reaches a lookup, so a wrong value can only make eviction less fair. The
  token-expiry clamp is preserved via `SetUntil` (passing an absolute deadline
  rather than re-deriving a duration) — the one place this could have regressed
  and did not. Package is stdlib-only and logs nothing, enforced by a boundary
  test.
- **IdP lifecycle (AU-65/AU-69/AU-70).** `ProfileAdmitsSession` matches the
  profile id by **exact** string equality — no prefix stripping, no fold — and
  returns `false` for an empty id, so an absent `pvd` matches no provider.
  `SessionsNotBefore` is server-owned and assigned in both branches, so a request
  body cannot lower or zero it. `pvd`/`Iat` are inside the MAC'd payload.
- **`proxy.go` `authRequired` → `sessionCapable` widening.** Arms 2 and 3 are
  re-gated with `else if authRequired`, so where `authRequired` holds every
  branch is byte-identical to base; the only newly reachable behaviour is reading
  an HMAC-verified cookie whose profile is stored and enabled. No unauthenticated
  caller gains identity. The CHAOS-88 check is a tightening that degrades to
  exactly "no cookie".
- **Syslog/SIEM and alerts.** Every loss path is counted and surfaced — the
  "uncounted" enqueue results were each traced to a terminal charge. The alerts
  retry change is strictly *safer* than base (base destroyed queued alerts when
  `store == nil` after truncating the queue). No new regex, no attacker-sized
  allocation, no new persistence; the one file write is unchanged
  `fileutil.AtomicWrite(..., 0o600)`.
- **Admin control plane.** No new route is registered anywhere in the branch; no
  `requireRole` was added, removed or downgraded; no `auditEvent` or
  `saveConfigVersion` call was added or removed, and the credential/CDR
  no-versioning exclusions remain satisfied. New `static/index.html` render paths
  use `textContent` throughout — no `innerHTML`, no new inline script.
  `sha256sum api/openapi/openapi.json` matches the hash in the generated
  `types.gen.ts` header: no artifact drift.
- **Log injection (CWE-117).** `sanitizeLog` leads with the CodeQL-recognised
  `strings.ReplaceAll(s,"\n","_")` and scrubs all C0 + DEL. New untrusted log
  values are wrapped. `client=%s` in `session_provider_bounds.go` deviates from
  the preferred `%q` spelling, but `realClientIP` returns either a canonical
  `net.IP` string or the TCP peer host — it cannot carry spaces or injected
  fields, so there is no reachable field-forgery path. Not a finding.
- **Security gates.** No change to `.github/`, `.golangci.yml`, `Makefile`,
  `go.mod` or `go.sum`. The `tools/gosec` change is documentation that *tightens*
  practice (it records a measured silent-all-clear: a gosec built by the wrong
  compiler reported `Issues: 0` while hiding four HIGH G704 findings).

---

## 4. Verification

Toolchain: `GOVERSION=go1.27.3` (the `go.mod` `toolchain` pin), `GOTOOLCHAIN=auto`.

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./...` | pass |
| `go mod tidy -diff` | clean |
| `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build` | pass |
| `go test .` (root, full) | pass (425 s) |
| `go test ./internal/{session,identcache,syslog,alerts,feedsync,threatfeed}` | pass |
| `go test -race -run 'TestCPMergeBound_\|TestChaos73_\|TestChaos68_\|TestAU50\|TestAU71\|TestChaos79_\|Revocation\|TestChaos88_' .` | pass |
| `golangci-lint run --new-from-rev origin/main` (gate command, pinned v2.15.0 built with go1.27.3) | **0 issues** |
| `golangci-lint run` full tree, HEAD vs base | **174 vs 174** — net-neutral |
| `python3 docs/agent-context/check.py` | pass |
| New gates, differential oracle | 4 fail pre-fix / 8 pass post-fix |

**Not run / not proven here:** CodeQL, gosec, the `benchgate`-tagged lane, the
coverage-floor contract, the frontend npm tree, the `cmd/culvert-maint` module,
and every hosted required gate. A passing local selection is **not** a passing
merge gate.

---

## 5. Residual Risk

1. **R-2 and R-3 remain open by decision.** Both are fail-closed
   (over-revoking) and so are availability risks, not bypasses — but R-3 is
   reachable without an attacker and R-2 removes the operator's recovery path.
   Both want an owner decision, not a reviewer's unilateral loosening.
2. **The R-1 fix caps volume, not intent.** 4096 entries per enrolled node is
   still 4096 durable, gossiped revocations per node. The cap is a resource
   bound; it is not an entitlement check (that is R-2).
3. **No invalidation on the identity caches.** A positive LDAP/OIDC verdict
   survives a password change or account disable for up to `cache_ttl`. This is
   pre-existing posture on both revisions, but worth naming: base's random
   eviction incidentally shortened the window under load, and the new fairness
   policy deliberately preserves honest entries, so stale positives now reliably
   live out the full TTL.
4. **`idp_profiles` wire semantics.** Losing `omitempty` means a CP with zero
   profiles now serialises `[]` and durably wipes each DP's registry. This is the
   deliberate CHAOS-88 revocation lever and is tested, but a DP configured with a
   node-local `-idp-profiles-file` against a CP that has no profiles loses that
   configuration irreversibly.
5. **HA bundle revocation trim.** A standby may hold a subset of the leader's
   revocations, so a promotion can admit sessions the leader refused. Documented,
   counted and surfaced — recorded as a deliberate exception, not a defect.
