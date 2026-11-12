# Security Regression Review — 2026-11-12

**Scope.** `04aa647…3b09cff` (`origin/main`) — the window since the 2026-11-11
review, 10 merged pull requests (#1863 #1866 #1867 #1868 #1869 #1870 #1871
#1872 #1873 #1874), 37 files, +4,180/−72.

| PRs | Change | Security surface |
|---|---|---|
| **#1873 / #1874** | `fix(policy)`: a single-IP `SourceIP` decides on the ADDRESS, not its spelling (#1873); the policy API refuses a `sourceIP` the matcher can never match (#1874) | **access-policy source scoping** — a silently inert rule is fail-open for a Drop rule under first-match-wins |
| **#1872** | CHAOS-117: null node/token records are DROPPED at both ingestion boundaries instead of crash-looping the control plane | **cluster enrolment identity, CRL reachability, node authentication** — converts a crash into silent state loss |
| **#1863** | `fix(oidc)`: a userinfo response whose `sub` is not the ID token's is discarded | **authenticated identity binding** — cross-account group/identity confusion |
| **#1870** | `perf(identcache)`: the eviction victim comes from a heap, not a scan over every client | **client-identity cache** — wrong-identity reads, expiry enforcement, attacker-influenced cost |
| **#1871** | The 2026-11-11 review, plus `Scanner.clamStatusGen` (the ClamAV status single-flight becomes generation-aware) | **malware-scanning health honesty** — a stale "connected" keeps a fail-open node in rotation |
| **#1869** | `fix(install)`: the docker group is matched by exact name, not `grep -w` | local privilege (docker group is root-equivalent) |
| **#1868** | diagnostics row when the upstream pool configuration was refused | upstream-proxy configuration disclosure; diagnostics RBAC |
| **#1866 / #1867** | terminology governance review; CA-renewal alert now names the real upload panel; cluster slice-cap doc scoping; a frozen-fleet alert rule querying a nonexistent metric removed | operator remediation accuracy; alerting coverage |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed at `04aa647`?** Every verdict below is measured against
that revision, not against an ideal.

**Method.** Four changes in this window alter what the gateway *does* with an
identity, a policy decision, or a security control's state, and those took the
weight.

#1873 is the one most easily mis-filed as a pure bug fix. It **widens** what a
rule matches, and widening is direction-dependent: strictly safer for a Drop
rule, strictly more permissive for an Allow rule. So the question was not
whether the fix is correct but **where else the same matcher is reached** — and
it is reached from the Stage-1 authentication gate, which #1873 deliberately did
not change. That is finding **A**.

#1872 trades a crash loop for a silent drop. A crash is a fail-closed outcome in
the crudest possible way, so the load-bearing question is **what the dropped
record was load-bearing for**. Tracing its consumers rather than its comment
found that the enrolment duplicate-identity denial keys on the record *existing*.
That is finding **B**.

#1863 and #1870 were checked as claims, not as commit messages: the `sub`
comparison was read for its position relative to every field merge and for the
empty/missing case, and the identcache rewrite was checked for whether a lookup
can return another client's identity.

Claims that mattered were **executed or traced to source, not taken from a
comment.** Both findings were **reproduced in failing tests before being
fixed**, and both fixes were **mutation-checked** (the assertion was disabled and
the test observed to fail, then restored). Gates run at this SHA are listed
under *Verification*.

**No security regression in the access-policy, identity-cache, OIDC,
installer, diagnostics or documentation changes. Two findings — one Medium, one
Low — both fixed here. One accepted posture widening named explicitly, and five
residual risks recorded, two of them introduced by this window.**

---

## Executive Summary

**Nine of the ten pull requests in this window leave the posture at `04aa647`
unchanged or stronger. The tenth, #1872, closes a denial-of-service at the cost
of one narrow enrolment-evidence gap, which is fixed here.**

The window's centre of gravity is #1873/#1874, and it is worth stating plainly
what they fixed, because the same defect class turned out to be live one layer
up. A policy rule's `SourceIP` is documented as "a single IP or a CIDR". The
CIDR form was parsed, so it decided on the *address*. The single-IP form was
compared as a **string** against the peer address Go prints, so it decided on
the *spelling* — and nothing on the write path validated or canonicalised it.
A rule written `2001:DB8::10` therefore never matched the client
`2001:db8::10`, while the same rule written `2001:DB8::10/128` did. The rule was
accepted, displayed, and inert. For a Drop rule under first-match-wins that is
the fail-open direction: the deny silently does not exist.

#1873 fixed the matcher and #1874 made the API refuse values that remain
unmatchable. Both are improvements. But `matchIPOrCIDR` has a sibling,
`matchIPOrCIDRAddr`, that the Stage-1 **authentication** gate uses for an auth
rule's subject predicate, and it kept the string comparison. The auth path's own
validator (`validateCIDROrIP`) accepts every spelling `net.ParseIP` accepts, so
the identical defect was live on the authentication boundary, where the fail-open
direction is not a missing deny but a **missing credential challenge**. That is
finding A, and it is the more serious of the two because the preconditions are
only "an operator wrote an IPv6 literal the way vendors and IPAM exports print
it".

#1872 (CHAOS-117) is the other change that needed its trade examined rather than
accepted. One `null` in a persisted cluster document used to nil-deref the
detached heartbeat ticker — process-fatal, re-read on every restart, replicated
to standbys: one poisoned byte became a fleet-wide crash loop. Dropping the
record is the right call and the change is careful (same helper at both
ingestion boundaries, counter, sanitised log, alert, viewer-safe diagnostics
row, and the panic guard correctly paired with a deferred unlock). The
normalisation comment then claims a drop "cannot lose security state", on the
grounds that the CRL is a slice of values and "a dropped node must re-enrol (an
availability cost)". The first half holds. The second understates it: the
dropped record was the only thing on the control plane that named that node's
certificate serial, and `admitEnrollment`'s anti-identity-takeover denial is
keyed on `GetNode(...)` returning `ok`. After a drop the same node ID is
re-enrollable on a fresh token with **no predecessor to supersede** — so the
superseded certificate is never added to the CRL, the operator-set `draining`
status and admin labels are not carried forward, and no
`cluster.node.reenroll-*` audit entry or alert is written. The identity
replacement was indistinguishable from a first enrolment. That is finding B.

The remaining changes hold up. #1863 is a genuine identity-binding fix in the
right direction, and the check is complete: exact string equality, an explicit
empty/missing rejection, positioned before the first field merge, with the
caller independently rejecting an empty ID-token `sub`, and only one userinfo
call site in the repository. #1870 replaces a linear scan with two heaps and is
the largest diff in the window, but the read path (`Get`) is untouched — a plain
map read with a fresh `time.Now()` expiry check that consults no heap — so a
mis-ordered heap root could cause a wrong *eviction*, never a wrong *answer*;
victim selection was confirmed behaviourally identical to the pre-commit scan
over ~200k differential operations. #1869 errs toward a false negative and
cannot grant authority the invoking user lacks (the grant runs under `sudo`).
#1868 puts only fixed literals and bounded enums into a diagnostics row served
at the same `RoleViewer` that already returns those fields on `GET
/api/upstream`, so the disclosure delta is zero. #1871's `clamStatusGen` is
correct: the generation check precedes every store and every log line, so a
superseded probe publishes nothing.

---

## Security Findings

### Finding A — a Stage-1 auth rule's bare-IP subject decided on the spelling, so a `CredentialRequired` rule could be silently inert (Medium)

**Severity: Medium.** **CWE-290** (authentication bypass by spoofing/alternate
path), with **CWE-1025** (comparison using a non-canonical representation) as
the mechanism and **CWE-20** (improper input validation) on the write path.
**OWASP A07:2021 — Identification and Authentication Failures** (also
A01:2021 — Broken Access Control for the access-rule half #1873 fixed).

**Affected contract.** Stage-1 adaptive authentication: `matchIPOrCIDRAddr`
(`policy.go`) via `cidrPredicateMatches` → `matchSubjectAddr` →
`authRuleMatchesScratch` → `resolveAuthOutcomeFrom`, reached on the live request
path from `resolveRequestAuth` (`proxy.go:342`, called at `proxy.go:1664`).

**Affected assets.** Every destination an auth rule was written to protect;
the authenticated identity and group set that identity- and group-scoped access
rules then match on; the audit attribution of the requests that passed
unchallenged.

**Attack scenario.** An operator scopes a `CredentialRequired` auth rule to a
host or a small set of hosts by bare IPv6 literal — written the way vendor
documentation, IPAM exports and spreadsheets print it, e.g. `2001:DB8::10`
(upper case), `2001:0db8:0000:0000:0000:0000:0000:0010` (fully expanded), or
`::ffff:10.0.0.5` (4-in-6, which also covers an IPv4 client). The admin API
accepts it: `validateSubjectMatch` → `validateCIDROrIP` admits anything
`net.ParseIP` admits. The rule is persisted, listed in the UI, and shown in the
auth-policy dry-run as a configured control.

At request time the client IP is `net.SplitHostPort(r.RemoteAddr)` — the
canonical form Go prints, `2001:db8::10`. The predicate compares
`cidrOrIP == clientIP` as strings, which is false. `matchSubjectAddr` returns
false, `authRuleMatchesScratch` returns `("", false)`, and
`resolveAuthOutcomeFrom` falls through to the **global default**
(`cfg.DefaultAuthOutcome()`). Where that default is `Default` — the reserved,
inert outcome — the request is never challenged and proceeds unauthenticated.
The operator sees a configured rule; the gateway enforces nothing.

No attacker action is required to *create* the condition, which is what makes it
worse than it first reads: the bypass is a property of the operator's spelling,
not of anything the client sends. A client that simply is the named host is
never asked for credentials.

**Preconditions.** (1) An auth rule with `Outcome` `CredentialRequired` or
`SSORequired` whose subject CIDR predicate holds a **bare IP** (not CIDR) in any
spelling other than the canonical one; (2) the effective global default auth
outcome is not itself challenging. No attacker capability, no race, no
privileged position.

**Exploitability.** High once present — the client does nothing but connect.
**Likelihood of being present: moderate.** It requires a bare-IP subject in
non-canonical form, which is an ordinary operator typo/paste for IPv6 and is
never surfaced: nothing warns, nothing refuses, and the CIDR form of the same
text works, so the natural debugging move (append `/128`) silently "fixes" it
and hides the class. Measured: of seven spellings `validateCIDROrIP` accepts for
two addresses, **five** can never match.

**Impact.** Unauthenticated access to destinations an auth rule was written to
gate, with no identity recorded for the session. Downstream, identity- and
group-scoped access rules stop matching for that client, so the effect is not
only "no credential" but a silently different *policy* evaluation.

**Regression risk.** The defect is **pre-existing**, not introduced by this
window. It is reported here because this window fixed the identical defect on
the access path (#1873) and on the access write path (#1874) while leaving the
authentication path — the higher-severity direction — unchanged and
unvalidated. `warnInertSourceIP` returns early for `ruleTypeAuth`, and
`matchIPOrCIDRAddr` was not touched.

**Recommended fix / safe implementation (applied).** Mirror the access path
exactly rather than inventing a second contract: `matchIPOrCIDRAddr` now falls
back to `sourceLiteralPrefix` — the helper #1873 added — and compares
`netip.Addr` values with both sides `Unmap()`ed.

```go
if cidrOrIP == clientIP {
    return true
}
p, ok := sourceLiteralPrefix(cidrOrIP)
if !ok {
    return false
}
addr, err := netip.ParseAddr(clientIP)
return err == nil && addr.Zone() == "" && p.Contains(addr.Unmap())
```

Four properties made this the safe shape:

- **No rule that matched before stops matching.** The exact-string comparison
  is tried first and still wins; a parseable literal equal to the client string
  parses to the same address.
- **A zoned literal keeps the string comparison.** `sourceLiteralPrefix`
  rejects a zone, which is deliberate and not an oversight: a link-local peer
  address carries its zone in `clientIP` too, so exact-string is the only
  comparison that can be right there.
- **Both sides are `Unmap()`ed**, matching `clientSource.parseAddr`, so the
  4-in-6 and native spellings of an IPv4 address agree on both sides.
- **Allocation-free.** `netip.ParseAddr` fills a value; the `benchgate`
  allocation gates that cover the Stage-1 resolver pass unchanged.

No validation change was needed: after the matcher fix, every value
`validateCIDROrIP` accepts is matchable (a zoned literal matching a zoned peer
included), so refusing spellings on write would only break rules that now work.

**Required tests (added — `authpolicy_subject_literal_test.go`).**

- *Positive / malformed-input oracle*: for every spelling the auth API accepts,
  assert the Stage-1 outcome equals the canonical spelling's. Covers upper-case,
  fully expanded, unexpanded-zero-group, and both 4-in-6 cases, with the two
  canonical forms as controls. **Reproduced the bypass first**: 5 of 7
  sub-cases failed before the fix with `outcome "Default", want
  "CredentialRequired"`.
- *Negative control / boundary*: the address-based compare must not match a
  neighbouring address, a different family, or an unrelated address, and a zoned
  literal must stay inert against an unzoned client — so the fix is a
  canonicalisation, not a widening.
- *Direction test*: the `Exempt` case is asserted explicitly (see *Accepted
  posture change* below), including that the Exempt kill switch still suppresses
  a subject matched by address.

---

### Finding B — a dropped cluster node record made the same node ID re-enrollable with no CRL entry, no carried-forward maintenance state, and no audit (Low)

**Severity: Low** (high preconditions, bounded delta). **CWE-778**
(insufficient logging of a security-relevant event) as the primary defect, with
**CWE-290** (impersonation) and **CWE-672** (operation on a resource after
expiration/release) describing the consequence. **OWASP A09:2021 — Security
Logging and Monitoring Failures**, with A07:2021 for the identity half.

**Affected contract.** Cluster node-identity uniqueness and the CHAOS-12
re-enrolment evidence trail: `admitEnrollment`
(`controlplane_server.go:574-581`), the `priorNode` path
(`controlplane_server.go:503-522`) and `recordExpiredNodeReenrollment`'s CRL
append (`controlplane_server.go:656-659`), against
`normalizeClusterState`'s drop (`enrollment.go`).

**Affected assets.** The identity of an enrolled data-plane node; the
superseded node certificate (and therefore the mTLS trust the control plane
grants it); operator-set `draining` state and admin labels, which carry node-group
and bandwidth/QoS policy; the cluster audit trail.

**Attack scenario.** A node record in the control plane's persisted state is
`null` — from disk damage, or from an actor with write access to `cluster.json`,
or replicated from a damaged leader. Post-CHAOS-117 the control plane drops it
and stays up. An attacker holding a valid, unused enrolment token whose
`NodePrefix` matches then enrols as `dp-prod-3`:

1. The duplicate-identity denial does not fire — `GetNode("dp-prod-3")` returns
   `ok == false`, so the `PermissionDenied "enrollment denied"` branch is never
   reached and `priorNode` stays `nil`.
2. The control plane signs a certificate for that identity. The legitimate
   node's still-valid certificate is **never added to the CRL**, because
   `recordExpiredNodeReenrollment` lives behind `priorNode != nil` and, more
   fundamentally, because the serial it would have revoked was in the record
   that was dropped.
3. The legitimate node is evicted on its next handshake (serial mismatch at
   `controlplane_server.go:83-87`) while its certificate remains valid.
4. `draining` and admin labels are silently reset to `connected`/empty —
   the exact outcome the `priorNode` branch's own comment says must not happen.
5. No `cluster.node.reenroll-*` audit entry and no alert is written, so the
   identity swap is indistinguishable from a first enrolment.

**Preconditions.** A null node record on the control plane **and** a valid
unused enrolment token matching the prefix. Both are required.

**Exploitability.** Low. A token holder can already enrol a *new* trusted data
plane, so the delta is not first access: it is impersonation of a *specific*
existing node ID, eviction of the legitimate holder, loss of its maintenance
state, and the absence of any record that it happened.

**Impact.** A node identity is replaced with no evidence and no revocation of
the predecessor. The missing CRL entry is the part that cannot be repaired after
the fact.

**Regression risk.** **Introduced by this window** (#1872). Before CHAOS-117
the same null record crash-looped the control plane, which is an availability
failure but closes this path completely. The change is still correct — a
fleet-wide crash loop is worse — but it is a genuine trade, and the
normalisation comment claiming a drop "cannot lose security state" and costs
only availability overstated it.

**Recommended fix / safe implementation (applied).** The admit/deny **decision
is deliberately not changed**: a single-use admin-issued token is still
required, and denying enrolment outright would re-brick a node whose record was
damaged by disk corruption — reintroducing the availability failure CHAOS-117
set out to remove. What was missing is evidence, so evidence is what was added.

- `ClusterStore.droppedNodeIDs` retains the node IDs `normalizeClusterState`
  dropped, populated through `rememberDroppedNodesLocked` at **both** ingestion
  boundaries (`Load` and `ImportFullState`) under the store's write lock, read
  through `NodeRecordWasDropped` under the read lock. It is evidence, not state:
  deliberately **not persisted**, and it accumulates for the life of the process
  because the serial a drop took with it never becomes revocable again.
- `admitEnrollment` consults it only when `priorNode == nil`, and **after**
  `ValidateAndConsumeToken` has succeeded — so an unauthenticated prober cannot
  drive an audit entry or an alert by guessing node IDs.
- `recordDroppedNodeReenrollment` logs (`logger.Printf`, `sanitizeLog` + `%q`),
  writes a `cluster.node.reenroll-dropped` audit entry, and fires the existing
  `cluster_node_reenrolled` alert. Its detail states the thing an operator
  cannot otherwise infer and cannot fix later: **the predecessor's serial was
  lost with the record, so it could not be added to the CRL and stays valid
  until it expires.**
- The overstated `normalizeClusterState` comment is corrected in place.

The CRL leg is **unfixable by construction** and is recorded as residual risk
R1 rather than papered over: the dropped record was the only thing naming the
serial, so no code change can revoke it.

**Required tests (added — `enroll_dropped_record_reenroll_test.go`).**

- *Positive*: enrolment over a dropped record still succeeds with a valid token,
  and emits the audit entry (content-asserted on `Action`/`Object`, never on
  ring length — the bounded-audit-ring pitfall) plus exactly one alert, with the
  detail naming the CRL. **Mutation-checked**: disabling the call makes this
  test fail with "no cluster.node.reenroll-dropped audit entry"; restoring it
  passes.
- *Negative control*: an ordinary first enrolment of a never-dropped node ID is
  **not** flagged, and raises no alert — false positives would make the real
  signal unreadable.
- *Authentication test*: an invalid token is denied, writes **no** audit entry,
  fires **no** alert, and registers no node.
- *Boundary / regression*: both ingestion boundaries record what they dropped;
  a healthy node and an unknown node ID both report false; and a later import
  does not forget an earlier drop.
- *Concurrency*: 8 goroutines importing while 8 read `NodeRecordWasDropped`,
  under `-race`.

---

## Accepted posture change (named, not hidden)

Finding A's fix **widens** what a bare-IP subject matches, and widening is
direction-dependent. For `CredentialRequired`/`SSORequired` it is strictly more
restrictive: the client is now challenged where it previously was not. For
**`OutcomeExempt` it is more permissive** — an Exempt rule written in a
non-canonical spelling used to be silently inert, so the client still
authenticated; it now waives authentication for the address the operator named.

This is accepted, for the same reason #1873 accepted it for an access **Allow**
rule one PR earlier: it restores the operator's declared intent, and the
alternative — making the comparison depend on the rule's outcome — would be a
worse contract and a maintenance hazard. It is nonetheless a posture *change*
for any deployment holding such a rule, so it is asserted in a test
(`TestAuthSubjectBareIP_ExemptDirectionIsNamed`) rather than left to be
discovered, and the blast radius stays bounded by the two guards Exempt already
carries: `authRuleHasDestination` (or an explicit `BroadExemption`
acknowledgement) and the Exempt kill switch, which the test confirms still
suppresses a subject matched by address.

**Operator action:** a deployment upgrading across this change should review
auth rules with `Outcome: Exempt` and a bare-IP subject, and access rules with
`Action: Allow` and a bare-IP `SourceIP`, since a rule that was inert may now be
live. The `Policy: rule %q never matches any client` warning #1874 added covers
the values that remain unmatchable, not these.

---

## Regression Analysis

Per-PR verdict against `04aa647`.

| PR | Verdict | Basis |
|---|---|---|
| #1873 | **No regression; strengthens.** Widening is named. | A Drop rule that was inert now denies. The Allow direction widens — accepted, same argument as above. `clientSource.parseAddr` already `Unmap()`s, so the new rule prefix and the client address agree on 4-in-6; the access path is symmetric with no gap. Exposed finding A one layer up. |
| #1874 | **No regression; strengthens.** | Ingress-only validation (`apiPolicyCreate`/`Update`/`UpdateByID`). Bulk/restore paths deliberately excluded, so a rule already on disk or in a config version keeps loading and is warned about instead — correct direction: refusing on load would stop an existing policy file from loading. Auth rules are routed to `/api/authpolicy` and skipped, which is why finding A survived. |
| #1872 | **No regression in authentication; one evidence gap (finding B), fixed.** | Node auth fails closed on a missing record (`verifyNodeCert` → `NotFound`); token lookup miss → "invalid token"; the CRL is a slice of values and is untouched; `RevokeNode` always appends to the CRL, so a dropped revoked node cannot be resurrected. Nil handling covers every deref on the load path, and the panic guard is correctly paired with a deferred unlock. |
| #1863 | **No regression; strengthens materially.** | Exact string equality, empty/missing `sub` rejected explicitly, positioned before the first field merge (`id.Email`); the reject path writes no field. The caller independently rejects an empty ID-token `sub` beforehand, so the check is fail-closed even standalone. One userinfo call site in the repository. Error message interpolates neither `sub`. |
| #1870 | **No regression.** | `Get` is untouched — a plain map read with a fresh `time.Now()` expiry check that consults no heap — so a bad heap root can cause a wrong eviction, never a wrong answer. Index bookkeeping verified by differential testing against the pre-commit implementation (identical surviving set and eviction counts); heap length is bounded by the configured cap, not by request count. Standing CHAOS-76/`BetterVictim` fairness behaviour under a many-address flood is identical before and after — pre-existing design, R4. |
| #1871 | **No regression; strengthens.** | `clamStatusGen` is checked **before** any store and any log line, so a superseded probe publishes nothing; only the flight that still owns the handle clears it. Transition log sanitises with `obs.Sanitize` + `%q`. |
| #1869 | **No regression.** | `id -nG` prints group names only, and the `==` right-hand side is quoted so it is a literal, not a glob. Residual direction is a false *negative*, which runs `sudo usermod` — and that cannot grant authority the invoking user lacks, since the call already requires sudo. |
| #1868 | **No regression.** | Every value reaching the row is a fixed literal, a bounded enum (`upstreamBoundedReason` discards the error), or an `int`; no URL, authority, username or credential. Served inside `buildOperatorContract` behind handler-level `requireRole(w, r, RoleViewer)` on both renderers, through the single `writeOperatorContract` redaction point. The same fields are already returned at `RoleViewer` by `GET /api/upstream`, so the disclosure delta is zero. |
| #1866 | **No regression; improves remediation accuracy.** | The CA-renewal withheld action now names a panel that exists. An operator who cannot find the upload panel does not renew, and an expiring inspection CA is a fail-closed outage — so pointing at the real control is a posture improvement, not cosmetics. |
| #1867 | **No regression; one coverage reduction, justified.** | Removing an alert rule that queries a nonexistent metric removes a rule that could never fire: no coverage is lost, and a permanently-silent rule is worse than none because it reads as coverage. Slice-cap doc scoping is prose. |

**CI/workflow changes in this window are additive only**: `./internal/identcache`
was appended to the `benchgate` package list in `pr-fast-gate.yml`,
`qa-gate.yml` and `proxy-weekly-stress.yml`. No gate was weakened, no timeout
shortened, no `GOTOOLCHAIN` override introduced.

---

## Residual Risk

- **R1 — A dropped node record's certificate serial can never be revoked
  (introduced this window, #1872; accepted, unfixable by construction).** The
  dropped record was the only thing on the control plane naming that serial, so
  the predecessor certificate stays valid until its own expiry and cannot be
  revoked by node ID. Finding B's fix makes the replacement *visible* (audit,
  alert, log naming the un-revocable predecessor) but cannot make it revocable.
  Mitigation is operational: on a `cluster.node.reenroll-dropped` entry, treat
  the predecessor as compromised and rotate the cluster CA if the node's
  identity mattered.
- **R2 — Cluster state loss on the HA replication path is not durably
  observable (introduced this window, #1872).** `ImportFullState` does not call
  `noteStateFileEntriesDropped`, so a standby that just lost nodes shows no
  diagnostics row; its alert is latched `sync.Once` per process; and
  `saveLocked()` immediately rewrites the standby's own `cluster.json` without
  the null records, so after a restart there is no on-disk trace, no row, and no
  re-alert. The operator text asserting "The file was not modified" is also
  false once any save runs. Separately, if *every* node record is dropped,
  `clusterRoleAndOK`'s `nodesOK := in.total == 0 || …` reports the control plane
  **healthy**, because "zero nodes" is modelled as a fresh CP. Not fixed here:
  it is a diagnostics/alerting contract change spanning `state_corruption.go`,
  `diagnose.go` and the HA import path, which is a larger scope than a review
  commit should carry unreviewed. **Recommended as the next cluster-observability
  task.**
- **R3 — Whole-document cluster state loss is still silent (pre-existing).**
  `"cluster_state":null` or `{}` from a leader wipes the standby's whole roster
  *and CRL* and persists it, producing no drop counter and no alert because
  `repair.empty()` is true. The new CHAOS-117 observability covers null
  *records*, not a null *document*.
- **R4 — Identity-cache eviction fairness under a many-address flood
  (pre-existing, CHAOS-76 design).** Each attacker bucket has `live == 1` and
  ties with a legitimate single-entry client, so the tie breaks on "oldest
  first" and the legitimate client's entry can be evicted. Measured identical
  before and after #1870, so it is not a regression of this window; a
  single-address flood cannot do it (the flooder's bucket is always the victim),
  which is the fairness policy working.
- **R5 — The CHAOS-117 ingestion-boundary class gate parses only
  `enrollment.go`.** `TestCHAOS117_EveryIngestionBoundaryNormalises` does not
  see the two other `ClusterState` decoders in `restore.go`. Neither panics
  today (both only take `len(st.Nodes)`, and that count *includes* null records,
  so the restore guard errs toward blocking — the safe direction), but a future
  decoder in another file escapes the gate.

- **R6 — `matchIPOrCIDR` and `matchIPOrCIDRAddr` are now near-identical, and
  that is how finding A survived #1873 in the first place.** The two differ only
  in whether the client address arrives pre-parsed, and after this fix their
  bare-IP tails are the same six lines. #1873 changed one and not the other, and
  nothing in the build or the test suite objects — the divergence was invisible
  until the auth path was traced by hand. This review tripped on it a second
  time: a mutation check aimed at the auth tail matched the access tail instead,
  because both are followed by near-identical text, and the first attempt
  silently measured the wrong function (caught because the auth tests still
  passed, then redone against the right one). Recorded rather than refactored:
  merging them means giving the Stage-1 hot path either an extra parse or an
  extra branch, which is a performance decision for the owner and is gated by
  `benchgate`, not something a security review should take unilaterally. A
  cheaper mitigation is a differential test asserting the two agree on a shared
  table of (value, clientIP) pairs, which would have failed on #1873's merge.

Two robustness notes on #1870, recorded without a reachable failure scenario and
therefore not findings: `evictOneLocked` returns `true` unconditionally after
`removeLocked`, so a stale memo naming an absent key would spin `store`'s
`for len(c.entries) >= maxEntries` loop while holding the mutex (no stale memo
was reachable under differential fuzzing); and the `b.head == pos(frontKey)`
invariant that makes compaction front-preserving is relied on but stated
nowhere.

---

## Files

Changed by this review:

| File | Change |
|---|---|
| `policy.go` | Finding A fix: `matchIPOrCIDRAddr` compares a bare-IP subject on the address via `sourceLiteralPrefix`, both sides `Unmap()`ed, zoned literals unchanged. |
| `authpolicy_subject_literal_test.go` | **New.** Finding A oracle, negative controls, and the named Exempt direction. |
| `enrollment.go` | Finding B fix: `ClusterStore.droppedNodeIDs`, `rememberDroppedNodesLocked`, `NodeRecordWasDropped`; recorded at both ingestion boundaries; overstated `normalizeClusterState` comment corrected. |
| `controlplane_server.go` | Finding B fix: `admitEnrollment` records a dropped-record re-enrolment after token consumption; `recordDroppedNodeReenrollment` logs, audits and alerts. |
| `enroll_dropped_record_reenroll_test.go` | **New.** Finding B positive, negative control, authentication, boundary and concurrency tests. |
| `docs/agent-context/workflows/verification.md` | Stale toolchain prose corrected: the pin is `go1.27.4` and the language minimum `go 1.27.0` (#1864 moved the toolchain last window; the prose still said `go1.27.3` / `go 1.26.6`). |
| `CHANGELOG.md` | Both fixes recorded. |
| `docs/engineering/SECURITY-REGRESSION-REVIEW-2026-11-12.md` | This review. |

---

## Verification

Run at this SHA with the pinned toolchain. `go env GOVERSION` = `go1.27.4`,
`GOTOOLCHAIN` = `auto`, matching `go.mod`'s `toolchain go1.27.4`.

| Check | Result |
|---|---|
| `go build ./...`, `CGO_ENABLED=0` release build, `GOOS=linux GOARCH=arm64` cross-build | pass |
| `go vet ./...` | pass |
| `go mod tidy -diff` | clean |
| `go test -run 'TestAuthSubjectBareIP' .` **before** the finding-A fix | **fails 5/7 sub-cases** (the reproducer) |
| `go test -run 'TestAuthSubjectBareIP' .` after | pass |
| `go test -race -count=1 -run 'TestAuthSubjectBareIP\|TestSrcPrefix\|SourceLiteral\|TestMatchIPOrCIDR\|Subject\|AuthPolicy\|AuthRule\|Slice6\|PolicySourceIP\|SourceIPValidate' .` | pass |
| Finding-B tests with the fix disabled | **fails** ("no `cluster.node.reenroll-dropped` audit entry") |
| Finding-B tests, `-race` | pass (5/5) |
| `go test -tags benchgate -run 'TestBenchGate_' -count=1 -p 1` over all ten benchgate packages (root + `admission`, `threatfeed`, `catgroup`, `session`, `decryptprofile`, `catoverride`, `secscan`, `catdb`, `identcache`) | pass |
| `python3 docs/agent-context/check.py` | pass |
| `golangci-lint` v2.15.0, `--new-from-rev origin/main` (the gate's own command) | **2 issues in this review's own code, both fixed, re-run clean** |
| `golangci-lint` v2.15.0, full-tree | 176 issues, all pre-existing; none in a function this review touched |
| `go test -race -count=1 -timeout=40m .` (root, full) | see note |

**Linter findings in this review's own code.** The diff-scoped run — the command
the Fast PR Gate actually runs — reported two issues introduced here, and both
were **fixed rather than suppressed**, per
`docs/agent-context/conventions.md` ("Do not add suppressions to conceal a new
insecure path", and keep suppressions narrow and explained):
`recordDroppedNodeReenrollment` took a `context.Context` it never used
(`unparam`) — the parameter was removed, since `admitEnrollment` has already
resolved the peer address for its rate limiter and passes the value; and the
test's audit-ring scan copied a 136-byte `AuditEntry` per iteration
(`gocritic rangeValCopy`) — changed to an index-based range, which is also the
convention this repository states explicitly. The full-tree run was read
alongside it because `cyclop`, `funlen` and `gocognit` attribute to a
function's declaration line and so `--new-from-rev` cannot see a function made
more complex: none of the 176 pre-existing findings falls in a function this
review touched, and no new complexity finding appeared for
`matchIPOrCIDRAddr`, `recordDroppedNodeReenrollment` or the new `ClusterStore`
methods.

**Linter build note.** `golangci-lint` v2.15.0 installed with a plain `go install`
**panicked** in `go/types` on this module, because `go install` built it with
go1.26.11 while the module's language version is 1.27 — exactly the trap
`docs/agent-context/conventions.md` records as repeatedly mis-filed as "local
lint is unavailable". Rebuilt with `GOTOOLCHAIN=go1.27.4 go install …@v2.15.0`
it loads the module correctly. Results recorded in the pull request.

**Scope of these results.** These are focused and local checks at this
revision. They are **not** aggregate CI approval: the required
`✅ Fast PR Gate — APPROVED` and `✅ Deep PR Gate — APPROVED` checks, the
sharded race lanes with their completeness check and privileged regression, and
the merged coverage-floor artifact all run on the pull request. Not run locally:
the frontend tree (untouched), `cmd/culvert-maint` (untouched), and the
packaging/release-evidence workflows. Readiness and permission to merge remain
separate decisions, and nothing in this review authorises a merge.
