# Security Regression Review — 2026-11-13

**Scope.** `3b09cff…feb11e8` (`origin/main`) — the window since the 2026-11-12
review, 8 merged pull requests (#1875 #1876 #1877 #1878 #1879 #1880 #1881
#1882), 56 files, +3,957/−238.

| PRs | Change | Security surface |
|---|---|---|
| **#1882** | `perf(ssrf)`: the DNS verdict cache becomes a bounded two-generation structure; `CacheCleanup` rotates in O(1) instead of sweeping every entry under the exclusive lock | **SSRF guard decision cache** — a stale "public" verdict, or an attacker-minted key space, sits directly under `isPrivateHost` |
| **#1880** | `perf(session)`: `Decode` asks the revocation list once (`StatusFor`) instead of twice, and the two checks now answer under ONE mutex acquisition | **session revocation on the proxy authentication hot path** — logout and account-deletion enforcement, and their rejection precedence |
| **#1879** | The 2026-11-12 review itself: the Stage-1 bare-IP auth-subject fix (`matchIPOrCIDRAddr`), and the dropped-cluster-record re-enrollment evidence trail (`droppedNodeIDs`, `recordDroppedNodeReenrollment`) | **Stage-1 authentication gate; cluster enrollment identity and CRL reachability** |
| **#1881** | CHAOS-118: the last five `go`-detached background rounds get per-round panic guards, each paired with a converted deferred lock release | **unsafe panic recovery / fail-closed integrity** — a guard over a trailing `Unlock` converts a loud crash into a silent permanent lock wedge |
| **#1877** | A Diagnostics WARN row when a configured parent-proxy pool has zero eligible parents (plain-HTTP egress is failing open to DIRECT) | **egress-chain bypass visibility; diagnostics RBAC and disclosure** |
| **#1878** | `fix(install-runner)`: the runner token is prompted on the terminal, not read from the piped script body, and the script refuses when there is no terminal | **CI runner registration secret; fail-closed installer** |
| **#1875 / #1876** | Terminology governance: `enroll`/`enrollment` spelled one way in operator-visible text; CDR Diagnostics states documented | operator remediation accuracy (no runtime behavior) |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed at `3b09cff`?** Every verdict below is measured against
that revision, not against an ideal.

**Method.** Three changes in this window move a security control's *data
structure* or its *lock discipline* while claiming the decision is unchanged,
and those took the weight. A claim of that shape is only worth what the
invariant behind it is worth, so each was checked against the invariant rather
than against its commit message.

#1882 replaces the structure that caches the SSRF verdict. The load-bearing
invariant is not "the cache is bounded" but **"no verdict is ever served past
`cacheTTL`, and a miss is always safer than a hit."** Both halves were traced:
the per-entry expiry is still tested on every `Lookup` in whichever generation
holds the entry, promotion out of the previous generation carries the
**original** expiry rather than refreshing it, and a dropped generation can only
force a live re-resolution, which is fresher. Nothing writes into `prev`, so a
key lives in exactly one generation and a stale verdict cannot shadow a fresh
one.

#1880 moves the explicit-logout check **after** the base64/JSON decode it used
to precede. The question is therefore not whether revocation still happens but
**whether anything can now reach a non-error return that previously could
not** — and nothing can: the HMAC is verified before either check, the three
rejections keep their original precedence, and every path out of the moved
region is still an error. The one real behavioral difference — the account
question is now evaluated for an *expired* cookie too, so an already-expired
account-revocation entry is lazily evicted a little earlier — was traced to
`userRevokedLocked` and changes no verdict, because an entry past its own expiry
is already unenforced for every cookie.

#1881 is the change whose *safe* direction is the least obvious, and the review
agrees with how it was resolved. A naive panic guard is a security regression,
not a fix: wrapping a round that holds a mutex via a trailing `Unlock` converts
a process crash into a permanently held lock with no crash, no restart and no
alert. Each of the five rounds was checked for exactly that, and each lock it
touches was converted to a deferred release — function-scoped where nothing
follows the section, closure-scoped where the work after it must **not** hold
the lock (the CHAOS-50 rule). The Root CA recovery loop is the one where
"keep going" would have been wrong, and it charges a contained panic as a
**failed** attempt rather than inheriting a zero value that would read as
"recovered" — the fail-closed choice.

Claims that mattered were **executed or traced to source, not taken from a
comment.** The finding below was **reproduced in a failing test before being
fixed**, and the fix was **mutation-checked twice** (the fix was reverted and
the test observed to fail; then a first version of the boundary assertion was
found to be satisfied by `%q` alone, and was tightened until removing
`sanitizeLog` fails it). Gates run at this SHA are listed under *Verification*.

**No security regression in the SSRF cache, session revocation, Stage-1 auth,
panic-guard, diagnostics, installer or documentation changes. One finding —
Low — fixed here. One accepted posture widening re-stated because it reaches
production in this window, and seven residual risks recorded, three of them
introduced by this window and one pre-existing.**

---

## Executive Summary

**Seven of the eight pull requests in this window leave the posture at
`3b09cff` unchanged or stronger. The eighth, #1879, adds a security alert whose
own delivery path silently suppresses all but one of a batch — which is the
normal shape of the event it reports.** That is the single finding, it is Low,
and it is fixed in this change.

The window's two performance passes (#1882, #1880) both sit on security
decision paths, and both were checked as rewrites of a control rather than as
optimisations.

**#1882 — the SSRF verdict cache.** `internal/ssrf` caches, for 30 s, whether a
host resolved to a private address; `isPrivateHost` consults it before every
CONNECT and SOCKS5 dial. The host key is client-controlled, so the single
unbounded map it replaced was an attacker-minted key space swept entry-by-entry
under the same exclusive lock the pre-flight check takes. The replacement holds
at most two generations of 16,384 keys and retires one whole generation at a
time. Three properties decide whether this is safe, and all three hold:

- **Nothing is served past its TTL.** `Lookup` tests `e.expires` after reading
  from either generation, so a rotation changes *which* entries exist, never
  *how long* one is honoured.
- **Promotion cannot refresh freshness.** A hit in `prev` is copied into `cur`
  with its **original** `expires`, under a re-check that refuses to overwrite a
  newer `cur` entry with an older `prev` one.
- **Eviction fails safe in the only direction that exists.** A missing entry
  causes a live DNS lookup, and a DNS *error* is still not cached — the
  fail-closed rule the file documents and keeps. There is no eviction outcome
  that produces a more permissive verdict than the entry it dropped.

The attacker-facing trade is real but strictly favourable: a wildcard-DNS flood
can now thrash the cache into re-resolving legitimate hosts, where before it
could exhaust memory and stall all proxied traffic for ~200 ms per sweep. More
upstream DNS queries is a better failure than unbounded retention plus a global
stall, and neither outcome changes a verdict. Recorded as residual risk 4.

**#1880 — session revocation.** `Decode` is the first credential arm
`resolveRequestAuth` tries, so it runs on every authenticated proxy request.
Collapsing `IsRevoked` + `IsUserRevoked` into one `StatusFor` acquisition makes
the two answers **more** consistent, not less: they are now read under a single
hold of the same mutex, so the pair can no longer straddle a concurrent
`Revoke`/`RevokeUser`. The rejection order (revoked → expired → user-revoked) is
unchanged and pinned by a test. The move of the logout check to after the
payload decode is unobservable for any input that can reach it, because the MAC
over that payload is verified first; a contrived MAC-valid-and-malformed input
is refused either way, with a different message no caller branches on.

**#1879 — the Stage-1 auth-subject fix reaches production here.** The matcher
now decides a bare-IP subject predicate on the **address**, not its spelling,
which is what the CIDR branch beside it always did. The direction matters and is
re-stated below under *Accepted posture change*: for a `CredentialRequired` or
`SSORequired` rule this is strictly stricter, and for an `OutcomeExempt` rule it
is strictly more permissive — an authentication waiver written in a
non-canonical spelling was silently inert and is now live. That is the
operator's stated intent restored, not a new grant, and `sourceLiteralPrefix`
was read to confirm it widens to exactly one address (`PrefixFrom(addr,
addr.BitLen())`) and keeps the exact-string comparison for zoned literals.

**#1881 — the panic guards are the right shape.** The two rounds that are not
merely observability were the ones to check, and both were handled correctly:
the IdP metadata watchdog *enforces* the staleness ceiling and is the supervisor
that re-arms SSO recovery, so it is guarded per **round** (a goroutine-level
`recover` would have left SSO down with nothing retrying it and every surface
green); and the Root CA recovery loop charges a contained panic as a failed
attempt, so a panic cannot be mistaken for "SSL inspection recovered". Every
lock inside a newly guarded round was converted to a deferred release, which is
the part a guard makes mandatory rather than optional.

**#1877 — the new Diagnostics row discloses nothing new.** It is report-only,
derived from the same in-memory `upstreamPool.List()` eligibility and
`DirectFallback()` latch the Upstream page and `/metrics` already read. It
carries counts and fixed prose only — no authority, URL, username or
credential — does not dial or probe, and does not call `Effective()` (which
would stamp the mode-since clock). It is reached through `apiDiagnostics` and
`apiHealthExplain`, both `requireRole(w, r, RoleViewer)` and both routed through
`writeOperatorContract`, the single role-redaction chokepoint. Unauthenticated
`/healthz` does not build the operator contract, so no new state reaches an
unauthenticated probe and no load-balancer verdict changes.

**#1878 — the installer change is a fail-closed improvement.** Under the
documented `curl … | bash`, stdin *is* the script, so the previous bare `read`
consumed the script's own next line as the registration token. The fix prompts
on `/dev/tty` and **refuses** when there is no terminal, telling the operator to
pass `RUNNER_TOKEN` instead. Residual risk 6 notes that the prompt still echoes.

---

## Security Findings

### Finding A — the dropped-record re-enrollment alert shares one dedup key across every node, so a batch of identity replacements delivers one webhook and silently drops the rest (Low)

**Affected contract.** `recordDroppedNodeReenrollment`
(`controlplane_server.go`) is the only operator-facing signal that a node ID
whose stored record was dropped as an unusable null entry has been re-enrolled
under a fresh certificate whose **predecessor can never reach the CRL**. Its own
doc comment states the signal fires "loudly and **once per enrollment**".

**The defect.** `internal/alerts.Store.Dispatch` suppresses a duplicate on
`event + ":" + payload.Detail` within `dedupTTL` (30 s). The producer's `Detail`
was a **constant** string; the node ID lived only in `Host` and in the audit
record's `Object`, neither of which is part of the dedup key. Every node's
replacement therefore shared one key, and only the first within any 30-second
window was dispatched to a webhook.

**Why this is the normal shape, not an edge case.** A single corrupt
`cluster.json` does not drop one record — `normalizeClusterState` drops **every**
null record it holds in one pass, and `clusterStateRepair.NilNodes` is a list.
The documented remediation (`state_corruption.go`: "re-create the dropped
entries … re-enroll the affected nodes and re-issue any pending enrollment
tokens") then has those nodes re-enroll **together**. So the multi-node batch is
precisely the situation the alert exists for, and precisely the situation in
which it reported one node and stayed silent about the others.

**Attack scenario.** An adversary who holds or obtains admin-issued enrollment
tokens — the stated precondition, since the admit decision is unchanged and
deliberately still requires one — re-enrolls several node IDs whose records were
lost to a corruption event. Each replacement leaves a predecessor certificate
that is valid until its own expiry and **cannot be revoked**, because the only
record naming its serial is gone. The operator receives one webhook alert naming
one node, and the remaining replacements arrive with no webhook notification at
all. The adversary does not need to *create* the corruption: a real
corruption event plus the operator's own batch remediation produces the same
suppression, and an adversary can simply enroll inside that window, where their
replacement is the one most likely to be the suppressed duplicate.

**Preconditions.** (1) A prior null-record drop at either ingestion boundary
(`ClusterStore.Load` or `ImportFullState`) for the node IDs in question —
`NodeRecordWasDropped` gates the whole path. (2) A valid, unspent, admin-issued
single-use enrollment token per node. (3) At least one webhook subscribed to
`cluster_node_reenrolled`. (4) Two or more such enrollments within `dedupTTL`.

**Exploitability.** Low as a deliberate attack — it needs admin-issued tokens,
which already permit enrolling a node. **Likelihood as an operational failure:
high**, because the batch is the documented remediation path and 30 s is far
longer than a fleet of nodes needs to re-enroll once tokens are issued.

**Impact.** Loss of a security notification, not loss of a security decision.
The **audit trail is intact** — `auditAdd` is a ring append with no dedup, and
each node gets its own `cluster.node.reenroll-dropped` entry with the node ID in
`Object` — and the server log line is per enrollment. What is lost is the
*push* signal for every replacement after the first, i.e. the one channel an
operator without a log pipeline or a metrics stack actually watches. Detection
gap, no privilege or policy change.

**Affected assets.** Cluster node identity; the CRL's completeness; the
operator's ability to notice an un-revocable predecessor certificate.

**CWE.** CWE-778 (Insufficient Logging) — specifically alert suppression of a
security-relevant event.
**OWASP.** A09:2021 Security Logging and Monitoring Failures.
**Security severity.** Low.
**Regression risk.** None by this fix's direction: the dedup key becomes
*narrower*, so the change can only cause **more** deliveries, never fewer. That
is the same direction `internal/alerts` itself documents for its cap eviction
("Eviction fails toward MORE deliveries, never fewer … Silencing a real alert to
save memory would be the wrong trade for a security control").

**Why the existing tests could not see it.** `enroll_dropped_record_reenroll_test.go`
is thorough — positive, negative control, authentication, both ingestion
boundaries, concurrency — but it asserts through the `enrollAlertFire` seam,
which captures the **dispatch decision** and by construction never reaches
`Store.Dispatch` or its dedup. The seam exists for a good documented reason
(delivery-based assertions are flaky under the shared delivery semaphore), and
the consequence is that a producer-side dedup-key defect is invisible to it.
`recordExpiredNodeReenrollment` escapes the same trap only **incidentally**, by
embedding per-node certificate serials in its detail.

**Suggested fix (applied).** Name the node in `Detail`, which is what makes the
dedup key per-node, mirroring the expired-node producer. The node ID is
client-supplied (`EnrollRequest.NodeID`), and promoting it into `Detail`
promotes it into a `logger.Printf` argument, an audit record and a webhook body
— so it passes `sanitizeLog` **before** entering the detail (CWE-117), with
`%q` as the second layer, per `docs/agent-context/conventions.md`. Nothing else
changes: not the admit decision, not the audit action or `Object`, not the alert
event, `Host`, `Actor` or `Source`, and not the recording point (still after
`RegisterNode`, so a failed enrollment still claims nothing).

**Safe implementation.**

```go
safeNodeID := sanitizeLog(nodeID)
detail := fmt.Sprintf("node %q enrolled under a node ID whose stored record was earlier dropped as an unusable "+
    "null entry; the predecessor certificate's serial was lost with that record, so it could NOT be added to the "+
    "CRL and stays valid until it expires — confirm this enrollment was expected, and verify the control plane's "+
    "cluster.json", safeNodeID)
logger.Printf("Enrollment: RE-ENROLLED over a DROPPED record from %q — %s",
    sanitizeLog(sourceIP), detail)
```

**Required tests** (`enroll_dropped_reenroll_alert_dedup_test.go`, new):

| Test | Class | Pins |
|---|---|---|
| `TestEnroll_DroppedRecordAlertsAreDistinctPerNode` | regression + positive | two full enrollments over dropped records produce **different** `event+Detail` dedup keys; each detail names its own node and not the other; `CRL`, `Host` and `Source` preserved |
| `TestEnroll_DroppedRecordAuditEntryStillIdentifiesTheNode` | negative control | widening the detail does not disturb the audit entry the roster-side evidence is read from; the entry is self-contained |
| `TestRecordDroppedNodeReenrollment_SanitizesTheNodeIDInTheDetail` | boundary / malformed | a node ID carrying `\n`, `\r`, `NUL` and a forged log line reaches the detail through `sanitizeLog` (control bytes folded to `_`), and **not** merely `%q`-escaped |
| `TestEnroll_ReenrollmentAlertKeysDoNotCollideAcrossProducers` | negative control | the two producers share the `cluster_node_reenrolled` event and therefore one dedup namespace; neither can suppress the other |

Authentication, authorization and concurrency for this path are already covered
by the existing file (`…EvidenceRequiresAValidToken`,
`…EvidenceRequiresASuccessfulEnrolment`,
`TestClusterStore_DroppedNodeIDsConcurrentReadAndImport`) and were re-run rather
than duplicated.

**Mutation checks.** Reverting the fix fails
`TestEnroll_DroppedRecordAlertsAreDistinctPerNode` with the shared key printed.
The boundary test needed a second round: its first form asserted only the
absence of raw control bytes, which **`%q` alone satisfies** — removing
`sanitizeLog` left it green. It now asserts the sanitized shape
(`dp-evil_Enrollment`) and rejects the `%q`-escaped-but-intact form, and
removing `sanitizeLog` fails it.

---

## Accepted posture change (named, not hidden)

**A Stage-1 `Exempt` rule written in a non-canonical IP spelling becomes live in
this window.** #1879's matcher fix is direction-dependent, and the direction is
stated here rather than left to be discovered, because this is the window in
which it reaches `origin/main`:

- For `CredentialRequired` / `SSORequired`, the fix is **strictly stricter**: a
  rule that named a client and never matched it now challenges that client,
  where `resolveAuthOutcomeFrom` previously fell through to the global default.
  This is the fail-open the 2026-11-12 review closed.
- For `OutcomeExempt` — an authentication **waiver** — the same fix is
  **strictly more permissive**. A deployment holding an exempt rule written
  `2001:DB8::10` or `::ffff:10.0.0.5` had authentication silently *enforced* for
  that client; after this change the waiver applies, with no operator action.

This is the operator's stated intent restored, and it widens to **exactly one
address**: `sourceLiteralPrefix` returns `PrefixFrom(addr, addr.BitLen())` —
a `/32` or `/128` — both sides `Unmap()`ed, and a zoned literal keeps the
exact-string comparison it always had. It is not a widening to a different host,
and it makes the bare-IP branch agree with the CIDR branch beside it, which has
always matched a 4-in-6 client through `net.IPNet.Contains`. The
`CULVERT_AUTHBYPASS_DISABLE` kill switch still suppresses `Exempt` only, so the
break-glass control over this outcome is unchanged. No code change is proposed;
the operator-visible consequence is recorded.

---

## Regression Analysis

Measured against `3b09cff`, per surface the window touched:

| Surface | Verdict | Basis |
|---|---|---|
| SSRF guard (`internal/ssrf`) | **no regression** | expiry still enforced per entry in both generations; promotion preserves the original `expires`; negative (DNS-error) results still uncached; eviction can only force a fresher live lookup; nothing writes `prev`, so a key is in one generation and a stale verdict cannot shadow a fresh one; `prev = nil` is only ever read/`delete`d, so no nil-map write |
| Session revocation (`internal/session`) | **no regression; consistency improved** | both answers now under ONE mutex hold, so the pair cannot straddle a concurrent revoke; rejection precedence unchanged and test-pinned; MAC verified before the moved checks, so the reordering is unobservable; the earlier lazy eviction only drops an entry already past its own expiry |
| Stage-1 auth subject (`policy.go`, `authpolicy.go`) | **no regression; fail-open closed** | widens to exactly one address; zoned and unparseable literals keep exact-string comparison; `cidrPredicateMatches` precomputes only values containing `/`, so bare IPs take the same fixed path; unknown predicate still fails closed; `Exempt` direction named above |
| Panic guards / lock discipline (CHAOS-118) | **no regression; a new wedge class avoided** | every lock inside a newly guarded round converted to a deferred release; closure scope used where post-section work must not hold the lock (CHAOS-50); Root CA round charges a contained panic as a **failed** attempt rather than inheriting a zero value that reads as "recovered"; IdP watchdog guarded per round so the supervisor survives |
| Cluster enrollment identity (`enrollment.go`, `controlplane_server.go`) | **finding A, fixed** | admit decision unchanged (single-use admin token still required); evidence recorded only after `RegisterNode`; audit entry per node and un-deduped; the **alert** shared one dedup key — fixed here |
| Diagnostics / RBAC (`#1877`) | **no regression** | `requireRole(…, RoleViewer)` on both renderers; single `writeOperatorContract` redaction chokepoint; counts and fixed prose only; no dial, probe or `Effective()` call; `/healthz` does not build the contract |
| Installer (`#1878`) | **no regression; fail-closed added** | prompts on `/dev/tty`, refuses with no terminal instead of consuming the script body |
| Audit/config versioning | **unchanged** | no versioned configuration mutation in this window; the enrollment path audits without `saveConfigVersion`, as it did before |
| Tests | **no weakening** | every test diff in the window is additive or terminology; no assertion relaxed, no skip added; `chaos105_worker_guard_test.go` **extends** its guarded-worker registry by five entries and anchors its source reads to `pkgSourceDir()` |

---

## Attack Scenarios

Considered and traced, with the outcome in each case:

| Scenario | Outcome |
|---|---|
| **SSRF via cache poisoning** — mint a key that later serves a "public" verdict for a private host | Not reachable. `Store` is only called with a freshly resolved verdict and a fresh `expires`; promotion copies an existing entry verbatim; expiry is checked on every read. |
| **SSRF via cache eviction** — flood unique hosts so a private host's "private" verdict is evicted | Harmless by direction. A miss re-resolves, and a DNS error is uncached, so the guard re-runs rather than defaulting to allow. |
| **DNS-amplification via cache thrash** — force re-resolution of all legitimate traffic | Possible (residual risk 4), and strictly better than the behaviour it replaced (unbounded retention plus a ~200 ms global stall per sweep). No verdict changes. |
| **Session replay after logout** — exploit the moved revocation check | Not reachable. The MAC is verified first; a revoked cookie is still refused, now under the same lock hold as the account check. |
| **Account-revocation eviction** — use an expired cookie to drop a live account revocation | Not reachable. `userRevokedLocked` evicts only an entry already past its own expiry, which is unenforced for every cookie by then. |
| **Auth waiver via IP spelling** — present a 4-in-6 address to hit an IPv4 `Exempt` rule | Behaviour change, named above. No new exposure: the address identity is unchanged, the CIDR branch already matched 4-in-6, and anyone able to control the client IP string could use the canonical spelling. |
| **Lock wedge via a contained panic** | Avoided. Checked per round; every lock in a guarded round releases on `defer`. |
| **"SSL inspection recovered" forged by a panic** | Avoided. `runInspectionCARecoveryLoop` charges a contained panic as `attempted=true, err≠nil` and keeps retrying on backoff. |
| **Diagnostics disclosure to a viewer** | Counts and fixed prose only; no authority, URL or credential; same data the Upstream page and `/metrics` already expose to the same roles. |
| **Audit/log injection via a node ID** | Addressed in finding A's fix: `sanitizeLog` before the detail, `%q` on the value, test-pinned against the `%q`-only form. |
| **Alert suppression of an identity replacement** | **Finding A.** Fixed. |

---

## Residual Risk

1. **A dropped record's certificate serial stays un-revocable, by
   construction.** CHAOS-117's drop removes the only record naming the
   predecessor's serial, so no CRL entry can ever be added for it and the
   certificate remains valid until its own expiry. The evidence trail
   (#1879, plus finding A's fix) makes this *visible*; it does not make it
   recoverable. Unchanged by this review and correctly documented at the
   owner.
2. **`ClusterStore.droppedNodeIDs` grows for the life of the process and is
   keyed on replicated content.** Each `ImportFullState` unions the null node
   IDs it dropped into the set, and nothing ever removes one. A follower
   receiving repeated imports naming distinct null node IDs accumulates
   entries without bound. The only writer is the HA leader over an
   mTLS-authenticated channel, and a malicious leader is already outside the
   trust boundary, so this is recorded rather than filed as a finding — but the
   set is unbounded and the "never stops being relevant" rationale does not
   bound it.
3. **A re-enrollment alert can repeat for a node whose record was later
   deleted.** `droppedNodeIDs` is never cleared, so if an admin deletes a node
   that re-enrolled over a dropped record and it enrolls again,
   `priorNode == nil` holds and the replacement signal fires a second time. The
   statement remains true (the lost serial is still un-revocable), so this is
   noise rather than a false claim.
4. **Cache thrash under a wildcard-DNS flood (introduced by #1882).** A client
   minting ≥16,384 distinct destination hosts rotates generations fast enough to
   evict legitimate hot entries, pushing their verdicts back onto live DNS. The
   SSRF decision stays correct; the cost is upstream resolver load and
   per-request latency. Strictly better than the unbounded-growth plus
   exclusive-lock-sweep behaviour it replaces, and bounded by the existing
   admission and connection limits rather than by the cache.
5. **The revocation read path is still an exclusive mutex (introduced by
   #1880, and explicitly scoped out there).** `StatusFor` halves the
   acquisitions; it does not make the read lock-free. The owner records the
   three rejected designs and the measurements, and states that a lock-free
   read needs the store itself to become concurrent — a redesign of a
   security-critical structure. Accepted as scoped, with the benchmark harness
   (`revocation_readpath_bench_test.go`) left in place as the oracle for it.
6. **The runner-registration token still echoes on the terminal (#1878).**
   `read -rp` without `-s` prints the pasted token. The token is short-lived and
   the behaviour predates this window, but the change is the moment the prompt
   became a real interactive prompt rather than a bug. Not changed here: it is
   outside this review's scope and the fix (`read -rsp` plus a newline) belongs
   with the installer's owner.

7. **Pre-existing, found while tracing finding A, and outside this window's
   scope: an enrollment node ID is not charset-validated, and it reaches the
   audit CSV export unquoted-by-content.** `EnrollRequest.NodeID` is checked
   for non-emptiness and for equality with the CSR's CommonName
   (`validateEnrollCSR`), not against a character set, and it lands in the
   audit entry's `Object`. Both export encoders are safe against *injection* —
   `encoding/csv` quotes a field containing a newline, comma or quote, and the
   JSON encoder escapes — so there is no log- or response-splitting path. What
   remains is spreadsheet **formula** interpretation of a cell beginning `=`,
   `+`, `-` or `@` when an operator opens the CSV, which applies to the whole
   audit export and to every client-influenced field in it, not to this change.
   Separately, `controlplane_server.go`'s successful-enrollment log line prints
   `req.NodeID` with `%q` but without `sanitizeLog`, which the conventions ask
   for so CodeQL can see the barrier; `%q` makes it safe in fact. Neither is a
   regression in this window and neither is changed here; both are recorded so
   the next pass over this file does not have to rediscover them.

---

## Files

Changed by this review:

| File | Change |
|---|---|
| `controlplane_server.go` | Finding A fix: `recordDroppedNodeReenrollment`'s detail names the node (via `sanitizeLog`, printed with `%q`) so the `internal/alerts` dedup key is per-node; the reason is recorded at the function so the constant detail is not reintroduced. Four British spellings in this function's own comments corrected to the `PRODUCT-TERMINOLOGY.md` contract #1875 established. |
| `enroll_dropped_reenroll_alert_dedup_test.go` | **New.** Finding A regression oracle, negative controls for the audit entry and the sibling producer, and the sanitization boundary test. |
| `CHANGELOG.md` | The fix recorded. |
| `docs/engineering/SECURITY-REGRESSION-REVIEW-2026-11-13.md` | This review. |

Reviewed and unchanged: `internal/ssrf/ssrf.go`, `internal/session/session.go`,
`policy.go`, `authpolicy.go`, `enrollment.go`, `syslog_health.go`,
`idp_metadata_health.go`, `rootca_recovery.go`, `mcp_telemetry.go`,
`state_corruption.go`, `diagnostics.go`, `diagnostics_upstream_egress.go`,
`store.go`, `main.go`, `scripts/install-runner.sh`, `static/index.html`, and the
window's test and documentation changes.

---

## Verification

Run at this revision with the pinned toolchain. `go env GOVERSION` =
`go1.27.4`, `GOTOOLCHAIN` = `auto`, matching `go.mod`'s `toolchain go1.27.4`.

| Check | Result |
|---|---|
| `gofmt -l` (Go tree) | clean |
| `go vet ./...` | pass |
| `go mod tidy -diff` | clean |
| `CGO_ENABLED=0 go build -ldflags="-s -w"` release build | pass |
| `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build` cross-build | pass |
| `python3 docs/agent-context/check.py` | pass (486 navigation links, 117 route edges; static integrity only) |
| Finding-A tests **before** the fix | **3 of 4 fail** (the reproducer; the cross-producer control passes, as it must) |
| Finding-A tests after the fix | pass (4/4) |
| Mutation: fix reverted | `TestEnroll_DroppedRecordAlertsAreDistinctPerNode` **fails**, printing the shared dedup key |
| Mutation: `sanitizeLog` removed from the detail | `TestRecordDroppedNodeReenrollment_SanitizesTheNodeIDInTheDetail` **fails** (first form of the assertion did **not** — see note) |
| `go test -race -count=1 -run 'Enroll\|Reenroll\|ReEnroll\|CHAOS117\|CHAOS105\|CHAOS118\|Audit\|Alert\|Cluster' .` | pass (162 s) |
| `go test -race -count=2 -shuffle=on ./internal/alerts ./internal/session ./internal/ssrf ./internal/identcache` | pass (the four owners whose code this window rewrote) |
| `TEST_SEED=20260421 go test -count=2 -shuffle=on -timeout=20m ./...` (the Deep determinism command) | **pass** — 117 packages `ok`, no failures, exit 0 |
| `go test -tags benchgate -run 'TestBenchGate_' -count=1 -p 1 -timeout=10m` over all ten benchgate packages (root + `admission`, `threatfeed`, `catgroup`, `session`, `decryptprofile`, `catoverride`, `secscan`, `catdb`, `identcache`) | pass (10/10) |
| `golangci-lint` v2.15.0, `--new-from-rev origin/main` (the gate's own command, run on the committed tree) | **`0 issues.`** |
| `golangci-lint` v2.15.0, full-tree | 174 issues, all pre-existing; **none in `controlplane_server.go`** and none in a function this review touched |

**Why the full-tree lint run was read alongside the diff-scoped one.**
`cyclop`, `funlen` and `gocognit` attribute a finding to a function's
DECLARATION line, so `--new-from-rev` cannot see a function this change made
longer. `recordDroppedNodeReenrollment` grew by the `fmt.Sprintf` and its
comment; the full-tree run reports no finding against it, and none of the 174
pre-existing findings falls in a file this review touched. Lint was installed
with `GOTOOLCHAIN=go1.27.4 go install …@v2.15.0`, which is the step
`docs/agent-context/conventions.md` records as the difference between a working
linter and the "local lint is unavailable" misdiagnosis.

**Mutation-check note.** The boundary assertion had to be tightened before it
was worth anything. Its first form asserted only that the detail carried no raw
control byte — a property `%q` satisfies on its own, so removing `sanitizeLog`
left the test **green**. It now asserts the sanitized shape (a folded `_`) and
explicitly rejects the `%q`-escaped-but-intact form, and the mutation fails it.
Recorded because the weaker assertion is the easy one to write and would have
pinned nothing.

**Scope of these results.** These are focused and local checks at this
revision. They are **not** aggregate CI approval: the required
`✅ Fast PR Gate — APPROVED` and `✅ Deep PR Gate — APPROVED` checks, the sharded
race lanes with their completeness check and privileged regression, and the
merged coverage-floor artifact all run on the pull request. Not run locally: the
frontend tree (untouched), `cmd/culvert-maint` (untouched), and the
packaging/release-evidence workflows. Readiness and permission to merge remain
separate decisions, and nothing in this review authorises a merge, a deploy or
any policy change.
