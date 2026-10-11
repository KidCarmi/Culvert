# Security regression review — 2026-10-11

**Window reviewed:** the in-flight change set, i.e. the open pull requests
targeting `main@fbf6a37`, plus the revocation plane in `main` that two of them
touch. `main` itself did not advance in this window — the previous review
(PR #1597) closed at `fbf6a37` — so reviewing merged history again would have
re-covered ground. The value here is in the changes that have **not** landed
yet, which is where a regression is still cheap to stop.

**Posture:** one defect found in `main` and **fixed in this PR** with gates;
four findings reported against branches this PR does not own; three changes
reviewed in depth and cleared.

---

## Executive summary

| ID | Where | Severity | Status |
|---|---|---|---|
| **SEC-REVEXP-1** | `main` — `internal/session` | **Medium** | **Fixed here**, 7 new gates |
| SEC-REVCAP-1 | PR #1591 (`claude/serene-cerf-bax9uv`) | Medium | Reported, not fixed (not our branch) |
| SEC-REVCAP-2 | PR #1591 | Low–Medium | Reported |
| SEC-DIAG-CIDR-1 | PR #1596 (`claude/friendly-brahmagupta-vzcuij`) | Low | Reported |
| SEC-CATDB-DEGRADE-1 | PR #1599 (`claude/serene-cerf-7z0geb`) | Low | Accepted residual, recorded |
| — | PR #1598 IDNA memo | — | **No regression** |
| — | PR #1590 urlcat lock-free view | — | **No regression** |
| — | PR #1594 config BOM | — | **No regression** |
| — | PR #1528 appliance readiness | — | **Not reviewed** (see §7) |

The one defect in shipped code is a disagreement between two expiry predicates
that made explicit logout fail **open** for up to one second. It is reproduced,
fixed and gated in this PR. Everything else is a report against a branch whose
author owns the fix; nothing was pushed to another author's branch.

---

## 1. SEC-REVEXP-1 — a revoked session cookie was honoured for up to one second after logout

**Fixed in this PR.** `internal/session/revocation_expiry.go` (new),
`internal/session/session.go` (four call sites).

### The defect

Two predicates answered "has this session's lifetime ended?" and they
disagreed:

| Site | Test |
|---|---|
| `Decode` — `internal/session/session.go` | accepts while `time.Now().Unix() <= s.Exp` |
| `IsRevoked`, `IsUserRevoked`, `ExportRevocations`, `MergeRevocations` | retained while `!time.Now().After(exp)` |

Every production revocation expiry is a **whole second**: `revokeSessionCookie`
stores `time.Unix(s.Exp, 0)` and `MergeRevocations` stores
`time.Unix(e.Expiry, 0)`. `time.Now()` carries a sub-second remainder. So for
the entire wall-clock second numbered `s.Exp`:

- `now.After(exp)` is **true** → the revocation is evicted, and `delete`d;
- `now.Unix() > s.Exp` is **false** → `Decode` **accepts** the cookie.

The revocation was destroyed, not merely ignored — and `ExportRevocations`
applied the same test, so the hole propagated: the entry vanished from the
on-disk revocations file (`SaveRevocations`) and from the next DP→CP gossip
export on the same tick.

### Reproduced

Probe against the real `Decode`, before the fix:

```
now=22:15:24.300  now.Unix()=1791756924  s.Exp=1791756924
IsRevoked=false   Decode err=<nil>
FAIL-OPEN CONFIRMED: revocation evicted while Decode still accepts the cookie
```

### Attack scenario

1. An attacker holds a session cookie obtained by any means the threat model
   already covers (XSS-free exfiltration, a shared or forensically recovered
   browser profile, a captured proxy log, a stolen backup).
2. The legitimate user clicks **Log out**, or an admin deletes the account.
   Culvert records the revocation and returns success.
3. Any request the attacker makes inside the wall-clock second numbered
   `s.Exp` is served: `IsRevoked` evicts the record and reports "not revoked",
   then `Decode`'s own expiry test still admits the session.

- **Preconditions:** possession of a valid cookie; a request landing in the
  final second of its lifetime.
- **Exploitability:** low — a ≤1 s window at a time the attacker can compute
  (`exp` is in the cookie they hold, so the window is *predictable*, which is
  what keeps this above "theoretical").
- **Likelihood:** low. **Impact:** full session use, i.e. whatever role that
  session carries, including `RoleAdmin`.
- **Affected assets:** admin console session authentication; the persisted
  revocations file; cluster-wide revocation propagation.
- **CWE:** CWE-613 (Insufficient Session Expiration), with CWE-672 (Operation
  on a Resource after Expiration) as the mechanism.
- **OWASP:** A07:2021 Identification and Authentication Failures.
- **Regression risk of the fix:** low, and one-directional — see below.

### The fix

One predicate, in `revocation_expiry.go`:

```go
func revocationLive(now, exp time.Time) bool { return now.Unix() <= exp.Unix() }
```

The **revocation list** is the side that moved, because a revocation must
outlive the session it revokes and never the reverse. The change can only
retain an entry *longer* (by under one second) and never drop one sooner, so it
cannot resurrect a session, cannot refuse a legitimate logout, and cannot
unbound the list — retention is still capped by the session TTL that set the
expiry.

Tightening `Decode` instead was rejected: it would shorten every session by up
to a second and change the meaning of the `exp` claim this appliance signs and
ships in a cookie — a wire-contract change to settle an internal disagreement.

### Required tests — all present

`internal/session/revocation_expiry_test.go`. Every one was confirmed to
**fail** against the pre-fix predicate and pass after it:

- **Regression / differential:** `EvictionNeverPrecedesDecode` (the probe above,
  inverted); `DifferentialAcrossOffsets` (property: "Decode accepts" ⇒ "the
  revocation is live", swept ±5 s).
- **Boundary:** `EntrySurvivesTheFinalSecond` — the entry is still *in the map*,
  not merely reported.
- **Negative control:** `UnambiguouslyPastEntriesStillEvict` — 2 s / 1 min / 24 h
  old entries still evict, so the fail-closed direction did not become a leak.
- **Persistence + cluster:** `ExportDropsOnlyWhatDecodeRejects`,
  `MergeAdmitsTheFinalSecond`.
- **Malformed input:** `MalformedPeerExpiries` — `Expiry` of `0`, `-1`,
  `-(1<<40)`, `1` all refused, none panics.
- **Authentication/authorization surface:** `UserRevocationHonoursTheSameOracle`
  — the username-keyed list that gates every session of a deleted account.
- **Concurrency:** `ConcurrentReadersAndWriters` — 8 goroutines × 300 iterations
  across all five entry points under `-race`, asserting the entry survives
  concurrent eviction passes.

### One existing assertion was tightened, deliberately

`TestRevocationList_PastExpiryEvicts` revoked with `time.Now().Add(-time.Millisecond)`
— an expiry *inside the current second*, which under the corrected oracle is
still live. It now uses `-time.Minute`. The property it exists to assert ("an
entry whose expiry has genuinely passed is evicted") is unchanged and still
asserted; what changed is that it is now stated at a resolution the oracle can
distinguish. The second-resolution boundary itself is pinned by two new tests.
This is the only pre-existing assertion the fix touches, and it is recorded
here rather than left for a reviewer to find.

---

## 2. SEC-REVCAP-1 — PR #1591's entry cap is applied to the reload path, so the deliberately uncapped local list cannot survive a restart

**Severity: Medium. Reported, not fixed** — `claude/serene-cerf-bax9uv` is not
this PR's branch.

PR #1591 is a genuine and well-argued fix: it authenticates the public
`/api/auth/logout` path instead of bounding it, and bounds the untrusted-origin
paths instead of authenticating them. Its own stated reasoning is the finding:

> *"Evicting a revocation entry resurrects a revoked session — a fail-OPEN
> failure of a security control, so a cap here is not free the way a cap on a
> cache is."* — `internal/session/revocation_bounds.go:221`

The local MAC-verified path is therefore exempted from
`MaxRevocationEntries = 65536` (`revocation_bounds.go:92`), on purpose, so the
list can grow past it. But **`LoadRevocations` reads that same list back
through `MergeRevocations`** (`internal/session/session.go:322` → `:225` →
`admitUntrustedLocked`, `revocation_bounds.go:273`), where the cap *is*
enforced. The uncapped list cannot be reloaded intact.

**Attack scenario.** No attacker action is required beyond holding a cookie
through a restart:

1. A deployment accumulates more than 65 536 live revocations inside one
   session TTL (clamped to ≤ 7 days). Each entry is one logout, and in a
   cluster each node merges every peer's entries, so the budget is
   **fleet-wide, not per node** — roughly 9 400 logouts/day at a 7-day TTL.
2. The node restarts (upgrade, crash, container reschedule).
3. `LoadRevocations` admits 65 536 entries and silently drops the rest — in
   arbitrary order, because the file was written from a Go map iteration in
   `ExportRevocations`.
4. Every session whose revocation was dropped authenticates again until its
   natural expiry — up to 7 days.

- **Preconditions:** fleet-wide live revocations > 65 536; one restart.
- **Exploitability:** does not need an attacker; it needs scale.
- **Impact:** silent, long-lived resurrection of explicitly revoked sessions.
- **CWE:** CWE-613; CWE-770 (allocation without limits) is the pressure that
  motivated the cap. **OWASP:** A07:2021.

**Recommended fix (safe implementation).** Treat the on-disk file as a
different trust tier from cluster gossip — it is this node's own prior state,
written by this node under `0o600`:

- Admit the reload path past the entry cap, keeping the **key-size** bound
  (which is what contains an over-long forged key), so the local list's
  deliberate exemption survives the restart it exists to survive; **or**
- if a hard ceiling must hold across restarts, make the cap evict by
  **soonest expiry first** rather than refusing arrivals, so the entries
  dropped are the ones closest to expiring anyway rather than an arbitrary
  subset — and raise `RevokeCapacity` to an operator **alert**, not only a
  counter.

**Required tests:** reload of a persisted list larger than the cap retains
every still-live entry (or drops only soonest-expiry entries); a
`RevokeCapacity` refusal on the reload path is surfaced; a differential test
asserting `len(ExportRevocations())` round-trips through
`SaveRevocations`/`LoadRevocations` for a list above the cap.

---

## 3. SEC-REVCAP-2 — PR #1591's Control-Plane per-node cap is 16× below the node cap, and the subset it keeps is randomised

**Severity: Low–Medium. Reported.**

`maxRevocationsPerNode = 4096` (`controlplane.go:258`) truncates each DP→CP
push, and `a.perNode[nodeID] = kept` (`:285`) **replaces** the retained set
rather than merging it. The pushed slice comes from `ExportRevocations`, which
iterates a Go map — so the kept 4096 is a *different arbitrary subset* on every
3-second tick.

Peers merge additively, so the fleet does converge; the cost is **propagation
delay** for exactly the entries that matter most (the newest revocations). For
a node holding `N > 4096` live revocations, a specific new revocation needs
≈ `N/4096` ticks to be selected — ≈ 48 s at `N = 65 536`, and the tail is
geometric, so the 95th percentile is several minutes. Above a peer's own
65 536 cap the loss becomes permanent (and is then SEC-REVCAP-1).

- **Impact:** a session revoked on node A keeps authenticating on nodes B and C
  for a window that grows with the revocation count, which is precisely the
  cluster-wide invalidation `revocationSyncLoop` exists to provide.
- **CWE:** CWE-613. **OWASP:** A07:2021.

**Recommended fix.** Make truncation deterministic and preference-ordered —
sort by expiry and keep the **newest** (the furthest-from-expiry) entries, or
have the CP merge into `perNode` instead of replacing — and align the CP cap
with the node cap so the two tiers do not disagree by 16×.

**Required tests:** a node with > `maxRevocationsPerNode` live entries
propagates a *stable* set across consecutive ticks; a newly added revocation
reaches `MergedExcluding` within one tick regardless of list size.

---

## 4. SEC-DIAG-CIDR-1 — PR #1596 puts the rejected entry text on a Viewer-role API

**Severity: Low. Reported.**

`access_cidr_diag.go` stores `err.Error()` and splices it into the diagnostics
message. That error text carries the **offending entry verbatim**, and
`/api/diagnostics` is gated at `RoleViewer` (`diagnostics.go:1933`), while the
nav entry for the view is `data-min-role="admin"` (`static/index.html:882`).

The same file's own contract says so explicitly:

> *"Any field added in the future that could leak sensitive data must be
> redacted to admin-only at the API layer before being returned here."*
> — `diagnostics.go:1924-1927`

and `socks5_health.go:436` already records the precedent that a diagnostics row
"must not carry internal addresses".

**Cleared:** XSS. The legacy renderer escapes both fields —
`escHtml(c.message)` and `escHtml(c.operator_action)` at
`static/index.html:18363` and `:18370` — and no `dangerouslySetInnerHTML` exists in
`frontend/src`. So an admin-supplied `<img onerror=…>` masquerading as a CIDR
does **not** execute. Worth keeping in mind only because the row is the first
to route operator-controlled free text to this surface.

**Recommended fix:** keep the raw entry in the admin-only log line that already
prints it, and put only the list name plus a rejected-entry count on the
Viewer-visible row.

**Also noted (not security):** the clear-on-success call exists for the
allowlist (`ui_config.go:1773`) but has no counterpart on the trusted-proxy
endpoint, and `applyAdminNetwork` only calls `noteAccessCIDRResult` when the
saved list is non-empty (`admin_settings.go:667`, `:683`). A rejection can
therefore stay latched after the operator has fixed it, and the message then
asserts "the previous list stays in force" when it no longer does. Stale
warnings on a security row cost operator trust. **Required test:** a valid save
on each of the two endpoints clears its own latch.

---

## 5. SEC-CATDB-DEGRADE-1 — PR #1599 trades indefinite Layer-2 enforcement for availability

**Severity: Low. Accepted residual, recorded rather than contested.**

PR #1599 contains a memory fault (`SIGBUS` on a badger mapping) that previously
killed the process, and latches `degraded` so Layer-2 category lookups are
refused for the life of the process. The policy outcome on failure —
"uncategorised" — is explicitly **unchanged and pre-existing**, and the PR says
so (`internal/catdb/catdb.go`, `getExact` doc comment).

The posture change is nonetheless real and worth stating plainly: before, a
damaged store stopped the gateway (no traffic, no bypass); now the gateway keeps
serving with community-feed category enforcement **off for every host until
someone restarts the node**. A category-scoped Deny rule that depends on
Layer 2 silently stops matching.

**Why it is accepted:** visibility is handled properly — a `diagWarn`
`category_feed_db` row with an operator action
(`catfeeddb_health.go:143`), `culvert_catfeeddb_memory_faults_total`, and
`culvert_catfeeddb_available` correctly flipping to 0
(`metrics.go:1088`). Layer 1 (admin-managed `catStore`) remains
authoritative. This is the posture CHAOS-05/07 already established.

**Residual to record:** a `diagWarn` is not an alert, there is no fail-closed
option for deployments that would rather refuse uncategorised traffic than
under-enforce, and recovery requires a manual restart. Recommend an alert hook
on the latch, and that `ContainFault`'s per-goroutine scope — badger's own
compaction goroutines remain exposed, as the PR notes — stays on the register.

**Also noted:** `logger.Printf("SESSION_REVOKE_REFUSED %s …", sanitizeLog(…), sanitizeLog(…))`
in PR #1591's `session_revocation_bounds.go:134` prints sanitized values with
`%s`, where `docs/agent-context/conventions.md` requires `%q`. CWE-117 is
contained — `sanitizeLog` scrubs all C0 controls and DEL — so this is a
convention deviation CI may flag, not a defect.

---

## 6. Reviewed in depth, no regression found

### PR #1598 — memoized IDNA normalization (`internal/hostutil/idnamemo.go`)

This memoizes `NormalizeHostStrict`'s slow path on a client-controlled key, in
front of the fail-closed canonicalization gate that RISK-013 exists to protect.
Four ways it could have gone wrong, each checked:

- **Cache-key confusion → policy bypass.** Every hit re-verifies the full key
  (`e.host == host`, `idnamemo.go`), so a direct-mapped collision is a *miss*,
  never a wrong answer. Entries are immutable once published and swapped by
  `atomic.Pointer`, so a reader sees one entry or the previous one, never a mix.
- **Unbounded growth → memory exhaustion.** Fixed 1024 slots, one entry each,
  overwrite on collision — no eviction bookkeeping and a hard ceiling. Both
  retained fields are refused above `maxMemoHostLen = 253`, which matters
  because the HTTP path admits up to 1 KiB of raw authority *before*
  `rejectOversizeCanonicalHost` runs.
- **Slot thrashing.** Per-process `maphash.MakeSeed()`; and the penalty for a
  forced miss is recomputation, i.e. today's cost.
- **Staleness.** None available: `idna.ToASCII` under the zero-option profile is
  a pure function of its input, with no clock, configuration, I/O or process
  state. A new `x/net` is a new binary and an empty table.

Two details show the right instincts rather than luck: `strings.Clone` on the
key, so an entry cannot pin a request header's backing array; and the fast
path (pure-ASCII, ACE-free, which is most traffic) never touches the table, so
the hot path keeps its 0-alloc shape. The negative result (`ok=false`) is
cached, which is correct for a pure function. **No regression.**

### PR #1590 — lock-free forward read view (`internal/urlcat`)

The security contract is stated in the code: a map reachable from a published
view is never mutated in place, and every mutator of `index`/`adminIndex` must
`publishForwardLocked()` before releasing `s.mu`. A missed publish is a silently
mis-enforced policy — an added host that never matches a Deny rule. Verified by
enumeration rather than by trusting the comment:

- Only two publish sites exist (`rebuildIndex`, `addHostToIndexes`), and
  **every** mutator reaches one of them under the write lock: `Load`,
  `restoreEntries`, `setMem`, `deleteMem`, `removeHostMem`, `New`, and
  `addHostMem`.
- `rebuildIndex` builds fresh outer maps *and* fresh inner sets, so nothing a
  reader can be walking is touched. `addHostToIndexes` clones the inner set and
  now also copies-on-write the outer map it changes.
- A nil view reads exactly as the nil maps it mirrors: no category, no match —
  identical to the zero-value `Store`'s prior behaviour.
- `TestCatIndexView_MutatorInventoryIsComplete` and
  `…_EveryMutatorRepublishes` make the contract a wall for future mutators,
  which is the part that keeps this safe after the PR merges.

**No regression.** One **pre-existing** (unchanged) defect noted in passing:
`addHostToIndexes` seeds `adminIndex[key]` from a set copied out of
`index[key]`, so with **duplicate category names** differing in `BuiltIn`,
`MatchesHostAdmin` can see built-in hosts. The PR documents duplicates as an
unsupported configuration and does not make this worse.

### PR #1594 — UTF-8 BOM in `config.yaml`

`bufio.Peek(3)`/`Discard(3)` ahead of the decoder. `yaml.DisallowUnknownField()`
is preserved, so nothing new is admitted; a 3-byte prefix strip cannot smuggle a
key. If anything this closes a posture gap in the safe direction: a BOM-prefixed
`config.yaml` previously failed to decode, and an operator's *restrictive*
configuration failing to load is worse than it loading. **No regression.**

---

## 7. Not reviewed, and why

**PR #1528 (`feat/onprem-appliance-readiness`)** — 1 205 files, 165 761
insertions, the bulk of it newly vendored `third_party/` code, and it touches
exactly the surfaces this role cares most about: restore paths, enforced upgrade
transitions, offline rollback, `ui_auth.go`, `ui_middleware.go`, `ui_session.go`
and `ui_access_policy.go`. A credible review of signature validation, path
handling on restore and the session/RBAC changes in that diff is not
compressible into the tail of this run, and a shallow pass over it would be
worse than an honest gap. **Recommend a dedicated review before merge**, with
the vendored tree reviewed as a supply-chain question (provenance and diff
against upstream) separately from the first-party diff.

Also not reviewed: the dependency bumps (#1511 Go 1.27.0-alpine, #1510/#1512
etcd 3.7.2, #1449 gRPC 1.84.0) — no first-party code to regress; they need a
CVE/changelog pass, not a code review.

**Housekeeping, outside this review's remit:** #1594/#1586 (config BOM) and
#1596/#1587 (diagnostics rows) look like duplicate pairs, and #1589/#1590/#1591
still target the superseded base `3fcc07e`.

---

## 8. Verification performed

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./internal/session/` | pass |
| `gofmt -l internal/session/` | clean |
| `go test ./internal/session/ -race -count=1` | pass (full package) |
| `go test . -run 'TestRevokeUserSessions\|TestSession\|TestLogout\|TestDecode\|Revocation\|Revoke' -count=1` | pass |
| New gates fail against pre-fix predicate | confirmed — all 7 |
| `python3 docs/agent-context/check.py` | exit 0 |
| `golangci-lint run ./internal/session/...` | **could not run locally** — the installed binary is built with Go 1.25 and panics on this Go 1.26 module (`package requires newer Go version go1.26`). CI's pinned version is authoritative. |

Not run: the full-module `go test ./...` aggregate and the hosted Fast PR Gate.
A passing local check is not a passing merge gate.

## 9. Residual risk

- SEC-REVEXP-1 is closed for the token and username lists and for the
  export/merge paths. The session **cookie** `MaxAge` is a browser-side hint and
  was never a control; nothing here changes that.
- SEC-REVCAP-1 and SEC-REVCAP-2 remain **open on PR #1591's branch**. If that
  PR merges unchanged, cluster-wide and across-restart revocation completeness
  is bounded by caps that disagree with each other and with the deliberately
  uncapped local path. They should be settled before merge, not after.
- SEC-DIAG-CIDR-1 and SEC-CATDB-DEGRADE-1 are low and remain with their
  authors.
- PR #1528 is unreviewed and is the largest unassessed security surface in the
  queue.
