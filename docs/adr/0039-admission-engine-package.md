# ADR-0039: Admission engine package

- Status: implementation design, 2026-09-30, recorded before extraction.
- Baseline: `31a7562fc9ae807523664b028401e5b5fc35065e`, includes #1522/#1523.
- Extends ADR-0038; package-isolation step 3, no policy or algorithm change.

`internal/admission` owns IPFilter, RateLimiter, immutable prefix/exemption
views, sliding windows, remote counts/receipt time, enablement and freshness
transition history. Constructors create no goroutines. Locks, publication order,
zero-value support and transferred immutable remote maps retain ADR-0038's
contracts. Active local limiting requires NewRateLimiter; NewIPFilter initializes
the writer map. Existing zero-value read/configuration behavior stays supported.

The API is the existing exported filter/limiter operations, NewIPFilter and
NewRateLimiter. PrefixFromIPNet is a pure conversion also used by policy; there
is one implementation. ExportHotDeltas returns engine-owned HotCount values:
these are current qualifying in-window counts, NOT increments since the previous
export. Export neither clears nor deducts counts. Main converts to its unchanged
RateLimitDelta wire DTO. The historical method name stays for call-site continuity.

ClusterFreshness derives the live status. ObserveClusterFreshness owns the
mutex/latch/episode update and returns the observed status plus a transition
(None, Stale, Recovered). Main formats the existing log messages from that result;
it does not recalculate freshness or count episodes. Observation remains off the
admission hot path. Composition runs one gossip observer per limiter as before.

Main retains rl/ipf handles (permanent local aliases/construction wrappers, not
a temporary second implementation), configuration,
persistence/rollback, HTTP/SOCKS5, gossip transport/DTOs, fleet aggregation,
cleanup-loop cancellation, metrics/API rendering and transition logging. No
mutable engine internals are exported for tests. White-box tests and publication
negative controls move beside their owner; real production integrations stay root.

## Enforcement and migration

Move engine tests/benchmarks without renaming entries or changing build tags.
Split mixed security/distributed/CHAOS files by behavioral owner. Record package,
name, tag and source ownership for every moved entry. Root integration tests use
constructors and observable results; future/stale stamp injection stays private
to engine tests. Keep snapshot/rollback, wire serialization and cancellation
coverage in main.

The 70% security.go contract follows admission's implementation, with a separate
70% residual shim contract and 70% freshness contract. Other floors and global
55% stay intact. Required Fast, main QA and weekly benchgate entry points must
include root AND admission; source-contract negative controls reject omission.
Non-root and independent coverage discovery remain automatic. Boundary checks
reject application/persistence imports and shared mutable admission owners.

## Coordination

All 30 open PR file lists inspected. #1485 touches security.go and Fast, #1437
and #1414 touch gossip (the latter also CHAOS-61); #1470 touches policy's prefix
consumer; #1509 changes QA's action version. Several touch CLAUDE.md. Preserve
these behaviors; recheck overlap before handoff. No open PR uses ADR-0039.
The policy pure-core assessment is the next separate design, not this extraction.

## Amendment, 2026-10-05 — zero-value precondition replaced by a guarantee

Security regression review of the extraction found the recorded zero-value
contract above ("use NewIPFilter before adding individual addresses"; "active
local admission requires NewRateLimiter") to be a documented PRECONDITION with
no enforcement: the three remaining map writes — `IPFilter.addLocked`,
`RateLimiter.Allow`, `RateLimiter.AllowClusterAware` — panicked on a nil map,
while `addExemptionLocked` already lazily initialized. Measured: a bare
`IPFilter{}` panics on `Add` and on `AddAll`, and a bare `RateLimiter{}` that
has been `Configure`d panics on `Allow`.

The extraction makes that trap strictly easier to reach rather than harder.
Both types now carry only unexported fields, so the complete literal package
main previously wrote (`&IPFilter{single: map[string]bool{}}`) no longer
compiles outside this package and `&IPFilter{}` — the silently broken shape —
is the only literal form left. The two reachable panic sites are the DP
snapshot apply path (`applySnapshotAdmission` → `AddAll`, so a Control Plane
config push would crash the node applying it) and the request path.

The precondition is therefore replaced by a guarantee: every map write lazily
initializes, using the idiom already present in `addExemptionLocked`. This is
an availability hardening, not a policy change — the nil checks sit in the cold
miss branch (a nil map reads as a miss), the allocation benchgates still measure
zero, and `TestBareLiteral_MatchesConstructedInstance` differentially pins a
bare instance equal to a constructed one across every mode and probe. The
constructors remain the blessed construction path.

Gates: `internal/admission/bare_literal_safety_test.go` (5), each verified
failing against the reintroduced pre-fix shape, and four of them additionally
verified failing against the cheapest wrong fix — skipping the store when the
map is nil, which silences the panic while silently not enforcing the entry.
