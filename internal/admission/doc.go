// Package admission owns IP filtering and per-IP local/distributed rate limits.
//
// NewIPFilter and NewRateLimiter construct independent owners and start no
// goroutines. Callers own configuration persistence, Cleanup scheduling,
// cancellation and transport. Remote maps passed to ApplyRemoteCounts transfer
// ownership and must not subsequently be mutated. Configuration/enablement
// changes retain local and remote history.
//
// The constructors remain the blessed construction path, but a zero filter and
// a zero limiter are now fully usable rather than usable-with-a-precondition:
// every map write lazily initializes, so a bare IPFilter{} accepts Add/AddAll
// and a bare RateLimiter{} enforces once Configure()d. ADR-0039 recorded the
// narrower contract ("use NewIPFilter before adding individual addresses";
// "active local admission requires NewRateLimiter"), which this deliberately
// strengthens: both types have only unexported fields, so the bare literal is
// the sole literal form available outside this package, and the three write
// sites that lacked the lazy init already present in addExemptionLocked
// panicked on a nil map — on the DP snapshot apply path (AddAll) and on the
// request path (Allow/AllowClusterAware). Verdicts are unchanged; a bare
// instance is differentially pinned equal to a constructed one.
//
// ClusterFreshness derives the verdict from the current window and receipt
// stamp. ObserveClusterFreshness additionally owns diagnostic episode accounting;
// callers render its result and serialize observation/logging in their loop.
package admission
