// Package admission owns IP filtering and per-IP local/distributed rate limits.
//
// NewIPFilter and NewRateLimiter construct independent owners and start no
// goroutines. Callers own configuration persistence, Cleanup scheduling,
// cancellation and transport. Remote maps passed to ApplyRemoteCounts transfer
// ownership and must not subsequently be mutated. Configuration/enablement
// changes retain local and remote history.
//
// A zero filter supports reads and mode/CIDR operations as before; use
// NewIPFilter before adding individual addresses. A zero limiter supports
// disabled admission, configuration and distributed-state diagnostics; active
// local admission requires NewRateLimiter to initialize its shard maps.
//
// ClusterFreshness derives the verdict from the current window and receipt
// stamp. ObserveClusterFreshness additionally owns diagnostic episode accounting;
// callers render its result and serialize observation/logging in their loop.
package admission
