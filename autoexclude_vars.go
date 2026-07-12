package main

// autoexclude_vars.go — package-main glue for the adaptive decryption-exclusion
// cache, which lives in internal/autoexclude (mirrors the decryptprofile_vars.go
// shim over internal/decryptprofile). The cache is a VOLATILE, in-memory learned
// set — never persisted, never synced CP→DP, and therefore off every config
// surface. main owns the singleton + the hot-path resolvers (resolveFailOpen /
// recordAutoExclude / classifyInspectFailure in decryptprofile_resolve.go) + the
// admin API + UI; the engine exposes only the store.

import "github.com/KidCarmi/Culvert/internal/autoexclude"

// AutoExcludeCache is the learned-exclusion store (engine type autoexclude.Cache).
type AutoExcludeCache = autoexclude.Cache

// AutoExcludeReason classifies why a host was learned (engine type).
type AutoExcludeReason = autoexclude.Reason

// Re-export the learn reasons so the hot-path classifier and metrics stay on the
// unqualified names.
const (
	autoExReasonUnsupported  = autoexclude.ReasonUnsupported
	autoExReasonClientCert   = autoexclude.ReasonClientCertRequired
	autoExReasonClientPinned = autoexclude.ReasonClientPinned
)

// autoExclude is the process-wide adaptive decryption-exclusion cache. It is
// consulted on the proxy hot path ONLY for sessions whose matched rule opts into
// fail-open (resolveFailOpen), and populated ONLY from those sessions' qualifying
// inspect failures — so a deployment with no fail-open profile keeps an inert,
// empty cache and byte-identical behavior. Built with the documented PAN-OS-
// aligned defaults (12h TTL, 1h pinned TTL, 2 distinct-client confirm-count); the
// posture is surfaced read-only via the /api/decryption-exclusions Stats block.
// Tests swap this singleton (swapAutoExclude) for isolation.
var autoExclude = autoexclude.New(autoexclude.Config{})
