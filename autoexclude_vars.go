package main

// autoexclude_vars.go — package-main glue for the adaptive decryption-exclusion
// cache, which lives in internal/autoexclude (mirrors the decryptprofile_vars.go
// shim over internal/decryptprofile). The cache is a VOLATILE, in-memory learned
// set — never persisted, never synced CP→DP, and therefore off every config
// surface. main owns the singleton + the hot-path resolvers (resolveFailOpen /
// recordAutoExclude / classify{Origin,Client}InspectFailure in
// autoexclude_resolve.go) + the admin API + UI; the engine exposes only the store.

import (
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
)

// AutoExcludeCache is the learned-exclusion store (engine type autoexclude.Cache).
type AutoExcludeCache = autoexclude.Cache

// AutoExcludeReason classifies why a host was learned (engine type).
type AutoExcludeReason = autoexclude.Reason

// Re-export the learn reasons so the hot-path classifier and metrics stay on the
// unqualified names.
const (
	autoExReasonClientCert   = autoexclude.ReasonClientCertRequired
	autoExReasonUnsupported  = autoexclude.ReasonUnsupportedParams
	autoExReasonClientPinned = autoexclude.ReasonClientPinned
)

// autoExcludeCache holds the process-wide adaptive decryption-exclusion cache
// behind an atomic pointer (F9a). The pointer is read locklessly on the proxy hot
// path (Observe/Contains), so a plain package var — never a data race TODAY only
// because it is never reassigned at runtime — would become a textbook race the
// moment any feature reconfigures the cache at runtime (e.g. F10 per-profile
// tunables via reload). An atomic.Pointer makes the hot-path read a single-word
// atomic Load (no measurable cost) and the swap a race-free Store, so runtime
// reconfiguration is safe by construction. Access ONLY via autoExclude() (read)
// and setAutoExclude() (swap) — never touch the pointer directly off those.
var autoExcludeCache atomic.Pointer[AutoExcludeCache]

func init() {
	// Built with the documented PAN-OS-aligned defaults (12h TTL, 1h pinned TTL, 2
	// distinct-client confirm-count); the posture is surfaced read-only via the
	// /api/decryption-exclusions Stats block. A deployment with no fail-open profile
	// keeps this cache inert and empty (byte-identical behavior).
	autoExcludeCache.Store(autoexclude.New(autoexclude.Config{}))
}

// autoExclude returns the current cache. This is the hot-path read (a single
// atomic Load); it is consulted ONLY for sessions whose matched rule opts into
// fail-open (resolveFailOpen) and populated ONLY from those sessions' qualifying
// inspect failures.
func autoExclude() *AutoExcludeCache { return autoExcludeCache.Load() }

// setAutoExclude atomically swaps the singleton. It is the ONLY writer — used by
// tests for isolation (swapAutoExclude) and reserved for a future runtime-reconfig
// path (F10). A concurrent hot-path autoExclude() read sees either the old or the
// new cache, never a torn pointer.
func setAutoExclude(c *AutoExcludeCache) { autoExcludeCache.Store(c) }
