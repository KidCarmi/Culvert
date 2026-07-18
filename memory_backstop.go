package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
)

// memory_backstop.go — GOMEMLIMIT soft memory backstop (panel review P0-2).
//
// Applying a large ConfigSnapshot on a Data Plane node is a build-then-swap
// operation: ReplaceFeedEntries builds the new blocklist maps while the old
// ones are still live, on top of the freshly-unmarshaled slices and the wire
// buffer. A legitimate 2 M-host snapshot peaks a few hundred MiB.
//
// SCOPE OF PROTECTION (important — do not over-claim): Go's soft memory limit
// makes the runtime GC harder as the heap approaches the limit. It reclaims
// GARBAGE — the wire buffer, the decompression buffer, the unmarshaled input
// slice once the maps are built, and the OLD maps once the swap completes. It
// CANNOT reclaim memory that is still REACHABLE, so it does not shrink the
// instant during the swap when the old maps, the new maps, and the input slice
// are all live at once (~410–470 MiB at 2 M hosts). GOMEMLIMIT therefore turns
// a transient-garbage spike into GC pressure instead of an OOM, and buys
// headroom around the reachable peak — but it is NOT a substitute for sizing a
// DP node above that reachable peak. See docs/operator/cluster-config-capacity.md
// for the minimum-memory sizing guidance at 2 M; a true bound would require a
// streaming/chunked apply that never holds both maps (a documented follow-up).
//
// initMemoryBackstop sets debug.SetMemoryLimit to ~80% of the detected
// container memory limit, UNLESS the operator already pinned GOMEMLIMIT (the Go
// runtime honors that env var itself at startup, so we must not override an
// explicit choice). If no finite container limit is detectable (host mode,
// unlimited cgroup, parse error) it is a no-op — we never guess a limit from
// total host RAM, which could throttle a legitimately large deployment.

const memoryBackstopFraction = 80 // percent of the container limit

// Outcome enums for memoryBackstopStatus.Mode, surfaced read-only via
// checkMemoryBackstop (the /api/diagnostics operator contract).
const (
	memBackstopOperatorPinned = "operator_pinned"
	memBackstopActive         = "active"
	memBackstopNotDetected    = "not_detected"
	memBackstopCapTooSmall    = "cap_too_small"
)

// memoryBackstopStatus is the outcome of the one-shot initMemoryBackstop
// decision, cached for the diagnostics handler. The zero value (Mode=="")
// means the startup probe has not run yet (e.g. a unit-test process).
type memoryBackstopStatus struct {
	Mode         string
	SoftMiB      int64  // populated only for memBackstopActive
	ContainerMiB int64  // populated for memBackstopActive and memBackstopCapTooSmall
	Pinned       string // raw operator-set GOMEMLIMIT value, only for memBackstopOperatorPinned
}

// memoryBackstopState holds the cached result of initMemoryBackstop.
// atomic.Value gives race-free reads from the diagnostics handler without
// locking, mirroring storageWritableState (diagnostics.go).
var memoryBackstopState atomic.Value

// loadMemoryBackstopStatus returns the cached startup decision, or the zero
// value if initMemoryBackstop has not run yet. Read-only; never re-probes.
func loadMemoryBackstopStatus() memoryBackstopStatus {
	if v := memoryBackstopState.Load(); v != nil {
		if s, ok := v.(memoryBackstopStatus); ok {
			return s
		}
	}
	return memoryBackstopStatus{}
}

// initMemoryBackstop wires the soft memory limit. Safe to call once at startup.
func initMemoryBackstop() {
	if v := strings.TrimSpace(os.Getenv("GOMEMLIMIT")); v != "" {
		// Operator set it explicitly; the runtime already applied it.
		logger.Printf("MemoryBackstop: GOMEMLIMIT=%s set by operator; leaving runtime limit as-is", sanitizeLog(v))
		memoryBackstopState.Store(memoryBackstopStatus{Mode: memBackstopOperatorPinned, Pinned: v})
		return
	}
	limit, ok := detectContainerMemoryLimit()
	if !ok {
		logger.Printf("MemoryBackstop: no finite container memory limit detected; soft limit not set (set GOMEMLIMIT to enable)")
		memoryBackstopState.Store(memoryBackstopStatus{Mode: memBackstopNotDetected})
		return
	}
	soft := limit / 100 * memoryBackstopFraction
	// Guard against a pathologically small cap producing a limit that would
	// GC-thrash the process to a halt.
	const minSoftLimit = 128 << 20 // 128 MiB
	if soft < minSoftLimit {
		logger.Printf("MemoryBackstop: container limit %d MiB too small for a safe soft limit; not set", limit>>20)
		memoryBackstopState.Store(memoryBackstopStatus{Mode: memBackstopCapTooSmall, ContainerMiB: limit >> 20})
		return
	}
	debug.SetMemoryLimit(soft)
	logger.Printf("MemoryBackstop: soft memory limit set to %d MiB (%d%% of the %d MiB container limit) — config-apply pressure degrades to GC, not OOM",
		soft>>20, memoryBackstopFraction, limit>>20)
	memoryBackstopState.Store(memoryBackstopStatus{Mode: memBackstopActive, SoftMiB: soft >> 20, ContainerMiB: limit >> 20})
}

// checkMemoryBackstop reports the outcome of the GOMEMLIMIT soft memory
// backstop decision made once at startup (initMemoryBackstop) as an
// OperatorContract row. Read-only — it never re-probes cgroup files or
// touches debug.SetMemoryLimit; it only reflects the cached decision so an
// admin can confirm backstop posture from the Diagnostics panel instead of
// grepping startup logs.
func checkMemoryBackstop() OperatorContractCheck {
	st := loadMemoryBackstopStatus()
	switch st.Mode {
	case memBackstopOperatorPinned:
		return OperatorContractCheck{
			Code:    "memory_backstop",
			Status:  diagOK,
			Message: fmt.Sprintf("operator-pinned GOMEMLIMIT=%s in effect (Culvert leaves it as-is)", st.Pinned),
		}
	case memBackstopActive:
		return OperatorContractCheck{
			Code:   "memory_backstop",
			Status: diagOK,
			Message: fmt.Sprintf("soft memory limit set to %d MiB (%d%% of the %d MiB detected container limit)",
				st.SoftMiB, memoryBackstopFraction, st.ContainerMiB),
		}
	case memBackstopCapTooSmall:
		return OperatorContractCheck{
			Code:           "memory_backstop",
			Status:         diagWarn,
			Message:        fmt.Sprintf("detected container memory limit (%d MiB) is too small for a safe soft backstop; none was set", st.ContainerMiB),
			OperatorAction: "Raise the container memory limit, or set GOMEMLIMIT explicitly if a smaller pinned limit is intentional.",
		}
	case memBackstopNotDetected:
		return OperatorContractCheck{
			Code:    "memory_backstop",
			Status:  diagOK,
			Message: "no finite container memory limit detected; soft backstop not set (expected outside a memory-capped container — set GOMEMLIMIT to opt in)",
		}
	default:
		return OperatorContractCheck{
			Code:    "memory_backstop",
			Status:  diagOK,
			Message: "memory backstop status unavailable — startup probe has not run",
		}
	}
}

// detectContainerMemoryLimit returns the cgroup memory limit in bytes, or
// (0,false) when none/unlimited. Handles cgroup v2 (memory.max) and v1
// (memory.limit_in_bytes). A "max" or effectively-unlimited value (the kernel
// reports unlimited as a near-int64-max sentinel) is treated as no limit.
func detectContainerMemoryLimit() (int64, bool) {
	// cgroup v2 (unified hierarchy) — the modern default.
	if b, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		if n, ok := parseCgroupMemLimit(string(b)); ok {
			return n, true
		}
		return 0, false
	}
	// cgroup v1 fallback.
	if b, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if n, ok := parseCgroupMemLimit(string(b)); ok {
			return n, true
		}
	}
	return 0, false
}

// parseCgroupMemLimit parses a cgroup memory-limit file value (v2 "memory.max"
// or v1 "memory.limit_in_bytes"). Returns (bytes,true) only for a finite,
// positive limit; the literal "max" and the kernel's unlimited sentinels yield
// (0,false). Pure — the file-reading is the caller's job so this is testable.
func parseCgroupMemLimit(raw string) (int64, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || s == "max" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || !isFiniteMemLimit(n) {
		return 0, false
	}
	return n, true
}

// isFiniteMemLimit rejects the kernel's "unlimited" sentinels. cgroup v1 reports
// unlimited as a value near max-int64 (often 0x7FFFFFFFFFFFF000); anything at or
// above this threshold is not a real cap. Also rejects non-positive values.
func isFiniteMemLimit(n int64) bool {
	const unlimitedThreshold = int64(1) << 62 // 4 EiB — no real container is this large
	return n > 0 && n < unlimitedThreshold
}
