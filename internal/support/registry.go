package support

import (
	"fmt"
	"sort"
	"sync"
)

// registry is the process-wide collector set. Collectors register from their
// owning package at init/startup, mirroring register*Routes.
var (
	regMu    sync.RWMutex
	registry = map[string]Collector{} // keyed by CollectorMeta.ID
	regPaths = map[string]string{}    // Path → ID, to reject duplicate paths
)

// Register adds a collector. Duplicate ID or Path is a wiring bug (fatal at
// startup, not a runtime condition) — it panics, matching the repo's
// route/config-surface parity discipline.
func Register(c Collector) {
	regMu.Lock()
	defer regMu.Unlock()
	m := c.Meta()
	if m.ID == "" || m.Path == "" {
		panic("support.Register: collector has empty ID or Path")
	}
	if _, dup := registry[m.ID]; dup {
		panic(fmt.Sprintf("support.Register: duplicate collector ID %q", m.ID))
	}
	if other, dup := regPaths[m.Path]; dup {
		panic(fmt.Sprintf("support.Register: path %q claimed by both %q and %q", m.Path, other, m.ID))
	}
	registry[m.ID] = c
	regPaths[m.Path] = m.ID
}

// Collectors returns the registered collectors sorted by ID (deterministic
// ordering — the spec requires collector-ID-ascending section order).
func Collectors() []Collector {
	regMu.RLock()
	defer regMu.RUnlock()
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Collector, 0, len(ids))
	for _, id := range ids {
		out = append(out, registry[id])
	}
	return out
}

// resetRegistryForTest clears the registry so a test can register a controlled
// set in isolation (mirrors swapAutoExclude). Returns a restore func.
func resetRegistryForTest() func() {
	regMu.Lock()
	prevReg, prevPaths := registry, regPaths
	registry, regPaths = map[string]Collector{}, map[string]string{}
	regMu.Unlock()
	return func() {
		regMu.Lock()
		registry, regPaths = prevReg, prevPaths
		regMu.Unlock()
	}
}
