package main

// controlplane_delta.go — T3 P1: CP-side blocklist delta ring.
//
// The blocklist is the dominant ConfigSnapshot slice (~95%+ of the wire bytes at
// enterprise scale: a 2 M-host list is ~60 MiB, everything else is KBs). On each
// config publish the CP records the blocklist {added, removed} between the
// previous and new published version into a bounded ring, so a lagging DP can
// catch up incrementally via GetConfigDelta (slice 4) — shipping a small delta
// plus the tiny non-blocklist remainder instead of re-pulling the whole
// snapshot. Only the blocklist is delta-encoded in P1; the other slices are
// small and ride along in full.
//
// Bounds (red-team-derived — the ring must never itself become a memory-DoS or
// an unbounded-retention vector):
//   - entry count (maxDeltaRingEntries) and TOTAL retained bytes
//     (maxDeltaRingBytes) — oldest entries evicted first past either bound;
//   - a SINGLE version whose delta exceeds maxSingleDeltaBytes (e.g. an admin
//     replaced the whole list) is stored as a RESYNC MARKER: its host slices are
//     dropped and a DP that needs to traverse it falls back to a full pull. A
//     giant delta is never cheaper than a full snapshot, so this loses nothing.
//
// The ring stores a CONTIGUOUS chain of per-version deltas (base = target-1). A
// non-contiguous publish (concurrent reorder, HA-promotion version jump) CLEARS
// the ring — the chain is no longer valid, so every DP older than the newest
// entry correctly gets a resync until the chain rebuilds. Correctness over
// bytes: a spurious resync only costs one full pull.

import (
	"sync"

	"github.com/KidCarmi/Culvert/internal/blocklist"
)

const (
	// maxDeltaRingEntries bounds how many recent versions the ring retains.
	maxDeltaRingEntries = 256
	// maxDeltaRingBytes bounds the TOTAL retained delta payload across all
	// entries (added+removed host bytes). Independent of the entry count so a
	// burst of large deltas cannot balloon CP memory.
	maxDeltaRingBytes = 32 << 20 // 32 MiB
	// maxSingleDeltaBytes: a single version's delta above this is stored as a
	// resync marker (host slices dropped). Kept well under maxDeltaRingBytes so
	// one huge delta cannot dominate the ring.
	maxSingleDeltaBytes = 8 << 20 // 8 MiB
)

// blocklistDelta is one version's blocklist change relative to the previous
// published version.
type blocklistDelta struct {
	Version int64    `json:"version"` // target version this delta produces
	Base    int64    `json:"base"`    // version it applies on top of (Version-1)
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	FP      string   `json:"fp"`     // synced fingerprint of the blocklist AT Version
	Epoch   int64    `json:"epoch"`  // issuing CP's fencing epoch at publish time
	Resync  bool     `json:"resync"` // true ⇒ delta too large; DP must full-resync to reach Version
	bytes   int      // retained payload size (added+removed), for the byte budget
}

// blocklistDeltaRing is a bounded, contiguous ring of per-version blocklist
// deltas. The zero value is ready to use. Safe for concurrent use.
type blocklistDeltaRing struct {
	mu         sync.Mutex
	entries    []blocklistDelta // ascending Version, contiguous (entries[i+1].Version == entries[i].Version+1)
	totalBytes int
}

// hostSliceBytes approximates the retained size of a host slice.
func hostSliceBytes(hosts []string) int {
	n := 0
	for _, h := range hosts {
		n += len(h) + 1
	}
	return n
}

// record appends the delta for a newly published version. oldHosts/newHosts are
// the previous and new blocklists; base/target are their versions; fp is the
// synced fingerprint of newHosts (advertised as the target a DP must reach);
// epoch is the issuing CP's fencing epoch. A non-contiguous target clears the
// ring first (the existing chain is no longer valid).
func (r *blocklistDeltaRing) record(base, target int64, oldHosts, newHosts []string, fp string, epoch int64) {
	added, removed := diffHosts(oldHosts, newHosts)
	d := blocklistDelta{Version: target, Base: base, FP: fp, Epoch: epoch}
	d.bytes = hostSliceBytes(added) + hostSliceBytes(removed)
	if d.bytes > maxSingleDeltaBytes {
		// Too large to retain; a DP traversing this version resyncs.
		d.Resync = true
		d.bytes = 0
	} else {
		d.Added, d.Removed = added, removed
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// Contiguity: the chain must be gap-free. A non-contiguous target (base does
	// not match the newest retained version) invalidates the existing chain.
	if len(r.entries) > 0 && base != r.entries[len(r.entries)-1].Version {
		r.entries = nil
		r.totalBytes = 0
	}
	r.entries = append(r.entries, d)
	r.totalBytes += d.bytes
	r.evictLocked()
}

// evictLocked drops oldest entries until BOTH bounds are satisfied. Called with
// r.mu held.
func (r *blocklistDeltaRing) evictLocked() {
	for len(r.entries) > maxDeltaRingEntries || (r.totalBytes > maxDeltaRingBytes && len(r.entries) > 1) {
		r.totalBytes -= r.entries[0].bytes
		r.entries = r.entries[1:]
	}
	if r.totalBytes < 0 {
		r.totalBytes = 0
	}
}

// chain returns the ordered deltas that advance a DP from base to the newest
// retained version. ok is false when base is older than the oldest retained
// version (a gap — the DP must full-resync). An empty chain with ok=true means
// the DP is already current (base == newest). If ANY delta in the range is a
// resync marker, ok is false (the DP cannot traverse it incrementally).
func (r *blocklistDeltaRing) chain(base int64) (chain []blocklistDelta, latest int64, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		return nil, 0, false
	}
	oldest := r.entries[0]
	newest := r.entries[len(r.entries)-1]
	latest = newest.Version
	if base == newest.Version {
		return nil, latest, true // already current
	}
	// base+1 must be retained (base >= oldest.Base). oldest.Base is the version
	// the oldest retained delta applies on top of; a DP at exactly that version
	// can traverse the whole ring.
	if base < oldest.Base || base > newest.Version {
		return nil, latest, false
	}
	for i := range r.entries {
		if r.entries[i].Base < base {
			continue
		}
		if r.entries[i].Resync {
			return nil, latest, false
		}
		// Copy out the header + slice references (callers only read).
		chain = append(chain, r.entries[i])
	}
	return chain, latest, true
}

// stats returns the retained entry count, total bytes, and version span for
// observability.
func (r *blocklistDeltaRing) stats() (entries, bytes int, oldest, newest int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entries = len(r.entries)
	bytes = r.totalBytes
	if entries > 0 {
		oldest = r.entries[0].Version
		newest = r.entries[entries-1].Version
	}
	return entries, bytes, oldest, newest
}

// diffHosts returns the hosts added and removed going from prev to next. Both
// inputs are treated as sets (deduped). Order of the result is unspecified.
func diffHosts(prev, next []string) (added, removed []string) {
	oldSet := make(map[string]struct{}, len(prev))
	for _, h := range prev {
		oldSet[h] = struct{}{}
	}
	newSet := make(map[string]struct{}, len(next))
	for _, h := range next {
		newSet[h] = struct{}{}
	}
	for h := range newSet {
		if _, ok := oldSet[h]; !ok {
			added = append(added, h)
		}
	}
	for h := range oldSet {
		if _, ok := newSet[h]; !ok {
			removed = append(removed, h)
		}
	}
	return added, removed
}

// blocklistSyncedFingerprint returns the synced fingerprint the CP advertises
// for a blocklist. Thin wrapper over the engine so callers in package main read
// naturally.
func blocklistSyncedFingerprint(hosts []string) string {
	return blocklist.FeedSetFingerprint(hosts)
}
