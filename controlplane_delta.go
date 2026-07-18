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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/KidCarmi/Culvert/internal/blocklist"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	d := blocklistDelta{Version: target, Base: base, FP: fp, Epoch: epoch}
	// A nil oldHosts means there was NO prior published snapshot to diff against
	// (fresh CP start, or an HA-promoted standby whose ConfigStore.snap was never
	// seeded). Diffing nil→newHosts would record a bogus "add-everything" delta
	// whose Base equals the seeded version — normally unreachable, but on a
	// seed==DP-version collision (clock rollback / HA promotion) a DP could match
	// it and apply a redundant full add. Mark it a resync marker instead so any DP
	// at that base cleanly full-syncs. (oldHosts is non-nil — []string{} — after
	// any real publish, so a genuinely-empty published blocklist still deltas.)
	if oldHosts == nil {
		d.Resync = true
	} else {
		added, removed := diffHosts(oldHosts, newHosts)
		d.bytes = hostSliceBytes(added) + hostSliceBytes(removed)
		if d.bytes > maxSingleDeltaBytes {
			// Too large to retain; a DP traversing this version resyncs.
			d.Resync = true
			d.bytes = 0
		} else {
			d.Added, d.Removed = added, removed
		}
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

// newestFP returns the fingerprint of the newest retained version, and whether
// that version equals want. Used by GetConfigDelta's unchanged path to honor the
// DP's KnownFP without an O(N) re-hash of the full list on every idle poll.
func (r *blocklistDeltaRing) newestFP(want int64) (fp string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		return "", false
	}
	newest := r.entries[len(r.entries)-1]
	if newest.Version != want {
		return "", false
	}
	return newest.FP, true
}

// diffHosts returns the hosts added and removed going from prev to next. Both
// inputs are NORMALIZED (lower/trim) and treated as sets (deduped) so the diff,
// the advertised fingerprint (feedSetFingerprint, same normalization), and the DP
// apply (ApplyDelta, same normalization) share ONE normalization contract — not a
// hidden dependency on every caller passing a pre-normalized bl.List(). Order of
// the result is unspecified.
func diffHosts(prev, next []string) (added, removed []string) {
	norm := func(hosts []string) map[string]struct{} {
		m := make(map[string]struct{}, len(hosts))
		for _, h := range hosts {
			if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
				m[h] = struct{}{}
			}
		}
		return m
	}
	oldSet := norm(prev)
	newSet := norm(next)
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

// applyBlocklistDeltaSnapshot applies a delta-mode reply on the DP: it advances
// the blocklist incrementally via bl.ApplyDelta, verifies the result converged
// to the CP's advertised target fingerprint, then applies the non-blocklist
// remainder wholesale. The caller MUST have already epoch-fenced (dpObserveEpoch
// on reply.Epoch) and validated the remainder's caps — this function does the
// blocklist-substituting apply only.
//
// On a fingerprint mismatch it returns an error WITHOUT applying the remainder,
// so only the blocklist is left mutated (and the caller's fall-through to a full
// resync heals it via the wholesale ReplaceFeedEntries) — the other stores are
// never advanced to a version whose blocklist we could not verify. This is the
// "detect divergence → resync, never silently persist it" contract.
func applyBlocklistDeltaSnapshot(remainder ConfigSnapshot, chain []blocklistDelta, targetFP string) error {
	for i := range chain {
		bl.ApplyDelta(chain[i].Added, chain[i].Removed)
	}
	// Delta-path memory-DoS cap (mirrors validateConfigSnapshot's BlockedHosts cap
	// on the full path). The added hosts ride in the chain, NOT in the remainder's
	// BlockedHosts, so the full-path cap would evaluate to 0 and pass — a buggy or
	// compromised CP could push millions of hosts via deltas past the 2 M ceiling
	// and OOM the DP. Enforce the ceiling on the realized set. Reject BEFORE Save so
	// an over-cap set is never persisted; the caller full-resyncs (the CP's own
	// commit-time cap keeps the full snapshot within bounds).
	if n := bl.Count(); n > maxSnapBlockedHosts {
		return fmt.Errorf("blocklist delta apply exceeds cap: %d > %d", n, maxSnapBlockedHosts)
	}
	// Verify convergence BEFORE persisting: on drift, do not durably write an
	// unverified blocklist to disk (the in-memory mutation is healed by the
	// caller's full resync; a persisted bad set would outlive the process).
	if got := bl.SyncedFingerprint(); got != targetFP {
		return fmt.Errorf("blocklist drift after delta apply (have %s, want %s)", got, targetFP)
	}
	bl.Save()
	// Everything except the blocklist, in the same order as the full path.
	applySnapshotTrafficExceptBlocklist(remainder)
	applySnapshotClusterRuntime(remainder)
	if err := syncSnapshotIdPProfiles(remainder); err != nil {
		return fmt.Errorf("idp sync: %w", err)
	}
	applySnapshotExtendedState(remainder)
	return nil
}

// gcDeltaRemainderCache shares ONE marshaled remainder (target snapshot minus the
// host-scale blocklist) across all DPs polling the same version, so a config
// change does not force N per-DP marshals of the non-blocklist slices (threat
// feeds + URL-category hosts are still host-scale) the way the full path's
// gcMarshalCache avoids re-marshaling the whole snapshot.
var gcDeltaRemainderCache deltaRemainderCache

type deltaRemainderCache struct {
	mu       sync.Mutex
	version  int64
	caFP     string
	enrolled bool
	bytes    json.RawMessage
}

// serve returns the marshaled remainder for (version, caFP, enrolled), marshaling
// (and caching) once per change. The enrolled variant dominates (a DP polls delta
// only after it holds a version, i.e. post-enrollment); the rare unenrolled
// bootstrap variant occasionally recomputes. Lock order is cache→store.
func (c *deltaRemainderCache) serve(version int64, caFP string, enrolled bool) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bytes != nil && c.version == version && c.caFP == caFP && c.enrolled == enrolled {
		return c.bytes, nil
	}
	snap := globalConfigStore.Get()
	snap.BlockedHosts = nil // the blocklist rides as the delta chain
	if caFP != "" {
		snap.CAFingerprint = caFP
	}
	if !enrolled {
		redactUnenrolledSnapshot(&snap)
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal remainder: %v", err)
	}
	c.version, c.caFP, c.enrolled, c.bytes = version, caFP, enrolled, b
	return b, nil
}

func (c *deltaRemainderCache) reset() {
	c.mu.Lock()
	c.version, c.caFP, c.enrolled, c.bytes = 0, "", false, nil
	c.mu.Unlock()
}

// chainPayloadBytes approximates the wire size of a delta chain's host slices.
func chainPayloadBytes(chain []blocklistDelta) int {
	n := 0
	for i := range chain {
		n += hostSliceBytes(chain[i].Added) + hostSliceBytes(chain[i].Removed)
	}
	return n
}

// GetConfigDelta serves the incremental blocklist catch-up path (T3 P1). A DP
// reports the blocklist version it holds; the CP returns the ordered {added,
// removed} chain to the newest version plus the non-blocklist remainder, or a
// resync directive when the DP is too far behind to be caught up incrementally.
// The blocklist is ~95%+ of the snapshot bytes at scale, so this turns a routine
// config change from a full ~60 MiB re-pull into a few-KB delta. (The remainder
// is NOT tiny — it still carries the host-scale threat-feed and URL-category
// slices; it is cached and shared across the fleet, and the assembled reply is
// frame-bounded below.)
//
// Same guards as GetConfig: refuse when no valid config is servable; throttle
// unenrolled callers per peer IP (the delta reveals blocklist changes); redact
// secrets from the remainder for unenrolled callers. Epoch-fenced via the reply
// Epoch (the DP ratchets it exactly like a full snapshot).
func (s *controlPlaneServer) GetConfigDelta(ctx context.Context, req json.RawMessage) (json.RawMessage, error) {
	if ok, reason := globalConfigStore.ServableConfig(); !ok {
		return nil, status.Errorf(codes.Unavailable, "control plane has no valid config to distribute: %s", reason)
	}
	var dreq getConfigDeltaRequest
	_ = json.Unmarshal(req, &dreq) // tolerate empty/garbage → KnownVersion 0 → resync

	enrolled := callerIsEnrolledNode(ctx)
	if !enrolled {
		if ip := peerSourceIP(ctx); ip != "" && !unenrolledConfigPullAllow(ip) {
			return nil, status.Errorf(codes.ResourceExhausted, "unenrolled config-pull rate exceeded; enroll to poll without limit")
		}
	}

	epoch := globalHA.CurrentEpoch()
	cur := globalConfigStore.Version()
	if dreq.KnownVersion == cur {
		// Idle-drift detection: if the DP reports a fingerprint for the current
		// version that disagrees with ours, it has drifted (e.g. a half-applied
		// prior delta or on-disk corruption) — force a resync instead of confirming
		// "unchanged". Cheap: read the ring's newest FP, no O(N) re-hash.
		if dreq.KnownFP != "" {
			if fp, ok := globalConfigStore.deltaRing.newestFP(cur); ok && fp != dreq.KnownFP {
				return json.Marshal(getConfigDeltaReply{Mode: "resync", TargetVersion: cur, Epoch: epoch})
			}
		}
		return json.Marshal(getConfigDeltaReply{Mode: "unchanged", TargetVersion: cur, Epoch: epoch})
	}

	chain, latest, ok := globalConfigStore.deltaRing.chain(dreq.KnownVersion)
	if !ok || latest != cur {
		// Gap, resync marker, or the ring lags the store version (the brief
		// record-after-unlock window, or a non-contiguous publish). Full resync.
		return json.Marshal(getConfigDeltaReply{Mode: "resync", TargetVersion: cur, Epoch: epoch})
	}

	caFP := globalClusterCA.CACertFingerprint()
	remainder, err := gcDeltaRemainderCache.serve(cur, caFP, enrolled)
	if err != nil {
		return nil, err
	}
	// Frame bound: the assembled reply (chain host slices + remainder) must fit the
	// CP↔DP frame. Estimate BEFORE marshaling the full reply so an oversized
	// catch-up degrades to a resync (a full pull) instead of allocating a >128 MiB
	// blob that gRPC would reject anyway. The chain is ring-bounded (≤32 MiB) and
	// the remainder ≤ the full snapshot; their sum can exceed the frame.
	if chainPayloadBytes(chain)+len(remainder) > maxSnapshotWireBytes {
		return json.Marshal(getConfigDeltaReply{Mode: "resync", TargetVersion: cur, Epoch: epoch})
	}
	targetFP := ""
	if n := len(chain); n > 0 {
		targetFP = chain[n-1].FP
	}
	return json.Marshal(getConfigDeltaReply{
		Mode:          "delta",
		BaseVersion:   dreq.KnownVersion,
		TargetVersion: cur,
		Epoch:         epoch,
		Deltas:        chain,
		TargetFP:      targetFP,
		Remainder:     remainder,
	})
}
