package blocklist

// delta.go — T3 P1: incremental delta application + a canonical content hash.
//
// The cluster delta-sync path (CP→DP) ships {added, removed} host sets between
// config versions instead of the full list. ApplyDelta mutates the enforcement
// maps IN PLACE (no full rebuild → no build-then-swap memory peak) and preserves
// the two invariants the red-team required:
//
//  1. A delta MUST NEVER remove an admin-managed MANUAL block. b.manual is the
//     attribution set for hosts an operator added locally; ReplaceFeedEntries
//     already re-injects it on every apply (PR #249). ApplyDelta mirrors that:
//     a `removed` entry that is in b.manual is skipped.
//  2. The content hash for drift detection is a CANONICAL, deterministic digest
//     of the enforcement set, so a DP can confirm it converged to exactly the CP
//     version it applied a delta toward — a missed/misapplied/reordered delta is
//     caught and forces a full resync rather than silently persisting.

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// ApplyDelta adds and removes hosts in place. Removes are processed first so an
// entry appearing in both sets ends up ADDED (re-add wins), matching the
// feed-refresh precedence. A removed host that is an admin MANUAL block is left
// in place (invariant 1). Normalization mirrors Add/ReplaceFeedEntries.
func (b *Store) ApplyDelta(added, removed []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, h := range removed {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || b.manual[h] {
			continue // never delete an admin manual block
		}
		if strings.HasPrefix(h, "*.") {
			delete(b.wildcards, h[1:])
		} else {
			delete(b.exact, h)
		}
		if b.feedSrc != nil {
			delete(b.feedSrc, h)
		}
	}
	for _, h := range added {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			b.wildcards[h[1:]] = true
		} else {
			b.exact[h] = true
		}
	}
}

// ContentHash returns a canonical SHA-256 over the enforcement set (exact +
// wildcards), independent of insertion order. Used for cluster drift detection:
// after applying a delta, a DP compares this to the version's advertised hash;
// a mismatch triggers a full resync. It is NOT a security/authenticity control
// (the CP asserts the target hash — authenticity is the mTLS + epoch fence, and
// signing is a separate cross-cutting hardening); it detects transport
// corruption, missed deltas, and misapplication.
//
// The host slice is copied under the read lock and then sorted+hashed OUTSIDE
// the lock so the O(N log N) work never stalls the IsBlocked hot path.
func (b *Store) ContentHash() string {
	b.mu.RLock()
	hosts := make([]string, 0, len(b.exact)+len(b.wildcards))
	for h := range b.exact {
		hosts = append(hosts, h)
	}
	for w := range b.wildcards {
		hosts = append(hosts, "*"+w) // wildcards are keyed by ".example.com" → "*.example.com"
	}
	b.mu.RUnlock()

	sort.Strings(hosts)
	sum := sha256.New()
	for _, h := range hosts {
		_, _ = sum.Write([]byte(h))
		_, _ = sum.Write([]byte{0}) // separator: disambiguate "a"+"bc" from "ab"+"c"
	}
	return hex.EncodeToString(sum.Sum(nil))
}
