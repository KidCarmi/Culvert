package blocklist

// delta.go — T3 P1: incremental delta application + a wire-fed synced fingerprint.
//
// The cluster delta-sync path (CP→DP) ships {added, removed} host sets between
// config versions instead of the full list. ApplyDelta mutates the enforcement
// maps IN PLACE (no full rebuild → no build-then-swap memory peak) and preserves
// the two invariants the red-team required:
//
//  1. A delta MUST NEVER remove an admin-managed MANUAL block. b.manual is the
//     attribution set for hosts an operator added locally; ReplaceFeedEntries
//     already re-injects it on every apply (PR #249). ApplyDelta mirrors that:
//     a `removed` entry that is in b.manual is skipped for ENFORCEMENT — but is
//     still XORed OUT of the synced fingerprint (invariant 2), because the CP's
//     authoritative set no longer contains it. Enforcement (with manual
//     protection) and the synced fingerprint (pure CP intent) are decoupled.
//
//  2. The drift-detection control is a SYNCED FINGERPRINT: a 256-bit
//     XOR-of-SHA256 over the CP-AUTHORITATIVE host set, fed ONLY by CP-supplied
//     data. It lets a DP confirm it converged to exactly the CP version it
//     applied a delta toward, independent of any DP-local manual blocks. Two
//     properties make it the right tool here:
//       - order-independent (XOR is commutative) — the CP and DP need not agree
//         on iteration order;
//       - incrementally maintainable in O(delta) — XOR is its own inverse, so a
//         remove is XORed out and an add XORed in, with no full-set storage and
//         no O(N log N) sort under the blocklist lock.
//     It is NOT a security/authenticity control (a semi-trusted CP asserts the
//     target fingerprint; authenticity is the mTLS + epoch fence + signing,
//     tracked separately). It detects transport corruption, missed/duplicated
//     deltas, and misapplication — any of which forces a full resync rather than
//     silently persisting divergent state.
//
// Why XOR and not a sorted digest: the DP must maintain the fingerprint of the
// CP's set WITHOUT re-deriving it from its own enforcement maps (which carry
// DP-local manual blocks the CP set never had). A sorted digest cannot be
// updated incrementally and, recomputed over enforcement-minus-manual, breaks
// whenever a manual block overlaps the CP feed. An XOR accumulator fed purely
// from the wire stream sidesteps both problems.

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// normDeltaHost normalizes a host token to the canonical form used by every
// blocklist ingest path (Add / ReplaceFeedEntries / AddManual): lower-case,
// trimmed. Wildcards keep their full "*.example.com" token. Returns ok=false
// for an empty token so callers can skip it.
func normDeltaHost(h string) (string, bool) {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return "", false
	}
	return h, true
}

// fpXOR folds one host token into a 256-bit XOR-of-SHA256 accumulator. XOR is
// commutative (order-independent) and its own inverse (a later XOR of the same
// token removes it), which is exactly what incremental delta maintenance needs.
func fpXOR(acc *[32]byte, token string) {
	sum := sha256.Sum256([]byte(token))
	for i := range acc {
		acc[i] ^= sum[i]
	}
}

// feedSetFingerprint computes the synced fingerprint over a full host list.
// Used on the CP side to advertise the target fingerprint for a version, and on
// the DP side by ReplaceFeedEntries to establish ground truth on a full apply.
// Both sides MUST feed identically-normalized tokens (normDeltaHost) so the
// fingerprints are comparable.
func feedSetFingerprint(hosts []string) [32]byte {
	var acc [32]byte
	for _, h := range hosts {
		if tok, ok := normDeltaHost(h); ok {
			fpXOR(&acc, tok)
		}
	}
	return acc
}

// FeedSetFingerprint returns the hex synced fingerprint of a host list. The CP
// calls this over the BlockedHosts it publishes to advertise the target a DP
// must converge to. It is a pure function of the (normalized) set — no Store
// state involved.
func FeedSetFingerprint(hosts []string) string {
	fp := feedSetFingerprint(hosts)
	return hex.EncodeToString(fp[:])
}

// SyncedFingerprint returns the hex fingerprint of the CP-authoritative set this
// Store has currently applied. A DP compares this to the CP's advertised target
// after a delta apply; a mismatch forces a full resync. Decoupled from
// enforcement + DP-local manual by construction (fed only by CP data).
func (b *Store) SyncedFingerprint() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return hex.EncodeToString(b.syncedFP[:])
}

// ApplyDelta adds and removes hosts in place. Removes are processed first so an
// entry appearing in both sets ends up ADDED (re-add wins), matching the
// feed-refresh precedence. A removed host that is an admin MANUAL block is left
// in ENFORCEMENT (invariant 1) but is still XORed out of the synced fingerprint
// (invariant 2 — the CP's authoritative set dropped it). Normalization mirrors
// Add/ReplaceFeedEntries.
//
// The synced fingerprint is maintained assuming a WELL-FORMED delta: each
// removed host was present in the base version's synced set and each added host
// absent from it (the CP computes added/removed as true set differences between
// consecutive versions, and the strict base_version==KnownVersion gate on the
// DP admits only gap-free, in-order deltas). A malformed/duplicated delta can
// double-toggle a token and corrupt the fingerprint — which is caught by the
// post-apply fingerprint comparison and forces a resync, never silent
// divergence.
func (b *Store) ApplyDelta(added, removed []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, h := range removed {
		tok, ok := normDeltaHost(h)
		if !ok {
			continue
		}
		// The CP-authoritative set no longer contains this host — drop it from
		// the synced fingerprint regardless of manual protection.
		fpXOR(&b.syncedFP, tok)
		if b.manual[tok] {
			continue // never delete an admin manual block from ENFORCEMENT
		}
		if strings.HasPrefix(tok, "*.") {
			delete(b.wildcards, tok[1:])
		} else {
			delete(b.exact, tok)
		}
		if b.feedSrc != nil {
			delete(b.feedSrc, tok)
		}
	}
	for _, h := range added {
		tok, ok := normDeltaHost(h)
		if !ok {
			continue
		}
		fpXOR(&b.syncedFP, tok)
		if strings.HasPrefix(tok, "*.") {
			b.wildcards[tok[1:]] = true
		} else {
			b.exact[tok] = true
		}
	}
}
