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

// ApplyDelta adds and removes hosts in place. A removed host that is an admin
// MANUAL block is left in ENFORCEMENT (invariant 1) but is still dropped from the
// synced fingerprint (invariant 2 — the CP's authoritative set dropped it).
// Normalization mirrors Add/ReplaceFeedEntries.
//
// Two properties are load-bearing:
//
//   - DEDUP / at-most-once (a CORRECTNESS control, not an optimization). The
//     syncedFP is a symmetric-difference (XOR-toggle) model; the enforcement maps
//     are idempotent set-assignment. The two agree ONLY when each token is applied
//     at most once. A corrupted/duplicated delta that toggled a token an EVEN
//     number of times would cancel in the fingerprint while the map changed once —
//     a SILENT divergence that the post-apply fingerprint comparison could not
//     catch (proven by adversarial review). Deduping added/removed here (a host in
//     BOTH ends up added — re-add wins) forces at-most-once, so any spurious change
//     is a VISIBLE fingerprint delta → caught → full resync, never silent.
//
//   - HASH-BEFORE-LOCK. The O(N) SHA-256 fingerprint folding runs OUTSIDE the
//     write lock into a local accumulator (XOR is commutative/associative), and
//     only a single 32-byte XOR merge + the map splice run under b.mu — mirroring
//     ReplaceFeedEntries' discipline so a large delta never stalls the IsBlocked
//     hot path for the duration of the hashing.
//
// The fingerprint is NOT an authenticity control (it is linear over the token
// hashes — trivially forgeable by a party that controls delta content); the
// delta path's tamper-resistance rests on mTLS + the epoch fence. The fingerprint
// detects transport corruption, missed/duplicated deltas, and misapplication.
func (b *Store) ApplyDelta(added, removed []string) {
	addSet := make(map[string]struct{}, len(added))
	for _, h := range added {
		if tok, ok := normDeltaHost(h); ok {
			addSet[tok] = struct{}{}
		}
	}
	remSet := make(map[string]struct{}, len(removed))
	for _, h := range removed {
		tok, ok := normDeltaHost(h)
		if !ok {
			continue
		}
		if _, dup := addSet[tok]; dup {
			continue // host in both sets → re-add wins, drop from removed
		}
		remSet[tok] = struct{}{}
	}

	// Fold the fingerprint delta outside the lock.
	var acc [32]byte
	for tok := range remSet {
		fpXOR(&acc, tok)
	}
	for tok := range addSet {
		fpXOR(&acc, tok)
	}

	b.mu.Lock()
	for i := range b.syncedFP {
		b.syncedFP[i] ^= acc[i]
	}
	for tok := range remSet {
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
	for tok := range addSet {
		if strings.HasPrefix(tok, "*.") {
			b.wildcards[tok[1:]] = true
		} else {
			b.exact[tok] = true
		}
	}
	b.mu.Unlock()
}
