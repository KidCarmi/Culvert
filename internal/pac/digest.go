package pac

// digest.go — the 2F-B identity model (contract C8). Three DISTINCT digests,
// each a canonical SHA-256 over length-framed JSON with sorted keys and no
// volatile fields:
//
//   - ProfileSpecDigest: the profile CONFIGURATION only (revision excluded) —
//     the identity the authoritative commit point and every reconciliation
//     decision are made on;
//   - PoolDigest: the referenced-pool snapshot — bound into a DIRECT
//     confirmation challenge, never consulted to decide whether a commit
//     happened (a later pool change must not ambiguate a committed profile);
//   - ArtifactDigest: the compiler output (CompileProfile / EvaluatePublish),
//     informational and challenge-bound only.
//
// Neither file mtimes nor artifact digests ever decide an outcome.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// canonicalJSON re-encodes v through an untyped value so object keys come out
// sorted (encoding/json sorts map keys) and struct field order cannot leak
// into the digest.
func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

// canonicalDigest frames the canonical bytes with a kind tag and their length
// so distinct kinds (and prefixes) can never collide.
func canonicalDigest(kind string, v any) string {
	b, err := canonicalJSON(v)
	if err != nil {
		return ""
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%d|", kind, len(b)) // hash.Hash never errors
	_, _ = h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// ProfileSpecDigest is the configuration identity of a profile: every field
// except the optimistic-concurrency Revision (volatile by definition).
func ProfileSpecDigest(p Profile) string {
	p.Revision = 0
	if p.Rules == nil {
		p.Rules = []Rule{}
	}
	return canonicalDigest("pac-profile-spec/v1", p)
}

// ReferencedPools returns the pools a profile can route to — its PoolID and
// every rule PoolID — as an ID-sorted snapshot (unknown IDs are omitted).
func ReferencedPools(p Profile, pools map[string]Pool) []Pool {
	seen := map[string]bool{}
	var out []Pool
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		if pool, ok := pools[id]; ok {
			seen[id] = true
			out = append(out, pool)
		}
	}
	add(p.PoolID)
	for i := range p.Rules {
		add(p.Rules[i].PoolID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if out == nil {
		out = []Pool{}
	}
	return out
}

// PoolDigest is the identity of a referenced-pool snapshot.
func PoolDigest(pools []Pool) string {
	sorted := append([]Pool(nil), pools...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	if sorted == nil {
		sorted = []Pool{}
	}
	return canonicalDigest("pac-pools/v1", sorted)
}

// CanonicalDigest exposes the framed canonical digest for callers that bind
// other structures (the DIRECT confirmation challenge in package main).
func CanonicalDigest(kind string, v any) string { return canonicalDigest(kind, v) }
