package supportmetrics

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"math"
	"sort"
	"strconv"
)

// SchemaVersion is the governed telemetry wire-schema version for the
// support-metric registry (roadmap/M7-proactive-telemetry-plan.md
// §3.2/§3.3/§8, which fix it at 3 for the binding wire contract). It is a
// fixed constant, not derived — bump it only for a deliberate, reviewed wire
// schema change coordinated with the merged design.
const SchemaVersion = 3

// registryHashNamespace namespaces the canonical hash encoding itself
// (distinct from SchemaVersion, which versions the wire schema). Bumping it
// would change every registry_hash even if no descriptor changed — reserved
// for a future change to this hashing scheme.
const registryHashNamespace = "culvert-support-metric-registry-hash-v1"

// Hash computes the deterministic registry_hash (§8): a lowercase-hex SHA-256
// over the governed schema — SchemaVersion plus, for EVERY descriptor sorted
// by ID, (ID, Type, PrivacyClass, TelemetryEligible, bucket ladder). It is:
//
//   - stable across process restarts (pure function of the descriptor
//     values, no randomness, no wall-clock);
//   - independent of the registry's construction/iteration order (sorted
//     internally);
//   - independent of metric VALUES (Read is never called here);
//   - changed by any eligibility change, and by any change to a governed
//     bucket ladder's labels OR thresholds — Descriptor.Buckets is the SAME
//     *BucketLadder value Read evaluates against (buckets.go), so a
//     threshold edit cannot silently diverge from what the hash commits to.
//
// Every field is either drawn from a closed, code-controlled vocabulary
// (idPattern-constrained IDs, the fixed Type/PrivacyClass enum strings) or
// written through writeBucketLadder's length-prefixed / fixed-width
// encoding — never a delimiter-joined string, so no field value can forge a
// collision with its neighbor.
func (r Registry) Hash() string {
	sorted := make([]Descriptor, len(r))
	copy(sorted, r)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	h := sha256.New()
	writeField := func(s string) {
		h.Write([]byte{0x00})
		h.Write([]byte(s))
	}

	h.Write([]byte(registryHashNamespace))
	writeField(strconv.Itoa(SchemaVersion))
	for _, d := range sorted {
		writeField(d.ID)
		writeField(d.Type.String())
		writeField(d.PrivacyClass.String())
		if d.TelemetryEligible {
			writeField("1")
		} else {
			writeField("0")
		}
		writeBucketLadder(h, d.Buckets)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// writeBucketLadder writes a collision-safe, length-prefixed encoding of a
// bucket ladder (or a fixed sentinel when the descriptor has none) into h.
// Each label is prefixed with its byte length (4-byte big-endian), so
// ["a,b"] and ["a","b"] cannot encode identically; each threshold is written
// as its 8-byte IEEE754 big-endian bit pattern — fixed width, so no
// delimiter is needed and no float text-formatting ambiguity exists.
func writeBucketLadder(h hash.Hash, b *BucketLadder) {
	h.Write([]byte{0x00})
	if b == nil {
		h.Write([]byte("no-buckets"))
		return
	}
	h.Write([]byte("buckets"))
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], uint32(len(b.Labels))) // #nosec G115 -- code-defined ladder, never attacker-sized
	h.Write(u32[:])
	for _, l := range b.Labels {
		binary.BigEndian.PutUint32(u32[:], uint32(len(l))) // #nosec G115 -- code-defined label, never attacker-sized
		h.Write(u32[:])
		h.Write([]byte(l))
	}
	binary.BigEndian.PutUint32(u32[:], uint32(len(b.Thresholds))) // #nosec G115 -- code-defined ladder, never attacker-sized
	h.Write(u32[:])
	var f64 [8]byte
	for _, t := range b.Thresholds {
		binary.BigEndian.PutUint64(f64[:], math.Float64bits(t))
		h.Write(f64[:])
	}
	if b.Descending {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
}
