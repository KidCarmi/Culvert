package supportmetrics

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// SchemaVersion is the governed telemetry wire-schema version for the
// support-metric registry (roadmap/M7-proactive-telemetry-plan.md §3/§8).
// It is a fixed constant, not derived — bump it only for a deliberate,
// reviewed wire-schema change.
const SchemaVersion = 1

// registryHashNamespace namespaces the canonical hash encoding itself
// (distinct from SchemaVersion, which versions the wire schema). Bumping it
// would change every registry_hash even if no descriptor changed — reserved
// for a future change to this hashing scheme.
const registryHashNamespace = "culvert-support-metric-registry-hash-v1"

// Hash computes the deterministic registry_hash (§8): a lowercase-hex SHA-256
// over the governed schema — SchemaVersion plus, for EVERY descriptor sorted
// by ID, (ID, Type, PrivacyClass, TelemetryEligible, Buckets). It is:
//
//   - stable across process restarts (pure function of the descriptor
//     values, no randomness, no wall-clock);
//   - independent of the registry's construction/iteration order (sorted
//     internally);
//   - independent of metric VALUES (Read is never called here);
//   - changed by any eligibility change, and by any governed bucket
//     definition change (Buckets participates in the digest).
//
// Fields are 0x00-delimited (not printable-character-delimited) so that no
// field value — every one drawn from a closed, code-controlled vocabulary
// (idPattern-constrained IDs, the fixed Type/PrivacyClass enum strings, and
// canonical bucket labels) — can forge a delimiter collision.
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
		writeField(strings.Join(d.Buckets, ","))
	}
	return hex.EncodeToString(h.Sum(nil))
}
