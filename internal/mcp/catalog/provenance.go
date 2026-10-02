package catalog

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// Provenance records HOW a catalog record's fingerprint came to be known.
//
// It exists because the two ways a record can appear are NOT equally good evidence and were,
// until this type, indistinguishable. `seedTools` (mcp_inventory.go) re-encodes operator-declared
// JSON into a synthetic tools/list result and feeds it through the SAME ingest path a real
// discovery uses, so a seeded record and a genuinely peer-observed one were byte-identical in the
// catalog. Nothing downstream — `ToolStillCurrent`, the activation preflight, the reviewed binding
// — could tell "the operator says the peer offers F1" from "an authenticated peer was observed
// advertising F1" (blocker 11).
//
// The distinction is NOT a caller-supplied flag. It is DERIVED from whether the record carries a
// PeerObservation, and a PeerObservation can only be attached by the dedicated observed-ingest
// entrypoint. A caller that wants peer provenance must therefore produce the evidence, not assert
// the conclusion.
type Provenance uint8

const (
	// OperatorSeeded — the record's fingerprint was computed from operator-declared inventory.
	// It is the ZERO VALUE, and that is deliberate: any record built without an explicit
	// authenticated observation is seeded, so a new construction path cannot default into
	// claiming peer evidence it never gathered.
	OperatorSeeded Provenance = iota
	// PeerObserved — the record's fingerprint was computed from a tools/list result returned by
	// an AUTHENTICATED peer over the supported transport, at PeerObservation.At.
	PeerObserved
)

// String returns the provenance label used on operator-facing surfaces and in bounded reasons.
func (p Provenance) String() string {
	switch p {
	case PeerObserved:
		return "peer_observed"
	case OperatorSeeded:
		return "operator_seeded"
	default:
		return "invalid"
	}
}

// PeerObservation is the bounded evidence that an AUTHENTICATED peer advertised a record.
//
// The ZERO VALUE means NO observation, and it is what every operator-seeded record carries. That
// is the fail-closed default in the only direction that matters: a record whose evidence was
// never gathered can never read as observed.
//
// Identity is the identity VERIFIED ON THE OBSERVATION'S TRANSPORT — not a value read out of the
// MCP payload, which the peer writes and could therefore choose. A tools/list response from a peer
// whose identity was not verified is not freshness evidence at all, so an observation carrying no
// identity is refused at the ingest boundary rather than stored and filtered later.
//
// There is deliberately no Source/kind field here. Presence IS the claim: Provenance is derived
// from Present(), so there is no second value that could disagree with the evidence beside it.
type PeerObservation struct {
	// At is when the authenticated observation completed, on the observer's clock.
	At time.Time
	// Identity is the server identity the transport verified for that observation.
	Identity registry.Identity
}

// Present reports whether this value carries a usable observation. BOTH halves are required: a
// timestamp with no verified identity does not say WHO was observed, and an identity with no
// timestamp does not say WHEN — and freshness is meaningless without both.
func (o PeerObservation) Present() bool { return !o.At.IsZero() && o.Identity != "" }

// Provenance reports how this record's fingerprint came to be known. It is DERIVED from the
// observation rather than stored beside it, so it is structurally impossible for a record to
// claim PeerObserved while carrying no evidence — the shape that would otherwise let a seeded
// record satisfy a peer-freshness gate.
func (r ToolRecord) Provenance() Provenance {
	if r.Observed.Present() {
		return PeerObserved
	}
	return OperatorSeeded
}
