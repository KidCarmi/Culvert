package cpdp

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// AckState is the state a DP reports for a specific signed snapshot.
type AckState uint8

const (
	// AckReceived — the snapshot was received (pre-validation).
	AckReceived AckState = iota
	// AckRejected — the snapshot was rejected whole; the DP retained its current
	// valid snapshot.
	AckRejected
	// AckValidated — the snapshot passed whole validation but is not yet active.
	AckValidated
	// AckApplied — the snapshot was atomically activated.
	AckApplied
	// AckRolledBack — the DP reverted to a retained target (rollback acknowledgement).
	AckRolledBack
)

// String returns the stable wire string for the ack state.
func (s AckState) String() string {
	switch s {
	case AckReceived:
		return "received"
	case AckRejected:
		return "rejected"
	case AckValidated:
		return "validated"
	case AckApplied:
		return "applied"
	case AckRolledBack:
		return "rolled_back"
	default:
		return "unknown"
	}
}

// Valid reports whether s is a defined ack state.
func (s AckState) Valid() bool { return s <= AckRolledBack }

const maxRejectReasonBytes = 256

// Acknowledgement is the typed, bounded report a DP sends the CP, bound to a
// SPECIFIC signed snapshot by content hash. It carries only SAFE fields — never a
// raw snapshot, credential data, private key, raw policy, tool arguments/output,
// or unbounded error text.
type Acknowledgement struct {
	AckID        string        `json:"ack_id"`
	NodeID       string        `json:"node_id"` // from authenticated enrollment identity
	Capability   Capability    `json:"capability"`
	ContentHash  string        `json:"content_hash"`
	Epoch        int64         `json:"epoch"`
	Revisions    Revisions     `json:"revisions"`
	State        AckState      `json:"state"`
	ActiveHash   string        `json:"active_hash"`
	PreviousHash string        `json:"previous_hash,omitempty"`
	DPVersion    CompatVersion `json:"dp_version"`
	Health       string        `json:"health"`
	RejectReason string        `json:"reject_reason,omitempty"` // bounded machine code, never raw text
	TimeUnixNano int64         `json:"time_unix_nano"`
	RetrySeq     int           `json:"retry_seq"`
}

// Validate checks that an acknowledgement is well-formed and bound: it must carry
// an ack id, an authenticated node id, a valid capability, a content hash, and a
// defined state, and its reject reason must be a bounded machine code. An
// acknowledgement missing any binding field fails closed.
func (a Acknowledgement) Validate() error {
	if a.AckID == "" {
		return mcperr.New(mcperr.ReasonAckInvalid, "cpdp.ack", "missing ack id")
	}
	if a.NodeID == "" {
		return mcperr.New(mcperr.ReasonAckInvalid, "cpdp.ack", "missing node id")
	}
	if !a.Capability.Valid() {
		return mcperr.New(mcperr.ReasonAckInvalid, "cpdp.ack", "invalid capability")
	}
	if a.ContentHash == "" {
		return mcperr.New(mcperr.ReasonAckInvalid, "cpdp.ack", "missing content hash")
	}
	if !a.State.Valid() {
		return mcperr.New(mcperr.ReasonAckInvalid, "cpdp.ack", "invalid state")
	}
	if len(a.RejectReason) > maxRejectReasonBytes {
		return mcperr.New(mcperr.ReasonAckInvalid, "cpdp.ack", "reject reason too large")
	}
	return nil
}

// Matches reports whether the acknowledgement binds to exactly (nodeID,
// capability, contentHash). The CP tracks acknowledgements per (node, capability,
// content hash); an acknowledgement for one snapshot can never satisfy another.
func (a Acknowledgement) Matches(nodeID string, capability Capability, contentHash string) bool {
	return a.NodeID == nodeID && a.Capability == capability && a.ContentHash == contentHash
}
