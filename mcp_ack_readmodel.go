package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp/publication"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// PR-UX-5 capability-specific acknowledgement read model.
//
// Truth model: fleet state is derived ONLY from real per-DP acknowledgements for
// the exact current signed content hash against the real intended DP node set. It
// is NEVER inferred from a stored envelope, a signed hash, a successful Admin API
// request, the desired/local mode, the absence of an error, or elapsed time. When
// no acknowledgement source is configured on this node (the shipped disabled-default
// posture: no publication coordinator is wired - see mcp_distribution_adapters.go),
// the model reports Configured=false with NO counts - the UI renders
// "unavailable / not configured", never a benign "0 DPs / fully acknowledged".

// mcpAckSource is the read-only acknowledgement projection the read model consumes.
// It is satisfied by *publication.AckTracker. Kept as an interface so the pure DTO
// builder is unit-testable with a real tracker and the shipped no-distribution
// posture is a plain nil.
type mcpAckSource interface {
	Counts(contentHash string, intended []string) publication.DistributionCounts
	AckFor(node, contentHash string) (cpdp.Acknowledgement, bool)
}

// mcpAckRow is the safe per-DP acknowledgement row. Every field maps to a real
// cpdp.Acknowledgement field. An intended node with NO acknowledgement for this
// hash is rendered with state "unavailable" (the truthful "no ack yet"), never a
// benign default.
type mcpAckRow struct {
	NodeID       string         `json:"node_id"`
	State        string         `json:"state"` // received|validated|applied|rejected|rolled_back|unavailable
	ContentHash  string         `json:"content_hash,omitempty"`
	ActiveHash   string         `json:"active_hash,omitempty"`
	PreviousHash string         `json:"previous_hash,omitempty"`
	Epoch        int64          `json:"epoch,omitempty"`
	Revisions    cpdp.Revisions `json:"revisions,omitempty"`
	DPVersion    uint32         `json:"dp_version,omitempty"`
	Health       string         `json:"health,omitempty"`
	RejectReason string         `json:"reject_reason,omitempty"`
	Incompatible bool           `json:"incompatible,omitempty"`
	TimeUnixNano int64          `json:"time_unix_nano,omitempty"`
	RetrySeq     int            `json:"retry_seq,omitempty"`
}

// mcpAckDTO is the capability-scoped acknowledgement read model returned by
// GET /api/mcp/distribution/acks. Configured=false ⇒ Counts is nil (never
// fabricated) and Rows is empty.
type mcpAckDTO struct {
	Capability        string                          `json:"capability"`
	Configured        bool                            `json:"configured"`
	ContentHash       string                          `json:"content_hash"`
	DistributionState string                          `json:"distribution_state"`
	AsOfUnixNano      int64                           `json:"as_of_unix_nano"`
	Intended          int                             `json:"intended"`
	Counts            *publication.DistributionCounts `json:"counts"`
	Rows              []mcpAckRow                     `json:"rows"`
}

// buildMCPAckDTO is the pure acknowledgement read-model builder. With src==nil it
// returns the truthful "not configured" model (Configured=false, Counts=nil). With
// a real source it tallies the exact counts and renders one row per intended node -
// the node's real ack state, or "unavailable" when it has not acknowledged this
// hash. It never fabricates fleet truth.
func buildMCPAckDTO(capability string, src mcpAckSource, intended []string, contentHash string, nowNano int64) mcpAckDTO {
	dto := mcpAckDTO{
		Capability:   capability,
		ContentHash:  contentHash,
		AsOfUnixNano: nowNano,
		Rows:         []mcpAckRow{},
	}
	if src == nil {
		// No acknowledgement source wired ⇒ node-local only. Truthfully unavailable:
		// no counts, no rows - never zero-as-healthy.
		dto.DistributionState = string(publication.StateLocalOnly)
		return dto
	}
	dto.Configured = true
	dto.Intended = len(intended)
	counts := src.Counts(contentHash, intended)
	dto.Counts = &counts
	dto.DistributionState = string(publication.DeriveState(counts))
	incompatibleCode := mcperr.ReasonSnapshotMinVersionUnmet.Code()
	for _, node := range intended {
		a, ok := src.AckFor(node, contentHash)
		if !ok {
			// Intended but no ack for THIS hash ⇒ unavailable (no benign default).
			dto.Rows = append(dto.Rows, mcpAckRow{NodeID: node, State: "unavailable"})
			continue
		}
		dto.Rows = append(dto.Rows, mcpAckRow{
			NodeID:       node,
			State:        a.State.String(),
			ContentHash:  a.ContentHash,
			ActiveHash:   a.ActiveHash,
			PreviousHash: a.PreviousHash,
			Epoch:        a.Epoch,
			Revisions:    a.Revisions,
			DPVersion:    uint32(a.DPVersion),
			Health:       a.Health,
			RejectReason: a.RejectReason,
			Incompatible: a.State == cpdp.AckRejected && a.RejectReason == incompatibleCode,
			TimeUnixNano: a.TimeUnixNano,
			RetrySeq:     a.RetrySeq,
		})
	}
	return dto
}

// mcpDistributionAckSource returns the acknowledgement source for a capability, or
// nil when signed CP→DP distribution is not configured on this node. In the shipped
// disabled-default posture NO publication coordinator / ack tracker is wired, so
// this is always nil and the read model reports "not configured" - the honest
// state. The seam exists so a future wired coordinator surfaces real acks with no
// UI change; wiring a new producer/transport is out of PR-UX-5 scope.
func mcpDistributionAckSource(_ rollout.Capability) mcpAckSource {
	return nil
}

// apiMCPDistributionAcks (PR-UX-5) is the bounded, additive, read-only,
// capability-scoped acknowledgement read model. Viewer-readable. It never mutates
// state and never fabricates fleet truth: with no configured distribution it
// reports Configured=false / distribution_state=local_only with no counts.
func apiMCPDistributionAcks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	capab := mcpRolloutCapability(r)
	contentHash := strings.TrimSpace(r.URL.Query().Get("content_hash"))
	src := mcpDistributionAckSource(capab)
	var intended []string
	if src != nil {
		intended = mcpEnrolledNodeIDs()
	}
	jsonOK(w, buildMCPAckDTO(capab.String(), src, intended, contentHash, time.Now().UnixNano()))
}
