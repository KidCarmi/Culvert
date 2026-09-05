package pac

// intent.go — the 2F-B trustable-publish operation model (contract C1).
//
// The durable, cluster-synced active profile store is the ONLY authoritative
// commit point. A publish or rollback first persists a node-local operation
// INTENT, then mutates the active store, then finalizes history. Because the
// two stores are separate durability domains, the intent is what lets a
// crash or a persistence failure at any boundary be classified afterwards —
// by reading the authoritative active state, never by guessing:
//
//   observed (revision, ProfileSpecDigest)         → class
//   (Expected+1, CandidateSpecDigest)              → committed  (finalize idempotently)
//   (Expected,   ExpectedActiveSpecDigest)         → aborted    (nothing happened)
//   anything else                                  → ambiguous  (refuse until repair)
//
// Every decided operation is kept in a bounded per-profile ring with the
// exact response it produced, so a repeated operationId is at-most-once and
// answers with the recorded result.

import (
	"encoding/json"
)

// Operation / lifecycle states.
const (
	OpPending   = "pending"
	OpCommitted = "committed"
	OpRecorded  = "recorded"
	OpAborted   = "aborted"
	OpAmbiguous = "ambiguous"

	LifecycleIdle      = "idle"
	LifecyclePending   = "pending"
	LifecycleAmbiguous = "ambiguous"

	// historyState values (the node-local history's truth about a profile).
	HistoryStateRecorded              = "recorded"
	HistoryStatePendingReconciliation = "pending_reconciliation"
	HistoryStateAmbiguous             = "ambiguous"
	HistoryStateReset                 = "history_reset"

	// MaxDecidedOps bounds the per-profile decided-operation ring.
	MaxDecidedOps = 64
)

// PendingOp is the durable intent of one publish/rollback operation.
type PendingOp struct {
	OperationID              string  `json:"operationId"`
	Action                   string  `json:"action"` // publish | rollback
	ProfileID                string  `json:"profileId"`
	ExpectedActiveRevision   int64   `json:"expectedActiveRevision"`
	ExpectedActiveSpecDigest string  `json:"expectedActiveSpecDigest"`
	CandidateSpecDigest      string  `json:"candidateSpecDigest"`
	CandidateSpec            Profile `json:"candidateSpec"`
	PoolDigest               string  `json:"poolDigest"`
	ArtifactDigest           string  `json:"artifactDigest"`
	ChallengePoolDigest      string  `json:"challengePoolDigest,omitempty"`
	ChallengeArtifactDigest  string  `json:"challengeArtifactDigest,omitempty"`
	Challenge                string  `json:"challenge,omitempty"` // accepted DIRECT challenge token (single-use record)
	TargetN                  int64   `json:"targetN,omitempty"`   // rollback target
	Actor                    string  `json:"actor"`
	AuditActor               string  `json:"auditActor,omitempty"` // the audit-ring actor string captured at intent time
	Reason                   string  `json:"reason,omitempty"`
	TS                       string  `json:"ts"`
	State                    string  `json:"state"`
	// Durable COMMITTED progression (2F-B correction, C1): once the
	// authoritative active store proves the commit, State becomes committed
	// and every post-commit effect advances a durable marker, so a crash at
	// any boundary is completed — never duplicated — by reconciliation.
	CommittedAt      string     `json:"committedAt,omitempty"`
	ObservedRevision int64      `json:"observedRevision,omitempty"`
	HistoryN         int64      `json:"historyN,omitempty"` // revision number recorded by history finalization
	Progress         OpProgress `json:"progress"`
}

// OpProgress records which post-commit effects of a committed operation are
// already durable. Each flag is persisted only AFTER its effect landed.
type OpProgress struct {
	History       bool `json:"history"`       // the published revision is recorded in the lifecycle
	ConfigVersion bool `json:"configVersion"` // the config-version snapshot exists (keyed by operationId)
	Cluster       bool `json:"cluster"`       // the CP→DP snapshot was (re)published
}

// Committed reports whether the intent has durably passed the authoritative
// commit point.
func (op *PendingOp) Committed() bool { return op != nil && op.State == OpCommitted }

// DecidedOp is the immutable record of a decided operation and the response
// it produced.
type DecidedOp struct {
	OperationID string          `json:"operationId"`
	Action      string          `json:"action"`
	State       string          `json:"state"` // recorded | aborted
	TS          string          `json:"ts"`
	Status      int             `json:"status"`
	Result      json.RawMessage `json:"result,omitempty"`
	Challenge   string          `json:"challenge,omitempty"`
}

// AmbiguousOp records an intent whose outcome could not be classified from
// the authoritative active state; the lifecycle refuses mutations until an
// admin repair.
type AmbiguousOp struct {
	Op                 PendingOp `json:"op"`
	ObservedRevision   int64     `json:"observedRevision"`
	ObservedSpecDigest string    `json:"observedSpecDigest"`
	ObservedAt         string    `json:"observedAt"`
}

// State reports the lifecycle state derived from the durable records.
func (lc *ProfileLifecycle) State() string {
	switch {
	case lc.Ambiguous != nil:
		return LifecycleAmbiguous
	case lc.PendingOp != nil:
		return LifecyclePending
	default:
		return LifecycleIdle
	}
}

// Decided returns the recorded decision for an operationId, if any.
func (lc *ProfileLifecycle) Decided(operationID string) (DecidedOp, bool) {
	for i := range lc.Operations {
		if lc.Operations[i].OperationID == operationID {
			return lc.Operations[i], true
		}
	}
	return DecidedOp{}, false
}

// RecordDecided appends a decision to the bounded ring (oldest evicted first).
func (lc *ProfileLifecycle) RecordDecided(d DecidedOp) {
	for i := range lc.Operations {
		if lc.Operations[i].OperationID == d.OperationID {
			lc.Operations[i] = d
			return
		}
	}
	lc.Operations = append(lc.Operations, d)
	if len(lc.Operations) > MaxDecidedOps {
		lc.Operations = append([]DecidedOp(nil), lc.Operations[len(lc.Operations)-MaxDecidedOps:]...)
	}
}

// ChallengeCommitted reports whether a DIRECT challenge token was already
// consumed by a decided (recorded) operation — a committed challenge is
// single-use.
func (lc *ProfileLifecycle) ChallengeCommitted(token string) bool {
	if token == "" {
		return false
	}
	for i := range lc.Operations {
		if lc.Operations[i].Challenge == token && lc.Operations[i].State == OpRecorded {
			return true
		}
	}
	return false
}

// RevisionByN is the exported revision lookup.
func (lc *ProfileLifecycle) RevisionByN(n int64) (PublishedRevision, bool) { return lc.revisionByN(n) }

// ClassifyOutcome decides an intent against the OBSERVED authoritative active
// profile (hasActive=false when no profile exists), using revision plus
// ProfileSpecDigest only.
func ClassifyOutcome(op *PendingOp, active Profile, hasActive bool) string {
	var rev int64
	digest := ""
	if hasActive {
		rev, digest = active.Revision, ProfileSpecDigest(active)
	}
	switch {
	case rev == op.ExpectedActiveRevision+1 && digest == op.CandidateSpecDigest:
		return OpCommitted
	case rev == op.ExpectedActiveRevision && digest == op.ExpectedActiveSpecDigest:
		return OpAborted
	default:
		return OpAmbiguous
	}
}

// FinalizeCommitted records the committed intent as a published revision.
// Idempotent: a revision already carrying the operationId is returned as-is,
// so a crash between finalization attempts can never mint a duplicate.
func (lc *ProfileLifecycle) FinalizeCommitted(op *PendingOp) int64 {
	for i := range lc.Revisions {
		if lc.Revisions[i].OperationID == op.OperationID {
			return lc.Revisions[i].N
		}
	}
	n := lc.nextRevisionN()
	spec := op.CandidateSpec
	spec.Revision = n
	lc.Revisions = append(lc.Revisions, PublishedRevision{
		N: n, Spec: spec, Digest: op.ArtifactDigest, SpecDigest: op.CandidateSpecDigest, PoolDigest: op.PoolDigest,
		Author: op.Actor, Reason: op.Reason, TS: op.TS, OperationID: op.OperationID,
		StoreRevision: op.ObservedRevision,
	})
	lc.trimRevisions()
	lc.Draft = spec
	lc.DraftRevision++
	lc.ActiveN = n
	lc.DraftDirty = false
	return n
}

// Repair records the OBSERVED active profile as a new, repaired revision and
// clears the ambiguity. It never touches the active store.
func (lc *ProfileLifecycle) Repair(observed Profile, poolDigest, artifactDigest, author, ts, operationID string) int64 {
	n := lc.nextRevisionN()
	spec := observed
	spec.Revision = n
	lc.Revisions = append(lc.Revisions, PublishedRevision{
		N: n, Spec: spec, Digest: artifactDigest, SpecDigest: ProfileSpecDigest(observed), PoolDigest: poolDigest,
		Author: author, Reason: "repair: accept_active", TS: ts, OperationID: operationID, Repaired: true,
		StoreRevision: observed.Revision,
	})
	lc.trimRevisions()
	lc.Draft = spec
	lc.DraftRevision++
	lc.ActiveN = n
	lc.DraftDirty = false
	lc.Ambiguous = nil
	lc.PendingOp = nil
	return n
}
