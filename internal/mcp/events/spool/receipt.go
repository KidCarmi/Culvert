package spool

import "github.com/KidCarmi/Culvert/internal/mcp/events/model"

// CommitReceipt is opaque, immutable evidence that a decision event was DURABLY
// COMMITTED (append + fsync + crash-consistent checkpoint confirmed) — not merely
// enqueued. It is UNFORGEABLE through normal external construction: every field is
// unexported and there is no exported constructor that manufactures a valid
// receipt, so a caller in another package can only hold a receipt the spool
// itself minted. The zero value is invalid (Valid() == false).
//
// A receipt is BOUND to the decision it attests: its event digest, capability,
// tenant, partition, action class and policy/catalog revisions. A receipt for one
// request or tenant cannot authorize another — the credential-broker
// pre-materialization gate (and any future execution slice) verifies the binding
// with Matches before treating the receipt as permission to proceed. The receipt
// is not a secret and contains no materialized credential.
type CommitReceipt struct {
	valid           bool
	eventID         string
	tenant          string
	capability      model.Capability
	partition       model.Partition
	domainID        string
	actionClass     model.ActionClass
	sequence        uint64
	segmentID       uint32
	committedOffset int64
	eventDigest     string
	commitUnixNano  int64
	policyRevision  uint64
	catalogRevision uint64
}

// Valid reports whether this is a real minted receipt (not the zero value).
func (r CommitReceipt) Valid() bool { return r.valid }

// EventID returns the committed event's id.
func (r CommitReceipt) EventID() string { return r.eventID }

// Tenant returns the tenant the receipt is bound to.
func (r CommitReceipt) Tenant() string { return r.tenant }

// Capability returns the capability the receipt is bound to.
func (r CommitReceipt) Capability() model.Capability { return r.capability }

// Partition returns the partition the event was committed to.
func (r CommitReceipt) Partition() model.Partition { return r.partition }

// DomainID returns the durability-domain id the commit belongs to.
func (r CommitReceipt) DomainID() string { return r.domainID }

// ActionClass returns the critical action class the receipt attests.
func (r CommitReceipt) ActionClass() model.ActionClass { return r.actionClass }

// Sequence returns the committed monotonic partition sequence.
func (r CommitReceipt) Sequence() uint64 { return r.sequence }

// SegmentID returns the segment the event was committed to.
func (r CommitReceipt) SegmentID() uint32 { return r.segmentID }

// CommittedOffset returns the committed byte offset within the segment.
func (r CommitReceipt) CommittedOffset() int64 { return r.committedOffset }

// EventDigest returns the committed event's intrinsic content digest.
func (r CommitReceipt) EventDigest() string { return r.eventDigest }

// CommitUnixNano returns the commit timestamp.
func (r CommitReceipt) CommitUnixNano() int64 { return r.commitUnixNano }

// PolicyRevision returns the policy revision bound to the decision.
func (r CommitReceipt) PolicyRevision() uint64 { return r.policyRevision }

// CatalogRevision returns the catalog revision bound to the decision.
func (r CommitReceipt) CatalogRevision() uint64 { return r.catalogRevision }

// Matches reports whether the receipt is bound to the given decision identity. A
// future execution slice (or the credential-broker gate) uses this to confirm a
// receipt authorizes exactly this request/tenant/action and no other. All four
// must match AND the receipt must be valid.
func (r CommitReceipt) Matches(eventDigest, tenant string, capability model.Capability, actionClass model.ActionClass) bool {
	return r.valid &&
		r.eventDigest == eventDigest &&
		r.tenant == tenant &&
		r.capability == capability &&
		r.actionClass == actionClass
}
