package catalog

import (
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Promote is the trust-projection writer (ADR-0034 D2): it flips exactly ONE
// tool's eligibility to Usable, and only when the CURRENT record still matches the
// exact reviewed fingerprint. It is the catalog side of a human trust grant — the
// coordinator (package main) calls it AFTER durably persisting an active
// ToolApproval, so a crash between the two is repaired by startup Recover.
//
// It fails closed at every gate and never fabricates trust:
//
//   - the tool must exist in the current snapshot (else ReasonToolNotFound);
//   - a ServerDisabled record is NEVER promoted — the server-identity security
//     override wins over any approval (ReasonToolNotApprovable);
//   - the record's fingerprint must EXACTLY equal expected — the rug-pull guard.
//     A tool that drifted away from the reviewed capability is never promoted
//     (ReasonToolFingerprintMismatch);
//   - if the tool is already Usable at the same fingerprint the call is an
//     idempotent no-op (no new revision).
//
// Like DisableServer it uses a bounded optimistic CAS and returns
// ReasonToolApprovalStale on contention (the catalog advanced under the decision),
// so the caller re-reads and re-decides — it never fails open.
func (c *Catalog) Promote(key ToolKey, expected Fingerprint) (*Snapshot, error) {
	for attempt := 0; attempt < maxPublishRetries; attempt++ {
		base := c.cur.Load()
		rec, ok := base.byKey[key]
		if !ok {
			return nil, mcperr.New(mcperr.ReasonToolNotFound, "catalog.promote", "tool not present in catalog")
		}
		if rec.Eligibility == ServerDisabled {
			return nil, mcperr.New(mcperr.ReasonToolNotApprovable, "catalog.promote", "server disabled; identity override wins over approval")
		}
		if !rec.Fingerprint.Equal(expected) {
			return nil, mcperr.New(mcperr.ReasonToolFingerprintMismatch, "catalog.promote", "current fingerprint does not match the reviewed digest")
		}
		if rec.Eligibility == Usable {
			return base, nil // idempotent: already trusted at this exact fingerprint
		}
		rev := base.revision + 1
		next := base.clone(rev)
		updated := *rec
		updated.Eligibility = Usable
		updated.Revision = rev
		next.byKey[key] = &updated
		if err := c.tryPublish(base, next); err == nil {
			return next, nil
		}
	}
	return nil, mcperr.New(mcperr.ReasonToolApprovalStale, "catalog.promote", "snapshot contention exceeded retry bound")
}

// Demote is the trust-withdrawal writer (ADR-0034 D7): it returns a Usable tool to
// the sticky Quarantined floor so it re-enters review, used when a grant is revoked
// or expires. It is conservative by design — it never tries to reconstruct the
// tool's observed drift disposition; the next ingestion re-classifies it, and the
// sticky floor keeps it Quarantined until a fresh fingerprint-bound approval.
//
// Only a Usable record is touched: a tool that is already Quarantined/ReviewRequired
// /ServerDisabled, or absent, is a no-op (no new revision). Like DisableServer this
// is a security-relevant transition, so it uses the bounded CAS and returns
// ReasonStaleSnapshot on contention rather than failing open.
func (c *Catalog) Demote(key ToolKey) (*Snapshot, error) {
	for attempt := 0; attempt < maxPublishRetries; attempt++ {
		base := c.cur.Load()
		rec, ok := base.byKey[key]
		if !ok || rec.Eligibility != Usable {
			return base, nil // nothing to withdraw
		}
		rev := base.revision + 1
		next := base.clone(rev)
		updated := *rec
		updated.Eligibility = Quarantined
		updated.Revision = rev
		next.byKey[key] = &updated
		if err := c.tryPublish(base, next); err == nil {
			return next, nil
		}
	}
	return nil, mcperr.New(mcperr.ReasonStaleSnapshot, "catalog.demote", "snapshot contention exceeded retry bound")
}
