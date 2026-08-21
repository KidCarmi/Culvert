package cpdp

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// maxRevision bounds every component revision so a malformed/absurd counter is
// rejected before it can be used in an ordering comparison.
const maxRevision uint64 = 1 << 40

// Revisions is the complete, independent revision tuple carried by every MCP
// snapshot. Each component is tracked separately so that a policy-only or
// catalog-only change is distinguishable, and so one generic counter can never
// conceal an inconsistent component revision (MCP-CPDP-001).
type Revisions struct {
	// Config is the overall configuration revision — monotonic within a capability
	// and epoch, used for change detection and idempotent re-apply.
	Config uint64 `json:"config"`
	// Policy is the policy-bundle revision, tracked independently of Config.
	Policy uint64 `json:"policy"`
	// Catalog is the server-and-tool inventory revision (MCP-specific).
	Catalog uint64 `json:"catalog"`
	// Credential is the credential-profile METADATA/version only — never a secret.
	Credential uint64 `json:"credential"`
}

// ValidBounds reports whether every component revision is within [0, maxRevision].
// (uint64 is non-negative by construction; the upper bound guards against an
// absurd counter.)
func (r Revisions) ValidBounds() bool {
	return r.Config <= maxRevision && r.Policy <= maxRevision &&
		r.Catalog <= maxRevision && r.Credential <= maxRevision
}

// validate returns a bounds error if any component revision is out of range.
func (r Revisions) validate() error {
	if !r.ValidBounds() {
		return mcperr.New(mcperr.ReasonSnapshotRevisionInvalid, "cpdp.revision",
			"revision component out of bounds")
	}
	return nil
}

// CheckMonotonic evaluates the revision-ordering contract for a candidate tuple
// (cand) arriving to advance from the currently-active tuple (active), where
// candEpoch/activeEpoch are the respective configuration epochs. It enforces:
//
//   - a lower Config revision in the same or a lower epoch is rejected
//     (ReasonSnapshotRevisionRegression);
//   - credential metadata cannot move backwards silently — a lower Credential
//     revision in the same or a lower epoch is rejected;
//   - catalog cannot silently regress within the same or a lower epoch (an
//     intended catalog revert is an explicit rollback, not a stale publication);
//   - a HIGHER epoch is permitted to carry any revision (a new leader generation
//     re-bases the tuple) — but ONLY after the snapshot's authenticity has already
//     been proven by the caller; this function assumes signature/schema validation
//     has passed and does not itself bypass it.
//
// Idempotence (same revision, same content) and same-revision-different-content
// rejection are handled by the active store against the content hash; this
// function is the pure ordering rule and is content-hash agnostic.
func CheckMonotonic(active, cand Revisions, activeEpoch, candEpoch int64) error {
	if err := cand.validate(); err != nil {
		return err
	}
	// A strictly higher epoch re-bases: a new CP generation may publish any
	// revision tuple. Authenticity is proven upstream; ordering does not fence it.
	if candEpoch > activeEpoch {
		return nil
	}
	// Same or lower epoch: every tracked component must not regress. A lower epoch
	// that reaches here at all is already a stale-CP signal the epoch fence should
	// have rejected; the revision guard is the belt-and-braces second line.
	if candEpoch < activeEpoch {
		return mcperr.New(mcperr.ReasonSnapshotRevisionRegression, "cpdp.revision",
			"revision tuple from a lower epoch")
	}
	if cand.Config < active.Config {
		return mcperr.New(mcperr.ReasonSnapshotRevisionRegression, "cpdp.revision",
			"config revision regressed within epoch")
	}
	if cand.Credential < active.Credential {
		return mcperr.New(mcperr.ReasonSnapshotRevisionRegression, "cpdp.revision",
			"credential-metadata revision regressed within epoch")
	}
	if cand.Catalog < active.Catalog {
		return mcperr.New(mcperr.ReasonSnapshotRevisionRegression, "cpdp.revision",
			"catalog revision regressed within epoch (use explicit rollback)")
	}
	if cand.Policy < active.Policy {
		return mcperr.New(mcperr.ReasonSnapshotRevisionRegression, "cpdp.revision",
			"policy revision regressed within epoch")
	}
	return nil
}
