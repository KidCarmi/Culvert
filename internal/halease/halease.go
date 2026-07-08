// Package halease is the HA fencing-lease primitive (ADR-0005 S1): a single
// cluster-wide lease with a strictly-monotonic epoch (the fencing token),
// arbitrated by a strongly-consistent backend. etcd is the default
// implementation (Etcd); Fake is the in-memory implementation the
// Culvert-side HA logic is unit-tested against.
//
// S1 ships the primitive ONLY — nothing in the runtime consumes it yet.
// S2 wires Acquire into promotion, the keepalive loop, and self-fence;
// S3 stamps the epoch on every write sink; S5 adds flags/compose/GUI.
// Policy decisions (e.g. whether a clean shutdown releases the lease)
// deliberately live in those slices, not here.
package halease

import (
	"context"
	"time"
)

// Status is a point-in-time view of the lease.
type Status struct {
	Holder   string        // current holder's candidate ID ("" = free)
	Epoch    int64         // fencing token; strictly monotonic across the backend's life; 0 = never held
	ValidFor time.Duration // remaining lease time as reported by the backend (0 = free/expired/unknown)
}

// Provider is the backend-agnostic fencing-lease interface (ADR-0005).
// Implementations MUST guarantee:
//
//   - Acquire grants iff the lease is free or expired, and every grant
//     carries an epoch STRICTLY GREATER than any previously granted epoch
//     (the fencing property). When denied, the returned Status describes
//     the current holder.
//   - Renew succeeds iff (holderID, epoch) is still the live lease. A
//     lost/expired/superseded lease returns ok=false with a nil error —
//     loss is an outcome, not an error; errors are reserved for transport
//     failures where the truth is UNKNOWN (callers must fail toward
//     self-fence on both, but may retry transport errors within budget).
//   - Read never mutates state.
//
// The backend — not the caller's wall clock — is the lease-time authority
// (ADR-0005 Finding 3).
type Provider interface {
	// Acquire attempts to take the lease for candidateID.
	Acquire(ctx context.Context, candidateID string) (granted bool, st Status, err error)
	// Renew keepalives the lease previously granted to (holderID, epoch).
	Renew(ctx context.Context, holderID string, epoch int64) (ok bool, validFor time.Duration, err error)
	// Read returns the current lease state.
	Read(ctx context.Context) (Status, error)
	// Close releases client resources. It MUST NOT revoke a held lease —
	// release-on-shutdown is an S2 policy decision, not a primitive.
	Close() error
}
