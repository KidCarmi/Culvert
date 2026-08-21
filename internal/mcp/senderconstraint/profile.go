// Package senderconstraint is the listener-independent MCP sender-constraint core:
// DPoP proof parsing/verification, a bounded partitioned replay cache, and mTLS
// certificate-thumbprint binding. It receives request-binding metadata (HTTP
// method/URI, observed certificate thumbprint) and token confirmation values as
// explicit inputs; it performs no TLS handshake, no certificate-chain
// verification, and no network I/O.
//
// The zero Profile fails closed: a required sender-constrained profile that cannot
// safely admit a proof (missing constraint, replay, cache full) is rejected — there
// is no best-effort path.
package senderconstraint

// Profile is a deployment sender-constraint requirement.
type Profile uint8

const (
	// ProfileUnset — the zero value. FAILS CLOSED: not a usable profile.
	ProfileUnset Profile = iota
	// BearerControlled — a controlled/low-risk deployment where an unconstrained
	// bearer token is acceptable. The ONLY profile that permits bearer fallback.
	BearerControlled
	// DPoPRequired — every request must carry a valid, non-replayed DPoP proof bound
	// to the access token.
	DPoPRequired
	// MTLSRequired — the access token must be mTLS-bound (cnf.x5t#S256) and match the
	// observed peer certificate.
	MTLSRequired
	// DPoPOrMTLSRequired — either DPoP or mTLS binding is required (no bearer fallback).
	DPoPOrMTLSRequired
)

// AllowsBearer reports whether the profile permits an unconstrained bearer token.
// Only BearerControlled does; the zero profile and every constrained profile do not.
func (p Profile) AllowsBearer() bool { return p == BearerControlled }

// RequiresDPoP reports whether the profile can be satisfied by a DPoP proof.
func (p Profile) RequiresDPoP() bool { return p == DPoPRequired || p == DPoPOrMTLSRequired }

// RequiresMTLS reports whether the profile can be satisfied by an mTLS binding.
func (p Profile) RequiresMTLS() bool { return p == MTLSRequired || p == DPoPOrMTLSRequired }

// String returns the profile label.
func (p Profile) String() string {
	switch p {
	case BearerControlled:
		return "bearer_controlled"
	case DPoPRequired:
		return "dpop_required"
	case MTLSRequired:
		return "mtls_required"
	case DPoPOrMTLSRequired:
		return "dpop_or_mtls_required"
	default:
		return "unset"
	}
}
