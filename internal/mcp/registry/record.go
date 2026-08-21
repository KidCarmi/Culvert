// Package registry is the listener-independent server registry for the MCP
// Security Gateway (PR-2, Capability B only). It holds the immutable set of
// registered upstream MCP servers, each bound to a stable opaque ServerID and a
// PINNED verified identity, and it owns the server enable/disable lifecycle and
// the identity-change transition (MCP-SERVER-001/002/003).
//
// It is a pure data engine: it binds no socket, performs no TLS handshake or
// certificate retrieval, and makes no outbound call. Verified identity and
// endpoint data arrive as EXPLICIT caller-supplied inputs; the registry owns the
// comparison and the resulting state transition, never the network verification.
// Readers consult immutable Snapshots with no lock.
package registry

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// ServerID is the stable, opaque registry identity of a server. It is NOT a
// display name, hostname or URL — those are attributes, never identity. Two
// records with the same ServerID are the same server; everything else can change.
type ServerID string

// Endpoint is a canonical endpoint identity supplied by the caller (already
// resolved/canonicalized upstream — the registry does not parse URLs or dial).
// It is validated only for basic canonical well-formedness and uniqueness.
type Endpoint string

// Identity is the pinned, verified TLS/workload identity in a CANONICAL string
// representation chosen by the caller (e.g. a SPIFFE ID or a cert-key
// fingerprint). Identity comparison is EXACT over this canonical representation;
// the registry never interprets its structure.
type Identity string

// CredentialProfile is an OPAQUE reference to a scoped upstream credential class.
// The registry stores and compares it as an identifier only — it never holds a
// bearer token, password, private key or any raw credential material.
type CredentialProfile string

// OwnerScope is an ownership / tenant scope token. It is opaque to the registry.
type OwnerScope string

// Verification is a server's explicit identity-verification state.
type Verification uint8

const (
	// VerifyVerified — the pinned identity is the current trusted baseline.
	VerifyVerified Verification = iota
	// VerifyIdentityMismatch — a later verified identity did NOT match the pin; the
	// server is disabled until re-verified (MCP-SERVER-003). Terminal until a fresh
	// registration re-pins it.
	VerifyIdentityMismatch
)

// String returns the verification-state label.
func (v Verification) String() string {
	if v == VerifyIdentityMismatch {
		return "identity_mismatch"
	}
	return "verified"
}

// ServerRecord is one immutable registered-server record. Callers receive copies
// and never mutate it; a state change produces a NEW record in a NEW snapshot.
type ServerRecord struct {
	ID                ServerID
	Endpoint          Endpoint            // canonical endpoint identity
	PinnedIdentity    Identity            // verified, pinned TLS/workload identity
	Capability        protocol.Capability // Gateway only in PR-2
	CredentialProfile CredentialProfile   // opaque reference only
	OwnerScope        OwnerScope          // ownership / tenant scope
	Enabled           bool                // false ⇒ not eligible for discovery ingestion
	Verification      Verification        // explicit verification state
	Revision          uint64              // registry revision at which this record was last written
	CreatedAt         time.Time           // caller-supplied metadata
	UpdatedAt         time.Time           // caller-supplied metadata
}

// Usable reports whether the server is eligible for discovery ingestion: enabled
// AND with a verified (not mismatched) identity.
func (r ServerRecord) Usable() bool {
	return r.Enabled && r.Verification == VerifyVerified
}

// Registration is the caller-supplied input to Register. The registry validates
// it and stamps Enabled=true, Verification=VerifyVerified, and the Revision.
type Registration struct {
	ID                ServerID
	Endpoint          Endpoint
	PinnedIdentity    Identity
	Capability        protocol.Capability
	CredentialProfile CredentialProfile
	OwnerScope        OwnerScope
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func invalidReg(detail string) error {
	return mcperr.New(mcperr.ReasonInvalidRegistration, "registry.register", detail)
}

// validate checks a Registration against structural rules and the byte bounds.
// It never echoes the raw values (only fixed detail strings).
func (in Registration) validate(lim limits.CatalogLimits) error {
	if err := validateOpaqueToken(string(in.ID), lim.MaxServerIDBytes(), "server id"); err != nil {
		return err
	}
	if err := validateEndpoint(string(in.Endpoint), lim.MaxEndpointBytes()); err != nil {
		return err
	}
	if in.PinnedIdentity == "" {
		return invalidReg("pinned identity is required")
	}
	if err := validateOpaqueToken(string(in.PinnedIdentity), lim.MaxIdentityBytes(), "identity"); err != nil {
		return err
	}
	// PR-2 is Gateway-only: a Management record must never enter this namespace.
	if in.Capability != protocol.Gateway {
		return invalidReg("only Gateway servers are registrable in PR-2")
	}
	if in.CredentialProfile != "" {
		if err := validateOpaqueToken(string(in.CredentialProfile), lim.MaxCredProfileBytes(), "credential profile"); err != nil {
			return err
		}
	}
	if in.OwnerScope != "" {
		if err := validateOpaqueToken(string(in.OwnerScope), lim.MaxOwnerScopeBytes(), "owner scope"); err != nil {
			return err
		}
	}
	return nil
}

// validateOpaqueToken enforces non-empty, byte-bounded, valid-UTF-8, no ASCII
// control characters, and no surrounding whitespace (a minimal "canonical token"
// gate that does not interpret structure).
func validateOpaqueToken(s string, maxBytes int, name string) error {
	if s == "" {
		return invalidReg(name + " is empty")
	}
	if len(s) > maxBytes {
		return invalidReg(name + " exceeds byte bound")
	}
	if s[0] == ' ' || s[len(s)-1] == ' ' || s[0] == '\t' || s[len(s)-1] == '\t' {
		return invalidReg(name + " is not canonical (surrounding whitespace)")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return invalidReg(name + " contains a control character")
		}
	}
	return nil
}

// validateEndpoint is validateOpaqueToken plus the endpoint-specific rule that it
// must not contain interior whitespace (a canonical endpoint identity is a single
// token). It does NOT parse a URL or imply any network semantics.
func validateEndpoint(s string, maxBytes int) error {
	if err := validateOpaqueToken(s, maxBytes, "endpoint"); err != nil {
		return err
	}
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' {
			return invalidReg("endpoint is not canonical (interior whitespace)")
		}
	}
	return nil
}
