// Package cpdp implements the signed, immutable Control-Plane → Data-Plane
// snapshot model for the two MCP capabilities (Gateway and Management), plus the
// epoch fencing, minimum-DP-version compatibility gate, acknowledgement model,
// and signed rollback directive that PR-10 (MCP-CPDP-001..003, MCP-HA-001..002)
// requires. It is DECISION-ONLY distribution machinery: it distributes and
// activates decision state (policy/catalog/credential-metadata revisions), and
// it never executes an upstream tool, materializes a credential, or introduces a
// Data-Plane dependency on the Control Plane on any request/tool-call path.
//
// Design doctrine (see docs/design/mcp/CP-DP-HA-MODEL.md):
//
//   - Whole-snapshot validation, never partial apply. A single failed check
//     rejects the entire capability snapshot and leaves the current active
//     snapshot byte-unchanged.
//   - Validate-then-swap. Signature, schema, caps, revisions and minimum version
//     are all proven BEFORE any active-state mutation; runtime objects are built
//     off the active request path; the active pointer swap is one atomic step.
//   - Capability isolation. Gateway and Management have separate namespaces,
//     payloads, revisions, active/previous pointers, minimum-version
//     requirements, acknowledgements and rollback targets. A Gateway snapshot can
//     never activate Management state and vice versa; capability is a mandatory
//     SIGNED field and a mismatch fails closed.
//   - Reuse, do not reinvent. The signing envelope mirrors the release-catalog
//     ed25519 pattern; deterministic bytes come from internal/mcp/canonical;
//     epoch fencing reuses the ADR-0005 HA lease epoch; the private signing key
//     never leaves a scoped Signer (no raw-byte getter) and is never distributed
//     to a Data Plane.
//
// The package is a leaf: it depends only on internal/mcp/canonical and
// internal/mcp/mcperr, so it can be consumed by the apply/publication
// sub-packages and by package main's thin adapters without an import cycle.
package cpdp

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// SchemaVersion is the current MCP snapshot envelope schema version. A DP rejects
// any envelope whose declared schema version is not in the supported set — a
// newer/unknown schema is never partially interpreted (MCP-CPDP-002).
const SchemaVersion = 1

// supportedSchemaVersions is the closed set of envelope schema versions this
// build can interpret. It grows only by a deliberate edit here.
var supportedSchemaVersions = map[int]bool{1: true}

// schemaSupported reports whether a declared envelope schema version is one this
// build can interpret.
func schemaSupported(v int) bool { return supportedSchemaVersions[v] }

// SigAlgEd25519 is the ONLY accepted signature algorithm identifier. An unknown
// algorithm is never treated as ed25519 (downgrade guard, MCP-CPDP-001).
const SigAlgEd25519 = "ed25519"

// Capability names one of the two MCP capabilities. It is a mandatory SIGNED
// field of every snapshot envelope; a mismatch between the envelope's capability
// and the target store fails closed.
type Capability uint8

const (
	// CapabilityUnknown is the zero value: no capability. Fails closed.
	CapabilityUnknown Capability = iota
	// CapabilityGateway is the MCP Security Gateway capability (business tool
	// traffic). Its payload carries the reviewed server registry, tool catalog,
	// compiled policy, inspection profiles and credential-profile METADATA.
	CapabilityGateway
	// CapabilityManagement is the Culvert Management MCP capability (configuration).
	// Its payload carries only its own reviewed listener/access/operation state and
	// never a Gateway tool catalog or a Gateway credential profile.
	CapabilityManagement
)

// Valid reports whether c is one of the two real capabilities.
func (c Capability) Valid() bool {
	return c == CapabilityGateway || c == CapabilityManagement
}

// String returns the stable wire string for the capability. These strings are
// part of the signed manifest and MUST NOT change.
func (c Capability) String() string {
	switch c {
	case CapabilityGateway:
		return "gateway"
	case CapabilityManagement:
		return "management"
	default:
		return "unknown"
	}
}

// MarshalText encodes the capability as its stable wire string.
func (c Capability) MarshalText() ([]byte, error) {
	if !c.Valid() {
		return nil, mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.capability", "invalid capability")
	}
	return []byte(c.String()), nil
}

// UnmarshalText decodes a capability from its stable wire string. An unknown
// string fails closed rather than defaulting to a capability.
func (c *Capability) UnmarshalText(b []byte) error {
	switch string(b) {
	case "gateway":
		*c = CapabilityGateway
	case "management":
		*c = CapabilityManagement
	default:
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.capability", "unknown capability")
	}
	return nil
}

// ParseCapability resolves a capability from its wire string, failing closed on
// anything outside the closed set.
func ParseCapability(s string) (Capability, error) {
	var c Capability
	if err := c.UnmarshalText([]byte(s)); err != nil {
		return CapabilityUnknown, err
	}
	return c, nil
}
