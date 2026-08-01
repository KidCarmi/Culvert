package protocol

import (
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Version is an MCP protocol revision string.
type Version string

// The frozen V1 baseline (D-1 CLOSED). The supported set is a finite reviewed
// allowlist; every other revision — including the explicitly-rejected ones below
// — is denied at negotiation with no best-effort interpretation and no silent
// downgrade (MCP-PROTO-010).
const (
	// VersionPrimary is the primary supported revision.
	VersionPrimary Version = "2025-11-25"
	// VersionFloor is the compatibility floor.
	VersionFloor Version = "2025-06-18"
)

// supported is the exact allowlist. Membership is the ONLY thing that admits a
// version; a version string that merely "looks like" a revision is not accepted.
var supported = map[Version]struct{}{
	VersionPrimary: {},
	VersionFloor:   {},
}

// rejected names the versions Culvert explicitly excludes, so diagnostics can
// distinguish a known-excluded revision from an unknown string. 2026-07-28 is a
// non-final RC kept as comparison material only; admitting 2025-03-26 would
// re-admit batch/version-surface semantics the baseline removes.
var rejected = map[Version]struct{}{
	"2024-11-05": {},
	"2025-03-26": {},
	"2026-07-28": {},
}

// IsSupported reports whether v is in the reviewed allowlist.
func IsSupported(v Version) bool { _, ok := supported[v]; return ok }

// IsExplicitlyRejected reports whether v is a known, named-excluded revision (as
// opposed to an unknown future/garbage string). Both are denied; this only aids
// diagnostics.
func IsExplicitlyRejected(v Version) bool { _, ok := rejected[v]; return ok }

// SupportedVersions returns the allowlist (primary first) for callers that need
// to advertise or test it. The returned slice is a fresh copy.
func SupportedVersions() []Version {
	return []Version{VersionPrimary, VersionFloor}
}

// Negotiation is the outcome of an initialize-body version negotiation.
type Negotiation struct {
	Requested Version
	// Selected is always a supported version.
	Selected Version
	// Accepted is true when Requested was directly supported (Selected == Requested).
	Accepted bool
	// CounterOffered is true when Requested was unsupported and Culvert is
	// counter-offering Selected (the client then accepts or terminates). This is
	// the 200-InitializeResult path, preferred over a 4xx that would recruit a
	// legacy probe (MCP-PROTO-017).
	CounterOffered bool
}

// Negotiate performs the initialize-body version decision. A supported requested
// version is accepted as-is; any other requested version yields a counter-offer
// of the primary supported version. Culvert never adopts an unsupported version
// and never silently downgrades to a legacy adapter (MCP-PROTO-010).
func Negotiate(requested Version) Negotiation {
	if IsSupported(requested) {
		return Negotiation{Requested: requested, Selected: requested, Accepted: true}
	}
	return Negotiation{Requested: requested, Selected: VersionPrimary, CounterOffered: true}
}

// Adapter normalizes a decoded message from a specific supported version into the
// kernel's single internal, version-agnostic representation, so no downstream
// stage ever branches on protocol version (MCP-PROTO-011). For the V1 admitted
// six methods the two supported revisions share an identical envelope shape, so
// normalization is the identity — but the per-version adapter boundary is real
// and proven equivalent by tests, keeping the door open for a future revision
// with wire differences without leaking version into downstream code.
type Adapter interface {
	Version() Version
	Normalize(msg jsonrpc.Message) (jsonrpc.Message, error)
}

type identityAdapter struct{ v Version }

// Version returns the protocol version this adapter normalizes for.
func (a identityAdapter) Version() Version { return a.v }

// Normalize validates the message is one the kernel can carry for this version
// and returns the version-agnostic form. It rejects a decoded response that
// carries neither a result nor an error defensively (the decoder already
// guarantees this, but the adapter is the last version-aware stage and must not
// pass an internally inconsistent message downstream).
func (a identityAdapter) Normalize(msg jsonrpc.Message) (jsonrpc.Message, error) {
	if msg.Class == jsonrpc.ClassInvalid {
		return jsonrpc.Message{}, mcperr.New(mcperr.ReasonInvalidJSONRPC, "normalize", "unclassified message")
	}
	if msg.Class == jsonrpc.ClassResponse && msg.Result == nil && msg.Error == nil {
		return jsonrpc.Message{}, mcperr.New(mcperr.ReasonInvalidJSONRPC, "normalize", "response without result or error")
	}
	return msg, nil
}

var adapters = map[Version]Adapter{
	VersionPrimary: identityAdapter{v: VersionPrimary},
	VersionFloor:   identityAdapter{v: VersionFloor},
}

// AdapterFor returns the adapter for a supported version. An unsupported version
// has no adapter (default deny at negotiation, MCP-PROTO-010 / §8): the caller
// must never reach here with an unsupported version.
func AdapterFor(v Version) (Adapter, bool) {
	a, ok := adapters[v]
	return a, ok
}
