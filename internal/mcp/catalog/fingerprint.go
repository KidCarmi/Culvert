// Package catalog is the listener-independent tool catalog for the MCP Security
// Gateway (PR-2, Capability B only). It ingests an ALREADY-RECEIVED tools/list
// discovery result (never a network fetch), computes a deterministic per-tool
// fingerprint, classifies drift against the last known fingerprint, and records
// quarantine / review / server-disabled dispositions in immutable snapshots.
//
// It decides nothing about policy and executes no tool: PR-2 classifies and
// records (MCP-TOOL-001/002/003/005); the QUARANTINE/ALLOW enforcement of
// MCP-TOOL-004/006 is PR-6. There is deliberately NO API that turns an
// unknown-tool or privilege-expansion observation into a usable/allowed state.
package catalog

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// fingerprintFormatVersion is the fingerprint schema/version, folded into the
// composite hash so a future format change can never collide with an old one.
const fingerprintFormatVersion uint16 = 1

// ToolKey identifies a tool by (server registry id, tool name). Name ALONE is
// never identity: the same name behind two different server ids is two tools.
type ToolKey struct {
	Server registry.ServerID
	Name   string
}

// DestinationClass is the empirically OBSERVED network/resource breadth of a
// tool, supplied to ingestion as an explicit input (PR-2 makes no observation
// over the network). It is ORDERED for narrowing/broadening comparison, with
// DestUnknown standing outside the order (a change to/from it is ambiguous).
type DestinationClass uint8

const (
	// DestUnknown — not observed. Outside the narrowing/broadening order.
	DestUnknown DestinationClass = iota
	// DestNone — no external destination.
	DestNone
	// DestApproved — a single approved upstream service.
	DestApproved
	// DestInternal — the internal network.
	DestInternal
	// DestArbitrary — arbitrary network / any URL (the broadest).
	DestArbitrary
)

// rank returns the ordering rank and whether the class is ordered (DestUnknown
// is not).
func (d DestinationClass) rank() (int, bool) {
	switch d {
	case DestNone:
		return 0, true
	case DestApproved:
		return 1, true
	case DestInternal:
		return 2, true
	case DestArbitrary:
		return 3, true
	default:
		return 0, false
	}
}

// String returns the destination-class label.
func (d DestinationClass) String() string {
	switch d {
	case DestNone:
		return "none"
	case DestApproved:
		return "approved"
	case DestInternal:
		return "internal"
	case DestArbitrary:
		return "arbitrary"
	default:
		return "unknown"
	}
}

// Fingerprint is the deterministic composite identity of a tool observation
// (MCP-TOOL-001). It carries the eight fingerprint fields plus the format
// version. Output-schema PRESENCE is explicit (HasOutputSchema) so an absent
// output schema is distinguishable from a present-but-empty one — they never
// hash the same.
type Fingerprint struct {
	Server            registry.ServerID
	Identity          registry.Identity // canonical verified TLS/workload identity (pinned upstream identity)
	Name              string
	InputSchemaHash   [32]byte
	OutputSchemaHash  [32]byte // meaningful only when HasOutputSchema
	HasOutputSchema   bool
	DescriptiveHash   [32]byte // normalized description + canonical annotations + title
	CredentialProfile registry.CredentialProfile
	Destination       DestinationClass
	FormatVersion     uint16
}

// Equal reports byte-exact equality of two fingerprints across every field
// (including the output-schema presence marker and format version).
func (f Fingerprint) Equal(o Fingerprint) bool {
	return f.Server == o.Server &&
		f.Identity == o.Identity &&
		f.Name == o.Name &&
		f.InputSchemaHash == o.InputSchemaHash &&
		f.HasOutputSchema == o.HasOutputSchema &&
		(!f.HasOutputSchema || f.OutputSchemaHash == o.OutputSchemaHash) &&
		f.DescriptiveHash == o.DescriptiveHash &&
		f.CredentialProfile == o.CredentialProfile &&
		f.Destination == o.Destination &&
		f.FormatVersion == o.FormatVersion
}

// Sum returns the SHA-256 composite hash over every fingerprint field in a fixed
// order with length-prefixed segments (so no two distinct field layouts can
// collide). Two tools with the same name but different server id or identity
// necessarily hash differently.
func (f Fingerprint) Sum() [32]byte {
	h := sha256.New()
	writeSeg := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	var ver [2]byte
	binary.BigEndian.PutUint16(ver[:], f.FormatVersion)
	h.Write(ver[:])
	writeSeg([]byte(f.Server))
	writeSeg([]byte(f.Identity))
	writeSeg([]byte(f.Name))
	writeSeg(f.InputSchemaHash[:])
	if f.HasOutputSchema {
		h.Write([]byte{1})
		writeSeg(f.OutputSchemaHash[:])
	} else {
		h.Write([]byte{0})
	}
	writeSeg(f.DescriptiveHash[:])
	writeSeg([]byte(f.CredentialProfile))
	h.Write([]byte{byte(f.Destination)})
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func malformedDiscovery(detail string) error {
	return mcperr.New(mcperr.ReasonMalformedDiscovery, "catalog.ingest", detail)
}
