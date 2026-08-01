// Package inspection is the PR-7 MCP inspection layer composition root. It ties
// together semantic schema validation (inspection/schema, MCP-INSP-001), bounded
// output validation + truncation (MCP-INSP-002), deterministic DLP secret/PII
// classification (inspection/dlp, MCP-INSP-003), destination/SSRF/DNS-pin/redirect
// controls (inspection/destination, MCP-INSP-004/005/006), and best-effort
// injection labeling (MCP-INSP-007) into a request inspector, a response
// inspector, immutable capability-split profiles, a sanitized inspection summary
// that PR-6 policy consumes, and a redaction transform for the
// ALLOW_WITH_REDACTION obligation.
//
// PR-7 is DECISION-ONLY: nothing here calls a business MCP server, creates an
// upstream client, invokes tools/call, materializes a credential, contacts a
// provider, or durably commits an event. The inspector produces typed facts and
// sanitized evidence; the runtime maps those to a decision-only response that
// always retains execution_state "not_implemented".
//
// Every safe result type here carries ONLY sanitized metadata: classifications,
// severities, bounded JSON-pointer-like paths, counts, revisions, one-way hashes,
// a canonical destination class, and dispositions — never a raw secret, matched
// snippet, raw argument, raw output, private key, bearer token, or sensitive URL
// query string.
package inspection

import (
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/destination"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/dlp"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/schema"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Disposition is the typed inspection disposition for a classification. The zero
// value (DispUnset) FAILS CLOSED — it is treated as a block.
type Disposition uint8

const (
	// DispUnset — zero value; treated as block (fail closed).
	DispUnset Disposition = iota
	// DispPass — no action.
	DispPass
	// DispLabel — record a label; do not block or transform.
	DispLabel
	// DispRedact — the value must be redacted before any egress.
	DispRedact
	// DispBlock — the operation is blocked (hard security failure).
	DispBlock
)

// String returns the disposition label.
func (d Disposition) String() string {
	switch d {
	case DispPass:
		return "pass"
	case DispLabel:
		return "label"
	case DispRedact:
		return "redact"
	case DispBlock:
		return "block"
	default:
		return "unset"
	}
}

// Blocks reports whether the disposition is a hard block (including the fail-closed
// zero value).
func (d Disposition) Blocks() bool { return d == DispBlock || d == DispUnset }

// worse returns the more severe of two dispositions (Block > Redact > Label >
// Pass; Unset is treated as the most severe).
func worse(a, b Disposition) Disposition {
	rank := func(d Disposition) int {
		switch d {
		case DispPass:
			return 1
		case DispLabel:
			return 2
		case DispRedact:
			return 3
		case DispBlock:
			return 4
		default: // DispUnset — fail closed, most severe
			return 5
		}
	}
	if rank(a) >= rank(b) {
		return a
	}
	return b
}

// RedirectStatus is the safe redirect outcome fact.
type RedirectStatus uint8

const (
	// RedirectNone — no redirect chain evaluated.
	RedirectNone RedirectStatus = iota
	// RedirectClean — a redirect chain was evaluated and every hop passed.
	RedirectClean
	// RedirectRejected — a redirect hop was rejected.
	RedirectRejected
)

// String returns the redirect-status label.
func (r RedirectStatus) String() string {
	switch r {
	case RedirectClean:
		return "clean"
	case RedirectRejected:
		return "rejected"
	default:
		return "none"
	}
}

// PinnedEvidence is safe evidence for one pinned destination — origin, address
// count, resolver revision and a one-way hash. It never carries a raw URL/query.
type PinnedEvidence struct {
	Origin           string
	AddrCount        int
	ResolverRevision uint64
	Hash             string
	Class            destination.Class
}

// InspectionSummary is the immutable, sanitized fact set the runtime maps into the
// PR-6 DecisionInput. It carries NO raw arguments/output, NO secret matches, NO
// full URLs with sensitive queries, NO bearer/credential material — only typed
// facts and one-way hashes. The PR-6 evaluator stays deterministic and I/O-free;
// inspection did all resolver/scan work before evaluation.
type InspectionSummary struct {
	Revision           uint64
	SchemaStatus       schema.Status
	OutputSchemaStatus schema.Status
	SecretFound        bool
	PIIFound           bool
	InjectionSuspected bool
	MaxSeverity        dlp.Severity
	Disposition        Disposition
	DestClass          destination.Class
	DestInspected      bool
	Pinned             bool
	PinnedHash         string
	RedirectStatus     RedirectStatus
	Classes            []dlp.Classification

	// availability flags fed to policy.Inspection (fail closed when absent).
	DLPAvailable         bool
	RedactionAvailable   bool
	DestInspectAvailable bool
	SecretScanAvailable  bool

	// redaction obligation results (set only after a redaction transform).
	RedactionProfile string
	RedactionApplied bool
	OriginalHash     string
	TransformedHash  string
}

// InspectionResult is the full sanitized inspection outcome. HardFail marks a hard
// security failure that an ordinary PR-6 ALLOW rule can NEVER override; the runtime
// blocks with HardReason regardless of the policy action.
type InspectionResult struct {
	Summary  InspectionSummary
	Findings []dlp.Finding
	Redirect []destination.RedirectEvidence
	Pins     []PinnedEvidence

	HardFail   bool
	HardReason mcperr.Reason
}

// RedactionEvidence is the safe attestation of a redaction transform. It carries
// the profile id, the classifications removed, the count, the original and
// transformed canonical hashes and the transformed size — never any original value.
type RedactionEvidence struct {
	ProfileRef      string
	ProfileRevision uint64
	Classes         []dlp.Classification
	Count           int
	OriginalHash    string
	TransformedHash string
	TransformedSize int
}
