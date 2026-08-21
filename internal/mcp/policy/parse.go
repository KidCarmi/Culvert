package policy

import (
	"bytes"
	"encoding/json"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// rawSnapshot is the strict JSON policy-document shape (one format for PR-6; no YAML).
type rawSnapshot struct {
	SchemaVersion  int       `json:"schema_version"`
	Capability     string    `json:"capability"`
	PolicyRevision uint64    `json:"policy_revision"`
	DefaultAction  string    `json:"default_action"`
	Description    string    `json:"description"`
	Rules          []rawRule `json:"rules"`
}

// rawRule is the strict JSON rule shape.
type rawRule struct {
	ID               string          `json:"id"`
	Priority         int             `json:"priority"`
	Enabled          *bool           `json:"enabled"` // absent ⇒ enabled (default true)
	Conditions       []rawCondition  `json:"conditions"`
	Action           string          `json:"action"`
	Reason           string          `json:"reason"`
	Remediation      string          `json:"remediation"`
	Obligations      *rawObligations `json:"obligations"`
	Owner            string          `json:"owner"`
	ExpiryUnix       int64           `json:"expiry_unix"`
	AllowDestructive bool            `json:"allow_destructive"`
}

// rawObligations is the strict JSON obligation shape.
type rawObligations struct {
	Logging           string        `json:"logging"`
	Observation       string        `json:"observation"`
	RateLimitProfile  string        `json:"rate_limit_profile"`
	Destination       string        `json:"destination"`
	CredentialProfile string        `json:"credential_profile"`
	OnceCall          bool          `json:"once_call"`
	Session           *rawSession   `json:"session"`
	Redaction         *rawRedaction `json:"redaction"`
	Confirmation      bool          `json:"confirmation"`
	Approval          bool          `json:"approval"`
	TicketRequired    bool          `json:"ticket_required"`
}

type rawSession struct {
	SessionBound   bool `json:"session_bound"`
	TTLSeconds     int  `json:"ttl_seconds"`
	MaxCalls       int  `json:"max_calls"`
	RevokeRequired bool `json:"revoke_required"`
}

type rawRedaction struct {
	ProfileRef              string `json:"profile_ref"`
	TransformedHashRequired bool   `json:"transformed_hash_required"`
}

// schemaVersionV1 is the only supported policy-document schema version.
const schemaVersionV1 = 1

func snapshotErr(detail string) error {
	return mcperr.New(mcperr.ReasonPolicySnapshotInvalid, "policy.parse", detail)
}

// parseDocument strictly decodes a policy document: it enforces the byte cap, runs
// the canonical strict validator (rejecting duplicate object keys, invalid UTF-8,
// escaped unpaired surrogates, trailing data, multiple top-level values and
// over-depth), then unmarshals with unknown-field rejection (unknown top-level or
// rule fields). It performs no I/O.
func parseDocument(raw []byte, lim Limits) (rawSnapshot, error) {
	if len(raw) == 0 {
		return rawSnapshot{}, snapshotErr("empty policy document")
	}
	if len(raw) > lim.MaxSnapshotBytes() {
		return rawSnapshot{}, snapshotErr("policy document exceeds the byte bound")
	}
	// Strict structural validation (dup keys / UTF-8 / trailing / depth / bounds).
	if _, err := canonical.Decode(raw, canonical.Bounds{
		MaxBytes:         lim.MaxSnapshotBytes(),
		MaxDepth:         32,
		MaxObjectMembers: 1 << 16,
		MaxArrayElements: lim.MaxRulesPerSnap() + lim.MaxConditions() + 16,
		MaxStringBytes:   lim.MaxStringBytes(),
	}); err != nil {
		return rawSnapshot{}, snapshotErr("policy document failed strict decode: " + mcperr.Sanitize(mcperr.ReasonOf(err).Code(), 48))
	}
	// Unknown-field rejection (top-level + nested), via a strict decoder.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var rs rawSnapshot
	if err := dec.Decode(&rs); err != nil {
		return rawSnapshot{}, snapshotErr("policy document has an unknown or malformed field")
	}
	// No trailing content after the single top-level value (canonical already checks,
	// but assert against the json decoder too).
	if dec.More() {
		return rawSnapshot{}, snapshotErr("policy document has trailing content")
	}
	return rs, nil
}
