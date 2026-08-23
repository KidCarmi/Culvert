// Package redaction is the data-governance engine for support bundles
// (REDACTION-MODEL.md, ADR-0020). It classifies collected data by DataClass and
// redacts STRUCTURALLY at the source: SECRET/NEVER_EXPORT fields are dropped,
// SENSITIVE fields are masked, and any unclassified field fails closed to
// SENSITIVE (masked, never passed through). Regexes are a later backstop; the
// primary control is field-class-driven and deterministic.
package redaction

import "strings"

// DataClass is the ordered sensitivity taxonomy. Higher = more restricted.
type DataClass int

const (
	// ClassPublic is non-sensitive; safe for anyone (version, build, counts).
	ClassPublic DataClass = iota
	// ClassInternal is operationally revealing but not secret (rule names,
	// hostnames, health verdicts). Default ceiling for a shareable bundle.
	ClassInternal
	// ClassSensitive is identifying/confidential; masked before export
	// (usernames, client IPs, full URLs, DNs).
	ClassSensitive
	// ClassSecret is credential/authenticator material; dropped, never masked
	// and kept (passwords, HMACs, tokens, client secrets).
	ClassSecret
	// ClassNeverExport is key material that must never cross the process
	// boundary (KEK, CA/TLS private keys). The redactor only asserts, in tests,
	// that no collector can name such a field — the bytes are unreachable by
	// construction (internal/secret, ADR-0007).
	ClassNeverExport
)

// DefaultClass is the fail-closed class for any collected field with no explicit
// classification: masked, never leaked (REDACTION-MODEL §1/§9, P3).
const DefaultClass = ClassSensitive

// ShareableCeiling is the highest class permitted, post-redaction, in a
// shareable bundle. SENSITIVE data is only allowed in masked form (which the
// redactor treats as effectively INTERNAL), and SECRET/NEVER_EXPORT are dropped,
// so a redacted section's class_max never exceeds this by construction.
const ShareableCeiling = ClassInternal

// String is the canonical wire spelling used in manifests and reports.
func (c DataClass) String() string {
	switch c {
	case ClassPublic:
		return "PUBLIC"
	case ClassInternal:
		return "INTERNAL"
	case ClassSensitive:
		return "SENSITIVE"
	case ClassSecret:
		return "SECRET"
	case ClassNeverExport:
		return "NEVER_EXPORT"
	default:
		return "UNKNOWN"
	}
}

// ParseClass maps a struct-tag/wire spelling to a DataClass (case-insensitive).
// The second return is false for an unknown token — callers fail closed.
func ParseClass(s string) (DataClass, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "PUBLIC":
		return ClassPublic, true
	case "INTERNAL":
		return ClassInternal, true
	case "SENSITIVE":
		return ClassSensitive, true
	case "SECRET":
		return ClassSecret, true
	case "NEVER_EXPORT", "NEVEREXPORT":
		return ClassNeverExport, true
	default:
		return DefaultClass, false
	}
}

// maxClass returns the higher (more restricted) of two classes.
func maxClass(a, b DataClass) DataClass {
	if a > b {
		return a
	}
	return b
}
