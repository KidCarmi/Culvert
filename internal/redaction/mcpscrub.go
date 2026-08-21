package redaction

import "strings"

// This file exposes a NARROW, additive classification/transform surface over the
// existing bounded deterministic scrubber for the MCP inspection/DLP layer
// (internal/mcp/inspection). It creates NO second secret scrubber: every call
// delegates to the same process-wide defaultScrubber and preserves every
// invariant the scrubber already guarantees — fixed self-identifying credential
// patterns, RE2 / non-backtracking matching, zero-width-format-rune handling,
// whole-leaf fail-closed behaviour over maxScanBytes / maxReplacements,
// "[redacted:<name>]" replacement bounds, idempotence, and precision-first
// behaviour (no bare length/entropy rule, so SHAs/UUIDs/ULIDs pass through).
//
// The names returned are STABLE detector names (e.g. "jwt", "aws_secret",
// "bearer_token") — never the matched secret text. The fail-closed sentinel
// leaves ("oversized", "overflow") surface under those exact names so a caller
// can treat them as an oversized/over-count classification.

// ScrubDetail is Scrub plus the ordered detector names that fired. It returns the
// redacted string, the stable detector names for every redaction (duplicates
// preserved, one per redaction), and the redaction count (len(names) == n except
// on the whole-leaf fail-closed sentinels, where n==1 and names carry the single
// sentinel). The raw matched secret is NEVER returned. Bounded by the same
// maxScanBytes fail-closed cap as Scrub.
func (sc *Scrubber) ScrubDetail(s string) (out string, names []string, n int) {
	if s == "" {
		return "", nil, 0
	}
	if len(s) > maxScanBytes {
		return "[redacted:oversized]", []string{"oversized"}, 1
	}
	zw := strings.IndexFunc(s, isFormatRune) >= 0
	if !zw && !sc.detect.MatchString(s) {
		return s, nil, 0 // clean path — identical to Scrub
	}
	if zw {
		s = strings.Map(func(r rune) rune {
			if isFormatRune(r) {
				return -1
			}
			return r
		}, s)
		if len(s) > maxScanBytes {
			return "[redacted:oversized]", []string{"oversized"}, 1
		}
	}
	count := 0
	var got []string
	s = sc.applyTokenPass(s, &count, &got)
	for i := range sc.valueRules {
		s = sc.valueRules[i].apply(s, &count, &got)
	}
	if count > maxReplacements {
		return "[redacted:overflow]", []string{"overflow"}, 1
	}
	return s, got, count
}

// ScrubDetailDefault runs ScrubDetail with the process-wide default scrubber. It
// is the package-level entry point the MCP DLP classifier consumes so it never
// needs a Scrubber handle or a second scrubber instance.
func ScrubDetailDefault(s string) (out string, names []string, n int) {
	return defaultScrubber.ScrubDetail(s)
}

// SecretClass reports the coarse DLP classification for a scrubber detector name.
// It is a pure, fixed mapping (no allocation, no I/O) the MCP inspection layer
// uses to turn a scrubber hit into a stable data classification without
// re-deriving secret shapes. Unknown names fail closed to a generic credential
// secret classification (a hit is a hit).
func SecretClass(name string) string {
	switch name {
	case "pem", "rsa_private", "ec_private", "openssh_private", "pgp_private":
		return "private_key"
	case "jwt", "bearer_token":
		return "bearer_token"
	case "aws_secret", "aws_access", "gcp", "databricks", "vault", "twilio",
		"stripe", "sendgrid", "openai", "slack", "npm", "github", "gitlab":
		return "credential_secret"
	case "basic_auth_url", "credential_assignment":
		return "password_or_api_key"
	case "oversized", "overflow":
		return "oversized_or_unknown"
	default:
		return "credential_secret"
	}
}
