package canary

import "strings"

// Shadow Exit Review attestation (§1). Canary readiness requires the full 13-criterion Shadow
// Exit Review to have PASSED. That fact must be a durable, explicit, privileged attestation —
// never a hard-coded boolean, never synthesized on startup or because tests passed. This file
// holds the PURE record + validator (schema, identity binding, fail-closed verdict); the durable
// I/O, the admin-only creation path, and the identity facts live in package main
// (mcp_canary_attestation.go), which passes the current runtime identity in.

// ShadowExitAttestationSchemaVersion is the on-disk schema version. A record whose schema does
// not match EXACTLY is fail-closed: it does NOT attest (a newer schema is not silently trusted,
// an older/unknown one is not silently upgraded). Bump only with a migration.
const ShadowExitAttestationSchemaVersion = 1

// ShadowExitStatus is the attestation verdict. Only StatusPassed attests; the zero value
// (unset) never does, so a partially-written or defaulted record fails closed.
type ShadowExitStatus string

// Shadow Exit attestation verdicts (fixed vocabulary).
const (
	ShadowExitStatusUnset  ShadowExitStatus = ""
	ShadowExitStatusPassed ShadowExitStatus = "shadow_exit_review_passed"
)

// RuntimeIdentity binds an attestation to the software identity it was reviewed against, so a
// materially changed runtime (a redeploy to a different build) cannot inherit an old
// attestation. BuildVersion is the linker-injected build stamp (package main `version`). The
// architecture may extend this with config/policy identity later; build identity is the
// minimum that makes "materially changed runtime" detectable.
type RuntimeIdentity struct {
	BuildVersion string `json:"build_version"`
}

// buildStampCommitSep is the separator currentRuntimeIdentity (package main) uses to compose the
// runtime identity as "<version>+<commit>" (composeBuildStamp). '+' is RESERVED for the commit: the
// commit is appended last, so the component after the LAST '+' is always the commit digest.
const buildStampCommitSep = '+'

// Commit-stamp length bounds: a git short SHA (>= 7; our builds stamp `git rev-parse --short=12`)
// up to a full SHA-256 (64). A value outside this range is not a real commit digest.
const (
	minCommitStampLen = 7
	maxCommitStampLen = 64
)

// splitBuildStamp separates a composed "<version>+<commit>" stamp at the LAST '+'. ok is false when
// the stamp carries no '+' at all — a BARE version with no commit component (a `.git`-less build
// stamps an empty commit, so composeBuildStamp emits the bare version). Splitting on the last '+'
// tolerates a version that itself carries "+<metadata>": the commit is always the final segment.
func splitBuildStamp(s string) (version, commit string, ok bool) {
	idx := strings.LastIndexByte(s, buildStampCommitSep)
	if idx < 0 {
		return s, "", false
	}
	return s[:idx], s[idx+1:], true
}

// validCommitStamp reports whether c is a concrete commit digest: minCommitStampLen..maxCommitStampLen
// LOWERCASE-HEX characters. Requiring hex both proves a real commit is present AND stops a version's
// own "+<metadata>" segment (e.g. semver "+build.7") from being mistaken for a commit — closing the
// bare-version fail-open unambiguously (Codex P1, round-22).
func validCommitStamp(c string) bool {
	if len(c) < minCommitStampLen || len(c) > maxCommitStampLen {
		return false
	}
	for i := 0; i < len(c); i++ {
		switch ch := c[i]; {
		case ch >= '0' && ch <= '9', ch >= 'a' && ch <= 'f':
			// lowercase hex digit (matches ValidEvidenceDigest's canonical-hex check)
		default:
			return false
		}
	}
	return true
}

// Valid reports whether an identity carries a UNIQUE, immutable build stamp: the composed
// "<version>+<commit>" form (currentRuntimeIdentity → composeBuildStamp) with a concrete lowercase-hex
// commit digest. A BARE version with no commit component is NOT unique — the same version tag can
// cover materially different commits, and a `.git`-less source archive built with the same VERSION arg
// stamps an EMPTY commit that collapses to that bare version — so it must not satisfy the identity
// binding and fails closed (Codex P1, round-22): merely rejecting a small placeholder list let every
// bare non-placeholder tag (e.g. "v1.2.3") through, allowing one build to reuse another's
// attestation/rehearsal/runtime record. The COMMIT digest is the uniqueness anchor; the version part
// is informational, so even a "dev" version is a valid identity when it carries a real commit.
func (i RuntimeIdentity) Valid() bool {
	_, commit, ok := splitBuildStamp(i.BuildVersion)
	if !ok {
		return false
	}
	return validCommitStamp(commit)
}

// ShadowExitAttestation is the durable, schema-versioned record that the Shadow Exit Review
// PASSED. It is created ONLY by an explicit privileged admin action (or an accepted signed
// evidence mechanism), carries the exact review/evidence identity, and is bound to the runtime
// identity it was made against.
type ShadowExitAttestation struct {
	SchemaVersion int              `json:"schema_version"`
	Status        ShadowExitStatus `json:"status"`
	// ReviewID is the exact Shadow Exit Review identity (the review artifact / case id).
	ReviewID string `json:"review_id"`
	// EvidenceDigest is a hex digest of the exact Shadow Exit evidence bundle the review
	// signed off on — the "which evidence" binding, so an attestation names its evidence.
	EvidenceDigest string `json:"evidence_digest"`
	// Identity is the runtime the review was made against; a later runtime that differs is
	// not covered by this attestation.
	Identity RuntimeIdentity `json:"identity"`
	// AttestedBy is the privileged actor who created the attestation (admin identity).
	AttestedBy string `json:"attested_by"`
	// AttestedAtUnixNano is when it was created (audit/ordering only; never a validity input).
	AttestedAtUnixNano int64 `json:"attested_at_unix_nano"`
}

// AttestationReason classifies why an attestation does not satisfy the Shadow Exit prerequisite.
// Fixed vocabulary; never interpolated with runtime data.
type AttestationReason string

// Attestation rejection sub-reasons (fixed vocabulary; AttestationOK is the admissible value).
const (
	AttestationOK               AttestationReason = ""
	AttestationMissing          AttestationReason = "attestation_missing"             // no attestation present
	AttestationSchemaUnknown    AttestationReason = "attestation_schema_unknown"      // schema != current (fail closed)
	AttestationNotPassed        AttestationReason = "attestation_not_passed"          // status is not PASSED
	AttestationNoReviewID       AttestationReason = "attestation_no_review_id"        // missing review identity
	AttestationNoEvidence       AttestationReason = "attestation_no_evidence_digest"  // missing evidence digest
	AttestationBadEvidence      AttestationReason = "attestation_bad_evidence_digest" // evidence digest not a canonical hex digest
	AttestationNoAttestor       AttestationReason = "attestation_no_attestor"         // missing privileged actor
	AttestationIdentityMismatch AttestationReason = "attestation_identity_mismatch"   // build changed since attested
)

// ValidateAttestation returns AttestationOK ONLY when a is a well-formed, PASSED attestation
// bound to the CURRENT runtime identity. It is PURE and fail-closed: a nil record, an unknown
// schema, a non-PASSED status, a missing review/evidence/attestor field, or a build-identity
// mismatch each yields a named reason and NOT-attested. Passing `current` in (never reading it
// here) keeps the record engine free of package-main identity facts.
func ValidateAttestation(a *ShadowExitAttestation, current RuntimeIdentity) AttestationReason {
	if a == nil {
		return AttestationMissing
	}
	// Schema must match EXACTLY — a newer schema is not silently trusted, an older/unknown one
	// is not silently upgraded. Corruption that flips the version fails here.
	if a.SchemaVersion != ShadowExitAttestationSchemaVersion {
		return AttestationSchemaUnknown
	}
	if a.Status != ShadowExitStatusPassed {
		return AttestationNotPassed
	}
	if a.ReviewID == "" {
		return AttestationNoReviewID
	}
	if a.EvidenceDigest == "" {
		return AttestationNoEvidence
	}
	if !ValidEvidenceDigest(a.EvidenceDigest) {
		return AttestationBadEvidence
	}
	if a.AttestedBy == "" {
		return AttestationNoAttestor
	}
	// Identity binding: the attestation must name a concrete build AND it must be the build
	// running now. A redeploy to a different version leaves the old attestation in place but it
	// no longer covers the current runtime — it must be re-reviewed (materially changed runtime).
	if !current.Valid() || a.Identity.BuildVersion != current.BuildVersion {
		return AttestationIdentityMismatch
	}
	return AttestationOK
}

// AttestationValid is the boolean form used by the readiness fact.
func AttestationValid(a *ShadowExitAttestation, current RuntimeIdentity) bool {
	return ValidateAttestation(a, current) == AttestationOK
}

// evidenceDigestLen is the canonical length of a hex-encoded SHA-256 evidence digest (32 bytes).
const evidenceDigestLen = 64

// ValidEvidenceDigest reports whether s is a canonical lowercase-hex SHA-256 digest (exactly 64
// lowercase hex characters) — the documented encoding that identifies the reviewed Shadow Exit
// evidence bundle. A nonempty-but-malformed value (e.g. "x", "not-a-digest") is rejected so a review
// can never be attested against an unidentifiable evidence reference (Codex P2). It is enforced both
// at the admin POST (trust boundary) and in ValidateAttestation (durable defense-in-depth).
func ValidEvidenceDigest(s string) bool {
	if len(s) != evidenceDigestLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			// canonical lowercase hex digit
		default:
			return false
		}
	}
	return true
}
