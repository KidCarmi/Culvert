package urlcatfeed

// F2 — pinned feed signing identity (SSOT).
//
// The feed has its OWN keyless signing identity, DISTINCT from the release
// catalog's ci.yml identity (F0 §5): a dedicated signing workflow file
// (publish-feeds.yml) and a dedicated tag namespace (feeds-v*). This is a
// separate pinned IDENTITY, not a separate cryptographic root — verification
// reuses the shared Sigstore public-good trusted root by value (verify.go takes
// the root bytes; the caller passes the same baked root the catalog uses).
//
// These constants are the single source of truth in the binary. The repo-root
// feeds_identity.env carries the SAME two strings for CI's cosign verify, and
// feeds_identity_ssot_test.go (package main) pins them byte-equal so CI and the
// binary can never drift.
const (
	// OfficialIssuer is the EXACT GitHub Actions OIDC issuer (no regex).
	OfficialIssuer = "https://token.actions.githubusercontent.com"

	// OfficialSANRegex anchors the SAN to a TAGGED release run of THIS repo's
	// dedicated feed signing workflow (publish-feeds.yml) on a feeds-v* tag —
	// exact repo + exact workflow file + tag ref, no wildcard. Only that run can
	// mint a feed-valid identity.
	OfficialSANRegex = `^https://github\.com/KidCarmi/Culvert/\.github/workflows/publish-feeds\.yml@refs/tags/feeds-v.*$`
)

// Identity is a pinned certificate identity policy: an exact OIDC issuer and an
// anchored SAN regex. Both are required.
type Identity struct {
	Issuer   string
	SANRegex string
}

// OfficialIdentity returns the baked default feed identity policy.
func OfficialIdentity() Identity {
	return Identity{Issuer: OfficialIssuer, SANRegex: OfficialSANRegex}
}
