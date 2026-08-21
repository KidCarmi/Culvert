// Package profile defines the immutable credential-profile model for the PR-4
// MCP credential broker (Capability B — the MCP Security Gateway). A profile
// binds a credential to a tenant, environment, registered server, tool class and
// resource scope, and declares the credential kind, power ceiling, permitted
// operations, cache/rotation/failure policy and lease bound — WITHOUT ever
// carrying credential plaintext.
//
// The package is listener-independent and performs no network I/O: it validates
// caller-supplied trusted configuration into immutable snapshots. It never
// materializes a secret (that is the broker's scoped callback) and holds no
// mutable global state.
package profile

import (
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// ID is an opaque, stable credential-profile identifier. Profiles are
// ALWAYS selected by this opaque id, never by display name, hostname or free text.
type ID string

// ProviderID is an opaque, stable credential-provider identifier.
type ProviderID string

// CredentialVersion is an opaque provider-assigned credential version token. It is
// never parsed for meaning; equality and revocation-tombstone matching only.
type CredentialVersion string

// Environment is an opaque deployment-environment token (e.g. "prod", "staging").
type Environment string

// maxIDBytes bounds every opaque identifier so an attacker-influenced value cannot
// drive unbounded memory in maps/keys.
const maxIDBytes = 512

func idErr(detail string) error {
	return mcperr.New(mcperr.ReasonCredentialProfileMissing, "credentials.profile", detail)
}

// validID checks an opaque identifier: non-empty, within the byte bound, and free
// of control characters (which would corrupt logs / keys). It never reflects the
// value's content beyond a sanitized echo.
func validID(kind, s string) error {
	if s == "" {
		return idErr(kind + " is empty")
	}
	if len(s) > maxIDBytes {
		return idErr(kind + " exceeds the maximum length")
	}
	if hasControl(s) {
		return idErr(kind + " contains control characters")
	}
	return nil
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// hasUnsafeWildcard reports whether a scope selector contains a wildcard or other
// unsafe globbing metacharacter. Resource scope selectors must be EXACT — a
// wildcard would broaden the grant beyond what the profile can bound.
func hasUnsafeWildcard(s string) bool {
	return s == "" || strings.ContainsAny(s, "*?[]") || hasControl(s)
}
