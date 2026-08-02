package destination

import (
	"sort"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// forbiddenSchemes can NEVER be allowlisted, even by explicit config — they are
// dangerous by construction (local file, inline data, script, legacy fetch).
var forbiddenSchemes = map[string]struct{}{
	"file": {}, "data": {}, "javascript": {}, "gopher": {}, "ftp": {},
	"unix": {}, "blob": {}, "ws": {}, "wss": {},
}

// PolicyConfig is the mutable input to NewPolicy.
type PolicyConfig struct {
	// Schemes is the allowlist (e.g. {"https"}). Empty ⇒ fail closed (no scheme
	// permitted). A forbidden scheme in the list is a hard configuration error.
	Schemes []string
	// AllowPrivate permits private/internal destinations. It is TEST- or
	// ENVIRONMENT-scoped ONLY; a production policy must leave it false. There is no
	// broad production allow_private bypass.
	AllowPrivate bool
	// AllowCrossOriginRedirect permits a redirect to a different origin.
	AllowCrossOriginRedirect bool
	// AllowSchemeDowngrade permits an https→http redirect (default false).
	AllowSchemeDowngrade bool
	// ResolverRevision stamps pins made under this policy.
	ResolverRevision uint64
}

// Policy is an immutable destination policy. Its scheme set is stored as a sorted
// slice (tiny; linear membership) so the value shares no mutable map with callers.
type Policy struct {
	schemes                  []string
	allowPrivate             bool
	allowCrossOriginRedirect bool
	allowSchemeDowngrade     bool
	resolverRevision         uint64
}

// NewPolicy validates cfg and returns an immutable Policy. It rejects an empty
// scheme allowlist (fail closed) and any forbidden scheme.
func NewPolicy(cfg PolicyConfig) (Policy, error) {
	if len(cfg.Schemes) == 0 {
		return Policy{}, mcperr.New(mcperr.ReasonListenerConfigInvalid, "destination.policy", "empty scheme allowlist")
	}
	set := make([]string, 0, len(cfg.Schemes))
	seen := map[string]struct{}{}
	for _, s := range cfg.Schemes {
		if s == "" {
			return Policy{}, mcperr.New(mcperr.ReasonListenerConfigInvalid, "destination.policy", "empty scheme")
		}
		if _, bad := forbiddenSchemes[s]; bad {
			return Policy{}, mcperr.New(mcperr.ReasonListenerConfigInvalid, "destination.policy", "forbidden scheme in allowlist")
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		set = append(set, s)
	}
	sort.Strings(set)
	return Policy{
		schemes:                  set,
		allowPrivate:             cfg.AllowPrivate,
		allowCrossOriginRedirect: cfg.AllowCrossOriginRedirect,
		allowSchemeDowngrade:     cfg.AllowSchemeDowngrade,
		resolverRevision:         cfg.ResolverRevision,
	}, nil
}

// schemeAllowed reports whether scheme is on the allowlist.
func (p Policy) schemeAllowed(scheme string) bool {
	for _, s := range p.schemes {
		if s == scheme {
			return true
		}
	}
	return false
}

// AllowPrivate reports the test/env-scoped private-destination flag.
func (p Policy) AllowPrivate() bool { return p.allowPrivate }

// ResolverRevision returns the revision pins are stamped with.
func (p Policy) ResolverRevision() uint64 { return p.resolverRevision }

// DefaultGatewayPolicy returns the narrow production Gateway destination policy:
// https only, no private, no cross-origin redirect, no scheme downgrade.
func DefaultGatewayPolicy() Policy {
	p, err := NewPolicy(PolicyConfig{Schemes: []string{"https"}})
	if err != nil {
		panic("destination: gateway default policy invalid: " + err.Error())
	}
	return p
}
