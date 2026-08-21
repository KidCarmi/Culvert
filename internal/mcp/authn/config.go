// Package authn is the listener-independent MCP token-validation core for both
// capabilities. It validates JWTs against caller-supplied trusted keys and opaque
// tokens against caller-supplied introspection results, enforces issuer / audience
// (canonical Culvert resource) / scope / time / tenant / capability rules, and
// composes token validation, sender-constraint verification and principal
// resolution into an immutable identity context.
//
// It performs NO network I/O: no JWKS fetch, no HTTP introspection, no TLS
// handshake. Trusted keys, introspection results and observed TLS-binding material
// arrive as explicit inputs. It makes no allow/deny policy decision (PR-6) and
// never brokers a credential (PR-4) — after validation the consumer receives only
// the immutable identity.ResolvedContext, never a raw token.
package authn

import (
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// CapabilityAuthConfig is the immutable, validated auth configuration for ONE
// capability. Management and Gateway carry INDEPENDENT configs; a credential,
// scope or resource for one must never validate for the other. All fields are
// caller-supplied trusted configuration.
type CapabilityAuthConfig struct {
	capability        protocol.Capability
	trustedIssuers    map[string]struct{}
	acceptedClientIDs map[string]struct{}
	canonicalResource string // exact expected audience/resource (e.g. /mcp/management or /mcp/gateway/<id>)
	requiredScopes    map[string]struct{}
	allowedScopes     map[string]struct{} // superset that may appear; others are ignored (not rejected) unless blanket/wildcard
	wildcardAllowed   map[string]struct{} // the ONLY wildcard scopes explicitly permitted
	senderProfile     senderconstraint.Profile
	minAssurance      identity.AssuranceLevel
	lim               limits.AuthLimits
}

// Capability returns the surface this config governs.
func (c CapabilityAuthConfig) Capability() protocol.Capability { return c.capability }

// CanonicalResource returns the exact expected canonical Culvert resource.
func (c CapabilityAuthConfig) CanonicalResource() string { return c.canonicalResource }

// SenderProfile returns the required sender-constraint profile.
func (c CapabilityAuthConfig) SenderProfile() senderconstraint.Profile { return c.senderProfile }

// Limits returns the auth bounds.
func (c CapabilityAuthConfig) Limits() limits.AuthLimits { return c.lim }

// CapabilityConfigInput is the mutable input to NewCapabilityConfig.
type CapabilityConfigInput struct {
	Capability        protocol.Capability
	TrustedIssuers    []string
	AcceptedClientIDs []string
	CanonicalResource string
	RequiredScopes    []string
	AllowedScopes     []string // optional additional scopes that may appear
	WildcardScopes    []string // the only wildcard scopes explicitly permitted
	SenderProfile     senderconstraint.Profile
	MinAssurance      identity.AssuranceLevel
	Limits            limits.AuthLimits
}

func cfgErr(detail string) error {
	return mcperr.New(mcperr.ReasonDelegationChainInvalid, "authn.config", detail)
}

// blanketScopes are never acceptable as required or allowed scopes: a shared
// cross-capability scope defeats the whole capability-isolation contract.
var blanketScopes = map[string]struct{}{
	"mcp": {}, "mcp.access": {}, "mcp.*": {}, "*": {}, "openid": {}, "all": {},
}

// NewCapabilityConfig validates the input into an immutable CapabilityAuthConfig.
// It rejects a missing canonical resource, an empty issuer/scope set, a blanket
// scope, a wildcard scope not in the explicit wildcard allowlist, and a
// fail-open (zero) sender profile.
func NewCapabilityConfig(in CapabilityConfigInput) (CapabilityAuthConfig, error) {
	if in.CanonicalResource == "" {
		return CapabilityAuthConfig{}, cfgErr("canonical resource is required")
	}
	if len(in.TrustedIssuers) == 0 {
		return CapabilityAuthConfig{}, cfgErr("at least one trusted issuer is required")
	}
	if len(in.RequiredScopes) == 0 {
		return CapabilityAuthConfig{}, cfgErr("at least one required scope is required (no blanket access)")
	}
	if in.SenderProfile == senderconstraint.ProfileUnset {
		return CapabilityAuthConfig{}, cfgErr("sender-constraint profile must be set (the zero profile fails closed)")
	}
	// At least one EFFECTIVE accepted client id is required. An empty allowlist (or
	// one made of only empty strings, which toSet drops) would silently accept every
	// client_id, disabling the Management/Gateway client-registration separation —
	// fail closed instead.
	if len(toSet(in.AcceptedClientIDs)) == 0 {
		return CapabilityAuthConfig{}, cfgErr("at least one accepted client id is required (client-registration separation)")
	}
	cfg := CapabilityAuthConfig{
		capability:        in.Capability,
		trustedIssuers:    toSet(in.TrustedIssuers),
		acceptedClientIDs: toSet(in.AcceptedClientIDs),
		canonicalResource: in.CanonicalResource,
		requiredScopes:    toSet(in.RequiredScopes),
		allowedScopes:     toSet(in.AllowedScopes),
		wildcardAllowed:   toSet(in.WildcardScopes),
		senderProfile:     in.SenderProfile,
		minAssurance:      in.MinAssurance,
		lim:               in.Limits,
	}
	for s := range cfg.requiredScopes {
		if _, bad := blanketScopes[s]; bad {
			return CapabilityAuthConfig{}, cfgErr("blanket/shared scope is not permitted: " + mcperr.Sanitize(s, 64))
		}
	}
	// Every required scope is implicitly allowed.
	for s := range cfg.requiredScopes {
		cfg.allowedScopes[s] = struct{}{}
	}
	return cfg, nil
}

// ConfigSet holds the two INDEPENDENT capability configs and proves, at
// construction, that Management and Gateway do not overlap on any identity-bearing
// value (issuer∩clientID∩resource∩scope). An overlap that violates the accepted
// separation contract fails construction.
type ConfigSet struct {
	mgmt    CapabilityAuthConfig
	gateway CapabilityAuthConfig
}

// NewConfigSet validates the two configs and their non-overlap.
func NewConfigSet(mgmt, gateway CapabilityAuthConfig) (*ConfigSet, error) {
	if mgmt.capability != protocol.Management {
		return nil, cfgErr("management config is not the Management capability")
	}
	if gateway.capability != protocol.Gateway {
		return nil, cfgErr("gateway config is not the Gateway capability")
	}
	if mgmt.canonicalResource == gateway.canonicalResource {
		return nil, cfgErr("management and gateway share a canonical resource")
	}
	if overlaps(mgmt.requiredScopes, gateway.requiredScopes) || overlaps(mgmt.allowedScopes, gateway.allowedScopes) {
		return nil, cfgErr("management and gateway share a scope (capability isolation violated)")
	}
	// Issuers MAY be shared (one IdP can serve both), but a client id must not be
	// accepted by both capabilities — a single client is scoped to one surface.
	if overlaps(mgmt.acceptedClientIDs, gateway.acceptedClientIDs) {
		return nil, cfgErr("management and gateway accept a shared client id")
	}
	return &ConfigSet{mgmt: mgmt, gateway: gateway}, nil
}

// For returns the config for a capability.
func (s *ConfigSet) For(c protocol.Capability) CapabilityAuthConfig {
	if c == protocol.Management {
		return s.mgmt
	}
	return s.gateway
}

func toSet(xs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		if x != "" {
			m[x] = struct{}{}
		}
	}
	return m
}

func overlaps(a, b map[string]struct{}) bool {
	for k := range a {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}
