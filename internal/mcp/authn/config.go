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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"

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
	// cfgID is a stable content identity over every acceptance-relevant field. It
	// binds a VerifiedCredential to the exact config it was validated against, so a
	// credential verified for one capability can never be presented to
	// AuthenticateVerified under another (OVN-06).
	cfgID string
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
	cfg.cfgID = computeConfigID(cfg)
	return cfg, nil
}

// computeConfigID hashes every acceptance-relevant field into a stable identity.
// Length-framed segments prevent field-boundary collisions; set members are sorted
// so the identity is a function of CONTENT, not of map iteration order.
func computeConfigID(c CapabilityAuthConfig) string {
	h := sha256.New()
	seg := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	segSet := func(label string, m map[string]struct{}) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		seg(label)
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(keys)))
		h.Write(n[:])
		for _, k := range keys {
			seg(k)
		}
	}
	seg("cap:" + c.capability.String())
	seg("res:" + c.canonicalResource)
	segSet("iss", c.trustedIssuers)
	segSet("cli", c.acceptedClientIDs)
	segSet("req", c.requiredScopes)
	segSet("alw", c.allowedScopes)
	segSet("wld", c.wildcardAllowed)
	h.Write([]byte{byte(c.senderProfile), byte(c.minAssurance)})
	// The AUTH LIMITS are part of the identity, not incidental tuning. They decide
	// how strictly a credential is parsed and how much of it is accepted —
	// MaxTokenBytes, MaxClaimBytes, MaxScopes and MaxAudiences all gate validation,
	// and the temporal bounds gate the lifetime checks. Omitting them let two configs
	// that differ ONLY in strictness share an id, which is exactly the case the id
	// exists to refuse: a credential validated under the permissive one would be
	// redeemable under the stricter one, where AuthenticateVerified re-checks time
	// and nothing else. Every accessor is included, in a fixed order, so adding a
	// limit without adding it here is the only way to reintroduce the gap.
	// Fed through seg as a decimal string rather than a fixed-width binary word: the
	// int64->uint64 conversion that would need is a gosec G115 overflow conversion,
	// and suppressing it would be suppressing a real question (these are durations
	// and counts, non-negative by construction today, but nothing in the type says
	// so). A length-framed decimal is just as canonical and just as collision-safe,
	// and this runs once per config construction, never on the request path.
	num := func(v int64) { seg(strconv.FormatInt(v, 10)) }
	seg("lim")
	num(int64(c.lim.MaxTokenTTL()))
	num(int64(c.lim.ClockSkew()))
	num(int64(c.lim.MaxFutureNbf()))
	num(int64(c.lim.MaxAuthAge()))
	num(int64(c.lim.MaxDPoPProofAge()))
	num(int64(c.lim.NonceLifetime()))
	num(int64(c.lim.MaxReplayEntries()))
	num(int64(c.lim.MaxReplayPerPart()))
	num(int64(c.lim.MaxTokenBytes()))
	num(int64(c.lim.MaxClaimBytes()))
	num(int64(c.lim.MaxScopes()))
	num(int64(c.lim.MaxAudiences()))
	return hex.EncodeToString(h.Sum(nil))
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

// MinAssurance returns the capability's minimum-assurance floor. It is exposed so a
// composition root that knows its own SUBJECT MODEL can prove the (profile, floor)
// pair is satisfiable before it binds a listener — authn itself cannot, because an
// attested workload reaches High under any profile (see effectiveAssurance).
func (c CapabilityAuthConfig) MinAssurance() identity.AssuranceLevel { return c.minAssurance }
