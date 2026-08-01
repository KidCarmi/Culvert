package authn

import (
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// validateClaims applies the capability policy to a normalized claim set (shared by
// the JWT and opaque paths): trusted issuer, finite non-expired lifetime within the
// TTL bound, canonical audience, required subject/client/tenant, and required
// scopes with no blanket/unpermitted-wildcard scope. It makes NO allow/deny method
// decision (PR-6); it establishes authenticated entitlement metadata only.
func validateClaims(c *Claims, cfg CapabilityAuthConfig, now time.Time) error {
	if _, ok := cfg.trustedIssuers[c.Issuer]; !ok {
		return mcperr.New(mcperr.ReasonIssuerRejected, "authn.validate", "issuer not trusted for this capability")
	}
	if err := validateTime(c, cfg, now); err != nil {
		return err
	}
	if err := validateAudience(c, cfg); err != nil {
		return err
	}
	if c.Subject == "" {
		return mcperr.New(mcperr.ReasonDelegationChainInvalid, "authn.validate", "missing subject")
	}
	if c.ClientID == "" {
		return mcperr.New(mcperr.ReasonDelegationChainInvalid, "authn.validate", "missing client")
	}
	if len(cfg.acceptedClientIDs) > 0 {
		if _, ok := cfg.acceptedClientIDs[c.ClientID]; !ok {
			return mcperr.New(mcperr.ReasonCapabilityMismatch, "authn.validate", "client not accepted by this capability")
		}
	}
	if c.Tenant == "" {
		return mcperr.New(mcperr.ReasonTenantMismatch, "authn.validate", "missing tenant")
	}
	return validateScopes(c, cfg)
}

// validateTime enforces finite expiry, non-expiry (with skew), not-yet-valid,
// future-nbf bound, and the maximum token lifetime.
func validateTime(c *Claims, cfg CapabilityAuthConfig, now time.Time) error {
	lim := cfg.lim
	if !c.HasExpiry {
		return mcperr.New(mcperr.ReasonTokenExpired, "authn.validate", "token has no finite expiry")
	}
	skew := lim.ClockSkew()
	exp := time.Unix(c.Expiry, 0)
	if now.After(exp.Add(skew)) {
		return mcperr.New(mcperr.ReasonTokenExpired, "authn.validate", "token expired")
	}
	if c.HasNbf {
		nbf := time.Unix(c.NotBefore, 0)
		if now.Before(nbf.Add(-skew)) {
			return mcperr.New(mcperr.ReasonTokenNotYetValid, "authn.validate", "token not yet valid")
		}
		if nbf.Sub(now) > lim.MaxFutureNbf() {
			return mcperr.New(mcperr.ReasonTokenTTLExceeded, "authn.validate", "nbf too far in the future")
		}
	}
	var lifetime time.Duration
	switch {
	case c.HasIat:
		iat := time.Unix(c.IssuedAt, 0)
		// An issuance time in the future (beyond skew) is invalid regardless of nbf:
		// without this, a token whose iat/exp are years ahead but a few minutes apart
		// would pass both the expiry and max-TTL checks and be usable immediately.
		if iat.Sub(now) > skew {
			return mcperr.New(mcperr.ReasonTokenNotYetValid, "authn.validate", "token issued in the future beyond clock skew")
		}
		if exp.Before(iat) {
			return mcperr.New(mcperr.ReasonTokenTTLExceeded, "authn.validate", "expiry precedes issuance")
		}
		lifetime = exp.Sub(iat)
	default:
		lifetime = exp.Sub(now)
	}
	if lifetime > lim.MaxTokenTTL() {
		return mcperr.New(mcperr.ReasonTokenTTLExceeded, "authn.validate", "token lifetime exceeds the maximum")
	}
	return nil
}

// validateAudience requires the effective audience to be exactly the capability's
// canonical Culvert resource. A missing audience, a foreign audience (upstream URL,
// SWG client id, the other capability's resource) is rejected.
func validateAudience(c *Claims, cfg CapabilityAuthConfig) error {
	if len(c.Audiences) == 0 {
		return mcperr.New(mcperr.ReasonAudienceMissing, "authn.validate", "token carries no audience")
	}
	// The effective audience set must contain ONLY the canonical Culvert resource.
	// A token co-issued for Culvert AND an upstream/unrelated service is an ambiguous
	// multi-audience credential reusable across trust boundaries, so a foreign
	// co-audience is rejected even when the canonical resource is also present
	// (duplicate copies of the canonical resource are fine).
	found := false
	for _, a := range c.Audiences {
		if a == cfg.canonicalResource {
			found = true
			continue
		}
		return mcperr.New(mcperr.ReasonAudienceRejected, "authn.validate", "token carries a foreign co-audience alongside the canonical Culvert resource")
	}
	if !found {
		return mcperr.New(mcperr.ReasonAudienceRejected, "authn.validate", "audience is not the canonical Culvert resource for this capability")
	}
	return nil
}

// validateScopes requires every configured required scope to be present, and
// rejects any blanket scope or any wildcard scope not in the explicit allowlist.
// A token bearing only the OTHER capability's scopes fails the required-scope
// check — the cross-capability scope rejection.
func validateScopes(c *Claims, cfg CapabilityAuthConfig) error {
	present := make(map[string]struct{}, len(c.Scopes))
	for _, s := range c.Scopes {
		if s == "" || hasControl(s) {
			return mcperr.New(mcperr.ReasonScopeMissing, "authn.validate", "malformed scope token")
		}
		if _, blanket := blanketScopes[s]; blanket {
			return mcperr.New(mcperr.ReasonScopeMissing, "authn.validate", "blanket scope is not permitted")
		}
		if strings.HasSuffix(s, "*") {
			if _, ok := cfg.wildcardAllowed[s]; !ok {
				return mcperr.New(mcperr.ReasonScopeMissing, "authn.validate", "wildcard scope is not in the accepted allowlist")
			}
		}
		present[s] = struct{}{}
	}
	for req := range cfg.requiredScopes {
		if _, ok := present[req]; !ok {
			return mcperr.New(mcperr.ReasonScopeMissing, "authn.validate", "a required scope is missing")
		}
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
