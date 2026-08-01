package authn

import (
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// IntrospectionResult is normalized RFC 7662-style opaque-token metadata supplied
// by the caller. PR-3 validates this metadata; it never performs HTTP
// introspection. The caller's Introspector returns already-obtained results.
type IntrospectionResult struct {
	Active    bool
	Issuer    string
	Audiences []string
	Subject   string
	ClientID  string
	Scope     string // space-delimited scopes (RFC 7662 `scope`)
	Tenant    string
	Expiry    int64
	HasExpiry bool
	NotBefore int64
	HasNbf    bool
	IssuedAt  int64
	HasIat    bool
	CnfJKT    string
	CnfX5T    string
}

// Introspector returns normalized metadata for an opaque token. It performs NO
// network I/O — the caller-supplied implementation returns metadata it has already
// obtained. Remote introspection, caching and revocation distribution are out of
// scope for PR-3.
type Introspector interface {
	Introspect(token string) (IntrospectionResult, error)
}

// ValidateOpaque introspects an opaque token (via the caller's adapter) and
// validates the returned metadata against the capability config. An inactive or
// malformed result is rejected.
func ValidateOpaque(token string, cfg CapabilityAuthConfig, in Introspector, now time.Time) (*Claims, error) {
	if token == "" {
		return nil, mcperr.New(mcperr.ReasonCredentialMissing, "authn.opaque", "empty token")
	}
	if len(token) > cfg.lim.MaxTokenBytes() {
		return nil, mcperr.New(mcperr.ReasonResourceLimit, "authn.opaque", "token too large")
	}
	res, err := in.Introspect(token)
	if err != nil {
		return nil, mcperr.New(mcperr.ReasonMalformedToken, "authn.opaque", "introspection failed")
	}
	return ValidateIntrospection(res, cfg, now)
}

// ValidateIntrospection validates an already-obtained introspection result.
func ValidateIntrospection(res IntrospectionResult, cfg CapabilityAuthConfig, now time.Time) (*Claims, error) {
	if !res.Active {
		return nil, mcperr.New(mcperr.ReasonInactiveToken, "authn.opaque", "introspection reports the token inactive")
	}
	if res.CnfJKT != "" && res.CnfX5T != "" {
		return nil, mcperr.New(mcperr.ReasonMalformedToken, "authn.opaque", "cnf carries both jkt and x5t#S256")
	}
	scopes := strings.Fields(res.Scope)
	if len(scopes) > cfg.lim.MaxScopes() {
		return nil, mcperr.New(mcperr.ReasonResourceLimit, "authn.opaque", "too many scopes")
	}
	if len(res.Audiences) > cfg.lim.MaxAudiences() {
		return nil, mcperr.New(mcperr.ReasonResourceLimit, "authn.opaque", "too many audiences")
	}
	c := &Claims{
		Issuer:    res.Issuer,
		Audiences: res.Audiences,
		Subject:   res.Subject,
		ClientID:  res.ClientID,
		Scopes:    scopes,
		Tenant:    res.Tenant,
		Expiry:    res.Expiry,
		HasExpiry: res.HasExpiry,
		NotBefore: res.NotBefore,
		HasNbf:    res.HasNbf,
		IssuedAt:  res.IssuedAt,
		HasIat:    res.HasIat,
		CnfJKT:    res.CnfJKT,
		CnfX5T:    res.CnfX5T,
		HasCnf:    res.CnfJKT != "" || res.CnfX5T != "",
	}
	if err := validateClaims(c, cfg, now); err != nil {
		return nil, err
	}
	return c, nil
}
