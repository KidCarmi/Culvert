package authn

import (
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Claims is the normalized, typed view of a token's claim set (JWT payload or
// opaque introspection metadata). It is extracted via ONE strict decode path
// (canonical.Decode → *Node), so duplicate keys, invalid UTF-8 and escaped
// unpaired surrogates are rejected before any claim is read. It never carries the
// raw token.
type Claims struct {
	Issuer      string
	Audiences   []string
	Subject     string
	ClientID    string
	Scopes      []string
	Tenant      string
	Expiry      int64
	HasExpiry   bool
	NotBefore   int64
	HasNbf      bool
	IssuedAt    int64
	HasIat      bool
	AuthTime    int64
	HasAuthTime bool
	CnfJKT      string // cnf.jkt (DPoP)
	CnfX5T      string // cnf["x5t#S256"] (mTLS)
	HasCnf      bool
}

func malformedToken(detail string) error {
	return mcperr.New(mcperr.ReasonMalformedToken, "authn.claims", detail)
}

// tenantClaimKeys is the ordered set of claim names consulted for the tenant, in
// preference order. A token must carry exactly one; the first found wins.
var tenantClaimKeys = []string{"tenant", "tid", "tenant_id"}

// extractClaims reads a normalized Claims from a strict claims node. It enforces
// the scope/audience counts against the bounds and rejects malformed numeric
// dates. It does NOT apply policy (issuer/audience/scope acceptance) — that is the
// validator's job.
func extractClaims(n *canonical.Node, lim limits.AuthLimits) (*Claims, error) {
	if n == nil || n.Kind != canonical.KindObject {
		return nil, malformedToken("claims are not a JSON object")
	}
	c := &Claims{}
	c.Issuer, _ = strClaim(n, "iss")
	c.Subject, _ = strClaim(n, "sub")
	if cid, ok := strClaim(n, "client_id"); ok {
		c.ClientID = cid
	} else if azp, ok := strClaim(n, "azp"); ok {
		c.ClientID = azp
	}
	for _, k := range tenantClaimKeys {
		if t, ok := strClaim(n, k); ok {
			c.Tenant = t
			break
		}
	}
	auds, err := extractAudiences(n, lim)
	if err != nil {
		return nil, err
	}
	c.Audiences = auds
	scopes, err := extractScopes(n, lim)
	if err != nil {
		return nil, err
	}
	c.Scopes = scopes
	if err := extractDates(n, c); err != nil {
		return nil, err
	}
	if err := extractCnf(n, c); err != nil {
		return nil, err
	}
	return c, nil
}

// extractAudiences reads `aud` as either a string or an array of strings.
func extractAudiences(n *canonical.Node, lim limits.AuthLimits) ([]string, error) {
	v, ok := n.Get("aud")
	if !ok {
		return nil, nil
	}
	switch v.Kind {
	case canonical.KindString:
		return []string{v.Str}, nil
	case canonical.KindArray:
		if len(v.Arr) > lim.MaxAudiences() {
			return nil, mcperr.New(mcperr.ReasonResourceLimit, "authn.claims", "too many audiences")
		}
		out := make([]string, 0, len(v.Arr))
		for _, e := range v.Arr {
			if e.Kind != canonical.KindString {
				return nil, malformedToken("aud array element is not a string")
			}
			out = append(out, e.Str)
		}
		return out, nil
	default:
		return nil, malformedToken("aud is neither a string nor an array")
	}
}

// extractScopes reads OAuth scopes from `scope` (space-delimited string, RFC 8693)
// or `scp` (array of strings). Exact, case-sensitive tokens; empty tokens dropped.
func extractScopes(n *canonical.Node, lim limits.AuthLimits) ([]string, error) {
	if v, ok := n.Get("scope"); ok {
		if v.Kind != canonical.KindString {
			return nil, malformedToken("scope is not a string")
		}
		return boundScopes(strings.Fields(v.Str), lim)
	}
	if v, ok := n.Get("scp"); ok {
		if v.Kind != canonical.KindArray {
			return nil, malformedToken("scp is not an array")
		}
		out := make([]string, 0, len(v.Arr))
		for _, e := range v.Arr {
			if e.Kind != canonical.KindString {
				return nil, malformedToken("scp element is not a string")
			}
			out = append(out, e.Str)
		}
		return boundScopes(out, lim)
	}
	return nil, nil
}

func boundScopes(xs []string, lim limits.AuthLimits) ([]string, error) {
	if len(xs) > lim.MaxScopes() {
		return nil, mcperr.New(mcperr.ReasonResourceLimit, "authn.claims", "too many scopes")
	}
	return xs, nil
}

// extractDates reads the NumericDate claims exp/nbf/iat/auth_time as exact
// integers; a fractional or non-numeric date is malformed.
func extractDates(n *canonical.Node, c *Claims) error {
	if v, ok := intClaim(n, "exp"); ok {
		c.Expiry, c.HasExpiry = v, true
	} else if _, present := n.Get("exp"); present {
		return malformedToken("exp is not an integer NumericDate")
	}
	if v, ok := intClaim(n, "nbf"); ok {
		c.NotBefore, c.HasNbf = v, true
	} else if _, present := n.Get("nbf"); present {
		return malformedToken("nbf is not an integer NumericDate")
	}
	if v, ok := intClaim(n, "iat"); ok {
		c.IssuedAt, c.HasIat = v, true
	} else if _, present := n.Get("iat"); present {
		return malformedToken("iat is not an integer NumericDate")
	}
	if v, ok := intClaim(n, "auth_time"); ok {
		c.AuthTime, c.HasAuthTime = v, true
	} else if _, present := n.Get("auth_time"); present {
		return malformedToken("auth_time is not an integer NumericDate")
	}
	return nil
}

// extractCnf reads the sender-confirmation claim: cnf.jkt (DPoP) or cnf["x5t#S256"]
// (mTLS). Presenting BOTH is ambiguous and rejected.
func extractCnf(n *canonical.Node, c *Claims) error {
	cnf, ok := n.Get("cnf")
	if !ok {
		return nil
	}
	if cnf.Kind != canonical.KindObject {
		return malformedToken("cnf is not an object")
	}
	c.HasCnf = true
	c.CnfJKT, _ = strClaim(cnf, "jkt")
	c.CnfX5T, _ = strClaim(cnf, "x5t#S256")
	if c.CnfJKT != "" && c.CnfX5T != "" {
		return malformedToken("cnf carries both jkt and x5t#S256 (ambiguous confirmation method)")
	}
	return nil
}

func strClaim(n *canonical.Node, key string) (string, bool) {
	v, ok := n.Get(key)
	if !ok || v.Kind != canonical.KindString {
		return "", false
	}
	return v.Str, true
}

func intClaim(n *canonical.Node, key string) (int64, bool) {
	v, ok := n.Get(key)
	if !ok || v.Kind != canonical.KindNumber {
		return 0, false
	}
	return parseIntExact(v.Num)
}

// parseIntExact parses a base-10 integer token exactly (no exponent/fraction).
func parseIntExact(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	i, neg := 0, false
	if s[0] == '-' {
		neg, i = true, 1
		if len(s) == 1 {
			return 0, false
		}
	}
	var v int64
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		v = v*10 + int64(s[i]-'0')
	}
	if neg {
		v = -v
	}
	return v, true
}
