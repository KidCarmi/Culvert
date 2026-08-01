package authn

import (
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/jose"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// ValidateJWT verifies a compact JWT against the capability config and the
// caller-supplied trusted keys, and returns its normalized Claims. It validates
// the compact shape, the signing-algorithm allowlist (rejecting none/HMAC/unknown
// and algorithm confusion), the signature, and then every claim
// (issuer/audience/time/TTL/scope/tenant/subject/client). It performs no network
// I/O. The raw token is never returned or retained.
func ValidateJWT(token string, cfg CapabilityAuthConfig, keys KeyResolver, now time.Time) (*Claims, error) {
	lim := cfg.lim
	if token == "" {
		return nil, mcperr.New(mcperr.ReasonCredentialMissing, "authn.jwt", "empty token")
	}
	if len(token) > lim.MaxTokenBytes() {
		return nil, mcperr.New(mcperr.ReasonResourceLimit, "authn.jwt", "token too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, mcperr.New(mcperr.ReasonMalformedToken, "authn.jwt", "not a compact JWT")
	}
	header, err := decodeSegment(parts[0], lim)
	if err != nil {
		return nil, err
	}
	alg, ok := strClaim(header, "alg")
	if !ok {
		return nil, mcperr.New(mcperr.ReasonUnsupportedAlgorithm, "authn.jwt", "missing alg")
	}
	if !jose.SupportedAlg(alg) {
		return nil, mcperr.New(mcperr.ReasonUnsupportedAlgorithm, "authn.jwt", "alg not in allowlist (none/HMAC/unknown rejected)")
	}
	kid, _ := strClaim(header, "kid")
	payload, err := decodeSegment(parts[1], lim)
	if err != nil {
		return nil, err
	}
	claims, err := extractClaims(payload, lim)
	if err != nil {
		return nil, err
	}
	if claims.Issuer == "" {
		return nil, mcperr.New(mcperr.ReasonIssuerRejected, "authn.jwt", "missing issuer")
	}
	key, err := keys.ResolveKey(claims.Issuer, kid, alg)
	if err != nil {
		return nil, err // unknown key id / untrusted issuer key
	}
	sig, err := jose.B64URLDecode(parts[2])
	if err != nil {
		return nil, err
	}
	if err := jose.Verify(alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, err // signature invalid / algorithm confusion
	}
	if err := validateClaims(claims, cfg, now); err != nil {
		return nil, err
	}
	return claims, nil
}

// decodeSegment base64url-decodes a compact segment and strictly decodes its JSON
// object (canonical.Decode rejects duplicate keys / invalid UTF-8 / surrogates).
func decodeSegment(seg string, lim limits.AuthLimits) (*canonical.Node, error) {
	raw, err := jose.B64URLDecode(seg)
	if err != nil {
		return nil, err
	}
	n, err := canonical.Decode(raw, jwtClaimBounds(lim))
	if err != nil {
		return nil, mcperr.New(mcperr.ReasonMalformedToken, "authn.jwt", "segment is not strict JSON")
	}
	return n, nil
}

func jwtClaimBounds(lim limits.AuthLimits) canonical.Bounds {
	return canonical.Bounds{
		MaxBytes:         lim.MaxClaimBytes(),
		MaxDepth:         32,
		MaxObjectMembers: 256,
		MaxArrayElements: lim.MaxAudiences() + lim.MaxScopes() + 8,
		MaxStringBytes:   lim.MaxClaimBytes(),
	}
}
