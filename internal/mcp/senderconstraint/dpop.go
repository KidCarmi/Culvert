package senderconstraint

import (
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/jose"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// DPoPInput is the explicit material for one DPoP verification. The access token
// is supplied only to compute and compare `ath`; it is never retained. All request
// binding (method/URI/nonce) and the token's confirmation thumbprint (cnf.jkt) are
// caller-supplied — no network I/O.
type DPoPInput struct {
	Capability  protocol.Capability
	ProofJWT    string // the DPoP proof compact JWS
	HTTPMethod  string // expected htm (exact)
	HTTPURI     string // expected htu (exact, canonical)
	AccessToken string // to compute ath; NEVER stored
	ExpectedJKT string // the access token's cnf.jkt; the proof key must match
	Issuer      string // for the replay partition
	Client      string // for the replay partition
	Nonce       string // required server nonce; empty ⇒ no nonce required
}

// DPoPResult carries the verified proof-key thumbprint (jkt) for the identity
// context. It contains no key material and no token.
type DPoPResult struct {
	Thumbprint string
}

func dpopMalformed(detail string) error {
	return mcperr.New(mcperr.ReasonDPoPMalformed, "senderconstraint.dpop", detail)
}

func dpopBinding(detail string) error {
	return mcperr.New(mcperr.ReasonDPoPBindingMismatch, "senderconstraint.dpop", detail)
}

// VerifyDPoP verifies a DPoP proof against the request and the access token, and
// records the proof jti in the replay cache. It validates: proof type dpop+jwt;
// supported asymmetric alg; embedded PUBLIC jwk (no private material); signature;
// exact htm/htu; iat within the configured window; non-empty jti; ath == the hash
// of the presented access token; the proof-key thumbprint == the token's cnf.jkt;
// and the optional nonce. A replayed jti (or a full cache) fails closed.
func VerifyDPoP(in DPoPInput, cache *ReplayCache, lim limits.AuthLimits, now time.Time) (DPoPResult, error) {
	if len(in.ProofJWT) > lim.MaxTokenBytes() {
		return DPoPResult{}, mcperr.New(mcperr.ReasonResourceLimit, "senderconstraint.dpop", "proof too large")
	}
	header, claims, signingInput, sig, err := splitProof(in.ProofJWT, lim)
	if err != nil {
		return DPoPResult{}, err
	}
	if typ := stringClaim(header, "typ"); typ != "dpop+jwt" {
		return DPoPResult{}, dpopMalformed("proof typ is not dpop+jwt")
	}
	alg := stringClaim(header, "alg")
	if alg != jose.ES256 && alg != jose.EdDSA {
		return DPoPResult{}, mcperr.New(mcperr.ReasonUnsupportedAlgorithm, "senderconstraint.dpop", "unsupported DPoP alg")
	}
	jwkNode, ok := header.Get("jwk")
	if !ok {
		return DPoPResult{}, dpopMalformed("proof missing embedded jwk")
	}
	key, err := jose.ParsePublicJWK(jwkNode)
	if err != nil {
		return DPoPResult{}, err // includes private-material rejection
	}
	if err := jose.Verify(alg, key, signingInput, sig); err != nil {
		return DPoPResult{}, err
	}
	thumb, err := jose.Thumbprint(jwkNode)
	if err != nil {
		return DPoPResult{}, err
	}
	if err := checkProofClaims(in, claims, thumb, lim, now); err != nil {
		return DPoPResult{}, err
	}
	jti := stringClaim(claims, "jti")
	partKey := PartitionKey(in.Issuer, in.Client, thumb)
	if err := cache.CheckAndAdd(in.Capability, partKey, jti, lim.MaxDPoPProofAge()); err != nil {
		return DPoPResult{}, err
	}
	return DPoPResult{Thumbprint: thumb}, nil
}

// checkProofClaims validates the DPoP claim set (htm/htu/iat/jti/ath/nonce/cnf).
func checkProofClaims(in DPoPInput, claims *canonical.Node, thumb string, lim limits.AuthLimits, now time.Time) error {
	htm := stringClaim(claims, "htm")
	if !jose.ConstantTimeEqual(htm, in.HTTPMethod) {
		return dpopBinding("htm does not match the request method")
	}
	htu := stringClaim(claims, "htu")
	if htu != in.HTTPURI {
		return dpopBinding("htu does not match the request URI")
	}
	iat, ok := numberClaim(claims, "iat")
	if !ok {
		return dpopMalformed("proof missing iat")
	}
	skew := lim.MaxDPoPProofAge()
	iatT := time.Unix(iat, 0)
	if now.Sub(iatT) > skew || iatT.Sub(now) > skew {
		return dpopMalformed("proof iat outside the acceptance window")
	}
	if jti := stringClaim(claims, "jti"); jti == "" {
		return dpopMalformed("proof missing jti")
	}
	ath := stringClaim(claims, "ath")
	if ath == "" {
		return dpopBinding("proof missing ath")
	}
	if !jose.ConstantTimeEqual(ath, jose.SHA256B64URL([]byte(in.AccessToken))) {
		return dpopBinding("ath does not match the presented access token")
	}
	// The access token MUST itself be DPoP-bound: a proof only proves possession of
	// its OWN key, so without a token-carried cnf.jkt to bind that key to, any holder
	// of a bare bearer token could mint a proof. Fail closed on an unbound token (this
	// also blocks a DPoPOrMTLS downgrade — an mTLS-bound token, cnf.jkt empty, cannot
	// be routed through the DPoP path).
	if in.ExpectedJKT == "" {
		return dpopBinding("access token is not DPoP-bound (missing cnf.jkt); cannot sender-constrain")
	}
	if !jose.ConstantTimeEqual(thumb, in.ExpectedJKT) {
		return dpopBinding("proof key does not match the access-token cnf thumbprint")
	}
	if in.Nonce != "" {
		nonce := stringClaim(claims, "nonce")
		if !jose.ConstantTimeEqual(nonce, in.Nonce) {
			return mcperr.New(mcperr.ReasonDPoPNonce, "senderconstraint.dpop", "proof nonce missing or mismatched")
		}
	}
	return nil
}

// splitProof splits a compact proof JWS and strictly decodes its header and claim
// objects into canonical nodes (duplicate keys / invalid UTF-8 / surrogates
// rejected by canonical.Decode).
func splitProof(proof string, lim limits.AuthLimits) (header, claims *canonical.Node, signingInput, sig []byte, err error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return nil, nil, nil, nil, dpopMalformed("proof is not a compact JWS")
	}
	hb, err := jose.B64URLDecode(parts[0])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pb, err := jose.B64URLDecode(parts[1])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sig, err = jose.B64URLDecode(parts[2])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	b := claimBounds(lim)
	header, err = canonical.Decode(hb, b)
	if err != nil {
		return nil, nil, nil, nil, dpopMalformed("proof header is not strict JSON")
	}
	claims, err = canonical.Decode(pb, b)
	if err != nil {
		return nil, nil, nil, nil, dpopMalformed("proof claims are not strict JSON")
	}
	signingInput = []byte(parts[0] + "." + parts[1])
	return header, claims, signingInput, sig, nil
}

func claimBounds(lim limits.AuthLimits) canonical.Bounds {
	return canonical.Bounds{
		MaxBytes:         lim.MaxClaimBytes(),
		MaxDepth:         32,
		MaxObjectMembers: 256,
		MaxArrayElements: lim.MaxAudiences() + lim.MaxScopes() + 8,
		MaxStringBytes:   lim.MaxClaimBytes(),
	}
}

func stringClaim(n *canonical.Node, key string) string {
	v, ok := n.Get(key)
	if !ok || v.Kind != canonical.KindString {
		return ""
	}
	return v.Str
}

// numberClaim reads an integer numeric claim (e.g. a NumericDate), rejecting a
// non-integer or fractional token so a malformed numeric date cannot slip through.
func numberClaim(n *canonical.Node, key string) (int64, bool) {
	v, ok := n.Get(key)
	if !ok || v.Kind != canonical.KindNumber {
		return 0, false
	}
	return parseInt(v.Num)
}

// parseInt parses a base-10 integer token exactly (no exponent, no fraction).
func parseInt(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	neg := false
	i := 0
	if s[0] == '-' {
		neg = true
		i = 1
		if len(s) == 1 {
			return 0, false
		}
	}
	var v int64
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false // fractional/exponent/garbage ⇒ malformed numeric date
		}
		v = v*10 + int64(s[i]-'0')
	}
	if neg {
		v = -v
	}
	return v, true
}
