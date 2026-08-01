package authn

import (
	"crypto"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// KeyResolver resolves a JWS verification key for a token. It performs NO network
// I/O (no JWKS fetch): implementations serve caller-supplied trusted keys only.
type KeyResolver interface {
	// ResolveKey returns the public key for (issuer, kid, alg), or an error if no
	// trusted key matches. It must never fetch over the network.
	ResolveKey(issuer, kid, alg string) (crypto.PublicKey, error)
}

// StaticKeyResolver is a fixed, in-memory trusted-key set keyed by (issuer, kid).
// It is the caller-supplied trust anchor for JWT validation — the only source of
// verification keys in this listener-independent PR.
type StaticKeyResolver struct {
	keys map[string]crypto.PublicKey // key = issuer\x00kid
}

// NewStaticKeyResolver returns an empty resolver.
func NewStaticKeyResolver() *StaticKeyResolver {
	return &StaticKeyResolver{keys: make(map[string]crypto.PublicKey)}
}

// Add registers a trusted public key for (issuer, kid).
func (r *StaticKeyResolver) Add(issuer, kid string, key crypto.PublicKey) {
	r.keys[issuer+"\x00"+kid] = key
}

// ResolveKey returns the trusted key for (issuer, kid), or a signature-invalid
// error when none is registered (an unknown key id cannot verify a signature).
func (r *StaticKeyResolver) ResolveKey(issuer, kid, _ string) (crypto.PublicKey, error) {
	if k, ok := r.keys[issuer+"\x00"+kid]; ok {
		return k, nil
	}
	return nil, mcperr.New(mcperr.ReasonSignatureInvalid, "authn.keys", "no trusted key for issuer/kid")
}
