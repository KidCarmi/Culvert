// Package jose is the listener-independent JWS/JWK primitive shared by the MCP
// token-validation (authn) and sender-constraint (DPoP) layers. It parses PUBLIC
// JWKs, verifies compact-JWS signatures against a supported asymmetric-algorithm
// allowlist with a strict key-type match (closing algorithm confusion), and
// computes RFC 7638 JWK thumbprints.
//
// It performs no network I/O and holds no private key material: ParsePublicJWK
// rejects any JWK carrying a private component. `alg=none`, HMAC, and any alg
// outside the allowlist are rejected — there is no symmetric path, so an
// asymmetric public key can never be coerced into an HMAC secret.
package jose

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"math/big"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Supported JWS algorithms (asymmetric only).
const (
	ES256 = "ES256" // ECDSA P-256 + SHA-256
	RS256 = "RS256" // RSASSA-PKCS1-v1_5 + SHA-256
	PS256 = "PS256" // RSASSA-PSS + SHA-256
	EdDSA = "EdDSA" // Ed25519
)

var supportedAlgs = map[string]struct{}{ES256: {}, RS256: {}, PS256: {}, EdDSA: {}}

// SupportedAlg reports whether alg is in the allowlist. `none`, HMAC (HS*) and any
// unknown/missing alg return false.
func SupportedAlg(alg string) bool {
	_, ok := supportedAlgs[alg]
	return ok
}

func malformed(detail string) error {
	return mcperr.New(mcperr.ReasonMalformedToken, "jose", detail)
}

func unsupportedAlg(detail string) error {
	return mcperr.New(mcperr.ReasonUnsupportedAlgorithm, "jose", detail)
}

// B64URLDecode decodes raw (unpadded) base64url.
func B64URLDecode(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, malformed("invalid base64url segment")
	}
	return b, nil
}

// B64URLEncode encodes raw (unpadded) base64url.
func B64URLEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// SHA256B64URL returns base64url(sha256(b)) — used for DPoP `ath` and for hashing
// tokens into a sanitized correlation digest.
func SHA256B64URL(b []byte) string {
	sum := sha256.Sum256(b)
	return B64URLEncode(sum[:])
}

// ParsePublicJWK parses a canonical JWK object node into a crypto.PublicKey. It
// supports EC P-256, RSA and OKP Ed25519, and REJECTS any JWK that carries a
// private component ("d"), so a proof/JWK can never smuggle private key material.
func ParsePublicJWK(n *canonical.Node) (crypto.PublicKey, error) {
	if n == nil || n.Kind != canonical.KindObject {
		return nil, malformed("jwk is not an object")
	}
	if _, hasPriv := n.Get("d"); hasPriv {
		return nil, mcperr.New(mcperr.ReasonDPoPMalformed, "jose", "jwk carries private key material")
	}
	kty, ok := stringMember(n, "kty")
	if !ok {
		return nil, malformed("jwk missing kty")
	}
	switch kty {
	case "EC":
		return parseECPublic(n)
	case "OKP":
		return parseOKPPublic(n)
	case "RSA":
		return parseRSAPublic(n)
	default:
		return nil, unsupportedAlg("unsupported jwk kty")
	}
}

func parseECPublic(n *canonical.Node) (crypto.PublicKey, error) {
	crv, _ := stringMember(n, "crv")
	if crv != "P-256" {
		return nil, unsupportedAlg("unsupported EC curve")
	}
	xb, err := coord(n, "x")
	if err != nil {
		return nil, err
	}
	yb, err := coord(n, "y")
	if err != nil {
		return nil, err
	}
	if len(xb) > 32 || len(yb) > 32 {
		return nil, malformed("EC coordinate too large for P-256")
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	// On-curve validation via crypto/ecdh (the non-deprecated path): build the
	// uncompressed SEC1 point and let NewPublicKey perform the on-curve check.
	pt := make([]byte, 1+32+32)
	pt[0] = 4
	x.FillBytes(pt[1:33])
	y.FillBytes(pt[33:])
	if _, err := ecdh.P256().NewPublicKey(pt); err != nil {
		return nil, malformed("EC point is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func parseOKPPublic(n *canonical.Node) (crypto.PublicKey, error) {
	crv, _ := stringMember(n, "crv")
	if crv != "Ed25519" {
		return nil, unsupportedAlg("unsupported OKP curve")
	}
	xb, err := coord(n, "x")
	if err != nil {
		return nil, err
	}
	if len(xb) != ed25519.PublicKeySize {
		return nil, malformed("bad Ed25519 public key length")
	}
	return ed25519.PublicKey(xb), nil
}

func parseRSAPublic(n *canonical.Node) (crypto.PublicKey, error) {
	nb, err := coord(n, "n")
	if err != nil {
		return nil, err
	}
	eb, err := coord(n, "e")
	if err != nil {
		return nil, err
	}
	if len(nb) < 256 { // reject < 2048-bit moduli
		return nil, unsupportedAlg("RSA modulus too small")
	}
	e := 0
	for _, c := range eb {
		e = e<<8 | int(c)
	}
	if e < 3 {
		return nil, malformed("bad RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

// Verify checks a compact-JWS signature over signingInput using key, dispatching
// by alg with a strict key-type match. A key whose type cannot serve alg (e.g. an
// RSA key presented for ES256) is an algorithm-confusion attempt and is rejected.
func Verify(alg string, key crypto.PublicKey, signingInput, sig []byte) error {
	if !SupportedAlg(alg) {
		return unsupportedAlg("algorithm not in allowlist")
	}
	digest := sha256.Sum256(signingInput)
	switch alg {
	case ES256:
		return verifyES256(key, digest[:], sig)
	case EdDSA:
		return verifyEd25519(key, signingInput, sig)
	case RS256:
		return verifyRS256(key, digest[:], sig)
	case PS256:
		return verifyPS256(key, digest[:], sig)
	default:
		return unsupportedAlg("algorithm not in allowlist")
	}
}

func sigInvalid() error {
	return mcperr.New(mcperr.ReasonSignatureInvalid, "jose", "signature verification failed")
}

func verifyES256(key crypto.PublicKey, digest, sig []byte) error {
	pk, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return unsupportedAlg("ES256 requires an EC key (algorithm confusion)")
	}
	if len(sig) != 64 {
		return malformed("ES256 signature length")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pk, digest, r, s) {
		return sigInvalid()
	}
	return nil
}

func verifyEd25519(key crypto.PublicKey, signingInput, sig []byte) error {
	pk, ok := key.(ed25519.PublicKey)
	if !ok {
		return unsupportedAlg("EdDSA requires an Ed25519 key (algorithm confusion)")
	}
	if !ed25519.Verify(pk, signingInput, sig) {
		return sigInvalid()
	}
	return nil
}

func verifyRS256(key crypto.PublicKey, digest, sig []byte) error {
	pk, ok := key.(*rsa.PublicKey)
	if !ok {
		return unsupportedAlg("RS256 requires an RSA key (algorithm confusion)")
	}
	if err := rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest, sig); err != nil {
		return sigInvalid()
	}
	return nil
}

func verifyPS256(key crypto.PublicKey, digest, sig []byte) error {
	pk, ok := key.(*rsa.PublicKey)
	if !ok {
		return unsupportedAlg("PS256 requires an RSA key (algorithm confusion)")
	}
	if err := rsa.VerifyPSS(pk, crypto.SHA256, digest, sig, nil); err != nil {
		return sigInvalid()
	}
	return nil
}

// Thumbprint computes the RFC 7638 JWK SHA-256 thumbprint (base64url) of a public
// JWK. The required members are emitted in lexicographic order with no whitespace,
// deterministically, so the same key always yields the same thumbprint.
func Thumbprint(n *canonical.Node) (string, error) {
	if n == nil || n.Kind != canonical.KindObject {
		return "", malformed("jwk is not an object")
	}
	kty, ok := stringMember(n, "kty")
	if !ok {
		return "", malformed("jwk missing kty")
	}
	var canonicalJSON string
	switch kty {
	case "EC":
		crv, _ := stringMember(n, "crv")
		x, _ := stringMember(n, "x")
		y, _ := stringMember(n, "y")
		if crv == "" || x == "" || y == "" {
			return "", malformed("EC jwk missing required members")
		}
		canonicalJSON = `{"crv":` + q(crv) + `,"kty":"EC","x":` + q(x) + `,"y":` + q(y) + `}`
	case "OKP":
		crv, _ := stringMember(n, "crv")
		x, _ := stringMember(n, "x")
		if crv == "" || x == "" {
			return "", malformed("OKP jwk missing required members")
		}
		canonicalJSON = `{"crv":` + q(crv) + `,"kty":"OKP","x":` + q(x) + `}`
	case "RSA":
		e, _ := stringMember(n, "e")
		nn, _ := stringMember(n, "n")
		if e == "" || nn == "" {
			return "", malformed("RSA jwk missing required members")
		}
		canonicalJSON = `{"e":` + q(e) + `,"kty":"RSA","n":` + q(nn) + `}`
	default:
		return "", unsupportedAlg("unsupported jwk kty for thumbprint")
	}
	return SHA256B64URL([]byte(canonicalJSON)), nil
}

// ConstantTimeEqual reports whether two strings are equal in constant time.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func stringMember(n *canonical.Node, key string) (string, bool) {
	v, ok := n.Get(key)
	if !ok || v.Kind != canonical.KindString {
		return "", false
	}
	return v.Str, true
}

func coord(n *canonical.Node, key string) ([]byte, error) {
	s, ok := stringMember(n, key)
	if !ok {
		return nil, malformed("jwk missing member " + key)
	}
	return B64URLDecode(s)
}

// q emits a minimal JSON string literal for a base64url/ASCII value (no escaping
// needed — JWK member values are base64url or short curve names).
func q(s string) string { return `"` + s + `"` }
