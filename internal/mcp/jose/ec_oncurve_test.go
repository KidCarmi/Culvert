package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"testing"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func p256Coord(i *big.Int) string {
	b := make([]byte, 32)
	i.FillBytes(b)
	return b64u(b)
}

// A JWK's x and y are attacker-supplied: a DPoP proof carries its own public key,
// and a JWKS document is fetched from a configured IdP. Accepting a point that is
// not on P-256 hands the verifier a key that was never validated, which is exactly
// what the Go 1.26 deprecation of ecdsa.PublicKey's X/Y fields warns about.
//
// The rejection existed but NOTHING pinned it, so a refactor of parseECPublic
// could have dropped it silently — including the refactor that replaced the
// crypto/ecdh round-trip with ecdsa.ParseUncompressedPublicKey. This is that pin.
func TestParseECPublic_RejectsOffCurvePoint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// A valid key must parse — otherwise the rejection below proves nothing.
	valid := jwkNode(t, map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": p256Coord(key.X), "y": p256Coord(key.Y),
	})
	if _, err := ParsePublicJWK(valid); err != nil {
		t.Fatalf("a valid P-256 JWK was rejected: %v", err)
	}

	// Perturbing y by one takes the point off the curve while keeping both
	// coordinates structurally well-formed 32-byte values.
	offY := new(big.Int).Add(key.Y, big.NewInt(1))
	offY.Mod(offY, elliptic.P256().Params().P)
	off := jwkNode(t, map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": p256Coord(key.X), "y": p256Coord(offY),
	})
	if _, err := ParsePublicJWK(off); err == nil {
		t.Fatal("an off-curve P-256 point was accepted as a public key")
	}
}

// The point at infinity (x = y = 0) is well-formed and on no useful curve point;
// accepting it would yield a degenerate key. ParseUncompressedPublicKey rejects it,
// and the previous crypto/ecdh path did too — this pins that neither regressed.
func TestParseECPublic_RejectsPointAtInfinity(t *testing.T) {
	zero := p256Coord(big.NewInt(0))
	n := jwkNode(t, map[string]any{"kty": "EC", "crv": "P-256", "x": zero, "y": zero})
	if _, err := ParsePublicJWK(n); err == nil {
		t.Fatal("the point at infinity was accepted as a public key")
	}
}

// An oversized coordinate must be refused before any curve arithmetic: a >32-byte
// value is not a P-256 coordinate however it reduces.
func TestParseECPublic_RejectsOversizedCoordinate(t *testing.T) {
	big33 := make([]byte, 33)
	for i := range big33 {
		big33[i] = 0xff
	}
	n := jwkNode(t, map[string]any{
		"kty": "EC", "crv": "P-256", "x": b64u(big33), "y": b64u(big33),
	})
	if _, err := ParsePublicJWK(n); err == nil {
		t.Fatal("an oversized EC coordinate was accepted")
	}
}
