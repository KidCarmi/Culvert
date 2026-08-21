package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func jwkNode(t *testing.T, m map[string]any) *canonical.Node {
	t.Helper()
	b, _ := json.Marshal(m)
	n, err := canonical.Decode(b, canonical.Bounds{MaxBytes: 8192, MaxDepth: 8, MaxObjectMembers: 16, MaxArrayElements: 8, MaxStringBytes: 4096})
	if err != nil {
		t.Fatalf("decode jwk: %v", err)
	}
	return n
}

func TestES256SignVerify(t *testing.T) {
	p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := []byte("header.payload")
	h := sha256.Sum256(msg)
	r, s, _ := ecdsa.Sign(rand.Reader, p, h[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	if err := Verify(ES256, &p.PublicKey, msg, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// A tampered message fails.
	if err := Verify(ES256, &p.PublicKey, []byte("tampered"), sig); mcperr.ReasonOf(err) != mcperr.ReasonSignatureInvalid {
		t.Fatalf("tampered must fail signature: %v", err)
	}
}

func TestAlgorithmConfusionRejected(t *testing.T) {
	p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// An EC key presented for RS256 must be rejected (confusion), not verified.
	if got := mcperr.ReasonOf(Verify(RS256, &p.PublicKey, []byte("m"), make([]byte, 64))); got != mcperr.ReasonUnsupportedAlgorithm {
		t.Fatalf("EC key for RS256 must be unsupported_algorithm, got %v", got)
	}
	// alg=none is not in the allowlist.
	if !SupportedAlg(ES256) || SupportedAlg("none") || SupportedAlg("HS256") || SupportedAlg("") {
		t.Fatal("allowlist wrong")
	}
}

func TestParsePublicJWKRejectsPrivate(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// A JWK carrying private material "d" must be rejected.
	n := jwkNode(t, map[string]any{"kty": "OKP", "crv": "Ed25519", "x": B64URLEncode(pub), "d": "AAAA"})
	if got := mcperr.ReasonOf(func() error { _, e := ParsePublicJWK(n); return e }()); got != mcperr.ReasonDPoPMalformed {
		t.Fatalf("private jwk must be rejected, got %v", got)
	}
}

func TestThumbprintDeterministic(t *testing.T) {
	p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Same key, different member ORDER in the JWK object → same thumbprint.
	a := jwkNode(t, map[string]any{"kty": "EC", "crv": "P-256", "x": B64URLEncode(p.X.Bytes()), "y": B64URLEncode(p.Y.Bytes())})
	b := jwkNode(t, map[string]any{"y": B64URLEncode(p.Y.Bytes()), "x": B64URLEncode(p.X.Bytes()), "crv": "P-256", "kty": "EC"})
	ta, err := Thumbprint(a)
	if err != nil {
		t.Fatal(err)
	}
	tb, _ := Thumbprint(b)
	if ta != tb {
		t.Fatal("thumbprint depends on member order")
	}
}

// FuzzParsePublicJWK proves JWK parsing never panics and never accepts private
// material.
func FuzzParsePublicJWK(f *testing.F) {
	for _, s := range []string{`{"kty":"EC","crv":"P-256","x":"a","y":"b"}`, `{"kty":"OKP","crv":"Ed25519","x":"a"}`, `{"kty":"RSA"}`, `{}`} {
		f.Add([]byte(s))
	}
	b := canonical.Bounds{MaxBytes: 8192, MaxDepth: 8, MaxObjectMembers: 16, MaxArrayElements: 8, MaxStringBytes: 4096}
	f.Fuzz(func(t *testing.T, raw []byte) {
		n, err := canonical.Decode(raw, b)
		if err != nil {
			return
		}
		if _, hasD := n.Get("d"); hasD {
			if _, e := ParsePublicJWK(n); e == nil {
				t.Fatal("accepted a JWK with private material")
			}
		}
		_, _ = ParsePublicJWK(n)
		_, _ = Thumbprint(n)
	})
}
