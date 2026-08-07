package mcpacceptance

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// b64u is base64url without padding (JOSE).
func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mintES256 signs a JWT with the ES256 key. header/claims are JSON objects. The
// signature is raw R||S (64 bytes), exactly as the MCP JWT validator expects.
func mintES256(signer *ecdsa.PrivateKey, header, claims map[string]any) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64u(hb) + "." + b64u(cb)
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, signer, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64u(sig), nil
}

// tokenParams bounds one minted bearer.
type tokenParams struct {
	issuer    string
	clientID  string
	audience  string
	scope     string
	tenant    string
	subject   string
	kid       string
	notBefore time.Time
	lifetime  time.Duration
}

// mintBearer mints a valid ES256 gateway bearer with real wall-clock validity. The
// lifetime is clamped under a conservative ceiling so it always stays within the
// capability MaxTokenTTL.
func mintBearer(signer *ecdsa.PrivateKey, p tokenParams) (string, error) {
	life := p.lifetime
	if life <= 0 || life > 10*time.Minute {
		life = 10 * time.Minute
	}
	now := p.notBefore
	if now.IsZero() {
		now = time.Now()
	}
	return mintES256(signer,
		map[string]any{"alg": "ES256", "typ": "JWT", "kid": p.kid},
		map[string]any{
			"iss": p.issuer, "sub": p.subject, "client_id": p.clientID,
			"aud": p.audience, "scope": p.scope, "tenant": p.tenant,
			"iat": now.Unix(), "exp": now.Add(life).Unix(),
		})
}

// mintExpired mints a structurally valid token whose exp is already in the past.
func mintExpired(signer *ecdsa.PrivateKey, p tokenParams) (string, error) {
	now := time.Now().Add(-30 * time.Minute)
	return mintES256(signer,
		map[string]any{"alg": "ES256", "typ": "JWT", "kid": p.kid},
		map[string]any{
			"iss": p.issuer, "sub": p.subject, "client_id": p.clientID,
			"aud": p.audience, "scope": p.scope, "tenant": p.tenant,
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		})
}

// jwkPublic renders the ES256 public key as a JWKS entry the trusted_jwks_file
// loader accepts (EC/P-256, x/y as the 32-byte coordinate halves, base64url). It
// derives x/y from the uncompressed ECDH encoding (0x04 || X(32) || Y(32)) rather
// than the deprecated big.Int coordinate fields.
func jwkPublic(pub *ecdsa.PublicKey, kid string) (map[string]any, error) {
	ep, err := pub.ECDH()
	if err != nil {
		return nil, err
	}
	raw := ep.Bytes() // 0x04 || X || Y for an uncompressed P-256 point
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("unexpected uncompressed point length %d", len(raw))
	}
	return map[string]any{
		"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
		"x": b64u(raw[1:33]), "y": b64u(raw[33:65]),
	}, nil
}
