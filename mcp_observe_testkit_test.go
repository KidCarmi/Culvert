package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ctxWithTimeout returns a short-lived context for bounded shutdown in tests.
func ctxWithTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// mcpTestPKI is the in-test certificate + key material for the observe listener:
// a self-signed CA that signs the server cert and a client cert (for mTLS), plus an
// ES256 signing key for minting JWT access tokens and its public JWK (JWKS file).
type mcpTestPKI struct {
	dir string

	caCertPEM  []byte
	serverCert string // path
	serverKey  string // path
	clientCA   string // path (== caCertPEM on disk)
	jwks       string // path

	signer    *ecdsa.PrivateKey // ES256 JWT signer
	kid       string
	issuer    string
	clientPEM []byte
	clientKey *ecdsa.PrivateKey
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
}

func mustB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// newMCPTestPKI builds the PKI + JWKS on disk under t.TempDir().
func newMCPTestPKI(t *testing.T) *mcpTestPKI {
	t.Helper()
	dir := t.TempDir()
	p := &mcpTestPKI{dir: dir, kid: "test-kid", issuer: "https://idp.test/issuer"}

	// CA.
	p.caKey = genEC(t)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mcp-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &p.caKey.PublicKey, p.caKey)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	p.caCert, _ = x509.ParseCertificate(caDER)
	p.caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Server cert (SAN 127.0.0.1) signed by the CA.
	srvKey := genEC(t)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, p.caCert, &srvKey.PublicKey, p.caKey)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	p.serverCert = p.write("server.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}))
	p.serverKey = p.write("server.key", pemKey(t, srvKey))
	p.clientCA = p.write("ca.crt", p.caCertPEM)

	// Client cert (for mTLS) signed by the CA.
	p.clientKey = genEC(t)
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "mcp-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, p.caCert, &p.clientKey.PublicKey, p.caKey)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	p.clientPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliDER})

	// JWKS with the ES256 public signing key.
	p.signer = genEC(t)
	p.jwks = p.write("jwks.json", p.jwksBytes(t))
	return p
}

func genEC(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return k
}

func pemKey(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func (p *mcpTestPKI) write(name string, b []byte) string {
	path := filepath.Join(p.dir, name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		panic(err)
	}
	return path
}

// jwksBytes renders a JWKS document with the ES256 public key (P-256). It uses the
// SEC1 uncompressed encoding (PublicKey.Bytes) rather than the raw X/Y big.Ints,
// which are deprecated for cryptographic use as of Go 1.26.
func (p *mcpTestPKI) jwksBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := p.signer.PublicKey.Bytes() // 0x04 || X(32) || Y(32) for P-256
	if err != nil {
		t.Fatalf("public bytes: %v", err)
	}
	if len(raw) != 65 || raw[0] != 0x04 {
		t.Fatalf("unexpected P-256 public encoding len=%d", len(raw))
	}
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256", "kid": p.kid, "use": "sig", "alg": "ES256",
		"x": mustB64(raw[1:33]),
		"y": mustB64(raw[33:65]),
	}
	doc, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	return doc
}

// freePort returns a currently-free localhost TCP port (best effort — the runtime
// binds a fixed declared port, so tests cannot use the ephemeral-port test seam
// which is gated behind AllowInsecure).
func freePort(t *testing.T) int {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer ln.Close() //nolint:errcheck // best-effort close of a transient probe listener
	return ln.Addr().(*net.TCPAddr).Port
}

// validConfig returns a complete, valid observe startup config for this PKI using
// the given canonical resource and sender-constraint mode.
func (p *mcpTestPKI) validConfig(t *testing.T, resource, sender string) mcpObserveStartupConfig {
	return mcpObserveStartupConfig{
		Enabled:           true,
		BindAddress:       "127.0.0.1",
		Port:              freePort(t),
		AllowedHosts:      []string{"127.0.0.1", "gw.test"},
		ConnectorMode:     "local-client",
		TLSCertFile:       p.serverCert,
		TLSKeyFile:        p.serverKey,
		ClientCAFile:      p.clientCA,
		ClientCertMode:    "require",
		CanonicalResource: resource,
		TrustedIssuers:    []string{p.issuer},
		AcceptedClientIDs: []string{"client-gw"},
		RequiredScopes:    []string{"gateway.tools.call"},
		SenderConstraint:  sender,
		MinAssurance:      "low",
		TrustedJWKSFile:   p.jwks,
	}
}
