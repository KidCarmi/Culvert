package mcpacceptance

// PKI-lifetime pre-run validation tests (the v1.0.203 incident class). Every test
// uses a deterministic injected clock and certificates generated with explicit
// absolute NotBefore/NotAfter values, so nothing depends on the wall clock and no
// test sleeps to induce expiry.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pkiAnchor mirrors the real incident issuance instant (v1.0.201 qualification PKI
// created 2026-08-08T11:19:47Z with a 72h window; the live run happened Aug 13).
var pkiAnchor = time.Date(2026, 8, 8, 11, 19, 47, 0, time.UTC)

// testCA is a deterministic-window CA plus its signing key.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	file string
}

// genTestCA writes a self-signed CA valid [nb, na) to dir/name.
func genTestCA(t *testing.T, dir, name string, nb, na time.Time) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: nb, NotAfter: na, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, name+".crt")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key, file: file}
}

// genTestLeaf writes a CA-signed leaf valid [nb, na) with the given role and SANs,
// returning the cert and key paths. When keyOverride is non-nil the WRITTEN key is
// keyOverride instead of the certificate's real key (the cert/key mismatch cases).
func genTestLeaf(t *testing.T, dir, name string, ca testCA, nb, na time.Time, server bool, sans []string, keyOverride *ecdsa.PrivateKey) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(len(name)) + 2), Subject: pkix.Name{CommonName: name},
		NotBefore: nb, NotAfter: na, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		for _, s := range sans {
			if ip := net.ParseIP(s); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, s)
			}
		}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	written := key
	if keyOverride != nil {
		written = keyOverride
	}
	kd, err := x509.MarshalECPrivateKey(written)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// pkiFixture assembles a minimal Fixture carrying only the fields
// validateFixturePKI reads.
func pkiFixture(caFile, clientCAFile, srvC, srvK, cliC, cliK, serverName string) *Fixture {
	return &Fixture{
		caFile: caFile, clientCAFile: clientCAFile,
		serverCertFile: srvC, serverKeyFile: srvK,
		clientCertFile: cliC, clientKeyFile: cliK,
		serverName: serverName,
	}
}

// stdPKI generates one CA and a server+client pair, all valid [anchor-1h, anchor+72h].
func stdPKI(t *testing.T, dir string) (ca testCA, srvC, srvK, cliC, cliK string) {
	t.Helper()
	nb, na := pkiAnchor.Add(-time.Hour), pkiAnchor.Add(72*time.Hour)
	ca = genTestCA(t, dir, "qual-ca", nb, na)
	srvC, srvK = genTestLeaf(t, dir, "server", ca, nb, na, true, []string{"127.0.0.1", "gw.test"}, nil)
	cliC, cliK = genTestLeaf(t, dir, "client", ca, nb, na, false, nil, nil)
	return
}

func wantPKIError(t *testing.T, err error, fragments ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected pre-run PKI rejection, got nil")
	}
	for _, f := range fragments {
		if !strings.Contains(err.Error(), f) {
			t.Fatalf("error %q does not contain %q", err, f)
		}
	}
	for _, banned := range []string{"PRIVATE KEY", "BEGIN EC"} {
		if strings.Contains(err.Error(), banned) {
			t.Fatalf("error leaks key material: %q", err)
		}
	}
}

// 1. Expired server certificate is rejected (validation time after NotAfter).
func TestPKI_ExpiredServerCertRejected(t *testing.T) {
	dir := t.TempDir()
	nb, na := pkiAnchor.Add(-time.Hour), pkiAnchor.Add(72*time.Hour)
	ca := genTestCA(t, dir, "ca", nb, pkiAnchor.Add(1000*time.Hour))
	srvC, srvK := genTestLeaf(t, dir, "server", ca, nb, na, true, []string{"127.0.0.1"}, nil)
	now := na.Add(43 * time.Hour) // Aug 13, the incident clock
	err := validateFixturePKI(pkiFixture(ca.file, ca.file, srvC, srvK, "", "", "127.0.0.1"), now, now)
	wantPKIError(t, err, "server certificate expired", "notAfter=")
}

// 2. Expired client certificate is rejected while the server material is valid.
func TestPKI_ExpiredClientCertRejected(t *testing.T) {
	dir := t.TempDir()
	longNA := pkiAnchor.Add(1000 * time.Hour)
	ca := genTestCA(t, dir, "ca", pkiAnchor.Add(-time.Hour), longNA)
	srvC, srvK := genTestLeaf(t, dir, "server", ca, pkiAnchor.Add(-time.Hour), longNA, true, []string{"127.0.0.1"}, nil)
	cliC, cliK := genTestLeaf(t, dir, "client", ca, pkiAnchor.Add(-time.Hour), pkiAnchor.Add(72*time.Hour), false, nil, nil)
	now := pkiAnchor.Add(115 * time.Hour)
	err := validateFixturePKI(pkiFixture(ca.file, ca.file, srvC, srvK, cliC, cliK, "127.0.0.1"), now, now)
	wantPKIError(t, err, "client certificate expired")
}

// 3. An expired CA fails the chain even when the leaves' own windows are fine; the
// reported window is the CA's, not the leaf's.
func TestPKI_ExpiredCARejected(t *testing.T) {
	dir := t.TempDir()
	caNA := pkiAnchor.Add(72 * time.Hour)
	ca := genTestCA(t, dir, "short-ca", pkiAnchor.Add(-time.Hour), caNA)
	longNA := pkiAnchor.Add(1000 * time.Hour)
	srvC, srvK := genTestLeaf(t, dir, "server", ca, pkiAnchor.Add(-time.Hour), longNA, true, []string{"127.0.0.1"}, nil)
	now := caNA.Add(43 * time.Hour)
	err := validateFixturePKI(pkiFixture(ca.file, ca.file, srvC, srvK, "", "", "127.0.0.1"), now, now)
	wantPKIError(t, err, "server certificate", `subject="short-ca"`)
}

// 4. A not-yet-valid server certificate is rejected as such.
func TestPKI_NotYetValidServerCertRejected(t *testing.T) {
	dir := t.TempDir()
	longNA := pkiAnchor.Add(1000 * time.Hour)
	ca := genTestCA(t, dir, "ca", pkiAnchor.Add(-time.Hour), longNA)
	srvC, srvK := genTestLeaf(t, dir, "server", ca, pkiAnchor.Add(24*time.Hour), longNA, true, []string{"127.0.0.1"}, nil)
	now := pkiAnchor
	err := validateFixturePKI(pkiFixture(ca.file, ca.file, srvC, srvK, "", "", "127.0.0.1"), now, now)
	wantPKIError(t, err, "server certificate not yet valid")
}

// 5. Material valid at `now` but expiring before the requested run horizon is
// rejected with the run-horizon error, using the actual requested timeout.
func TestPKI_ExpiresBeforeRunHorizonRejected(t *testing.T) {
	dir := t.TempDir()
	na := pkiAnchor.Add(72 * time.Hour)
	ca := genTestCA(t, dir, "ca", pkiAnchor.Add(-time.Hour), na)
	srvC, srvK := genTestLeaf(t, dir, "server", ca, pkiAnchor.Add(-time.Hour), na, true, []string{"127.0.0.1"}, nil)
	now := na.Add(-5 * time.Minute) // still valid at launch
	horizon := 15 * time.Minute     // the CLI -timeout; cert dies 5 minutes in
	err := validateFixturePKI(pkiFixture(ca.file, ca.file, srvC, srvK, "", "", "127.0.0.1"), now, now.Add(horizon))
	wantPKIError(t, err, "expires before the bounded run can complete")
	// The same material passes when the requested run fits inside the remaining
	// lifetime, proving the horizon (not a fixed age policy) is what is enforced.
	if err := validateFixturePKI(pkiFixture(ca.file, ca.file, srvC, srvK, "", "", "127.0.0.1"), now, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("shorter horizon within lifetime must pass, got: %v", err)
	}
}

// 6. A server certificate without the configured TLS server name is rejected.
func TestPKI_WrongServerNameRejected(t *testing.T) {
	dir := t.TempDir()
	na := pkiAnchor.Add(72 * time.Hour)
	ca := genTestCA(t, dir, "ca", pkiAnchor.Add(-time.Hour), na)
	srvC, srvK := genTestLeaf(t, dir, "server", ca, pkiAnchor.Add(-time.Hour), na, true, []string{"gw.test"}, nil)
	now := pkiAnchor
	err := validateFixturePKI(pkiFixture(ca.file, ca.file, srvC, srvK, "", "", "127.0.0.1"), now, now)
	wantPKIError(t, err, "not valid for configured TLS server name", "127.0.0.1")
}

// 7. A client certificate that does not chain to the configured client CA is
// rejected.
func TestPKI_ClientWrongChainRejected(t *testing.T) {
	dir := t.TempDir()
	na := pkiAnchor.Add(72 * time.Hour)
	serverCA := genTestCA(t, dir, "server-ca", pkiAnchor.Add(-time.Hour), na)
	clientCA := genTestCA(t, dir, "client-ca", pkiAnchor.Add(-time.Hour), na)
	rogueCA := genTestCA(t, dir, "rogue-ca", pkiAnchor.Add(-time.Hour), na)
	srvC, srvK := genTestLeaf(t, dir, "server", serverCA, pkiAnchor.Add(-time.Hour), na, true, []string{"127.0.0.1"}, nil)
	cliC, cliK := genTestLeaf(t, dir, "client", rogueCA, pkiAnchor.Add(-time.Hour), na, false, nil, nil)
	now := pkiAnchor
	err := validateFixturePKI(pkiFixture(serverCA.file, clientCA.file, srvC, srvK, cliC, cliK, "127.0.0.1"), now, now)
	wantPKIError(t, err, "client certificate does not chain to the configured CA")
}

// 8. A server certificate that does not chain to the configured server CA is
// rejected.
func TestPKI_ServerWrongChainRejected(t *testing.T) {
	dir := t.TempDir()
	na := pkiAnchor.Add(72 * time.Hour)
	trustCA := genTestCA(t, dir, "trust-ca", pkiAnchor.Add(-time.Hour), na)
	rogueCA := genTestCA(t, dir, "rogue-ca", pkiAnchor.Add(-time.Hour), na)
	srvC, srvK := genTestLeaf(t, dir, "server", rogueCA, pkiAnchor.Add(-time.Hour), na, true, []string{"127.0.0.1"}, nil)
	now := pkiAnchor
	err := validateFixturePKI(pkiFixture(trustCA.file, trustCA.file, srvC, srvK, "", "", "127.0.0.1"), now, now)
	wantPKIError(t, err, "server certificate does not chain to the configured CA")
}

// 9 + 10. Certificate/key mismatch (server and client) is rejected without key
// material in the error.
func TestPKI_CertKeyMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	na := pkiAnchor.Add(72 * time.Hour)
	ca := genTestCA(t, dir, "ca", pkiAnchor.Add(-time.Hour), na)
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := pkiAnchor

	srvC, srvBadK := genTestLeaf(t, dir, "server-bad", ca, pkiAnchor.Add(-time.Hour), na, true, []string{"127.0.0.1"}, wrongKey)
	wantPKIError(t,
		validateFixturePKI(pkiFixture(ca.file, ca.file, srvC, srvBadK, "", "", "127.0.0.1"), now, now),
		"server certificate/key pair", "invalid")

	srvC2, srvK2 := genTestLeaf(t, dir, "server-ok", ca, pkiAnchor.Add(-time.Hour), na, true, []string{"127.0.0.1"}, nil)
	cliC, cliBadK := genTestLeaf(t, dir, "client-bad", ca, pkiAnchor.Add(-time.Hour), na, false, nil, wrongKey)
	wantPKIError(t,
		validateFixturePKI(pkiFixture(ca.file, ca.file, srvC2, srvK2, cliC, cliBadK, "127.0.0.1"), now, now),
		"client certificate/key pair", "invalid")
}

// 11. Distinct server and client CAs are supported: each leaf validates against
// its own trust root.
func TestPKI_DistinctServerAndClientCAsAccepted(t *testing.T) {
	dir := t.TempDir()
	na := pkiAnchor.Add(72 * time.Hour)
	serverCA := genTestCA(t, dir, "server-ca", pkiAnchor.Add(-time.Hour), na)
	clientCA := genTestCA(t, dir, "client-ca", pkiAnchor.Add(-time.Hour), na)
	srvC, srvK := genTestLeaf(t, dir, "server", serverCA, pkiAnchor.Add(-time.Hour), na, true, []string{"127.0.0.1"}, nil)
	cliC, cliK := genTestLeaf(t, dir, "client", clientCA, pkiAnchor.Add(-time.Hour), na, false, nil, nil)
	now := pkiAnchor
	if err := validateFixturePKI(pkiFixture(serverCA.file, clientCA.file, srvC, srvK, cliC, cliK, "127.0.0.1"), now, now.Add(15*time.Minute)); err != nil {
		t.Fatalf("distinct CAs must validate: %v", err)
	}
}

// 12. Fully valid authoritative PKI with adequate remaining lifetime passes.
func TestPKI_ValidMaterialAccepted(t *testing.T) {
	dir := t.TempDir()
	ca, srvC, srvK, cliC, cliK := stdPKI(t, dir)
	now := pkiAnchor
	if err := validateFixturePKI(pkiFixture(ca.file, ca.file, srvC, srvK, cliC, cliK, "gw.test"), now, now.Add(15*time.Minute)); err != nil {
		t.Fatalf("valid PKI must pass: %v", err)
	}
	// A half-configured client pair is an operator error, not a silent skip.
	wantPKIError(t,
		validateFixturePKI(pkiFixture(ca.file, ca.file, srvC, srvK, cliC, "", "gw.test"), now, now),
		"both client_cert_file and client_key_file")
}

// A server certificate carrying only the ClientAuth EKU is rejected for the
// server role under standard x509 EKU semantics (no custom ASN.1 policy).
func TestPKI_ServerCertWrongEKURejected(t *testing.T) {
	dir := t.TempDir()
	na := pkiAnchor.Add(72 * time.Hour)
	ca := genTestCA(t, dir, "ca", pkiAnchor.Add(-time.Hour), na)
	// server=false gives the leaf ClientAuth-only EKU and no SANs; add the IP SAN
	// manually via a dedicated template so ONLY the EKU is wrong.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "eku-wrong"},
		NotBefore: pkiAnchor.Add(-time.Hour), NotAfter: na,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	certP := filepath.Join(dir, "eku-wrong.crt")
	keyP := filepath.Join(dir, "eku-wrong.key")
	if err := os.WriteFile(certP, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyP, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	now := pkiAnchor
	wantPKIError(t,
		validateFixturePKI(pkiFixture(ca.file, ca.file, certP, keyP, "", "", "127.0.0.1"), now, now),
		"server certificate")
}

// A CA expiring mid-run fails the horizon check even when the leaf outlives the
// requested window; the error names the CA as the failing certificate.
func TestPKI_CAExpiresMidRunRejected(t *testing.T) {
	dir := t.TempDir()
	caNA := pkiAnchor.Add(72 * time.Hour)
	ca := genTestCA(t, dir, "midrun-ca", pkiAnchor.Add(-time.Hour), caNA)
	leafNA := pkiAnchor.Add(1000 * time.Hour)
	srvC, srvK := genTestLeaf(t, dir, "server", ca, pkiAnchor.Add(-time.Hour), leafNA, true, []string{"127.0.0.1"}, nil)
	now := caNA.Add(-5 * time.Minute) // CA still valid at launch, dies 5 minutes in
	err := validateFixturePKI(pkiFixture(ca.file, ca.file, srvC, srvK, "", "", "127.0.0.1"), now, now.Add(15*time.Minute))
	wantPKIError(t, err, "expires before the bounded run can complete", `subject="midrun-ca"`)
}

// A fullchain tls_cert_file (leaf + intermediate) with only the root in
// server_ca_file verifies pre-run the same way the runtime handshake would (the
// presented chain supplies the intermediate).
func TestPKI_FullchainServerCertAccepted(t *testing.T) {
	dir := t.TempDir()
	na := pkiAnchor.Add(72 * time.Hour)
	root := genTestCA(t, dir, "root-ca", pkiAnchor.Add(-time.Hour), na)
	// Intermediate CA signed by root.
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(50), Subject: pkix.Name{CommonName: "int-ca"},
		NotBefore: pkiAnchor.Add(-time.Hour), NotAfter: na, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, root.cert, &intKey.PublicKey, root.key)
	if err != nil {
		t.Fatal(err)
	}
	intCert, err := x509.ParseCertificate(intDER)
	if err != nil {
		t.Fatal(err)
	}
	// Leaf signed by the intermediate.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(51), Subject: pkix.Name{CommonName: "chained-server"},
		NotBefore: pkiAnchor.Add(-time.Hour), NotAfter: na,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatal(err)
	}
	fullchain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intDER})...)
	certP := filepath.Join(dir, "fullchain.crt")
	keyP := filepath.Join(dir, "fullchain.key")
	if err := os.WriteFile(certP, fullchain, 0o600); err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyP, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	now := pkiAnchor
	if err := validateFixturePKI(pkiFixture(root.file, root.file, certP, keyP, "", "", "127.0.0.1"), now, now.Add(15*time.Minute)); err != nil {
		t.Fatalf("fullchain server cert with root-only CA file must pass: %v", err)
	}
}

// 13. Dev mode is unaffected: the ephemeral dev fixture's own generated material
// satisfies the same validator (self-contained, no operator PKI dependency), and
// the gate itself is only wired into the authoritative preflight.
func TestPKI_DevFixtureMaterialSelfContained(t *testing.T) {
	fx, err := NewFixture(t.TempDir(), NewSecretScan())
	if err != nil {
		t.Fatalf("NewFixture: %v", err)
	}
	now := time.Now() // dev generator stamps wall-clock windows (24h)
	if err := validateFixturePKI(fx, now, now.Add(15*time.Minute)); err != nil {
		t.Fatalf("dev fixture material must be self-consistent: %v", err)
	}
}

// 14 + v1.0.203 incident pin, harness level. Certificates that were VALID when
// created age past NotAfter before the run; the spec stays structurally valid; the
// authoritative run must fail during pre-run preflight with the expiry error,
// BEFORE any child process, tripwire, or network traffic. The artifact is a
// sentinel script that records execution; it must never run, and no evidence
// bundle claiming a live acceptance run may exist.
func TestPKI_V203IncidentClass_NoChildProcessOnExpiredPKI(t *testing.T) {
	env, _ := localOperatorEnv(t)
	dir := t.TempDir()

	// Incident-shaped PKI: issued at the anchor with 72h validity.
	nb, na := pkiAnchor.Add(-time.Hour), pkiAnchor.Add(72*time.Hour)
	ca := genTestCA(t, dir, "qual-ca", nb, na)
	srvC, srvK := genTestLeaf(t, dir, "server", ca, nb, na, true, []string{"127.0.0.1"}, nil)
	cliC, cliK := genTestLeaf(t, dir, "client", ca, nb, na, false, nil, nil)
	env.ServerCAFile, env.ClientCAFile = ca.file, ca.file
	env.TLSCertFile, env.TLSKeyFile = srvC, srvK
	env.ClientCertFile, env.ClientKeyFile = cliC, cliK
	env.TLSServerName = "127.0.0.1"

	// Sentinel artifact: creates a file if it is ever executed.
	sentinel := filepath.Join(dir, "executed.sentinel")
	script := "#!/bin/sh\ntouch " + sentinel + "\nsleep 60\n"
	bin := filepath.Join(dir, "culvert-sentinel")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(script))
	digest := "sha256:" + hex.EncodeToString(sum[:])

	spec := &Spec{
		Mode: ModeAuthoritative,
		Artifact: ArtifactSpec{
			BinaryPath:           bin,
			ExpectedDigest:       digest,
			ExpectedVersion:      "v1.0.203",
			ExpectedSourceCommit: "bc67b7b56d7021f071655cc343692a06db60d41b",
			Provenance:           &ProvenanceSpec{Verifier: "test", VerifiedDigest: digest},
		},
		Environment: env,
		EvidenceDir: t.TempDir(),
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("spec must stay structurally valid (the incident spec was): %v", err)
	}

	// The incident clock: two days after NotAfter.
	incidentNow := na.Add(43 * time.Hour)
	h, err := NewHarness(spec, Options{Now: func() time.Time { return incidentNow }, RunHorizon: 15 * time.Minute})
	if err != nil {
		t.Fatalf("NewHarness: %v", err)
	}
	_, runErr := h.Run(t.Context())
	if runErr == nil {
		t.Fatal("authoritative run with expired PKI must fail pre-run")
	}
	wantPKIError(t, runErr, "server certificate expired")

	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("child process was executed despite PKI pre-run failure (sentinel exists, stat err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(spec.EvidenceDir, "summary.json")); !os.IsNotExist(err) {
		t.Fatalf("evidence bundle must not claim a live run after pre-run rejection (summary.json present, stat err=%v)", err)
	}
}
