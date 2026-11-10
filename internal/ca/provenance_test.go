package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// These tests are the PKI trust-boundary contract: who may renew the
// inspection CA, and what a client that trusts only the operator's anchor can
// still validate. Each assertion names which of four different things it
// checks — a signature, a certificate path, the availability of a trust anchor,
// or nothing more than that — because one passing X.509 verification is not
// evidence of the others.

type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

// issueTestCA creates a CA certificate named cn valid for another `life`. A nil
// parent makes it self-signed.
func issueTestCA(t *testing.T, cn string, life time.Duration, parent *testCA) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Example Corp"}, CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(life),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create CA %q: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA %q: %v", cn, err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return &testCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// watchWithheld captures RenewalWithheldObserver calls for the test.
func watchWithheld(t *testing.T) *[]Provenance {
	t.Helper()
	var got []Provenance
	prev := RenewalWithheldObserver
	RenewalWithheldObserver = func(p Provenance, _ time.Time) { got = append(got, p) }
	t.Cleanup(func() { RenewalWithheldObserver = prev })
	return &got
}

const nearExpiry = 5 * 24 * time.Hour // inside the 30-day renewal window

func TestProvenance_ImportedRootIsNeverAutoReplaced(t *testing.T) {
	withheld := watchWithheld(t)
	root := issueTestCA(t, "Customer Root", nearExpiry, nil)
	cm := New()
	if err := cm.LoadCustomCA(root.certPEM, root.keyPEM); err != nil {
		t.Fatalf("LoadCustomCA: %v", err)
	}
	if got := cm.Provenance(); got != ProvenanceImported {
		t.Fatalf("provenance = %q, want imported", got)
	}
	if cm.RotateIfNeeded("", "") {
		t.Fatal("an imported root was auto-renewed")
	}
	if !cm.CACertForTest().Equal(root.cert) {
		t.Fatal("the imported root certificate was replaced")
	}
	if len(*withheld) != 1 || (*withheld)[0] != ProvenanceImported {
		t.Fatalf("withheld-renewal signal = %v, want one for imported", *withheld)
	}
	// Signing continues until expiry: certificate path to the customer's anchor.
	const host = "imported-root.example.com"
	served, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if err := verifyServedChain(t, served, poolOf(root.cert), host); err != nil {
		t.Fatalf("path to the customer root: %v", err)
	}
}

func TestProvenance_EnterpriseIntermediate(t *testing.T) {
	withheld := watchWithheld(t)
	entRoot := issueTestCA(t, "Enterprise Root", 365*24*time.Hour, nil)
	inter := issueTestCA(t, "Enterprise Issuing CA", nearExpiry, entRoot)
	cm := New()
	if err := cm.LoadCustomCA(inter.certPEM, inter.keyPEM); err != nil {
		t.Fatalf("LoadCustomCA: %v", err)
	}
	const host = "intermediate.example.com"
	served, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}

	// 1. Signature: the leaf is signed by the intermediate's key.
	if err := served.Leaf.CheckSignatureFrom(inter.cert); err != nil {
		t.Fatalf("leaf signature: %v", err)
	}
	// 2. Certificate path: a client holding ONLY the enterprise root must be
	// able to build leaf → intermediate → root from what is served.
	if err := verifyServedChain(t, served, poolOf(entRoot.cert), host); err != nil {
		t.Errorf("client trusting only the enterprise root cannot build a path: %v", err)
	}
	// 3. Trust-anchor availability: a valid signature and a complete chain are
	// still worth nothing to a client that was never given the anchor.
	stranger := issueTestCA(t, "Unrelated Root", 365*24*time.Hour, nil)
	if err := verifyServedChain(t, served, poolOf(stranger.cert), host); err == nil {
		t.Error("leaf validated without the enterprise trust anchor")
	}

	// 4. Lifecycle authority: the enterprise PKI renews this, not Culvert.
	if cm.RotateIfNeeded("", "") {
		t.Fatal("an enterprise-issued intermediate was auto-renewed")
	}
	if !cm.CACertForTest().Equal(inter.cert) {
		t.Fatal("the intermediate was replaced")
	}
	if len(*withheld) != 1 {
		t.Fatalf("withheld-renewal signals = %d, want 1", len(*withheld))
	}

	// 5. Restart: the record and the served chain both come back from disk.
	bundle := filepath.Join(t.TempDir(), "ca.bundle")
	if err := cm.SaveCA(bundle, "pass"); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}
	restarted := New()
	if err := restarted.LoadCA(bundle, "pass"); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if got := restarted.Provenance(); got != ProvenanceImported {
		t.Errorf("provenance after restart = %q, want imported", got)
	}
	served, err = restarted.GetCert(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatalf("GetCert after restart: %v", err)
	}
	if err := verifyServedChain(t, served, poolOf(entRoot.cert), host); err != nil {
		t.Errorf("after restart, no path to the enterprise root: %v", err)
	}
	if restarted.RotateIfNeeded(bundle, "pass") {
		t.Error("the intermediate was auto-renewed after restart")
	}
}

// writeLegacyBundle writes what every build before provenance tracking wrote:
// certificate and key, no record.
func writeLegacyBundle(t *testing.T, c *testCA) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.bundle")
	if err := os.WriteFile(path, append(append([]byte{}, c.certPEM...), c.keyPEM...), 0o600); err != nil {
		t.Fatalf("write legacy bundle: %v", err)
	}
	return path
}

func TestProvenance_LegacyBundleIsUnknownAndNotRenewed(t *testing.T) {
	withheld := watchWithheld(t)
	// Self-signed and named like Culvert's own root: neither is evidence of who
	// generated it.
	legacy := issueTestCA(t, "Culvert Root CA", nearExpiry, nil)
	path := writeLegacyBundle(t, legacy)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cm := New()
	if err := cm.LoadCA(path, ""); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if got := cm.Provenance(); got != ProvenanceUnknown {
		t.Fatalf("provenance = %q, want unknown", got)
	}
	if cm.RotateIfNeeded(path, "") {
		t.Fatal("a CA of unknown provenance was auto-renewed")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the legacy bundle was rewritten without a classification decision")
	}
	if len(*withheld) != 1 || (*withheld)[0] != ProvenanceUnknown {
		t.Fatalf("withheld-renewal signal = %v, want one for unknown", *withheld)
	}
	// Compatible operation is preserved: it still signs.
	const host = "legacy.example.com"
	served, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if err := verifyServedChain(t, served, poolOf(legacy.cert), host); err != nil {
		t.Fatalf("path to the legacy root: %v", err)
	}
}

func TestProvenance_LegacyClassification(t *testing.T) {
	legacy := issueTestCA(t, "Culvert Root CA", nearExpiry, nil)
	path := writeLegacyBundle(t, legacy)

	// Classified as managed: renewed under the same key, and the record is
	// written so the next boot needs no classification.
	cm := New()
	cm.SetLegacyProvenance(ProvenanceManaged)
	if err := cm.LoadCA(path, ""); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if !cm.RotateIfNeeded(path, "") {
		t.Fatal("a legacy CA classified as managed was not renewed")
	}
	const host = "classified.example.com"
	served, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if err := verifyServedChain(t, served, poolOf(legacy.cert), host); err != nil {
		t.Errorf("client trusting the pre-renewal root: %v", err)
	}
	next := New() // no classification supplied this time
	if err := next.LoadCA(path, ""); err != nil {
		t.Fatalf("LoadCA after renewal: %v", err)
	}
	if got := next.Provenance(); got != ProvenanceManaged {
		t.Errorf("provenance after renewal + restart = %q, want culvert-managed", got)
	}

	// A classification never overrides a record.
	root := issueTestCA(t, "Customer Root", nearExpiry, nil)
	imp := New()
	if err := imp.LoadCustomCA(root.certPEM, root.keyPEM); err != nil {
		t.Fatalf("LoadCustomCA: %v", err)
	}
	impPath := filepath.Join(t.TempDir(), "ca.bundle")
	if err := imp.SaveCA(impPath, ""); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}
	over := New()
	over.SetLegacyProvenance(ProvenanceManaged)
	if err := over.LoadCA(impPath, ""); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if got := over.Provenance(); got != ProvenanceImported {
		t.Errorf("recorded provenance overridden: got %q, want imported", got)
	}
	if over.RotateIfNeeded(impPath, "") {
		t.Error("an imported CA was renewed because of a legacy classification")
	}
}

// A build that predates provenance tracking reads the bundle by taking the
// CERTIFICATE and EC PRIVATE KEY blocks and skipping anything else. The record
// must stay a separate block so a downgrade still loads the CA.
func TestProvenance_BundleStaysReadableByOlderBuilds(t *testing.T) {
	cm := New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.bundle")
	if err := cm.SaveCA(path, ""); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		counts[b.Type]++
	}
	if counts["CERTIFICATE"] != 1 || counts["EC PRIVATE KEY"] != 1 || counts[provenancePEMType] != 1 || len(counts) != 3 {
		t.Fatalf("bundle blocks = %v, want one CERTIFICATE, one EC PRIVATE KEY, one %s", counts, provenancePEMType)
	}
	loaded := New()
	if err := loaded.LoadCA(path, ""); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if got := loaded.Provenance(); got != ProvenanceManaged {
		t.Errorf("provenance = %q, want culvert-managed", got)
	}
}

// At expiry an imported CA stops signing. It is not replaced, and the refusal
// is an error the caller sees — never a silently different certificate.
func TestProvenance_ExpiredImportedCARefusesAndIsNotReplaced(t *testing.T) {
	root := issueTestCA(t, "Customer Root", -time.Minute, nil) // already expired
	cm := New()
	if err := cm.LoadCustomCA(root.certPEM, root.keyPEM); err != nil {
		t.Fatalf("LoadCustomCA: %v", err)
	}
	if cm.RotateIfNeeded("", "") {
		t.Fatal("an expired imported CA was auto-replaced")
	}
	if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "expired.example.com"}); !errors.Is(err, ErrCAUnusable) {
		t.Fatalf("GetCert error = %v, want ErrCAUnusable", err)
	}
	if !cm.CACertForTest().Equal(root.cert) {
		t.Fatal("the expired imported CA was replaced")
	}
}

// Handshakes that race a managed renewal must each get a leaf that a client
// holding only the pre-renewal root accepts. Run under -race.
func TestProvenance_ConcurrentSigningDuringManagedRenewal(t *testing.T) {
	cm, oldRoot := nearExpiryManager(t)
	oldOnly := poolOf(oldRoot)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := "h" + string(rune('a'+i%26)) + ".example.com"
			served, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: host})
			if err != nil {
				errs <- err
				return
			}
			inter := x509.NewCertPool()
			for _, der := range served.Certificate[1:] {
				if c, perr := x509.ParseCertificate(der); perr == nil {
					inter.AddCert(c)
				}
			}
			if _, err := served.Leaf.Verify(x509.VerifyOptions{Roots: oldOnly, Intermediates: inter, DNSName: host}); err != nil {
				errs <- err
			}
		}(i)
	}
	if !cm.RotateIfNeeded("", "") {
		t.Fatal("managed near-expiry CA should renew")
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("leaf issued during renewal: %v", err)
	}
}
