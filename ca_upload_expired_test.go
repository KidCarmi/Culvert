package main

// ca_upload_expired_test.go — the admin MITM-CA upload must not replace a
// working inspection CA with one that cannot sign.
//
// POST /api/certs/upload target=mitm installs the uploaded CA and then
// overwrites the on-disk bundle with it. The engine's LoadCustomCA checks that
// the pair matches, that the certificate is a CA and that the key is ECDSA —
// and nothing about the certificate's validity window. So an already-expired CA
// (last year's intermediate, the most ordinary upload mistake there is) was
// answered 200 "persisted", and:
//
//   - at once, every inspect-matched CONNECT fails closed (CHAOS-28), for the
//     whole fleet, because the active CA can no longer sign;
//   - the previous, working CA key is gone: the bundle file now holds the
//     expired one;
//   - on the next restart ImportBundle refuses that bundle ("certificate
//     expired"), no CA is loaded, and handleTunnel's no-CA branch forwards every
//     inspect-matched CONNECT UNINSPECTED — and the recovery loop re-reads the
//     same bundle forever.
//
// These tests drive the real handler and then read the bundle back the way a
// restart does.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
)

// customCAPEM issues a self-signed ECDSA CA valid over [notBefore, notAfter].
func customCAPEM(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Customer Inspection CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// withPersistedWorkingCA gives the test its own inspection CA, generated and
// persisted the way first boot does, and returns the bundle path and that CA's
// PEM. Every process global the upload path touches is restored afterwards.
func withPersistedWorkingCA(t *testing.T) (bundlePath string, workingPEM []byte) {
	t.Helper()
	prevMgr := certMgr
	prevPath, prevPass := caRuntime.path, caRuntime.passphrase
	prevLoadErr := sslInspectionLoadFailure()
	t.Cleanup(func() {
		certMgr = prevMgr
		caRuntime.path, caRuntime.passphrase = prevPath, prevPass
		resetCALoadRecoveryForTest()
		resetCAUsabilityHealthForTest()
		sslInspectionLoadError.Store(prevLoadErr)
	})

	bundlePath = filepath.Join(t.TempDir(), "ca.bundle")
	certMgr = ca.New()
	// No passphrase: the bundle format is not under test, and PBKDF2-600k per
	// save/load would dominate the run.
	caRuntime.path, caRuntime.passphrase = bundlePath, ""
	if err := certMgr.LoadOrInitCA(bundlePath, ""); err != nil {
		t.Fatalf("LoadOrInitCA: %v", err)
	}
	return bundlePath, certMgr.CACertPEM()
}

func uploadMITMCA(t *testing.T, certPEM, keyPEM []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for field, value := range map[string]string{"target": "mitm", "cert": string(certPEM), "key": string(keyPEM)} {
		if err := mw.WriteField(field, value); err != nil {
			t.Fatalf("multipart field %s: %v", field, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/certs/upload", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiCertsUpload(w, adminCtx(r))
	return w
}

// assertWorkingCASurvived checks the three things an operator loses when an
// unusable CA is accepted: the live CA, its ability to sign, and the bundle a
// restart will read.
func assertWorkingCASurvived(t *testing.T, bundlePath string, workingPEM []byte) {
	t.Helper()
	if !bytes.Equal(certMgr.CACertPEM(), workingPEM) {
		t.Error("the working inspection CA was replaced in memory")
	}
	if err := certMgr.Usable(); err != nil {
		t.Errorf("the active inspection CA can no longer sign (every inspected CONNECT now fails): %v", err)
	}
	// What the next restart does: read the bundle into a fresh manager.
	restarted := ca.New()
	if err := restarted.LoadCA(bundlePath, ""); err != nil {
		t.Fatalf("the on-disk bundle no longer loads, so a restart comes up with NO inspection CA "+
			"and forwards inspect-matched CONNECTs uninspected: %v", err)
	}
	if !bytes.Equal(restarted.CACertPEM(), workingPEM) {
		t.Error("the on-disk bundle no longer holds the working inspection CA")
	}
}

func TestCertsUploadMITM_ExpiredCAIsRefusedAndWorkingCASurvives(t *testing.T) {
	bundlePath, workingPEM := withPersistedWorkingCA(t)
	certPEM, keyPEM := customCAPEM(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	w := uploadMITMCA(t, certPEM, keyPEM)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an expired CA; body=%q", w.Code, w.Body.String())
	}
	// The pair is well-formed and matching, so "invalid cert/key pair" would
	// send the operator looking for the wrong fault.
	if !strings.Contains(w.Body.String(), "expired") {
		t.Errorf("body = %q, want it to say the certificate has expired", w.Body.String())
	}
	assertWorkingCASurvived(t, bundlePath, workingPEM)
}

func TestCertsUploadMITM_NotYetValidCAIsRefusedAndWorkingCASurvives(t *testing.T) {
	bundlePath, workingPEM := withPersistedWorkingCA(t)
	certPEM, keyPEM := customCAPEM(t, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))

	w := uploadMITMCA(t, certPEM, keyPEM)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a not-yet-valid CA; body=%q", w.Code, w.Body.String())
	}
	assertWorkingCASurvived(t, bundlePath, workingPEM)
}

// Negative control: the same harness with a CA inside its validity window must
// still install and persist, or the two tests above prove nothing about expiry.
func TestCertsUploadMITM_ValidCAIsInstalledAndPersisted(t *testing.T) {
	bundlePath, workingPEM := withPersistedWorkingCA(t)
	certPEM, keyPEM := customCAPEM(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	w := uploadMITMCA(t, certPEM, keyPEM)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a valid CA; body=%q", w.Code, w.Body.String())
	}
	if bytes.Equal(certMgr.CACertPEM(), workingPEM) {
		t.Fatal("the uploaded CA was not installed")
	}
	if !bytes.Equal(certMgr.CACertPEM(), certPEM) {
		t.Error("the active CA is not the uploaded one")
	}
	restarted := ca.New()
	if err := restarted.LoadCA(bundlePath, ""); err != nil {
		t.Fatalf("LoadCA after upload: %v", err)
	}
	if !bytes.Equal(restarted.CACertPEM(), certPEM) {
		t.Error("the on-disk bundle does not hold the uploaded CA")
	}
	if got := restarted.Provenance(); got != ca.ProvenanceImported {
		t.Errorf("persisted provenance = %q, want imported", got)
	}
}
