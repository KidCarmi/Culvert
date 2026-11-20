package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withTempCDRCertsRoot points cdrCertsRoot at a fresh directory so
// loadCertExpiry's root guard admits the test's certificate files.
func withTempCDRCertsRoot(t *testing.T) string {
	t.Helper()
	prev := cdrCertsRoot
	cdrCertsRoot = t.TempDir()
	t.Cleanup(func() { cdrCertsRoot = prev })
	return cdrCertsRoot
}

// writeSluiceClientCert writes a self-signed certificate expiring at notAfter
// and returns an enrolled instance pointing at it.
func writeSluiceClientCert(t *testing.T, root, name string, notAfter time.Time) CDREnrolledInstance {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "client.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return CDREnrolledInstance{Name: name, Endpoint: name + ":8443", ClientCertPath: path}
}

func TestCDRClientCertRows_HealthyCertsContributeNothing(t *testing.T) {
	root := withTempCDRCertsRoot(t)
	now := time.Now()
	insts := []CDREnrolledInstance{
		writeSluiceClientCert(t, root, "fresh", now.Add(300*24*time.Hour)),
		// Inside the renewal window but above the warn threshold: renewal is
		// expected to be in progress, so this is not yet worth a warning.
		writeSluiceClientCert(t, root, "renewing", now.Add(20*24*time.Hour)),
		{Name: "unreadable", ClientCertPath: filepath.Join(root, "missing", "client.crt")},
	}
	if rows := cdrClientCertExpiryRows(insts, now); len(rows) != 0 {
		t.Fatalf("rows = %+v, want none", rows)
	}
}

func TestCDRClientCertRows_ExpiringCertWarnsWithoutNames(t *testing.T) {
	root := withTempCDRCertsRoot(t)
	now := time.Now()
	insts := []CDREnrolledInstance{
		writeSluiceClientCert(t, root, "sluice-east", now.Add(5*24*time.Hour+time.Hour)),
		writeSluiceClientCert(t, root, "sluice-west", now.Add(10*24*time.Hour+time.Hour)),
		writeSluiceClientCert(t, root, "sluice-ok", now.Add(200*24*time.Hour)),
	}
	rows := cdrClientCertExpiryRows(insts, now)
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want exactly one", rows)
	}
	got := rows[0]
	if got.Code != "cdr_client_cert" || got.Status != diagWarn {
		t.Fatalf("row = %s %s, want cdr_client_cert warn", got.Code, got.Status)
	}
	if !strings.HasPrefix(got.Message, "2 Sluice") || !strings.Contains(got.Message, "soonest in 5 days") {
		t.Errorf("message %q must count 2 instances and name the soonest expiry", got.Message)
	}
	if strings.Contains(got.Message, "sluice-") || strings.Contains(got.Message, root) {
		t.Errorf("message %q must not name instances or paths (viewer-visible row)", got.Message)
	}
	if !strings.Contains(got.OperatorAction, "CDR → Instances") || !strings.Contains(got.OperatorAction, "re-enroll") {
		t.Errorf("operator action %q must point at the instances panel and the re-enroll fallback", got.OperatorAction)
	}
}

func TestCDRClientCertRows_ExpiredCertReportsExpiredNotZeroDays(t *testing.T) {
	root := withTempCDRCertsRoot(t)
	now := time.Now()
	// One hour past expiry: daysUntil would truncate to 0.
	insts := []CDREnrolledInstance{writeSluiceClientCert(t, root, "lapsed", now.Add(-time.Hour))}
	rows := cdrClientCertExpiryRows(insts, now)
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "1 Sluice instance client certificate(s) have expired") {
		t.Fatalf("rows = %+v, want one expired row", rows)
	}
	if strings.Contains(rows[0].Message, "0 days") {
		t.Errorf("message %q must not read as 0 days left", rows[0].Message)
	}
}

func TestCDRClientCertRows_DisabledInstanceIgnored(t *testing.T) {
	root := withTempCDRCertsRoot(t)
	off := false
	inst := writeSluiceClientCert(t, root, "parked", time.Now().Add(-time.Hour))
	inst.Enabled = &off
	if rows := cdrClientCertExpiryRows([]CDREnrolledInstance{inst}, time.Now()); len(rows) != 0 {
		t.Fatalf("rows = %+v, want none for a disabled instance", rows)
	}
}

func TestCheckCDRClientCertExpiry_SilentWhileCDRDisabled(t *testing.T) {
	resetCDRState(t)
	root := withTempCDRCertsRoot(t)
	if _, err := cdrInstances.Add(writeSluiceClientCert(t, root, "lapsed", time.Now().Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	withActiveCDRConfig(t, CDRConfig{Enabled: false})
	if rows := checkCDRClientCertExpiry(); len(rows) != 0 {
		t.Fatalf("rows = %+v, want none while CDR is disabled", rows)
	}
	withActiveCDRConfig(t, CDRConfig{Enabled: true, FailMode: "closed", DefaultProfile: "default"})
	if rows := checkCDRClientCertExpiry(); len(rows) != 1 {
		t.Fatalf("rows = %+v, want one row once CDR is enabled", rows)
	}
}
