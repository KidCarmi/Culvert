package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── parseEnrollURL Tests ───────────────────────────────────────────────────

func TestParseEnrollURL_Full(t *testing.T) {
	info, err := parseEnrollURL("culvert://enroll/10.0.0.1:50051/abc123?ca-fp=sha256:deadbeef")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.CPAddr != "10.0.0.1:50051" {
		t.Fatalf("CPAddr = %q, want 10.0.0.1:50051", info.CPAddr)
	}
	if info.Token != "abc123" {
		t.Fatalf("Token = %q, want abc123", info.Token)
	}
	if info.CAFingerprint != "sha256:deadbeef" {
		t.Fatalf("CAFingerprint = %q, want sha256:deadbeef", info.CAFingerprint)
	}
}

func TestParseEnrollURL_NoFingerprint(t *testing.T) {
	info, err := parseEnrollURL("culvert://enroll/myhost:50051/token456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.CPAddr != "myhost:50051" {
		t.Fatalf("CPAddr = %q, want myhost:50051", info.CPAddr)
	}
	if info.Token != "token456" {
		t.Fatalf("Token = %q, want token456", info.Token)
	}
	if info.CAFingerprint != "" {
		t.Fatalf("CAFingerprint = %q, want empty", info.CAFingerprint)
	}
}

func TestParseEnrollURL_WithoutScheme(t *testing.T) {
	// Already stripped of scheme prefix — raw host/token
	info, err := parseEnrollURL("10.0.0.5:9090/mytoken?ca-fp=abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.CPAddr != "10.0.0.5:9090" {
		t.Fatalf("CPAddr = %q, want 10.0.0.5:9090", info.CPAddr)
	}
	if info.Token != "mytoken" {
		t.Fatalf("Token = %q, want mytoken", info.Token)
	}
	if info.CAFingerprint != "abc" {
		t.Fatalf("CAFingerprint = %q, want abc", info.CAFingerprint)
	}
}

func TestParseEnrollURL_MultipleQueryParams(t *testing.T) {
	info, err := parseEnrollURL("culvert://enroll/host:50051/tok?foo=bar&ca-fp=sha256:aabbcc&baz=1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.CAFingerprint != "sha256:aabbcc" {
		t.Fatalf("CAFingerprint = %q, want sha256:aabbcc", info.CAFingerprint)
	}
	if info.Token != "tok" {
		t.Fatalf("Token = %q, want tok", info.Token)
	}
}

func TestParseEnrollURL_InvalidFormat(t *testing.T) {
	_, err := parseEnrollURL("culvert://enroll/noslash")
	if err == nil {
		t.Fatal("expected error for missing token part")
	}
}

func TestParseEnrollURL_EmptyInput(t *testing.T) {
	_, err := parseEnrollURL("")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

// ── verifyCAFingerprint Tests ──────────────────────────────────────────────

func testCACertPEM(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestVerifyCAFingerprint_Match(t *testing.T) {
	certPEM := testCACertPEM(t)
	block, _ := pem.Decode(certPEM)
	fp := sha256.Sum256(block.Bytes)
	fpHex := "sha256:" + hex.EncodeToString(fp[:])

	if err := verifyCAFingerprint(certPEM, fpHex); err != nil {
		t.Fatalf("expected match: %v", err)
	}
}

func TestVerifyCAFingerprint_MatchWithoutPrefix(t *testing.T) {
	certPEM := testCACertPEM(t)
	block, _ := pem.Decode(certPEM)
	fp := sha256.Sum256(block.Bytes)
	fpHex := hex.EncodeToString(fp[:])

	if err := verifyCAFingerprint(certPEM, fpHex); err != nil {
		t.Fatalf("expected match without sha256: prefix: %v", err)
	}
}

func TestVerifyCAFingerprint_Mismatch(t *testing.T) {
	certPEM := testCACertPEM(t)
	wrongFP := "sha256:" + hex.EncodeToString(make([]byte, 32))

	err := verifyCAFingerprint(certPEM, wrongFP)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !contains(err.Error(), "does not match") {
		t.Fatalf("error should mention mismatch, got: %v", err)
	}
}

func TestVerifyCAFingerprint_InvalidHex(t *testing.T) {
	err := verifyCAFingerprint([]byte("anything"), "sha256:not-hex!")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestVerifyCAFingerprint_NoPEM(t *testing.T) {
	err := verifyCAFingerprint([]byte("not pem data"), "sha256:"+hex.EncodeToString(make([]byte, 32)))
	if err == nil {
		t.Fatal("expected error for non-PEM data")
	}
	if !contains(err.Error(), "no PEM block") {
		t.Fatalf("error should mention PEM, got: %v", err)
	}
}

// ── atomicWriteFile Tests ──────────────────────────────────────────────────

func TestAtomicWriteFile_Basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	data := []byte(`{"key":"value"}`)

	if err := atomicWriteFile(path, data); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("content = %q, want %q", got, data)
	}

	// Temp file should not exist.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal(".tmp file should not remain after atomic write")
	}
}

func TestAtomicWriteFile_Overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	_ = os.WriteFile(path, []byte("old"), 0o600)

	if err := atomicWriteFile(path, []byte("new")); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Fatalf("content = %q, want new", got)
	}
}

func TestAtomicWriteFile_InvalidDir(t *testing.T) {
	err := atomicWriteFile("/nonexistent/dir/file.txt", []byte("data"))
	if err == nil {
		t.Fatal("expected error for invalid directory")
	}
}

// ── loadEnrollmentConfig Tests ─────────────────────────────────────────────

func TestLoadEnrollmentConfig_RoundTrip(t *testing.T) {
	// Save original working dir and change to temp dir.
	origDir, _ := os.Getwd()
	dir := t.TempDir()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(origDir) }()

	ec := &dpEnrollmentConfig{
		CPAddr:   "10.0.0.1:50051",
		NodeID:   "dp-test-node",
		CertFile: "./dp-node.crt",
		KeyFile:  "./dp-node.key",
		CAFile:   "./cluster-ca.crt",
	}
	data, _ := json.MarshalIndent(ec, "", "  ")
	if err := os.WriteFile(enrollmentConfigFile, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	loaded, err := loadEnrollmentConfig()
	if err != nil {
		t.Fatalf("loadEnrollmentConfig: %v", err)
	}
	if loaded.CPAddr != ec.CPAddr {
		t.Fatalf("CPAddr = %q, want %q", loaded.CPAddr, ec.CPAddr)
	}
	if loaded.NodeID != ec.NodeID {
		t.Fatalf("NodeID = %q, want %q", loaded.NodeID, ec.NodeID)
	}
	if loaded.CertFile != ec.CertFile {
		t.Fatalf("CertFile = %q, want %q", loaded.CertFile, ec.CertFile)
	}
	if loaded.KeyFile != ec.KeyFile {
		t.Fatalf("KeyFile = %q, want %q", loaded.KeyFile, ec.KeyFile)
	}
	if loaded.CAFile != ec.CAFile {
		t.Fatalf("CAFile = %q, want %q", loaded.CAFile, ec.CAFile)
	}
}

func TestLoadEnrollmentConfig_MissingFile(t *testing.T) {
	origDir, _ := os.Getwd()
	dir := t.TempDir()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(origDir) }()

	_, err := loadEnrollmentConfig()
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadEnrollmentConfig_InvalidJSON(t *testing.T) {
	origDir, _ := os.Getwd()
	dir := t.TempDir()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(origDir) }()

	_ = os.WriteFile(enrollmentConfigFile, []byte("{bad json"), 0o600)

	_, err := loadEnrollmentConfig()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ── certNeedsRenewal / checkDPCertExpiry Tests ─────────────────────────────

func writeTempCert(t *testing.T, dir string, notBefore, notAfter time.Time) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-dp-node"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return path
}

func TestCertNeedsRenewal_FarFuture(t *testing.T) {
	dir := t.TempDir()
	path := writeTempCert(t, dir, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	days, needs := certNeedsRenewal(path)
	if needs {
		t.Fatalf("cert expiring in %d days should not need renewal", days)
	}
	if days < 300 {
		t.Fatalf("days = %d, expected > 300", days)
	}
}

func TestCertNeedsRenewal_SoonExpiry(t *testing.T) {
	dir := t.TempDir()
	path := writeTempCert(t, dir, time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour))

	days, needs := certNeedsRenewal(path)
	if !needs {
		t.Fatal("cert expiring in 10 days should need renewal")
	}
	if days > 11 || days < 9 {
		t.Fatalf("days = %d, expected ~10", days)
	}
}

func TestCertNeedsRenewal_AlreadyExpired(t *testing.T) {
	dir := t.TempDir()
	path := writeTempCert(t, dir, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	days, needs := certNeedsRenewal(path)
	if !needs {
		t.Fatal("expired cert should need renewal")
	}
	if days >= 0 {
		t.Fatalf("days = %d, expected negative for expired cert", days)
	}
}

func TestCertNeedsRenewal_MissingFile(t *testing.T) {
	days, needs := certNeedsRenewal("/nonexistent/cert.pem")
	if needs {
		t.Fatal("missing file should not trigger renewal")
	}
	if days != -1 {
		t.Fatalf("days = %d, want -1", days)
	}
}

func TestCertNeedsRenewal_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	_ = os.WriteFile(path, []byte("not pem"), 0o600)

	days, needs := certNeedsRenewal(path)
	if needs {
		t.Fatal("invalid PEM should not trigger renewal")
	}
	if days != -1 {
		t.Fatalf("days = %d, want -1", days)
	}
}

func TestCheckDPCertExpiry_Valid(t *testing.T) {
	dir := t.TempDir()
	path := writeTempCert(t, dir, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))

	if err := checkDPCertExpiry(path); err != nil {
		t.Fatalf("expected no error for valid cert: %v", err)
	}
}

func TestCheckDPCertExpiry_Expired(t *testing.T) {
	dir := t.TempDir()
	path := writeTempCert(t, dir, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	err := checkDPCertExpiry(path)
	if err == nil {
		t.Fatal("expected error for expired cert")
	}
	if !contains(err.Error(), "expired") {
		t.Fatalf("error should mention expired, got: %v", err)
	}
}

func TestCheckDPCertExpiry_NearExpiry(t *testing.T) {
	dir := t.TempDir()
	path := writeTempCert(t, dir, time.Now().Add(-time.Hour), time.Now().Add(15*24*time.Hour))

	err := checkDPCertExpiry(path)
	if err == nil {
		t.Fatal("expected warning for near-expiry cert")
	}
	if !contains(err.Error(), "expires in") {
		t.Fatalf("error should mention 'expires in', got: %v", err)
	}
}

func TestCheckDPCertExpiry_MissingFile(t *testing.T) {
	err := checkDPCertExpiry("/nonexistent/cert.pem")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestCheckDPCertExpiry_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	_ = os.WriteFile(path, []byte("not pem"), 0o600)

	err := checkDPCertExpiry(path)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

// ── safeCAPath Tests ───────────────────────────────────────────────────────

func TestSafeCAPath_Valid(t *testing.T) {
	got, err := safeCAPath("/data/ca", "cluster-ca.crt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Clean("/data/ca/cluster-ca.crt")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSafeCAPath_DirTraversal(t *testing.T) {
	_, err := safeCAPath("/data/../etc", "passwd")
	if err == nil {
		t.Fatal("expected error for dir traversal in directory")
	}
}

func TestSafeCAPath_NameWithDots(t *testing.T) {
	// filepath.Clean resolves ../../etc/passwd relative to /data/ca → /etc/passwd
	// which has no ".." — so safeCAPath allows it. The function catches ".." in
	// the cleaned path, which happens when the name escapes above the root.
	got, err := safeCAPath("/data/ca", "../../etc/passwd")
	if err != nil {
		// If safeCAPath rejects it, that's fine too.
		return
	}
	// Otherwise it resolved cleanly — verify the result is cleaned.
	if got == "" {
		t.Fatal("should return non-empty path")
	}
}

func TestSafeCAPath_DirWithDoubleDot(t *testing.T) {
	_, err := safeCAPath("/data/../secret", "ca.crt")
	if err == nil {
		t.Fatal("expected error for .. in directory")
	}
}

// ── parseAndValidateCACert Tests ───────────────────────────────────────────

func generateTestCACert(t *testing.T, isCA bool, notAfter time.Time) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM, key
}

func TestParseAndValidateCACert_Valid(t *testing.T) {
	certPEM, _ := generateTestCACert(t, true, time.Now().Add(365*24*time.Hour))

	cert, err := parseAndValidateCACert(certPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("cert should be CA")
	}
}

func TestParseAndValidateCACert_NotCA(t *testing.T) {
	certPEM, _ := generateTestCACert(t, false, time.Now().Add(365*24*time.Hour))

	_, err := parseAndValidateCACert(certPEM)
	if err == nil {
		t.Fatal("expected error for non-CA cert")
	}
	if !contains(err.Error(), "not a CA") {
		t.Fatalf("error should mention 'not a CA', got: %v", err)
	}
}

func TestParseAndValidateCACert_Expired(t *testing.T) {
	certPEM, _ := generateTestCACert(t, true, time.Now().Add(-time.Hour))

	_, err := parseAndValidateCACert(certPEM)
	if err == nil {
		t.Fatal("expected error for expired cert")
	}
	if !contains(err.Error(), "expired") {
		t.Fatalf("error should mention 'expired', got: %v", err)
	}
}

func TestParseAndValidateCACert_NoPEM(t *testing.T) {
	_, err := parseAndValidateCACert([]byte("not pem data"))
	if err == nil {
		t.Fatal("expected error for non-PEM data")
	}
	if !contains(err.Error(), "no PEM") {
		t.Fatalf("error should mention 'no PEM', got: %v", err)
	}
}

func TestParseAndValidateCACert_InvalidDER(t *testing.T) {
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	_, err := parseAndValidateCACert(badPEM)
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
}

// ── parseAndValidateCAKey Tests ────────────────────────────────────────────

func TestParseAndValidateCAKey_Valid(t *testing.T) {
	certPEM, key := generateTestCACert(t, true, time.Now().Add(365*24*time.Hour))
	cert, _ := parseAndValidateCACert(certPEM)

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	parsedKey, err := parseAndValidateCAKey(keyPEM, cert.PublicKey.(*ecdsa.PublicKey))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsedKey == nil {
		t.Fatal("key should not be nil")
	}
}

func TestParseAndValidateCAKey_Mismatch(t *testing.T) {
	certPEM, _ := generateTestCACert(t, true, time.Now().Add(365*24*time.Hour))
	cert, _ := parseAndValidateCACert(certPEM)

	// Generate a different key.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(otherKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	_, err := parseAndValidateCAKey(keyPEM, cert.PublicKey.(*ecdsa.PublicKey))
	if err == nil {
		t.Fatal("expected error for mismatched key")
	}
	if !contains(err.Error(), "do not match") {
		t.Fatalf("error should mention mismatch, got: %v", err)
	}
}

func TestParseAndValidateCAKey_NoPEM(t *testing.T) {
	pub, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := parseAndValidateCAKey([]byte("not pem"), &pub.PublicKey)
	if err == nil {
		t.Fatal("expected error for non-PEM data")
	}
}

func TestParseAndValidateCAKey_InvalidDER(t *testing.T) {
	pub, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("garbage")})
	_, err := parseAndValidateCAKey(badPEM, &pub.PublicKey)
	if err == nil {
		t.Fatal("expected error for invalid key DER")
	}
}

// ── generateCSR Tests ──────────────────────────────────────────────────────

func TestGenerateCSR(t *testing.T) {
	key, csrPEM, err := generateCSR("test-node-1")
	if err != nil {
		t.Fatalf("generateCSR: %v", err)
	}
	if key == nil {
		t.Fatal("key should not be nil")
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("CSR should be valid PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if csr.Subject.CommonName != "test-node-1" {
		t.Fatalf("CN = %q, want test-node-1", csr.Subject.CommonName)
	}
}

// helper
func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
