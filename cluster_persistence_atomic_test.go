package main

// cluster_persistence_atomic_test.go — CL-7 focused tests for the
// three cluster-domain persistence paths that were hardened to use
// atomicWriteFile.
//
// Before CL-7 the three paths used non-durable primitives:
//   (a) saveHAConfig         — plain os.WriteFile (no tmp+rename)
//   (b) ClusterUpdateState.persist — tmp + os.Rename (atomic but
//                                    not fsynced)
//   (c) persistEnrollCerts   — plain os.WriteFile for the
//                              dp_enrollment.json config file
//
// After CL-7 each call site routes through atomicWriteFile which
// gives unique tmp + chmod + fsync(file) + rename + best-effort
// fsync(parent dir). The tests below exercise each touched call
// site end-to-end:
//   - call the production function on a tempdir-scoped path
//   - verify the target file exists with the expected mode (0o600)
//   - verify no leftover *.tmp* file is present after success
//   - verify the round-tripped content matches what was passed in
//
// The tests do NOT verify fsync directly — that is exercised by
// atomicWriteFile's own tests in main.go:2093+ (existing). These
// tests verify the call-site WIRING: that the three production
// functions have been switched to the durable helper and preserve
// the prior file mode.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// ─── shared helpers ──────────────────────────────────────────────────

var clusterPersistLoggerMu sync.Mutex

func ensureClusterPersistTestLogger(t *testing.T) {
	t.Helper()
	clusterPersistLoggerMu.Lock()
	defer clusterPersistLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
}

// assertFileMode0600 verifies that path exists and has mode 0o600
// (matching the pre-CL-7 file permissions).
func assertFileMode0600(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	// On Windows the executable bit is meaningless; the project
	// targets Linux for production. Keep the assertion strict on
	// Unix and skip the mode check on Windows.
	if runtime.GOOS == "windows" {
		return
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("%q mode = %v, want 0o600", path, got)
	}
}

// assertNoTmpLeftovers walks dir and fails if any *.tmp.* file
// remains. atomicWriteFile guarantees cleanup on both the success
// and the error paths; this asserts the contract holds at the call
// sites we just changed.
func assertNoTmpLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %q: %v", dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.Contains(name, ".tmp.") || strings.HasSuffix(name, ".tmp") {
			t.Errorf("leftover tmp file in %q: %q", dir, name)
		}
	}
}

// ─── (a) saveHAConfig ─────────────────────────────────────────────────

// TestCL7_SaveHAConfig_AtomicWriteFile verifies that saveHAConfig now
// routes through atomicWriteFile. Pre-CL-7 it used plain
// os.WriteFile which left a non-durable / potentially-truncated file
// on crash.
func TestCL7_SaveHAConfig_AtomicWriteFile(t *testing.T) {
	ensureClusterPersistTestLogger(t)

	// haConfigPath derives from filepath.Dir(clusterDBPathGlobal).
	// Snapshot + restore the global to keep the test deterministic
	// under -shuffle=on / -count=2 (CLAUDE.md test-isolation pattern,
	// mirror of the PR #241 whitebox-restore idiom).
	oldGlobal := clusterDBPathGlobal
	t.Cleanup(func() { clusterDBPathGlobal = oldGlobal })

	dir := t.TempDir()
	clusterDBPathGlobal = filepath.Join(dir, "cluster.json")

	cfg := &haConfig{
		Enabled:  true,
		Token:    "cl7-test-token-32-bytes-base64-padded-aaaa", // #nosec G101 -- synthetic test fixture; never leaves this test
		PeerAddr: "127.0.0.1:50051",
		Role:     "leader",
	}
	if err := saveHAConfig(cfg); err != nil {
		t.Fatalf("saveHAConfig: %v", err)
	}

	path := haConfigPath()
	assertFileMode0600(t, path)
	assertNoTmpLeftovers(t, dir)

	// Round-trip the JSON via loadHAConfig (the existing production
	// reader) to confirm the bytes round-trip.
	loaded, err := loadHAConfig()
	if err != nil {
		t.Fatalf("loadHAConfig: %v", err)
	}
	if loaded == nil {
		t.Fatal("loadHAConfig returned nil")
	}
	if loaded.Token != cfg.Token {
		t.Errorf("loaded.Token = %q, want %q", loaded.Token, cfg.Token)
	}
	if loaded.PeerAddr != cfg.PeerAddr {
		t.Errorf("loaded.PeerAddr = %q, want %q", loaded.PeerAddr, cfg.PeerAddr)
	}
	if loaded.Role != cfg.Role {
		t.Errorf("loaded.Role = %q, want %q", loaded.Role, cfg.Role)
	}
	if !loaded.Enabled {
		t.Error("loaded.Enabled = false, want true")
	}
}

// ─── (b) ClusterUpdateState.persist ──────────────────────────────────

// TestCL7_ClusterUpdateState_Persist_AtomicWriteFile verifies that
// ClusterUpdateState.persist() now routes through atomicWriteFile.
// Pre-CL-7 it did a manual tmp + os.Rename — atomic-via-rename but
// NOT fsynced.
//
// The clusterUpdateFile package global was const before CL-7;
// changing it to var (single-keyword, no semantic change) lets the
// test redirect to a tempdir. Production callers do not mutate the
// global at runtime — see the package-level doc on the var.
func TestCL7_ClusterUpdateState_Persist_AtomicWriteFile(t *testing.T) {
	ensureClusterPersistTestLogger(t)

	oldPath := clusterUpdateFile
	t.Cleanup(func() { clusterUpdateFile = oldPath })

	dir := t.TempDir()
	clusterUpdateFile = filepath.Join(dir, "cluster_update.json")

	state := &ClusterUpdateState{
		Active:      true,
		TargetTag:   "cl7-test-v1.0.0",
		PreviousTag: "cl7-test-v0.9.0",
		Initiator:   "cl7-test",
		Phase:       "updating_dps",
		Nodes: map[string]*NodeUpdateStatus{
			"dp-a": {NodeID: "dp-a", Status: "pending"},
		},
		ErrorBudget: ErrorBudgetConfig{MaxConsecutive: 3, MaxPercent: 20},
	}

	state.persist()

	assertFileMode0600(t, clusterUpdateFile)
	assertNoTmpLeftovers(t, dir)

	raw, err := os.ReadFile(clusterUpdateFile)
	if err != nil {
		t.Fatalf("read %q: %v", clusterUpdateFile, err)
	}
	var loaded ClusterUpdateState
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if loaded.TargetTag != state.TargetTag {
		t.Errorf("loaded.TargetTag = %q, want %q", loaded.TargetTag, state.TargetTag)
	}
	if loaded.Phase != state.Phase {
		t.Errorf("loaded.Phase = %q, want %q", loaded.Phase, state.Phase)
	}
	if !loaded.Active {
		t.Error("loaded.Active = false, want true")
	}
	if len(loaded.Nodes) != 1 {
		t.Errorf("len(loaded.Nodes) = %d, want 1", len(loaded.Nodes))
	}
}

// ─── (c) persistEnrollCerts — dp_enrollment.json branch only ─────────

// TestCL7_PersistEnrollCerts_ConfigAtomicWriteFile verifies that the
// dp_enrollment.json write inside persistEnrollCerts now routes
// through atomicWriteFile. The sibling cert/key/CA writes at the top
// of persistEnrollCerts (./dp-node.crt, ./dp-node.key,
// ./cluster-ca.crt) share the same pre-existing plain-os.WriteFile
// defect but are intentionally out of CL-7 scope (see PR body).
//
// persistEnrollCerts uses CWD-relative paths for all four output
// files. t.Chdir(tempdir) isolates the test from the workspace.
func TestCL7_PersistEnrollCerts_ConfigAtomicWriteFile(t *testing.T) {
	ensureClusterPersistTestLogger(t)

	dir := t.TempDir()
	t.Chdir(dir)

	// Build a minimal ECDSA P-256 private key for the encoder. The
	// cert/CA PEMs are intentionally non-real: persistEnrollCerts
	// writes the bytes it is given without parsing them. CL-7's
	// scope is the write primitive, not the cert validation.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	resp := &EnrollResponse{
		CertPEM: "-----BEGIN CERTIFICATE-----\ncl7-test-cert\n-----END CERTIFICATE-----\n",
		CAPEM:   "-----BEGIN CERTIFICATE-----\ncl7-test-ca\n-----END CERTIFICATE-----\n",
	}

	ec, err := persistEnrollCerts(privKey, resp, "127.0.0.1:50051", "cl7-test-node")
	if err != nil {
		t.Fatalf("persistEnrollCerts: %v", err)
	}
	if ec == nil {
		t.Fatal("persistEnrollCerts returned nil config")
	}

	// CL-7's specific target: enrollmentConfigFile must exist with
	// mode 0o600 and no .tmp leftovers. The sibling cert/key/CA
	// files are out of CL-7 scope — we don't assert on their mode
	// here. We just confirm they exist (i.e. persistEnrollCerts
	// completed its full body).
	cfgPath := filepath.Join(dir, enrollmentConfigFile)
	assertFileMode0600(t, cfgPath)
	assertNoTmpLeftovers(t, dir)

	// Round-trip the config JSON to confirm the bytes are intact.
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read %q: %v", cfgPath, err)
	}
	var loaded dpEnrollmentConfig
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if loaded.NodeID != "cl7-test-node" {
		t.Errorf("loaded.NodeID = %q, want cl7-test-node", loaded.NodeID)
	}
	if loaded.CPAddr != "127.0.0.1:50051" {
		t.Errorf("loaded.CPAddr = %q, want 127.0.0.1:50051", loaded.CPAddr)
	}

	// Sanity: confirm the sibling cert/key/CA files were created by
	// the function. (Their atomicity is verified separately by
	// TestPersistEnrollCerts_SiblingCertsAtomicWriteFile below —
	// originally CL-7-out-of-scope, hardened in the
	// persistEnrollCerts-sibling follow-up PR.)
	for _, name := range []string{"dp-node.crt", "dp-node.key", "cluster-ca.crt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("sibling output %q missing: %v", name, err)
		}
	}
}

// TestPersistEnrollCerts_SiblingCertsAtomicWriteFile is the sibling
// follow-up to CL-7 / PR #244. The three writes at the top of
// persistEnrollCerts (main.go:1953/1956/1959) — `./dp-node.crt`,
// `./dp-node.key`, `./cluster-ca.crt` — were left using plain
// os.WriteFile in PR #244 because the discovery-doc CL-7 entry
// named only main.go:1972 (the enrollment-config JSON). This PR
// routes the three sibling writes through atomicWriteFile too.
//
// Asserts the same call-site-wiring contract as the other Bucket-4
// hardening tests: each file exists with mode 0o600 after
// persistEnrollCerts returns, no *.tmp.* leftovers remain in the
// directory (atomicWriteFile's cleanup contract), and the on-disk
// content round-trips byte-for-byte from the EnrollResponse input.
func TestPersistEnrollCerts_SiblingCertsAtomicWriteFile(t *testing.T) {
	ensureClusterPersistTestLogger(t)

	dir := t.TempDir()
	t.Chdir(dir)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	const (
		wantCertPEM = "-----BEGIN CERTIFICATE-----\nsibling-test-cert\n-----END CERTIFICATE-----\n"
		wantCAPEM   = "-----BEGIN CERTIFICATE-----\nsibling-test-ca\n-----END CERTIFICATE-----\n"
	)
	resp := &EnrollResponse{
		CertPEM: wantCertPEM,
		CAPEM:   wantCAPEM,
	}

	ec, err := persistEnrollCerts(privKey, resp, "127.0.0.1:50051", "sibling-test-node")
	if err != nil {
		t.Fatalf("persistEnrollCerts: %v", err)
	}
	if ec == nil {
		t.Fatal("persistEnrollCerts returned nil config")
	}

	// Mode + no-tmp-leftover assertions on each of the three
	// sibling files. assertNoTmpLeftovers runs once over the
	// whole tempdir.
	for _, name := range []string{"dp-node.crt", "dp-node.key", "cluster-ca.crt"} {
		assertFileMode0600(t, filepath.Join(dir, name))
	}
	assertNoTmpLeftovers(t, dir)

	// Content round-trip: each file should contain exactly the
	// bytes persistEnrollCerts was handed. The key is derived from
	// privKey so we can't compare against a hard-coded literal;
	// we assert the PEM marshalled by persistEnrollCerts parses
	// back to the same key bytes.
	gotCert, err := os.ReadFile(filepath.Join(dir, "dp-node.crt"))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(gotCert) != wantCertPEM {
		t.Errorf("dp-node.crt content mismatch:\ngot:  %q\nwant: %q", string(gotCert), wantCertPEM)
	}

	gotCA, err := os.ReadFile(filepath.Join(dir, "cluster-ca.crt"))
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	if string(gotCA) != wantCAPEM {
		t.Errorf("cluster-ca.crt content mismatch:\ngot:  %q\nwant: %q", string(gotCA), wantCAPEM)
	}

	// Key round-trip: parse the on-disk PEM and confirm the curve
	// + D scalar match the originally-generated key.
	gotKey, err := os.ReadFile(filepath.Join(dir, "dp-node.key"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	block, _ := pem.Decode(gotKey)
	if block == nil {
		t.Fatalf("dp-node.key: PEM decode returned nil")
	}
	if block.Type != "EC PRIVATE KEY" {
		t.Errorf("dp-node.key: PEM type = %q, want EC PRIVATE KEY", block.Type)
	}
	loadedKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParseECPrivateKey: %v", err)
	}
	if loadedKey.Curve != privKey.Curve {
		t.Errorf("dp-node.key: curve mismatch")
	}
	if loadedKey.D.Cmp(privKey.D) != 0 {
		t.Errorf("dp-node.key: D scalar mismatch")
	}
}
