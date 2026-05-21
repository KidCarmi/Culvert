package main

// cdr_revoke_rpc_no_versioning_test.go — regression coverage for the
// Category D-sec fix that removed saveConfigVersion from
// apiCDRRevokeRPC. Per roadmap/CATEGORY-D-PRIME-DIRECTION.md §3 and
// the upstream roadmap/CONFIG-VERSIONING-TRIAGE.md Category D′.
//
// Background
// ==========
// Before this PR, apiCDRRevokeRPC (cdr_ui.go) called:
//
//   auditEventDiff(r, "cdr.instance.revoke_rpc", ...)
//   saveConfigVersion(sessionAdmin(r), "cdr.instance.revoke_rpc")
//
// The saveConfigVersion call was security-dangerous AND misleading:
//
//   1. Restoring a revocation on rollback would silently un-revoke a
//      compromised credential / endpoint — a security regression by
//      definition. Same shape as auth.password_change in PR #261.
//   2. CDR state is not in the rollback surface anyway
//      (captureConfigBackup does NOT read cdr_instances.json), so the
//      snapshot was a no-op for the revocation state.
//
// This PR removes the saveConfigVersion call. The audit trail
// (auditEventDiff) is preserved.
//
// What this test asserts
// ======================
// A successful revoke flow:
//   1. Returns HTTP 200.
//   2. Emits an audit-ring entry with Action="cdr.instance.revoke_rpc"
//      (per CLAUDE.md "Test-authoring pitfalls": assert on a unique
//      Detail-string discriminator, not on len(auditGet()) deltas).
//   3. Does NOT produce a config-version envelope with
//      Meta.Action="cdr.instance.revoke_rpc" on disk.
//
// The test exercises the full handler — fake Sluice gRPC server,
// pooled caller client, real cert file under cdrCertsRoot — so the
// audit path actually fires. Cert directory writes require
// /data/integrations/sluice/<name>/ to be writable; restricted
// environments skip gracefully (same pattern as cdr_coverage_test.go
// at :242-244).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAPICDRRevokeRPC_DoesNotCreateConfigVersion is the regression
// guard for the Category D-sec fix. With the saveConfigVersion call
// restored on this handler, the test fails because an envelope with
// Meta.Action="cdr.instance.revoke_rpc" appears in the config-version
// directory.
func TestAPICDRRevokeRPC_DoesNotCreateConfigVersion(t *testing.T) {
	resetCDRState(t)
	tmp := snapshotConfigVersionsDir(t)

	const (
		targetInstance = "cdr-revoke-no-version-target"
		callerInstance = "cdr-revoke-no-version-caller"
	)

	// Cert directory lives under cdrCertsRoot, which is a const at
	// /data/integrations/sluice. Test environments without /data
	// access skip with a clear message (precedent at
	// cdr_coverage_test.go:242-244 and similar elsewhere).
	certDir, err := cdrInstanceCertsDir(targetInstance)
	if err != nil {
		t.Fatalf("cdrInstanceCertsDir(%q): %v", targetInstance, err)
	}
	if mkErr := os.MkdirAll(certDir, 0o700); mkErr != nil {
		t.Skipf("cannot write %s (test env restricted): %v", certDir, mkErr)
	}
	t.Cleanup(func() { _ = os.RemoveAll(certDir) })

	// Generate a real self-signed ECDSA cert. sluiceauth.Fingerprint
	// (called by loadCertFingerprint) parses the PEM and hashes the
	// DER, so the cert must be syntactically valid.
	clientCertPath := filepath.Join(certDir, "client.pem")
	pemBytes := mustGenerateTestCertPEM(t)
	if err := os.WriteFile(clientCertPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write client cert: %v", err)
	}

	// Seed the target instance in the registry.
	if _, err := cdrInstances.Add(CDREnrolledInstance{
		Name:           targetInstance,
		Endpoint:       "sluice-target:8443",
		ClientCertPath: clientCertPath,
	}); err != nil {
		t.Fatalf("cdrInstances.Add(target): %v", err)
	}

	// Spin up a fake Sluice pool member that will receive the
	// RevokeClient call. The caller instance must have a DIFFERENT
	// name (cdrPickOtherClient excludes the target by name).
	pc, stop := newPooledFake(t, callerInstance, &fakeSluice{})
	t.Cleanup(stop)
	withTempPool(t, pc)

	// Unique discriminator embedded in the Reason field so audit
	// ring assertion finds THIS run's entry under -count=N / -shuffle.
	discriminator := "test-revoke-no-version-" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000"), ".", "-")
	bodyBytes, _ := json.Marshal(map[string]string{
		"name":   targetInstance,
		"reason": discriminator,
	})

	w := httptest.NewRecorder()
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/cdr/revoke-rpc", bytes.NewReader(bodyBytes))
	r.Header.Set("Content-Type", "application/json")

	apiCDRRevokeRPC(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("apiCDRRevokeRPC status = %d; want 200 (body: %s)", w.Code, w.Body.String())
	}

	// Audit trail must still fire — the contract preserved by this PR
	// is "audit yes, version no". Search the ring for THIS run's
	// discriminator (the Reason string is embedded in Detail).
	assertAuditEntryWithDiscriminator(t, "cdr.instance.revoke_rpc", discriminator)

	// And the key assertion: no config-version envelope on disk has
	// Meta.Action == "cdr.instance.revoke_rpc".
	assertNoConfigVersionWithAction(t, tmp, "cdr.instance.revoke_rpc")
}

// assertAuditEntryWithDiscriminator scans the audit ring for an entry
// whose Action matches AND whose Detail contains the discriminator.
// Per CLAUDE.md test-authoring pitfalls, does NOT assert on
// len(auditGet()) deltas — the ring saturates at maxAuditLogs=500.
func assertAuditEntryWithDiscriminator(t *testing.T, action, discriminator string) {
	t.Helper()
	for _, e := range auditGet() {
		if e.Action == action && strings.Contains(e.Detail, discriminator) {
			return
		}
	}
	t.Errorf("no audit entry with Action=%q and Detail containing %q found (proves audit path did NOT execute — the test setup is broken OR the production removal removed too much)", action, discriminator)
}

// assertNoConfigVersionWithAction reads every envelope in dir and
// fails the test if any has Meta.Action matching. Reusable across
// the Category D′ removal PRs.
func assertNoConfigVersionWithAction(t *testing.T, dir, action string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read tmp dir: %v", err)
	}
	type envelope struct {
		Meta struct {
			Version int    `json:"version"`
			Actor   string `json:"actor"`
			Action  string `json:"action"`
		} `json:"meta"`
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var env envelope
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("unmarshal %s: %v", e.Name(), err)
		}
		if env.Meta.Action == action {
			t.Errorf("config-version envelope %s has Meta.Action=%q — the saveConfigVersion call was re-added; this handler is in Category D' (state not in the rollback surface) or D-sec (rollback would be a security regression) and MUST NOT create a config version. See roadmap/CONFIG-VERSIONING-TRIAGE.md + roadmap/CATEGORY-D-PRIME-DIRECTION.md.",
				e.Name(), env.Meta.Action)
		}
	}
}

// mustGenerateTestCertPEM creates a self-signed ECDSA P-256 cert in
// PEM form. The cert is only used so loadCertFingerprint can compute
// a SHA-256 fingerprint; subject / validity / SAN don't matter.
func mustGenerateTestCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "cdr-revoke-test-cert"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
