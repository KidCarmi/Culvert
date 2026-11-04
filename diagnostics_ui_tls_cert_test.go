package main

import (
	"crypto/tls"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAdminUITLSCertDiagnostics(t *testing.T) {
	adminUITLSCertMu.Lock()
	prevAt, prevKnown := adminUITLSCertNotAfter, adminUITLSCertKnown
	adminUITLSCertMu.Unlock()
	prevCorrupt := uiCustomTLSCorrupt
	t.Cleanup(func() {
		adminUITLSCertMu.Lock()
		adminUITLSCertNotAfter, adminUITLSCertKnown = prevAt, prevKnown
		adminUITLSCertMu.Unlock()
		uiCustomTLSCorrupt = prevCorrupt
	})
	set := func(known bool, d time.Duration, corrupt bool) {
		adminUITLSCertMu.Lock()
		adminUITLSCertNotAfter, adminUITLSCertKnown = time.Now().Add(d), known
		adminUITLSCertMu.Unlock()
		uiCustomTLSCorrupt = corrupt
	}

	set(false, 0, false)
	if rows := checkAdminUITLSCert(); len(rows) != 0 {
		t.Fatalf("self-signed fallback must add no row, got %+v", rows)
	}
	set(true, 90*24*time.Hour, false)
	if rows := checkAdminUITLSCert(); len(rows) != 0 {
		t.Fatalf("a healthy certificate must add no row, got %+v", rows)
	}

	set(true, 10*24*time.Hour+time.Hour, false)
	rows := checkAdminUITLSCert()
	if len(rows) != 1 || rows[0].Code != "ui_tls_cert_expiry" || rows[0].Status != diagWarn ||
		rows[0].OperatorAction == "" || !strings.Contains(rows[0].Message, "expires in 10 day") {
		t.Fatalf("expiring certificate must warn, got %+v", rows)
	}

	set(true, -time.Hour, false)
	rows = checkAdminUITLSCert()
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "has expired") {
		t.Fatalf("expired certificate must warn as expired, got %+v", rows)
	}

	set(false, 0, true)
	rows = checkAdminUITLSCert()
	if len(rows) != 1 || rows[0].Code != "ui_tls_cert_corrupt" || rows[0].Status != diagWarn {
		t.Fatalf("corrupt pair must warn, got %+v", rows)
	}

	// Saved-but-not-serving pair → pending-restart row; none once active.
	dir := t.TempDir()
	prevDir, prevActive := dataDir, uiCustomTLSActive
	t.Cleanup(func() { dataDir, uiCustomTLSActive = prevDir, prevActive })
	dataDir = dir
	set(false, 0, false)
	uiCustomTLSActive = false
	if rows := checkAdminUITLSCert(); len(rows) != 0 {
		t.Fatalf("no saved pair must add no row, got %+v", rows)
	}
	for _, f := range []string{customUITLSCertPath(), customUITLSKeyPath()} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rows = checkAdminUITLSCert()
	if len(rows) != 1 || rows[0].Code != "ui_tls_cert_pending" || rows[0].Status != diagWarn || rows[0].OperatorAction == "" {
		t.Fatalf("saved-but-inactive pair must warn pending, got %+v", rows)
	}
	uiCustomTLSActive = true
	if rows := checkAdminUITLSCert(); len(rows) != 0 {
		t.Fatalf("an active pair must add no pending row, got %+v", rows)
	}
	uiCustomTLSActive = false
	set(false, 0, true)
	if rows := checkAdminUITLSCert(); len(rows) != 1 || rows[0].Code != "ui_tls_cert_corrupt" {
		t.Fatalf("corrupt must not also read as pending, got %+v", rows)
	}
	dataDir = prevDir

	found := false
	for _, c := range buildOperatorContract().Checks {
		found = found || c.Code == "ui_tls_cert_corrupt"
	}
	if !found {
		t.Fatal("row missing from the assembled contract")
	}
}

// The expiry row's operator action must name the step that actually replaces
// the serving certificate for its source. resolveUITLSCertKey returns an
// explicit -tls-cert/-tls-key (flag or YAML) before it considers an uploaded
// pair, so "upload and restart" is false advice for an explicitly configured
// certificate: the same expiring pair stays active after the restart.
func TestAdminUITLSCertExpiryActionBySource(t *testing.T) {
	adminUITLSCertMu.Lock()
	prevAt, prevKnown := adminUITLSCertNotAfter, adminUITLSCertKnown
	adminUITLSCertMu.Unlock()
	prevCorrupt, prevActive := uiCustomTLSCorrupt, uiCustomTLSActive
	t.Cleanup(func() {
		adminUITLSCertMu.Lock()
		adminUITLSCertNotAfter, adminUITLSCertKnown = prevAt, prevKnown
		adminUITLSCertMu.Unlock()
		uiCustomTLSCorrupt, uiCustomTLSActive = prevCorrupt, prevActive
	})
	expiring := func(uploaded bool) OperatorContractCheck {
		t.Helper()
		adminUITLSCertMu.Lock()
		adminUITLSCertNotAfter, adminUITLSCertKnown = time.Now().Add(5*24*time.Hour), true
		adminUITLSCertMu.Unlock()
		uiCustomTLSCorrupt, uiCustomTLSActive = false, uploaded
		rows := checkAdminUITLSCert()
		if len(rows) != 1 || rows[0].Code != "ui_tls_cert_expiry" {
			t.Fatalf("expiring certificate must warn, got %+v", rows)
		}
		return rows[0]
	}

	explicit := expiring(false).OperatorAction
	for _, want := range []string{"-tls-cert/-tls-key", "tls_cert/tls_key", "remove the explicit"} {
		if !strings.Contains(explicit, want) {
			t.Errorf("explicit-path action must mention %q, got %q", want, explicit)
		}
	}
	if strings.HasPrefix(explicit, "Upload") {
		t.Errorf("explicit-path action must not lead with an upload that cannot take effect, got %q", explicit)
	}

	uploaded := expiring(true).OperatorAction
	if !strings.HasPrefix(uploaded, "Upload a replacement") || strings.Contains(uploaded, "-tls-cert") {
		t.Errorf("uploaded-pair action must direct a re-upload, got %q", uploaded)
	}

	// The auto self-signed fallback is never tracked, so it has no row and no
	// action at all — even when a stale uploaded flag is set.
	adminUITLSCertMu.Lock()
	adminUITLSCertKnown = false
	adminUITLSCertMu.Unlock()
	uiCustomTLSActive = false
	if rows := checkAdminUITLSCert(); len(rows) != 0 {
		t.Fatalf("self-signed fallback must add no row, got %+v", rows)
	}

	// The row is not admin-only and must stay path-free: neither rendering
	// carries a configured or data-directory path.
	for _, action := range []string{explicit, uploaded} {
		if strings.Contains(action, "/") && strings.Contains(action, ".pem") {
			t.Errorf("action must not carry a file path, got %q", action)
		}
	}
}

// Codex review, PR #1799: uiCustomTLSActive is set once at startup, so after
// the server boots with uploaded pair A and an admin uploads replacement B,
// the flag still reads true while adminUIServeOnce keeps serving A. The
// pending row must compare the saved certificate with the one actually
// serving, not trust the startup source flag.
func TestAdminUITLSCertPendingAfterReplacementUpload(t *testing.T) {
	withTempDataDirForUITLS(t)
	adminUITLSCertMu.Lock()
	prevAt, prevKnown, prevLeaf := adminUITLSCertNotAfter, adminUITLSCertKnown, adminUITLSCertChainSHA256
	adminUITLSCertMu.Unlock()
	t.Cleanup(func() {
		adminUITLSCertMu.Lock()
		adminUITLSCertNotAfter, adminUITLSCertKnown, adminUITLSCertChainSHA256 = prevAt, prevKnown, prevLeaf
		adminUITLSCertMu.Unlock()
	})

	now := time.Now()
	certA, keyA := newCAPair(t, "ui-a", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	certB, keyB := newCAPair(t, "ui-b", now.Add(-time.Hour), now.Add(90*24*time.Hour))

	// Boot with A: persisted, selected at startup, bound and serving.
	if err := persistCustomUITLS(certA, keyA); err != nil {
		t.Fatal(err)
	}
	if c, k := resolveUITLSCertKey("", ""); c != customUITLSCertPath() || k != customUITLSKeyPath() || !uiCustomTLSActive {
		t.Fatalf("persisted pair A must be selected at startup, got (%q, %q) active=%v", c, k, uiCustomTLSActive)
	}
	servingA, err := tls.X509KeyPair(certA, keyA)
	if err != nil {
		t.Fatal(err)
	}
	noteAdminUITLSCertExpiry(servingA)
	if rows := checkAdminUITLSCert(); len(rows) != 0 {
		t.Fatalf("serving the saved pair must add no row, got %+v", rows)
	}

	// Admin uploads replacement B: saved, but A is still the one served.
	if err := persistCustomUITLS(certB, keyB); err != nil {
		t.Fatal(err)
	}
	rows := checkAdminUITLSCert()
	if len(rows) != 1 || rows[0].Code != "ui_tls_cert_pending" || rows[0].Status != diagWarn {
		t.Fatalf("replacement B saved while A serves must warn pending, got %+v", rows)
	}

	// Once B is what the listener bound (restart or a re-bind attempt), the
	// pending row clears.
	servingB, err := tls.X509KeyPair(certB, keyB)
	if err != nil {
		t.Fatal(err)
	}
	noteAdminUITLSCertExpiry(servingB)
	if rows := checkAdminUITLSCert(); len(rows) != 0 {
		t.Fatalf("serving the replacement must clear the pending row, got %+v", rows)
	}
}

// TestAdminUITLSCertPendingAfterChainOnlyChange is the same-leaf case: the
// operator re-uploads the serving leaf and key with a corrected intermediate
// chain. The leaf is unchanged, but the listener keeps the chain it loaded at
// bind time until a restart, so the row must still report pending.
func TestAdminUITLSCertPendingAfterChainOnlyChange(t *testing.T) {
	withTempDataDirForUITLS(t)
	adminUITLSCertMu.Lock()
	prevAt, prevKnown, prevChain := adminUITLSCertNotAfter, adminUITLSCertKnown, adminUITLSCertChainSHA256
	adminUITLSCertMu.Unlock()
	t.Cleanup(func() {
		adminUITLSCertMu.Lock()
		adminUITLSCertNotAfter, adminUITLSCertKnown, adminUITLSCertChainSHA256 = prevAt, prevKnown, prevChain
		adminUITLSCertMu.Unlock()
	})

	now := time.Now()
	leaf, key := newCAPair(t, "ui-leaf", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	intermediate, _ := newCAPair(t, "ui-intermediate", now.Add(-time.Hour), now.Add(90*24*time.Hour))

	if err := persistCustomUITLS(leaf, key); err != nil {
		t.Fatal(err)
	}
	if c, k := resolveUITLSCertKey("", ""); c != customUITLSCertPath() || k != customUITLSKeyPath() || !uiCustomTLSActive {
		t.Fatalf("persisted pair must be selected at startup, got (%q, %q) active=%v", c, k, uiCustomTLSActive)
	}
	serving, err := tls.X509KeyPair(leaf, key)
	if err != nil {
		t.Fatal(err)
	}
	noteAdminUITLSCertExpiry(serving)
	if rows := checkAdminUITLSCert(); len(rows) != 0 {
		t.Fatalf("serving the saved pair must add no row, got %+v", rows)
	}

	bundle := append(append([]byte{}, leaf...), intermediate...)
	if err := persistCustomUITLS(bundle, key); err != nil {
		t.Fatal(err)
	}
	rows := checkAdminUITLSCert()
	if len(rows) != 1 || rows[0].Code != "ui_tls_cert_pending" || rows[0].Status != diagWarn {
		t.Fatalf("same leaf with a new chain saved while the old chain serves must warn pending, got %+v", rows)
	}

	servingBundle, err := tls.X509KeyPair(bundle, key)
	if err != nil {
		t.Fatal(err)
	}
	noteAdminUITLSCertExpiry(servingBundle)
	if rows := checkAdminUITLSCert(); len(rows) != 0 {
		t.Fatalf("serving the new chain must clear the pending row, got %+v", rows)
	}
}
