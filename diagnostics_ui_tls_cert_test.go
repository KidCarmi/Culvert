package main

import (
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

	found := false
	for _, c := range buildOperatorContract().Checks {
		found = found || c.Code == "ui_tls_cert_corrupt"
	}
	if !found {
		t.Fatal("row missing from the assembled contract")
	}
}
