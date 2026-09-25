package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Before this check, a corrupt/unrecoverable rewrite management identity
// (rewrite_identity.go, setRewriteIdentityDegraded) was visible only as a
// boot-time WARN log line and a 503 an admin would hit by opening the
// Rewrite Rules panel — every general-purpose status surface (dashboard,
// /api/diagnostics, /healthz, /readyz) reported green regardless. These
// tests pin the operator-contract row that closes that blind spot.

// TestDiagnostics_RewriteIdentityRow_OKWhenHealthy is the negative control:
// a node whose rewrite management identity is durable reports nothing to
// act on.
func TestDiagnostics_RewriteIdentityRow_OKWhenHealthy(t *testing.T) {
	clearRewriteIdentityDegraded()
	t.Cleanup(clearRewriteIdentityDegraded)

	ck := checkRewriteIdentity()
	if ck.Code != "rewrite_identity" {
		t.Fatalf("code = %q", ck.Code)
	}
	if ck.Status != diagOK {
		t.Errorf("status = %q, want %q (message: %s)", ck.Status, diagOK, ck.Message)
	}
	if ck.OperatorAction != "" {
		t.Errorf("healthy row carries an operator action: %q", ck.OperatorAction)
	}
}

// TestDiagnostics_RewriteIdentityRow_WarnsWhenDegraded: the state that used
// to be a single boot-time log line now reaches the operator contract, with
// the recorded reason surfaced to the admin.
func TestDiagnostics_RewriteIdentityRow_WarnsWhenDegraded(t *testing.T) {
	clearRewriteIdentityDegraded()
	t.Cleanup(clearRewriteIdentityDegraded)
	setRewriteIdentityDegraded("settings-owned rewrite rules refused: duplicate rewrite rule stableId")

	ck := checkRewriteIdentity()
	if ck.Status != diagWarn {
		t.Fatalf("status = %q, want %q", ck.Status, diagWarn)
	}
	if !strings.Contains(ck.Message, "settings-owned rewrite rules refused") {
		t.Errorf("message does not surface the latched reason class: %q", ck.Message)
	}
	if ck.OperatorAction == "" {
		t.Error("degraded row carries no operator action")
	}
}

// TestDiagnostics_RewriteIdentityRow_InDefaultReport pins the row into the
// operator contract, so it cannot be dropped silently.
func TestDiagnostics_RewriteIdentityRow_InDefaultReport(t *testing.T) {
	clearRewriteIdentityDegraded()
	t.Cleanup(clearRewriteIdentityDegraded)
	setRewriteIdentityDegraded("YAML seed identity ledger could not persist: disk full")

	c := buildOperatorContract()
	for i := range c.Checks {
		if c.Checks[i].Code == "rewrite_identity" {
			if c.Checks[i].Status != diagWarn {
				t.Errorf("status = %q, want %q", c.Checks[i].Status, diagWarn)
			}
			return
		}
	}
	t.Fatal("rewrite_identity row missing from the default operator contract")
}

// TestDiagnostics_RewriteIdentityRow_NeverEchoesRawPaths: the latched reason
// wraps persistence errors, and fileutil.AtomicWrite embeds the absolute
// settings path (and its temp-file path) in its error text. The row is
// viewer-reachable, so it surfaces only the code-controlled reason class —
// never the wrapped error. Drives the full /api/diagnostics handler so the
// endpoint-wide wall is exercised with this row in its degraded branch.
func TestDiagnostics_RewriteIdentityRow_NeverEchoesRawPaths(t *testing.T) {
	clearRewriteIdentityDegraded()
	t.Cleanup(clearRewriteIdentityDegraded)
	setRewriteIdentityDegraded("legacy stable-ID backfill (2 rule(s)) could not persist: atomic write /data/admin_settings.json: create temp: open /data/admin_settings.json.tmp.123: no space left on device")

	ck := checkRewriteIdentity()
	if strings.Contains(ck.Message, "/data/") || strings.Contains(ck.OperatorAction, "/data/") {
		t.Fatalf("row echoes a raw filesystem path: %+v", ck)
	}
	if !strings.Contains(ck.Message, "legacy stable-ID backfill (2 rule(s)) could not persist") {
		t.Errorf("row lost the reason class: %q", ck.Message)
	}

	w := httptest.NewRecorder()
	apiDiagnostics(w, viewerCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "/data/admin_settings.json") {
		t.Fatalf("/api/diagnostics echoes the latched raw path: %s", w.Body.String())
	}

	setRewriteIdentityDegraded("/data/admin_settings.json unreadable")
	if ck := checkRewriteIdentity(); strings.Contains(ck.Message, "/data/") {
		t.Fatalf("a path-bearing reason without a class prefix leaked: %q", ck.Message)
	}
}

func TestRewriteIdentityReasonClass(t *testing.T) {
	cases := map[string]string{
		"YAML seed identity ledger could not persist: disk full": "YAML seed identity ledger could not persist",
		"no separator here":   "no separator here",
		"":                    "identity could not be established",
		"/abs/path: boom":     "identity could not be established",
		`C:\\win\\path: boom`: "identity could not be established",
	}
	for in, want := range cases {
		if got := rewriteIdentityReasonClass(in); got != want {
			t.Errorf("rewriteIdentityReasonClass(%q) = %q, want %q", in, got, want)
		}
	}
}
