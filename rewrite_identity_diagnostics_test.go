package main

import (
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
	if !strings.Contains(ck.Message, "duplicate rewrite rule stableId") {
		t.Errorf("message does not surface the latched reason: %q", ck.Message)
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
