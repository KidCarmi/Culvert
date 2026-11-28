package main

import (
	"strings"
	"testing"
)

// withSOCKS5LegacyPolicyPostureReset isolates the process-global configured
// marker on both edges, so a failing test cannot leak a WARN row into a later
// test that asserts the aggregate diagnostics verdict.
func withSOCKS5LegacyPolicyPostureReset(t *testing.T) {
	t.Helper()
	resetSOCKS5LegacyPolicyPostureForTest()
	t.Cleanup(resetSOCKS5LegacyPolicyPostureForTest)
}

// TestSOCKS5LegacyPolicyPosture_WarningOnlyWhenConfigured pins the startup
// warning: one line when the listener is configured, nothing at all (and no
// diagnostics row) when SOCKS5 is disabled.
func TestSOCKS5LegacyPolicyPosture_WarningOnlyWhenConfigured(t *testing.T) {
	for _, port := range []int{0, -1} {
		withSOCKS5LegacyPolicyPostureReset(t)
		out := captureLogger(t, func() { logSOCKS5LegacyPolicyPosture(port) })
		if out != "" {
			t.Fatalf("port %d: SOCKS5 disabled must log nothing, got %q", port, out)
		}
		if rows := checkSOCKS5PolicyEnforcement(); len(rows) != 0 {
			t.Fatalf("port %d: SOCKS5 disabled must contribute no diagnostics row, got %+v", port, rows)
		}
	}

	withSOCKS5LegacyPolicyPostureReset(t)
	out := captureLogger(t, func() { logSOCKS5LegacyPolicyPosture(1080) })
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("want exactly one warning line, got %d: %q", n, out)
	}
	for _, want := range []string{"WARNING", "SOCKS5", "1080", "legacy", "NOT enforced", "SWG-901", "Limitations & Known Gaps"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning must mention %q, got %q", want, out)
		}
	}
}

// TestSOCKS5LegacyPolicyPosture_DiagnosticsRow pins the report-only operator
// contract row: present (WARN) only once the listener is configured, absent
// otherwise, and unchanged by the below-admin rendering.
func TestSOCKS5LegacyPolicyPosture_DiagnosticsRow(t *testing.T) {
	resetDiagVerdictGlobals(t)
	withSOCKS5LegacyPolicyPostureReset(t)

	if c := findDiagnosticCheck(buildOperatorContract(), socks5PolicyEnforcementCode); c != nil {
		t.Fatalf("SOCKS5 not configured: the report must carry no %s row, got %+v", socks5PolicyEnforcementCode, *c)
	}

	_ = captureLogger(t, func() { logSOCKS5LegacyPolicyPosture(1080) })
	contract := buildOperatorContract()
	c := findDiagnosticCheck(contract, socks5PolicyEnforcementCode)
	if c == nil {
		t.Fatalf("SOCKS5 configured: %s row missing from the operator contract", socks5PolicyEnforcementCode)
	}
	if c.Status != diagWarn {
		t.Fatalf("row must be a report-only WARN (never fail), got %+v", *c)
	}
	if !strings.Contains(c.Message, "legacy (not enforced)") || !strings.Contains(c.Message, "SWG-901") {
		t.Errorf("message must state the legacy posture and the contract, got %q", c.Message)
	}
	if !strings.Contains(c.OperatorAction, "unchanged") {
		t.Errorf("operator action must say traffic handling is unchanged, got %q", c.OperatorAction)
	}
	red := redactContractForRole(contract, false)
	if v := findDiagnosticCheck(red, socks5PolicyEnforcementCode); v == nil || v.Message != c.Message || v.Status != c.Status {
		t.Fatalf("below-admin rendering changed the row: %+v", v)
	}
}

// TestSOCKS5LegacyPolicyPosture_ReadinessUnchanged pins that the disclosure
// adds nothing to /ready: no row, and the default and strict verdicts are the
// same with and without the posture recorded. /readyz is unauthenticated, so a
// row there would announce the unenforced port to every network client.
func TestSOCKS5LegacyPolicyPosture_ReadinessUnchanged(t *testing.T) {
	withSOCKS5LegacyPolicyPostureReset(t)
	for _, target := range []string{"/ready", "/ready?strict=1"} {
		resetSOCKS5LegacyPolicyPostureForTest()
		beforeCode, beforeStatus, beforeChecks := readyChecks(t, target)

		_ = captureLogger(t, func() { logSOCKS5LegacyPolicyPosture(1080) })
		afterCode, afterStatus, afterChecks := readyChecks(t, target)

		if afterCode != beforeCode || afterStatus != beforeStatus {
			t.Fatalf("%s: verdict changed: before %s/%d, after %s/%d", target, beforeStatus, beforeCode, afterStatus, afterCode)
		}
		if len(afterChecks) != len(beforeChecks) {
			t.Fatalf("%s: readiness rows changed: before %d, after %d", target, len(beforeChecks), len(afterChecks))
		}
		for name, c := range afterChecks {
			if b, ok := beforeChecks[name]; !ok || b.Status != c.Status || b.Detail != c.Detail {
				t.Fatalf("%s: readiness row %q changed by the SOCKS5 posture disclosure: %+v", target, name, c)
			}
		}
	}
}
