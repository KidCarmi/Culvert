package main

import (
	"strings"
	"testing"
)

func verifyDiagRule(name string, mut func(*PolicyRule)) PolicyRule {
	r := PolicyRule{Name: name, SSLAction: SSLInspect, Action: ActionAllow}
	if mut != nil {
		mut(&r)
	}
	return r
}

func TestInspectUpstreamVerifyRows(t *testing.T) {
	withProfiles(t,
		DecryptionProfile{Name: "skipper", CertVerification: "skip"},
		DecryptionProfile{Name: "strict", CertVerification: "strict"},
		DecryptionProfile{Name: "inherit"},
	)
	off := false

	t.Run("verifying rules contribute nothing", func(t *testing.T) {
		rules := []PolicyRule{
			verifyDiagRule("plain", nil),
			verifyDiagRule("inherit", func(r *PolicyRule) { r.DecryptionProfile = "inherit" }),
			// A strict profile overrides the inline toggle: verification is on.
			verifyDiagRule("strict-wins", func(r *PolicyRule) { r.TLSSkipVerify = true; r.DecryptionProfile = "strict" }),
			// Skipping is irrelevant when the rule is disabled or does not inspect.
			verifyDiagRule("disabled", func(r *PolicyRule) { r.TLSSkipVerify = true; r.Enabled = &off }),
			verifyDiagRule("bypass", func(r *PolicyRule) { r.TLSSkipVerify = true; r.SSLAction = SSLBypass }),
		}
		if rows := checkInspectUpstreamVerify(rules); len(rows) != 0 {
			t.Fatalf("want no row, got %+v", rows)
		}
	})

	t.Run("inline skip is counted without a profile note", func(t *testing.T) {
		rules := []PolicyRule{
			verifyDiagRule("plain", nil),
			verifyDiagRule("inline", func(r *PolicyRule) { r.TLSSkipVerify = true }),
			// A dangling profile reference falls back to the inline toggle.
			verifyDiagRule("dangling", func(r *PolicyRule) { r.TLSSkipVerify = true; r.DecryptionProfile = "gone" }),
		}
		rows := checkInspectUpstreamVerify(rules)
		if len(rows) != 1 {
			t.Fatalf("want one row, got %+v", rows)
		}
		row := rows[0]
		if row.Code != "ssl_inspect_upstream_verify" || row.Status != diagWarn {
			t.Fatalf("unexpected row identity: %+v", row)
		}
		if !strings.HasPrefix(row.Message, "2 enabled SSL-inspection rule(s)") {
			t.Fatalf("want a count of 2, got %q", row.Message)
		}
		if strings.Contains(row.Message, "decryption profile") {
			t.Fatalf("no rule skips through a profile, got %q", row.Message)
		}
	})

	t.Run("profile-driven skip is called out and names nothing", func(t *testing.T) {
		rules := []PolicyRule{
			verifyDiagRule("inline-rule-name", func(r *PolicyRule) { r.TLSSkipVerify = true }),
			verifyDiagRule("hidden-rule-name", func(r *PolicyRule) { r.DecryptionProfile = "skipper" }),
		}
		rows := checkInspectUpstreamVerify(rules)
		if len(rows) != 1 {
			t.Fatalf("want one row, got %+v", rows)
		}
		msg := rows[0].Message
		if !strings.HasPrefix(msg, "2 enabled SSL-inspection rule(s)") ||
			!strings.Contains(msg, "1 of them skip verification through their decryption profile") {
			t.Fatalf("want 2 total and 1 through a profile, got %q", msg)
		}
		for _, leak := range []string{"inline-rule-name", "hidden-rule-name", "skipper"} {
			if strings.Contains(msg+rows[0].OperatorAction, leak) {
				t.Fatalf("viewer-visible row names %q: %q", leak, msg)
			}
		}
	})
}

// The row is wired into the report, and only while a rule actually skips.
func TestOperatorContract_InspectUpstreamVerifyRow(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)
	has := func() bool {
		for _, c := range buildOperatorContract().Checks {
			if c.Code == "ssl_inspect_upstream_verify" {
				return true
			}
		}
		return false
	}
	if has() {
		t.Fatal("row present with no skip-verify rule")
	}
	policyStore.Add(verifyDiagRule("skip-verify-contract-row", func(r *PolicyRule) {
		r.TLSSkipVerify = true
		r.DestFQDN = "legacy.example.com"
	}))
	if !has() {
		t.Fatal("row missing with an enabled skip-verify inspect rule")
	}
}
