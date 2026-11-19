package main

import (
	"strings"
	"testing"
)

// TestChaos122_RefusalRedactsADashLeadingValue — the flag package hands a
// string flag the NEXT token whatever it starts with, so in `-pass -Hunter2`
// the token "-Hunter2" is the password, not a flag name. The refusal's
// redaction keyed on the leading "-" alone and printed such a value verbatim to
// stderr, under a message that says "values redacted". A value is identified by
// position (it follows a flag that takes one), not by its first byte.
func TestChaos122_RefusalRedactsADashLeadingValue(t *testing.T) {
	err := refusePositionalArgs(false, []string{
		"STRAY",
		"-pass", "-Hunter2-pass",
		"--metrics-token", "--tok-secret",
		"-ha-token", "-",
	})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	for _, secret := range []string{"Hunter2", "tok-secret"} {
		if strings.Contains(msg, secret) {
			t.Errorf("the refusal echoed the dash-leading credential value %q to stderr:\n%s", secret, msg)
		}
	}
	for _, want := range []string{"-pass <value>", "--metrics-token <value>", "-ha-token <value>"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal must still name the discarded flag as %q; got:\n%s", want, msg)
		}
	}
}

// TestChaos122_RefusalStillNamesAFlagAfterABoolFlag — the negative control: a
// boolean flag does not consume the next token, so a flag name after it is a
// name and must stay visible (the operator needs to see it was discarded).
func TestChaos122_RefusalStillNamesAFlagAfterABoolFlag(t *testing.T) {
	got := redactArgValuesWith([]string{"-insecure", "-policy", "/data/policy.json"},
		func(name string) bool { return name == "insecure" })
	if want := "-insecure -policy <value>"; got != want {
		t.Fatalf("redactArgValuesWith = %q, want %q", got, want)
	}
}
