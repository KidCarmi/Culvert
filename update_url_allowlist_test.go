package main

// update_url_allowlist_test.go — H4 fix coverage.
//
// validateUpdaterURL must reject any non-default, non-loopback URL
// unless an operator has explicitly listed it in updaterURLAllowlist.
// SetUpdaterURLAllowlist replaces the package allowlist; tests must
// snapshot/restore so they don't leak into each other.

import (
	"strings"
	"testing"
)

func withUpdaterAllowlist(t *testing.T, urls []string, fn func()) {
	t.Helper()
	orig := append([]string(nil), updaterURLAllowlist...)
	SetUpdaterURLAllowlist(urls)
	defer func() { updaterURLAllowlist = orig }()
	fn()
}

// TestValidateUpdaterURL_DefaultURLAlwaysAllowed locks in the contract
// that the package-default URL is unconditionally accepted — the
// out-of-the-box Docker compose deployment must keep working without
// any operator allowlist configuration.
func TestValidateUpdaterURL_DefaultURLAlwaysAllowed(t *testing.T) {
	withUpdaterAllowlist(t, nil, func() {
		if err := validateUpdaterURL(defaultUpdaterURL); err != nil {
			t.Errorf("default URL must always validate; got %v", err)
		}
	})
}

// TestValidateUpdaterURL_LoopbackAllowed covers the local-sidecar use
// case (e.g. dev mode, or operators who run the updater on the host).
func TestValidateUpdaterURL_LoopbackAllowed(t *testing.T) {
	withUpdaterAllowlist(t, nil, func() {
		for _, u := range []string{
			"http://127.0.0.1:7123",
			"http://[::1]:7123",
		} {
			if err := validateUpdaterURL(u); err != nil {
				t.Errorf("loopback %q must validate; got %v", u, err)
			}
		}
	})
}

// TestValidateUpdaterURL_NonDefaultRejectedWithoutAllowlist is the
// canonical H4 guard: any URL that isn't the default and isn't
// loopback must be rejected when the allowlist is empty.
func TestValidateUpdaterURL_NonDefaultRejectedWithoutAllowlist(t *testing.T) {
	withUpdaterAllowlist(t, nil, func() {
		err := validateUpdaterURL("https://updater.attacker.example:7123")
		if err == nil {
			t.Fatal("expected rejection; got nil — H4 attack surface still open")
		}
		if !strings.Contains(err.Error(), "not in allowlist") {
			t.Errorf("error should explain the allowlist requirement; got %v", err)
		}
	})
}

// TestValidateUpdaterURL_AllowlistEntryAccepted confirms the operator
// opt-in path: a URL the admin explicitly trusted at startup is
// accepted.
func TestValidateUpdaterURL_AllowlistEntryAccepted(t *testing.T) {
	url := "https://updater.corp.example:7123"
	withUpdaterAllowlist(t, []string{url}, func() {
		if err := validateUpdaterURL(url); err != nil {
			t.Errorf("allowlisted URL must validate; got %v", err)
		}
	})
}

// TestValidateUpdaterURL_AllowlistMatchIsExact ensures we don't accept
// a URL that merely shares a prefix or suffix with an allowlist entry —
// the match is byte-exact, so there's no parser-confusion attack via
// trailing slashes or query strings.
func TestValidateUpdaterURL_AllowlistMatchIsExact(t *testing.T) {
	withUpdaterAllowlist(t, []string{"https://corp.example:7123"}, func() {
		// Same host but with a path → not in allowlist → rejected.
		if err := validateUpdaterURL("https://corp.example:7123/api"); err == nil {
			t.Error("URL with extra path should not match allowlist entry")
		}
		// Different scheme → rejected.
		if err := validateUpdaterURL("http://corp.example:7123"); err == nil {
			t.Error("URL with downgraded scheme should not match")
		}
	})
}

// TestValidateUpdaterURL_SchemeStillEnforced covers the regression
// case: even an allowlisted URL must use http/https. The H4 layer
// short-circuits AFTER the scheme check, so a malicious config file
// can't sneak a non-HTTP URL into the allowlist.
func TestValidateUpdaterURL_SchemeStillEnforced(t *testing.T) {
	withUpdaterAllowlist(t, []string{"ftp://updater.corp.example:21"}, func() {
		if err := validateUpdaterURL("ftp://updater.corp.example:21"); err == nil {
			t.Error("non-http(s) scheme must be rejected even when allowlisted")
		}
	})
}

// TestSetUpdaterURLAllowlist_ReplacesPriorEntries verifies that
// successive calls do not accumulate — the allowlist mirrors the most
// recent operator-supplied set.
func TestSetUpdaterURLAllowlist_ReplacesPriorEntries(t *testing.T) {
	orig := append([]string(nil), updaterURLAllowlist...)
	defer func() { updaterURLAllowlist = orig }()

	SetUpdaterURLAllowlist([]string{"https://a.example", "https://b.example"})
	if len(updaterURLAllowlist) != 2 {
		t.Fatalf("expected 2 entries; got %d", len(updaterURLAllowlist))
	}
	SetUpdaterURLAllowlist([]string{"https://c.example"})
	if len(updaterURLAllowlist) != 1 || updaterURLAllowlist[0] != "https://c.example" {
		t.Errorf("allowlist should be replaced; got %v", updaterURLAllowlist)
	}
}
