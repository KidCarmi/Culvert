package main

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/decryptprofile"
)

// withProfiles swaps the global store for a test one and restores it, so these
// tests never leak profile state into other tests (PR3d determinism lesson).
func withProfiles(t *testing.T, profiles ...DecryptionProfile) {
	t.Helper()
	prev := globalDecryptionProfiles
	s := decryptprofile.New()
	for _, p := range profiles {
		if _, err := s.Add(p); err != nil {
			t.Fatalf("seed profile %q: %v", p.Name, err)
		}
	}
	globalDecryptionProfiles = s
	t.Cleanup(func() { globalDecryptionProfiles = prev })
}

func matchWith(rule *PolicyRule) *PolicyMatch { return &PolicyMatch{Rule: rule} }
func bptr(b bool) *bool                       { return &b }

// TestResolveStripALPN_Precedence pins profile → inline → default.
func TestResolveStripALPN_Precedence(t *testing.T) {
	withProfiles(t,
		DecryptionProfile{Name: "h2", InspectHTTP2: bptr(true)},
		DecryptionProfile{Name: "strip", InspectHTTP2: bptr(false)},
		DecryptionProfile{Name: "silent"}, // InspectHTTP2 nil → falls through
	)
	cases := []struct {
		name string
		rule *PolicyRule
		want bool // want strip
	}{
		{"profile native H2 wins", &PolicyRule{DecryptionProfile: "h2", StripALPN: bptr(true)}, false},
		{"profile force-strip wins", &PolicyRule{DecryptionProfile: "strip", StripALPN: bptr(false)}, true},
		{"profile-without-h2 falls to inline", &PolicyRule{DecryptionProfile: "silent", StripALPN: bptr(false)}, false},
		{"dangling profile falls to inline", &PolicyRule{DecryptionProfile: "ghost", StripALPN: bptr(false)}, false},
		{"dangling profile, no inline → strip default", &PolicyRule{DecryptionProfile: "ghost"}, true},
		{"no profile, inline true", &PolicyRule{StripALPN: bptr(true)}, true},
		{"no profile, no inline → strip default", &PolicyRule{}, true},
	}
	for _, c := range cases {
		if got := resolveStripALPN(matchWith(c.rule)); got != c.want {
			t.Errorf("%s: resolveStripALPN = %v, want %v", c.name, got, c.want)
		}
	}
	// nil match / nil rule → strip default, never panics.
	if !resolveStripALPN(nil) || !resolveStripALPN(&PolicyMatch{}) {
		t.Fatal("nil match/rule must resolve to strip default")
	}
}

func TestResolveH2StallTimeout(t *testing.T) {
	withProfiles(t,
		DecryptionProfile{Name: "slow", StallTimeoutSecs: 120},
		DecryptionProfile{Name: "default"}, // 0 → engine default
	)
	if got := resolveH2StallTimeout(matchWith(&PolicyRule{DecryptionProfile: "slow"})); got != 120*time.Second {
		t.Fatalf("profile stall = %v, want 120s", got)
	}
	if got := resolveH2StallTimeout(matchWith(&PolicyRule{DecryptionProfile: "default"})); got != h2StreamStallTimeout {
		t.Fatalf("zero stall must inherit engine default, got %v", got)
	}
	if got := resolveH2StallTimeout(matchWith(&PolicyRule{DecryptionProfile: "ghost"})); got != h2StreamStallTimeout {
		t.Fatalf("dangling profile must inherit engine default, got %v", got)
	}
}

func TestResolveInspectSkipVerify(t *testing.T) {
	withProfiles(t,
		DecryptionProfile{Name: "skip", CertVerification: "skip"},
		DecryptionProfile{Name: "strict", CertVerification: "strict"},
		DecryptionProfile{Name: "inherit"}, // "" → rule TLSSkipVerify
	)
	// profile skip → skip regardless of rule.
	if !resolveInspectSkipVerify(matchWith(&PolicyRule{DecryptionProfile: "skip"}), false) {
		t.Fatal("CertVerification=skip must skip verify")
	}
	// profile strict → verify even if rule says skip.
	if resolveInspectSkipVerify(matchWith(&PolicyRule{DecryptionProfile: "strict"}), true) {
		t.Fatal("CertVerification=strict must verify (override rule skip)")
	}
	// inherit → rule value.
	if !resolveInspectSkipVerify(matchWith(&PolicyRule{DecryptionProfile: "inherit"}), true) {
		t.Fatal("CertVerification='' must inherit rule TLSSkipVerify=true")
	}
	// dangling / no profile → rule value.
	if resolveInspectSkipVerify(matchWith(&PolicyRule{DecryptionProfile: "ghost"}), false) {
		t.Fatal("dangling profile must inherit rule TLSSkipVerify=false")
	}
}

func TestApplyProfileUpstreamTLSVersions(t *testing.T) {
	withProfiles(t,
		DecryptionProfile{Name: "floor13", MinTLSVersion: "1.3"},
		DecryptionProfile{Name: "cap12", MaxTLSVersion: "1.2"},
	)
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	applyProfileUpstreamTLSVersions(cfg, matchWith(&PolicyRule{DecryptionProfile: "floor13"}))
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinTLSVersion=1.3 must raise floor, got %x", cfg.MinVersion)
	}
	cfg2 := &tls.Config{MinVersion: tls.VersionTLS12}
	applyProfileUpstreamTLSVersions(cfg2, matchWith(&PolicyRule{DecryptionProfile: "cap12"}))
	if cfg2.MaxVersion != tls.VersionTLS12 {
		t.Fatalf("MaxTLSVersion=1.2 must cap, got %x", cfg2.MaxVersion)
	}
	// No profile → config untouched.
	cfg3 := &tls.Config{MinVersion: tls.VersionTLS12}
	applyProfileUpstreamTLSVersions(cfg3, matchWith(&PolicyRule{}))
	if cfg3.MinVersion != tls.VersionTLS12 || cfg3.MaxVersion != 0 {
		t.Fatalf("no profile must leave config untouched: %+v", cfg3)
	}
}

// TestRuleReferencesDecryptionProfile pins the Where-Used / delete-block wiring.
func TestRuleReferencesDecryptionProfile(t *testing.T) {
	r := &PolicyRule{DecryptionProfile: "Prod-H2"}
	if got := ruleReferencesObject(r, "decryption-profile", "prod-h2"); got != "decryptionProfile" {
		t.Fatalf("case-insensitive ref = %q, want decryptionProfile", got)
	}
	if got := ruleReferencesObject(r, "decryption-profile", "other"); got != "" {
		t.Fatalf("non-matching ref = %q, want empty", got)
	}
	if !objectRefTypes["decryption-profile"] {
		t.Fatal("decryption-profile must be a known objectRefType")
	}
}
