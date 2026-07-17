package main

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// decryption_populate_test.go — ADR-0011 Phase 1 (population). The CONNECT bypass path
// now attaches a correct DecryptionOutcome to the close record. These pin the two new
// pieces of logic: resolveSSLDecision's source classification and bypassOutcome's
// outcome × decision-source matrix.

// TestResolveSSLDecision_ClassifiesSource pins that the decision source reflects WHICH
// arm of the precedence chain decided the action (behavior of the action itself is
// unchanged and covered by the existing autoexclude suite).
func TestResolveSSLDecision_ClassifiesSource(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)

	// No match (or a non-inspect rule) ⇒ policy bypass, classified manual_ssl_bypass; the
	// fail-open read never runs, so Consulted is false.
	if d := resolveSSLDecision(nil, "any.example", "1.2.3.4"); d.Action != SSLBypass || d.Source != decryptobs.DecisionManualSSLBypass || d.Consulted {
		t.Fatalf("nil match: action=%v source=%v consulted=%v want bypass/manual_ssl_bypass/false", d.Action, d.Source, d.Consulted)
	}

	// A fail-open inspect rule with an empty cache ⇒ inspect, policy_inspect, but the
	// fail-open read DID run and miss ⇒ Consulted true, scope carried.
	fo, foScope := bindFailOpenProfile(t, "fo", "fail-open")
	if d := resolveSSLDecision(fo, "clean.example", "1.2.3.4"); d.Action != SSLInspect || d.Source != decryptobs.DecisionPolicyInspect || !d.Consulted || d.ScopeID != foScope {
		t.Fatalf("clean inspect (consulted miss): action=%v source=%v consulted=%v scope=%v", d.Action, d.Source, d.Consulted, d.ScopeID)
	}

	// A learned exclusion under that scope ⇒ bypass, autoexclude_cache, with reason+scope, consulted.
	autoExclude().Observe(foScope, "fo", "seeded.example", autoexclude.ReasonClientPinned, "id:probe")
	d := resolveSSLDecision(fo, "seeded.example", "1.2.3.4")
	if d.Action != SSLBypass || d.Source != decryptobs.DecisionAutoexcludeCache ||
		d.ExclReason != autoexclude.ReasonClientPinned || d.ScopeID != foScope || !d.Consulted {
		t.Fatalf("learned: action=%v source=%v reason=%v scope=%v consulted=%v", d.Action, d.Source, d.ExclReason, d.ScopeID, d.Consulted)
	}
}

// TestBypassOutcome_Matrix pins the outcome × decision-source projection for every
// reachable bypass classification, and that a bypass carries TLS sentinels (no handshake
// happened) and the host is normalized (port stripped).
func TestBypassOutcome_Matrix(t *testing.T) {
	cases := []struct {
		name          string
		dec           sslResolution
		wantOutcome   string
		wantSource    string
		wantCacheHit  bool
		wantConsulted bool
	}{
		{"manual", sslResolution{Action: SSLBypass, Source: decryptobs.DecisionManualSSLBypass}, "bypass_manual", "manual_ssl_bypass", false, false},
		{"learned", sslResolution{Action: SSLBypass, Source: decryptobs.DecisionAutoexcludeCache, ExclReason: autoexclude.ReasonClientPinned, ScopeID: "prof1", Consulted: true}, "bypass_learned", "autoexclude_cache", true, true},
		// CA-not-ready on a fail-CLOSE / no-profile rule: cache never consulted.
		{"unavailable_failclose", sslResolution{Action: SSLInspect, Source: decryptobs.DecisionPolicyInspect}, "bypass_manual", "inspect_unavailable", false, false},
		// CA-not-ready on a fail-OPEN rule whose cache MISSED: consulted, not hit — the
		// distinction Codex flagged (PR #795); cache_consulted must be true here.
		{"unavailable_failopen_miss", sslResolution{Action: SSLInspect, Source: decryptobs.DecisionPolicyInspect, ScopeID: "prof2", Consulted: true}, "bypass_manual", "inspect_unavailable", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := bypassOutcome(c.dec, "host.example:443").toBlock(false)
			if b.Outcome != c.wantOutcome || b.DecisionSource != c.wantSource || b.CacheHit != c.wantCacheHit || b.CacheConsulted != c.wantConsulted {
				t.Fatalf("outcome=%s source=%s hit=%v consulted=%v want %s/%s/hit=%v/consulted=%v",
					b.Outcome, b.DecisionSource, b.CacheHit, b.CacheConsulted, c.wantOutcome, c.wantSource, c.wantCacheHit, c.wantConsulted)
			}
			if b.Host != "host.example" {
				t.Fatalf("host not normalized (port strip): %q", b.Host)
			}
			// A bypass does NO MITM handshake, so the TLS/cert/fail fields are sentinels.
			if b.TLSVersion != "unknown" || b.CertVerify != "not_checked" || b.FailStage != "none" || b.FailCategory != "none" {
				t.Fatalf("bypass must carry TLS/fail sentinels: %+v", b)
			}
		})
	}

	// The learned case carries the exclusion reason + scope (== profile id) for SIEM joins.
	b := bypassOutcome(sslResolution{Action: SSLBypass, Source: decryptobs.DecisionAutoexcludeCache, ExclReason: autoexclude.ReasonClientPinned, ScopeID: "prof1"}, "h").toBlock(false)
	if b.ExclReason != "client_pinned" || b.ExclScope != "prof1" || b.ProfileID != "prof1" {
		t.Fatalf("learned bypass must carry excl reason/scope/profile: %+v", b)
	}
}
