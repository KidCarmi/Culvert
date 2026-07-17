package main

import (
	"crypto/tls"
	"testing"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
	"github.com/KidCarmi/Culvert/internal/decryptobs"
	"github.com/KidCarmi/Culvert/internal/decryptprofile"
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

// TestInspectedOutcome_FromTLSState pins that the inspected block is built from the
// completed origin TLS state (version/cipher/ALPN mapping), reflects the fail-open scope
// read, and maps CertVerify off dec.SkipVerify.
func TestInspectedOutcome_FromTLSState(t *testing.T) {
	rule := &PolicyRule{ID: "r1", Name: "inspect-all"}
	match := &PolicyMatch{Rule: rule}

	// Verified inspect, TLS 1.3 / h2, fail-open scope consulted (miss).
	dec := sslResolution{
		Action:    SSLInspect,
		Source:    decryptobs.DecisionPolicyInspect,
		ScopeID:   "prof-fo",
		Consulted: true,
	}
	cs := tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2",
	}
	// inspectedOutcome threads hostOnly through unchanged — the inspect path passes an
	// already-port-stripped host, so the builder does no normalization of its own.
	b := inspectedOutcome(dec, "site.example", cs, match, false).toBlock(false)
	if b.Outcome != "inspected" || b.DecisionSource != "policy_inspect" {
		t.Fatalf("outcome/source: %s/%s want inspected/policy_inspect", b.Outcome, b.DecisionSource)
	}
	if b.TLSVersion != "1.3" || b.ALPN != "h2" {
		t.Fatalf("tls/alpn: %s/%s want 1.3/h2", b.TLSVersion, b.ALPN)
	}
	if b.Cipher != tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256) {
		t.Fatalf("cipher not named: %q", b.Cipher)
	}
	if b.CertVerify != "verified" || b.FailStage != "none" || b.FailCategory != "none" {
		t.Fatalf("inspected must be verified/none/none: %+v", b)
	}
	if b.Host != "site.example" {
		t.Fatalf("host not threaded: %q", b.Host)
	}
	if !b.CacheConsulted || b.ProfileID != "prof-fo" || b.CacheHit {
		t.Fatalf("fail-open consulted-miss: consulted=%v profile=%q hit=%v", b.CacheConsulted, b.ProfileID, b.CacheHit)
	}
	if b.RuleID != "r1" || b.RuleName != "inspect-all" {
		t.Fatalf("rule identity not carried: %+v", b)
	}

	// TLS 1.2 + skip-verify ⇒ CertVerify skipped; empty ALPN ⇒ the valid empty member.
	dec2 := sslResolution{Action: SSLInspect, Source: decryptobs.DecisionPolicyInspect, SkipVerify: true}
	cs2 := tls.ConnectionState{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	b2 := inspectedOutcome(dec2, "x", cs2, match, true).toBlock(false)
	if b2.TLSVersion != "1.2" || b2.CertVerify != "skipped" || b2.ALPN != "" {
		t.Fatalf("skip-verify/1.2/empty-alpn: tls=%s cert=%s alpn=%q", b2.TLSVersion, b2.CertVerify, b2.ALPN)
	}
	if !b2.CacheConsulted && b2.ProfileID != "" { // no fail-open scope ⇒ not consulted
		t.Fatalf("no-scope must not be consulted: %+v", b2)
	}
}

// TestInspectedOutcome_CertVerifyFromEffectiveSkip pins the END-TO-END data flow that
// CertVerify reflects the EFFECTIVE upstream verification the origin handshake performed:
// a decryption profile's CertVerification overrides the rule's inline dec.SkipVerify when
// the handshake tls.Config is built (upstreamInspectTLSConfigForMatch), and the record
// CAPTURES that config's InsecureSkipVerify (Codex #801). Threading the built config's
// effective skip — not re-resolving — is what closes the TOCTOU (see the sibling test).
func TestInspectedOutcome_CertVerifyFromEffectiveSkip(t *testing.T) {
	withProfiles(t,
		DecryptionProfile{Name: "skip", CertVerification: "skip"},
		DecryptionProfile{Name: "strict", CertVerification: "strict"},
	)
	cs := tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256}

	// Profile "skip" overrides a rule with inline SkipVerify=false ⇒ the handshake config
	// skips verification, so the captured-and-recorded value must say skipped.
	mSkip := matchWith(&PolicyRule{DecryptionProfile: "skip"})
	effSkip := upstreamInspectTLSConfigForMatch("h", false, mSkip).InsecureSkipVerify
	decNoInline := sslResolution{Action: SSLInspect, Source: decryptobs.DecisionPolicyInspect, SkipVerify: false}
	if b := inspectedOutcome(decNoInline, "h", cs, mSkip, effSkip).toBlock(false); b.CertVerify != "skipped" {
		t.Fatalf("profile skip over inline-false: cert_verify=%s want skipped", b.CertVerify)
	}

	// Profile "strict" overrides a rule with inline SkipVerify=true ⇒ the handshake config
	// verifies, so the recorded value must say verified.
	mStrict := matchWith(&PolicyRule{DecryptionProfile: "strict"})
	effVerify := upstreamInspectTLSConfigForMatch("h", true, mStrict).InsecureSkipVerify
	decInline := sslResolution{Action: SSLInspect, Source: decryptobs.DecisionPolicyInspect, SkipVerify: true}
	if b := inspectedOutcome(decInline, "h", cs, mStrict, effVerify).toBlock(false); b.CertVerify != "verified" {
		t.Fatalf("profile strict over inline-true: cert_verify=%s want verified", b.CertVerify)
	}
}

// TestInspectedOutcome_CertVerifyCapturedNotRederived pins the TOCTOU fix: the recorded
// cert_verify reflects the effectiveSkip CAPTURED from the handshake config, and a profile
// mutation AFTER that config was built (admin edit / CP→DP config sync landing mid-handshake)
// must NOT change the recorded value. Re-resolving the live store here would flip the audit
// record to the opposite of what the session actually did (CWE-367 → CWE-778).
func TestInspectedOutcome_CertVerifyCapturedNotRederived(t *testing.T) {
	withProfiles(t, DecryptionProfile{Name: "p", CertVerification: "skip"})
	m := matchWith(&PolicyRule{DecryptionProfile: "p"})
	cs := tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256}

	// Handshake config built while the profile says "skip" ⇒ the origin leg skipped verify.
	effSkip := upstreamInspectTLSConfigForMatch("h", false, m).InsecureSkipVerify
	if !effSkip {
		t.Fatal("precondition: profile skip must skip upstream verification")
	}

	// The profile now mutates to "strict" DURING the handshake window.
	globalDecryptionProfiles = decryptprofile.New()
	if _, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "p", CertVerification: "strict"}); err != nil {
		t.Fatalf("mutate profile: %v", err)
	}

	// A re-resolution would now yield "verified"; the captured value must still be "skipped".
	if got := resolveInspectSkipVerify(m, false); got {
		// resolveInspectSkipVerify now returns false (strict) — proving a re-derive would flip.
		t.Fatal("test premise: post-mutation re-resolution should return verify=true (skip=false)")
	}
	dec := sslResolution{Action: SSLInspect, Source: decryptobs.DecisionPolicyInspect}
	if b := inspectedOutcome(dec, "h", cs, m, effSkip).toBlock(false); b.CertVerify != "skipped" {
		t.Fatalf("cert_verify must reflect the captured handshake posture (skipped), got %s", b.CertVerify)
	}
}

// TestNonTLSFallbackOutcome pins the not_decrypted/non_tls_fallback classification for a
// CONNECT whose client spoke a non-TLS protocol (raw relay fallback): TLS/cert/fail fields
// stay at sentinels because no MITM handshake happened.
func TestNonTLSFallbackOutcome(t *testing.T) {
	b := nonTLSFallbackOutcome("ssh.example").toBlock(false)
	if b.Outcome != "not_decrypted" || b.DecisionSource != "non_tls_fallback" {
		t.Fatalf("outcome/source: %s/%s want not_decrypted/non_tls_fallback", b.Outcome, b.DecisionSource)
	}
	if b.Host != "ssh.example" {
		t.Fatalf("host: %q", b.Host)
	}
	if b.TLSVersion != "unknown" || b.CertVerify != "not_checked" || b.ALPN != "" ||
		b.FailStage != "none" || b.FailCategory != "none" {
		t.Fatalf("non-TLS fallback must carry sentinels: %+v", b)
	}
	if b.CacheConsulted || b.CacheHit || b.Rescued {
		t.Fatalf("non-TLS fallback carries no cache/rescue state: %+v", b)
	}
}

// TestTLSVersionEnum_And_ALPNEnum pins the bounded mapping for the version/ALPN helpers,
// including the coercion of out-of-vocabulary inputs to the sentinel/empty member.
func TestTLSVersionEnum_And_ALPNEnum(t *testing.T) {
	if tlsVersionEnum(tls.VersionTLS12) != decryptobs.TLSVersion12 ||
		tlsVersionEnum(tls.VersionTLS13) != decryptobs.TLSVersion13 {
		t.Fatal("1.2/1.3 mapping wrong")
	}
	// TLS 1.0/1.1 and 0 (no handshake) are out of the inspected vocabulary ⇒ unknown.
	if tlsVersionEnum(tls.VersionTLS10) != decryptobs.TLSVersionUnknown ||
		tlsVersionEnum(0) != decryptobs.TLSVersionUnknown {
		t.Fatal("out-of-vocab version must coerce to unknown")
	}
	if alpnEnum("h2") != decryptobs.ALPNH2 || alpnEnum("http/1.1") != decryptobs.ALPNHTTP11 {
		t.Fatal("h2/http1.1 mapping wrong")
	}
	if alpnEnum("") != decryptobs.ALPNNone || alpnEnum("spdy/3") != decryptobs.ALPNNone {
		t.Fatal("empty/unknown ALPN must coerce to the empty member")
	}
}
