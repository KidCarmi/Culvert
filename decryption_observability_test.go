package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
	"github.com/KidCarmi/Culvert/internal/decryptobs"
	"github.com/KidCarmi/Culvert/internal/logstore"
)

// TestDecBlock_NilOmitsKey pins the byte-identical claim: with no decryption decision
// (Dec == nil), the "dec" key is absent from the wire (block-level omitempty).
func TestDecBlock_NilOmitsKey(t *testing.T) {
	b, err := json.Marshal(logstore.Entry{Host: "example.com", Method: "CONNECT"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), `"dec"`) {
		t.Fatalf("nil Dec must omit the dec key entirely: %s", b)
	}
}

// TestDecBlock_PresentSerializesExplicitNegatives is the load-bearing §2.1 test: once the
// block is present, false booleans, "none" enums, "" (alpn/excl_reason), and 0 ints all
// serialize EXPLICITLY (queryable), while genuinely-optional empty strings are omitted.
func TestDecBlock_PresentSerializesExplicitNegatives(t *testing.T) {
	o := DecryptionOutcome{
		Outcome:        decryptobs.OutcomeNotDecrypted,
		DecisionSource: decryptobs.DecisionNonTLSFallback,
		Host:           "example.com",
		TLSVersion:     decryptobs.TLSVersionUnknown,
		ALPN:           decryptobs.ALPNNone, // "" — must serialize explicitly
		CertVerify:     decryptobs.CertVerifyNotChecked,
		FailStage:      decryptobs.FailStageNone,
		FailCategory:   decryptobs.FailCategoryNone,
		// bools false, ScopeRuleCount 0, ExclReason "" by zero value
	}
	b, err := json.Marshal(logstore.Entry{Dec: o.toBlock(false)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		`"dec":{`,
		`"schema_version":1`,
		`"outcome":"not_decrypted"`,
		`"decision_source":"non_tls_fallback"`,
		`"host":"example.com"`,
		`"tls_version":"unknown"`,
		`"alpn":""`, // the valid empty member serializes explicitly
		`"cert_verify":"not_checked"`,
		`"fail_stage":"none"`,
		`"fail_category":"none"`,
		`"excl_reason":""`, // explicit "no exclusion"
		`"cache_consulted":false`,
		`"cache_hit":false`,
		`"cache_learned":false`,
		`"rescued":false`,
		`"scope_rule_count":0`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("dec block missing explicit field %s\ngot: %s", want, s)
		}
	}
	// Genuinely-optional empties must be omitted (not present as "").
	for _, absent := range []string{`"sni"`, `"cipher"`, `"cert_fingerprint"`, `"excl_scope"`, `"node_id"`, `"rule_id"`, `"rule_name"`, `"profile_id"`, `"profile_name"`} {
		if strings.Contains(s, absent) {
			t.Errorf("optional-empty dec field %s must be omitted\ngot: %s", absent, s)
		}
	}
}

// TestDecBlock_ToBlockMapsEnumsAndRedaction pins the projection: typed enums flatten via
// String(), and redaction hashes host/SNI to a present token (never omits, never leaks).
func TestDecBlock_ToBlockMapsEnumsAndRedaction(t *testing.T) {
	o := DecryptionOutcome{
		Outcome:        decryptobs.OutcomeBypassLearned,
		DecisionSource: decryptobs.DecisionAutoexcludeCache,
		RuleID:         "rule123",
		ProfileID:      "prof456",
		ProfileName:    "corp",
		Host:           "secret.example.com",
		SNI:            "secret.example.com",
		TLSVersion:     decryptobs.TLSVersion13,
		Cipher:         "TLS_AES_128_GCM_SHA256",
		ALPN:           decryptobs.ALPNH2,
		CertVerify:     decryptobs.CertVerifyVerified,
		FailStage:      decryptobs.FailStageNone,
		FailCategory:   decryptobs.FailCategoryNone,
		ExclReason:     autoexclude.ReasonClientPinned,
		ExclScope:      "prof456",
		CacheConsulted: true,
		CacheHit:       true,
		ScopeRuleCount: 3,
	}

	blk := o.toBlock(false)
	if blk.SchemaVersion != decBlockSchemaVersion ||
		blk.Outcome != "bypass_learned" || blk.DecisionSource != "autoexclude_cache" ||
		blk.TLSVersion != "1.3" || blk.ALPN != "h2" || blk.CertVerify != "verified" ||
		blk.FailStage != "none" || blk.ExclReason != "client_pinned" ||
		blk.Host != "secret.example.com" || blk.ScopeRuleCount != 3 || !blk.CacheHit {
		t.Fatalf("unredacted projection wrong: %+v", blk)
	}

	r := o.toBlock(true)
	if r.Host == "secret.example.com" || !strings.HasPrefix(r.Host, "h_") {
		t.Fatalf("redacted host must be a present hash token, got %q", r.Host)
	}
	if r.SNI == "secret.example.com" || !strings.HasPrefix(r.SNI, "h_") {
		t.Fatalf("redacted SNI must be a present hash token, got %q", r.SNI)
	}
	if r.Host != o.toBlock(true).Host {
		t.Fatal("redaction must be deterministic/stable for the same host")
	}
	// Cipher is record-only telemetry (not identity) — preserved even under redaction.
	if r.Cipher != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("cipher must be preserved under redaction, got %q", r.Cipher)
	}
}

// TestRedactHost pins the §4 redaction helper: off = passthrough, on = present
// fixed-length hash token (never omission), empty stays empty, stable, collision-distinct.
func TestRedactHost(t *testing.T) {
	if got := redactHost("a.example.com", false); got != "a.example.com" {
		t.Errorf("redaction off must pass through, got %q", got)
	}
	if got := redactHost("", true); got != "" {
		t.Errorf("empty input stays empty, got %q", got)
	}
	h := redactHost("a.example.com", true)
	if !strings.HasPrefix(h, "h_") || len(h) != 14 { // "h_" + 12 hex
		t.Fatalf("hash token shape wrong: %q", h)
	}
	if redactHost("a.example.com", true) != h {
		t.Error("redaction must be stable across calls")
	}
	if redactHost("b.example.com", true) == h {
		t.Error("distinct hosts must yield distinct tokens")
	}
}
