package main

import (
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// decryption_wiring_test.go — ADR-0011 Phase 1 (wiring seam). The tunnel-close recorder
// can now carry a DecryptionOutcome onto the TUNNEL_CLOSED feed entry's nested dec block.
// No proxy-path caller passes a non-nil outcome yet (byte-identical); these tests exercise
// the seam directly so it is production-ready for the decision-path population slice.

// findDecTunnelEntry scans the ring for the TUNNEL_CLOSED entry with a unique host
// discriminator (saturation-tolerant, like the audit content-scan pattern).
func findDecTunnelEntry(t *testing.T, host string) LogEntry {
	t.Helper()
	entries := logGet()
	for i := range entries {
		if entries[i].Host == host && entries[i].Status == "TUNNEL_CLOSED" {
			return entries[i]
		}
	}
	t.Fatalf("no TUNNEL_CLOSED entry found for host %q", host)
	return LogEntry{}
}

// TestRecordTunnelCloseDec_EmitsBlock: a non-nil outcome projects onto the entry's dec block.
func TestRecordTunnelCloseDec_EmitsBlock(t *testing.T) {
	const host = "dec-wire-inspected.example" // unique discriminator
	o := &DecryptionOutcome{
		Outcome:        decryptobs.OutcomeInspected,
		DecisionSource: decryptobs.DecisionPolicyInspect,
		Host:           host,
		TLSVersion:     decryptobs.TLSVersion13,
		ALPN:           decryptobs.ALPNH2,
		CertVerify:     decryptobs.CertVerifyVerified,
		FailStage:      decryptobs.FailStageNone,
		FailCategory:   decryptobs.FailCategoryNone,
	}
	recordTunnelCloseGatedDec(nil, ProxyIdentity{ClientIP: "203.0.113.9"}, "CONNECT", host, 10, 20, time.Now(), "inspect", "", o, false)

	e := findDecTunnelEntry(t, host)
	if e.Dec == nil {
		t.Fatal("expected a dec block on the TUNNEL_CLOSED entry")
	}
	if e.Dec.Outcome != "inspected" || e.Dec.DecisionSource != "policy_inspect" ||
		e.Dec.TLSVersion != "1.3" || e.Dec.ALPN != "h2" || e.Dec.CertVerify != "verified" ||
		e.Dec.FailStage != "none" || e.Dec.Host != host || e.Dec.SchemaVersion != decBlockSchemaVersion {
		t.Fatalf("dec block wrong: %+v", e.Dec)
	}
}

// TestRecordTunnelCloseReason_NoDecBlock: the existing (nil-outcome) path leaves the dec
// block absent — the byte-identical default that every current proxy caller takes.
func TestRecordTunnelCloseReason_NoDecBlock(t *testing.T) {
	const host = "dec-wire-none.example"
	recordTunnelCloseGatedReason(nil, ProxyIdentity{ClientIP: "203.0.113.10"}, "CONNECT", host, 1, 2, time.Now(), "bypass", "")
	if e := findDecTunnelEntry(t, host); e.Dec != nil {
		t.Fatalf("a nil outcome must leave the dec block absent, got %+v", e.Dec)
	}
}

// TestRecordTunnelCloseDec_Redacts: with redaction on, the dec block's host is a present
// hash token, never the plaintext host (the top-level entry.Host is unaffected — that is
// the existing feed field, redacted by its own toggle, not this one).
func TestRecordTunnelCloseDec_Redacts(t *testing.T) {
	const host = "dec-wire-redact.example"
	o := &DecryptionOutcome{Outcome: decryptobs.OutcomeBypassManual, DecisionSource: decryptobs.DecisionManualSSLBypass, Host: host}
	recordTunnelCloseGatedDec(nil, ProxyIdentity{ClientIP: "203.0.113.11"}, "CONNECT", host, 1, 2, time.Now(), "bypass", "", o, true)

	e := findDecTunnelEntry(t, host)
	if e.Dec == nil {
		t.Fatal("expected a dec block")
	}
	if e.Dec.Host == host || !strings.HasPrefix(e.Dec.Host, "h_") {
		t.Fatalf("redacted dec.host must be a present hash token, got %q", e.Dec.Host)
	}
}
