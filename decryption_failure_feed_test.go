package main

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// decryption_failure_feed_test.go — ADR-0011: a FAILED decryption now writes a
// request-log feed row (status DECRYPT_FAILED) carrying the dec block, so the
// Decryption Health "view sessions → failed" drill-down resolves to the
// offending sessions instead of an empty feed. These tests pin the row shape,
// the log-only (no stat double-count) contract, the redaction posture, and that
// the taxonomy metric is still recorded.

// findDecFailEntry scans the ring for the DECRYPT_FAILED entry with a unique host
// discriminator (saturation-tolerant, like the tunnel-close/audit patterns).
func findDecFailEntry(t *testing.T, host string) (LogEntry, bool) {
	t.Helper()
	entries := logGet()
	for i := range entries {
		if entries[i].Host == host && entries[i].Status == decFailedStatus {
			return entries[i], true
		}
	}
	return LogEntry{}, false
}

func failOutcome(host string) *DecryptionOutcome {
	return &DecryptionOutcome{
		Outcome:        decryptobs.OutcomeFailed,
		DecisionSource: decryptobs.DecisionNoFailOpen502,
		Host:           host,
		SNI:            host,
		FailStage:      decryptobs.FailStageUpstreamHandshake,
		FailCategory:   decryptobs.FailCategoryOther,
	}
}

// TestRecordDecryptFailureEntry_WritesFilterableFeedRow: the failure produces a
// DECRYPT_FAILED feed row with a dec block whose Outcome is "failed" — the exact
// field ui_config.go's dec_outcome filter matches on — plus rule/identity/ERROR.
func TestRecordDecryptFailureEntry_WritesFilterableFeedRow(t *testing.T) {
	const host = "dec-fail-feed-row.example" // unique discriminator
	match := &PolicyMatch{Rule: &PolicyRule{ID: "r-fail", Name: "inspect-vendor"}}
	id := ProxyIdentity{ClientIP: "198.51.100.7", Identity: "alice@corp"}

	recordDecryptFailureEntry(failOutcome(host), id, host, match, false)

	e, ok := findDecFailEntry(t, host)
	if !ok {
		t.Fatal("no DECRYPT_FAILED feed row written for the failed decryption")
	}
	if e.Dec == nil {
		t.Fatal("DECRYPT_FAILED row missing its dec block — drill-down would not resolve")
	}
	if e.Dec.Outcome != "failed" {
		t.Fatalf("dec.Outcome = %q, want \"failed\" (the dec_outcome filter key)", e.Dec.Outcome)
	}
	if e.Dec.FailStage != "upstream_handshake" || e.Dec.FailCategory != "other" {
		t.Fatalf("dec taxonomy wrong: stage=%q category=%q", e.Dec.FailStage, e.Dec.FailCategory)
	}
	if e.Dec.Host != host {
		t.Fatalf("dec.Host = %q, want plaintext %q (redact off)", e.Dec.Host, host)
	}
	if e.Identity != "alice@corp" || e.IP != "198.51.100.7" || e.RuleMatched != "inspect-vendor" {
		t.Fatalf("row identity/ip/rule wrong: %+v", e)
	}
	if e.Level != "ERROR" {
		t.Fatalf("DECRYPT_FAILED level = %q, want ERROR (Auth & Errors tab)", e.Level)
	}
	if e.Method != "CONNECT" || e.SSLAction != "inspect" {
		t.Fatalf("row method/sslAction wrong: method=%q ssl=%q", e.Method, e.SSLAction)
	}
}

// TestRecordDecryptFailureEntry_LogOnlyNoStatDoubleCount: the row is written
// log-only (persistLogEntry, not the recordRequest* fan-out), so statTotal is
// NOT bumped — the CONNECT was already counted at POLICY_ALLOW time.
func TestRecordDecryptFailureEntry_LogOnlyNoStatDoubleCount(t *testing.T) {
	const host = "dec-fail-no-doublecount.example"
	id := ProxyIdentity{ClientIP: "198.51.100.8"}

	before := atomic.LoadInt64(&statTotal)
	recordDecryptFailureEntry(failOutcome(host), id, host, nil, false)
	if got := atomic.LoadInt64(&statTotal); got != before {
		t.Fatalf("statTotal delta = %d, want 0 (failure row must be log-only; CONNECT already counted)", got-before)
	}
	// ...but the feed row IS written (nil match ⇒ default-allow ⇒ still logged).
	if _, ok := findDecFailEntry(t, host); !ok {
		t.Fatal("nil-match failure must still write the feed row")
	}
}

// TestRecordDecryptFailureEntry_RedactsHost: with redaction ON the dec block's
// host/SNI are hashed (the §4 posture), matching the tunnel-close behavior.
func TestRecordDecryptFailureEntry_RedactsHost(t *testing.T) {
	swapTrafficKey(t, []byte("0123456789abcdef0123456789abcdef")) // Option B: redaction is keyed
	const host = "dec-fail-redacted.example"
	id := ProxyIdentity{ClientIP: "198.51.100.9"}

	recordDecryptFailureEntry(failOutcome(host), id, host, nil, true)

	e, ok := findDecFailEntry(t, host)
	if !ok {
		t.Fatal("no DECRYPT_FAILED row written")
	}
	if e.Dec == nil {
		t.Fatal("missing dec block")
	}
	if e.Dec.Host == host || !strings.HasPrefix(e.Dec.Host, "h_") {
		t.Fatalf("redact on: dec.Host = %q, want hashed h_...", e.Dec.Host)
	}
	if e.Dec.SNI == host || !strings.HasPrefix(e.Dec.SNI, "h_") {
		t.Fatalf("redact on: dec.SNI = %q, want hashed h_...", e.Dec.SNI)
	}
	// The top-level feed Host column stays plaintext (the primary host column,
	// same as recordTunnelCloseGatedDec) — redaction is a dec-block posture.
	if e.Host != host {
		t.Fatalf("top-level Host = %q, want plaintext %q", e.Host, host)
	}
}

// TestRecordDecryptFailureEntry_NilNoOp: a nil outcome writes nothing and does
// not panic (preserves recordDecryptFailure's nil-tolerance).
func TestRecordDecryptFailureEntry_NilNoOp(t *testing.T) {
	before := len(logGet())
	recordDecryptFailureEntry(nil, ProxyIdentity{ClientIP: "198.51.100.10"}, "nil.example", nil, false)
	if _, ok := findDecFailEntry(t, "nil.example"); ok {
		t.Fatal("nil outcome must not write a feed row")
	}
	_ = before
}

// TestDecryptFailureRow_CarriesLearnerFields pins the Codex #840 fix: a learn-only
// failure under a fail-open profile (unsupported-params) fed the auto-exclusion
// cache, so its DECRYPT_FAILED row must carry cache_learned + excl_reason +
// excl_scope — NOT a blanket cache_learned:false. withLearn is the projection seam;
// this exercises it with the real maybeFailOpenOrigin learn signal.
func TestDecryptFailureRow_CarriesLearnerFields(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	fo, scope := bindFailOpenProfile(t, "fo-fail-row", "fail-open")
	const host = "dec-fail-learned.example"
	id := ProxyIdentity{ClientIP: "198.51.100.20", Identity: "dave@corp"}
	herr := errors.New("tls: server selected unsupported protocol version 301") // learn-only

	// Mirror the production strip-path origin-failure site.
	learned, _ := maybeFailOpenOrigin(host, fo, id, herr)
	if learned == "" {
		t.Fatal("precondition: unsupported-params under fail-open must learn")
	}
	dec := sslResolution{Source: decryptobs.DecisionNoFailOpen502, ScopeID: scope, Consulted: true}
	recordDecryptFailureEntry(withLearn(originInspectFailureOutcome(herr, host, dec, fo), learned, dec.ScopeID), id, host, fo, false)

	e, ok := findDecFailEntry(t, host)
	if !ok || e.Dec == nil {
		t.Fatal("no DECRYPT_FAILED row / dec block for the learned failure")
	}
	if !e.Dec.CacheLearned {
		t.Error("cache_learned must be true — this session fed the learner")
	}
	if e.Dec.ExclReason == "" {
		t.Errorf("excl_reason must carry the learned reason, got empty (learned=%q)", learned)
	}
	if e.Dec.ExclScope != scope {
		t.Errorf("excl_scope = %q, want %q", e.Dec.ExclScope, scope)
	}
}

// TestDecryptFailureRow_NoLearnLeavesFieldsClear: a NON-learning failure (generic
// handshake failure) must NOT falsely stamp learner fields — withLearn("") is a
// no-op, so cache_learned stays false and exclusion fields empty.
func TestDecryptFailureRow_NoLearnLeavesFieldsClear(t *testing.T) {
	const host = "dec-fail-nolearn.example"
	id := ProxyIdentity{ClientIP: "198.51.100.21"}
	// withLearn with an empty reason (no learn) must not touch the outcome.
	o := withLearn(failOutcome(host), "", "some-scope")
	recordDecryptFailureEntry(o, id, host, nil, false)

	e, ok := findDecFailEntry(t, host)
	if !ok || e.Dec == nil {
		t.Fatal("no DECRYPT_FAILED row")
	}
	if e.Dec.CacheLearned {
		t.Error("cache_learned must stay false for a non-learning failure")
	}
	if e.Dec.ExclReason != "" || e.Dec.ExclScope != "" {
		t.Errorf("exclusion fields must stay empty for a non-learning failure: reason=%q scope=%q", e.Dec.ExclReason, e.Dec.ExclScope)
	}
}

// TestRecordDecryptFailureEntry_StillRecordsMetric: the taxonomy metric
// (culvert_decrypt_failures_total) is still incremented — the feed row is
// additive, it does not replace the metric.
func TestRecordDecryptFailureEntry_StillRecordsMetric(t *testing.T) {
	const host = "dec-fail-metric.example"
	before := globalDecFailureCount(t, "other", "upstream_handshake")
	recordDecryptFailureEntry(failOutcome(host), ProxyIdentity{ClientIP: "198.51.100.11"}, host, nil, false)
	if got := globalDecFailureCount(t, "other", "upstream_handshake"); got != before+1 {
		t.Fatalf("decFailures{other,upstream_handshake} delta = %d, want +1", got-before)
	}
}
