package main

import (
	"errors"
	"testing"

	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// decryption_connect_failure_test.go — ADR-0011 review finding ③: an inspect rule
// whose upstream TCP dial fails (origin unreachable) is now a FAILED decryption
// attempt (fail_stage=tcp_connect), visible to coverage + the failure taxonomy +
// the drill-down feed, instead of vanishing.

func TestClassifyConnectFailure(t *testing.T) {
	cases := []struct {
		name string
		err  error
		cat  decryptobs.FailCategory
	}{
		{"timeout", errors.New("dial tcp 10.0.0.9:443: i/o timeout"), decryptobs.FailCategoryTimeout},
		{"deadline", errors.New("context deadline exceeded"), decryptobs.FailCategoryTimeout},
		{"refused", errors.New("dial tcp 10.0.0.9:443: connect: connection refused"), decryptobs.FailCategoryOther},
		{"reset", errors.New("read tcp: connection reset by peer"), decryptobs.FailCategoryOther},
		{"dns", errors.New("dial tcp: lookup nope.example: no such host"), decryptobs.FailCategoryOther},
		{"nil", nil, decryptobs.FailCategoryOther},
	}
	for _, c := range cases {
		stage, cat := classifyConnectFailure(c.err)
		if stage != decryptobs.FailStageTCPConnect {
			t.Errorf("%s: stage = %q, want tcp_connect (a dial error precedes any handshake)", c.name, stage)
		}
		if cat != c.cat {
			t.Errorf("%s: category = %q, want %q", c.name, cat, c.cat)
		}
	}
}

// TestUpstreamConnectFailureOutcome_Projection: the builder yields a failed
// tcp_connect outcome carrying scope/identity, and — critically — does NOT set
// any auto-exclusion learner field (a dial failure must never learn/bypass).
func TestUpstreamConnectFailureOutcome_Projection(t *testing.T) {
	match := &PolicyMatch{Rule: &PolicyRule{ID: "r-conn", Name: "inspect-vendor"}}
	dec := sslResolution{Source: decryptobs.DecisionNoFailOpen502, ScopeID: "prof-01", Consulted: true}

	b := upstreamConnectFailureOutcome(errors.New("connect: connection refused"), "down.example", dec, match).toBlock(false)
	if b.Outcome != "failed" || b.FailStage != "tcp_connect" || b.FailCategory != "other" {
		t.Fatalf("connect-failure block wrong: outcome=%q stage=%q cat=%q", b.Outcome, b.FailStage, b.FailCategory)
	}
	if b.DecisionSource != "no_fail_open_502" || b.ProfileID != "prof-01" || b.RuleID != "r-conn" {
		t.Fatalf("connect-failure block missing source/scope/rule: %+v", b)
	}
	// A transport failure must NOT be attributed as a learner contribution.
	if b.CacheLearned || b.ExclReason != "" || b.ExclScope != "" || b.Rescued {
		t.Fatalf("dial failure must not set learner/rescue fields: learned=%v reason=%q scope=%q rescued=%v",
			b.CacheLearned, b.ExclReason, b.ExclScope, b.Rescued)
	}
	// TLS fields stay at sentinels (no negotiated session).
	if b.TLSVersion != "unknown" || b.ALPN != "" || b.CertVerify != "not_checked" {
		t.Fatalf("no-handshake sentinels wrong: tls=%q alpn=%q cert=%q", b.TLSVersion, b.ALPN, b.CertVerify)
	}
}

// TestConnectFailure_CountsAndDrillsDown: routed through recordDecryptFailureEntry
// (the production call), a connect failure bumps the failure taxonomy AND writes a
// DECRYPT_FAILED feed row with fail_stage=tcp_connect — so it is both counted and
// investigable, closing the coverage blind spot.
func TestConnectFailure_CountsAndDrillsDown(t *testing.T) {
	const host = "dec-connect-fail.example"
	id := ProxyIdentity{ClientIP: "198.51.100.30"}
	dec := sslResolution{Source: decryptobs.DecisionNoFailOpen502, ScopeID: "prof-conn", Consulted: true}

	before := globalDecFailureCount(t, "other", "tcp_connect")
	recordDecryptFailureEntry(upstreamConnectFailureOutcome(errors.New("connect: connection refused"), host, dec, nil), id, host, nil, false)
	if got := globalDecFailureCount(t, "other", "tcp_connect"); got != before+1 {
		t.Fatalf("decFailures{other,tcp_connect} delta = %d, want +1", got-before)
	}

	e, ok := findDecFailEntry(t, host)
	if !ok || e.Dec == nil {
		t.Fatal("connect failure must write a DECRYPT_FAILED drill-down row with a dec block")
	}
	if e.Dec.Outcome != "failed" || e.Dec.FailStage != "tcp_connect" {
		t.Fatalf("connect-failure row wrong: outcome=%q stage=%q", e.Dec.Outcome, e.Dec.FailStage)
	}
}
