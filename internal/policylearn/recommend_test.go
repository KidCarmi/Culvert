package policylearn

// M4 tests — deterministic recommendation generation + immutable evidence.
// Feeding is SYNCHRONOUS (aggregateLocked under the engine mutex) so every
// test is deterministic without transport races; transport semantics have
// their own M2 suites.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type hostCat struct{ cat, tier string }

func recResolver(cats map[string]hostCat) func(string) (string, string) {
	return func(host string) (string, string) {
		if hc, ok := cats[host]; ok {
			tier := hc.tier
			if tier == "" {
				tier = "admin"
			}
			return hc.cat, tier
		}
		return "", "none"
	}
}

func defaultRecCats() map[string]hostCat {
	return map[string]hostCat{
		"code.example":   {cat: "Dev Tools"},
		"ci.example":     {cat: "Dev Tools"},
		"pay.example":    {cat: "Finance"},
		"social.example": {cat: "Social Media"}, // resolvable but NOT allowlisted
		"ut1.example":    {cat: "Dev Tools", tier: "community"},
	}
}

// newRecEngine builds an engine with the M4 allowlist {"Dev Tools","Finance"}
// and the injected resolver above. dir=="" ⇒ memory-only.
func newRecEngine(t *testing.T, dir string, clk *testClock, mutate func(*Config)) *Engine {
	t.Helper()
	cfg := Config{
		Now:                     clk.now,
		RecommendableCategories: []string{"Dev Tools", "Finance"},
		Categories:              recResolver(defaultRecCats()),
	}
	if dir != "" {
		cfg.StorePath = filepath.Join(dir, "policy_learning.json")
		cfg.SubjectKeyPath = filepath.Join(dir, "subject.key")
	}
	if mutate != nil {
		mutate(&cfg)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

// recFeed folds one observation synchronously into the attributed session.
func recFeed(t *testing.T, e *Engine, clk *testClock, subject string, groups []string, host, ruleID, status string) {
	t.Helper()
	o := Observation{At: clk.now().Unix(), Subject: subject, AuthSource: "idp",
		Groups: groups, Host: host, Method: "GET", RuleID: ruleID, Status: status}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.aggSession == nil {
		t.Fatal("no attributable session")
	}
	e.aggregateLocked(e.aggSession, &o)
}

// feedHighEvidence: 6 subjects × 6 UTC days on code.example (36 allowed) —
// clears every default HIGH threshold (30 requests / 5 subjects / 5 days).
func feedHighEvidence(t *testing.T, e *Engine, clk *testClock) {
	t.Helper()
	for d := 0; d < 6; d++ {
		for u := 0; u < 6; u++ {
			recFeed(t, e, clk, fmt.Sprintf("user%d@corp.example", u), []string{"eng"}, "code.example", "rule-ulid-1", "OK")
		}
		clk.advance(24 * time.Hour)
	}
}

func mustGenerate(t *testing.T, e *Engine, sessionID string) GenerateResult {
	t.Helper()
	res, err := e.GenerateRecommendations(sessionID)
	if err != nil {
		t.Fatalf("GenerateRecommendations: %v", err)
	}
	return res
}

// ── Eligibility ──────────────────────────────────────────────────────────────

func TestGenerate_CompletedSessionProducesRecommendation(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	res := mustGenerate(t, e, s.ID)
	if len(res.Recommendations) != 1 || res.EligibleCells != 1 {
		t.Fatalf("result: %+v", res)
	}
	r := res.Recommendations[0]
	if r.Group != "eng" || r.Category != "Dev Tools" || r.SessionID != s.ID {
		t.Fatalf("recommendation identity: %+v", r)
	}
	if r.State != RecStateGenerated || r.ID == "" || r.EvidenceHash == "" || r.GeneratedAt == "" {
		t.Fatalf("recommendation lifecycle fields: %+v", r)
	}
	if r.Confidence != ConfidenceHigh || len(r.ConfidenceReasons) != 3 || len(r.ConfidenceLimits) != 0 {
		t.Fatalf("confidence: %q reasons=%v limits=%v", r.Confidence, r.ConfidenceReasons, r.ConfidenceLimits)
	}
	if r.Baseline.GuardrailsHash != e.GuardrailsHash() || r.SubjectKeyID == "" || r.EngineSchema != SchemaVersion {
		t.Fatalf("pins: %+v", r)
	}
	if r.Evidence.AllowedRequests != 36 || r.Evidence.ObservedAllowedSubjects != 6 || r.Evidence.AllowedObservationDays != 6 {
		t.Fatalf("evidence: %+v", r.Evidence)
	}
}

func TestGenerate_ActiveCancelledAndUnknownRefuse(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.GenerateRecommendations(s.ID); !errors.Is(err, ErrSessionNotCompleted) {
		t.Fatalf("active session generated: %v", err)
	}
	if _, err := e.CancelSession("op"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.GenerateRecommendations(s.ID); !errors.Is(err, ErrSessionNotCompleted) {
		t.Fatalf("cancelled session generated: %v", err)
	}
	if _, err := e.GenerateRecommendations("nope"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("unknown session: %v", err)
	}
}

func TestGenerate_SyntheticScopesAreEvidenceOnly(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	recFeed(t, e, clk, "", nil, "code.example", "r1", "OK")                 // s:unauth
	recFeed(t, e, clk, "bob@corp.example", nil, "code.example", "r1", "OK") // s:groupless
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	res := mustGenerate(t, e, s.ID)
	if len(res.Recommendations) != 0 || res.SkippedSyntheticScope != 2 || res.EligibleCells != 0 {
		t.Fatalf("synthetic scopes produced recommendations: %+v", res)
	}
}

func TestGenerate_AllowlistFailClosed(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	recFeed(t, e, clk, "a@corp.example", []string{"eng"}, "social.example", "r1", "OK")  // category off-allowlist
	recFeed(t, e, clk, "a@corp.example", []string{"eng"}, "unknown.example", "r1", "OK") // category "" (unknown)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	res := mustGenerate(t, e, s.ID)
	if len(res.Recommendations) != 0 || res.SkippedCategory != 2 {
		t.Fatalf("off-allowlist/unknown category recommended: %+v", res)
	}
}

func TestGenerate_BlockedOnlyCellSkippedButNeverRejectsMixedCell(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	// Same cell also sees policy blocks + pre-dispatch threat blocks: negative
	// evidence must not reject the cell (it stays eligible) and must surface as
	// request counts only.
	recFeed(t, e, clk, "user0@corp.example", []string{"eng"}, "code.example", "r-block", "POLICY_BLOCK")
	recFeed(t, e, clk, "user0@corp.example", []string{"eng"}, "code.example", "", "THREAT_BLOCKED")
	// Blocked-ONLY cell (Finance): no positive allowed evidence ⇒ skipped.
	recFeed(t, e, clk, "user0@corp.example", []string{"eng"}, "pay.example", "r-block", "POLICY_BLOCK")
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	res := mustGenerate(t, e, s.ID)
	if len(res.Recommendations) != 1 || res.SkippedNoAllowedEvidence != 1 {
		t.Fatalf("blocked-evidence handling: %+v", res)
	}
	ev := res.Recommendations[0].Evidence
	if ev.PolicyBlockedRequests != 1 || ev.ThreatBlockedRequests != 1 || ev.AllowedRequests != 36 {
		t.Fatalf("evidence counts: %+v", ev)
	}
	// The blocked observations must not have leaked into allowed evidence sets.
	if ev.ObservedAllowedSubjects != 6 || ev.AllowedObservationDays != 6 {
		t.Fatalf("blocked traffic inflated allowed evidence: %+v", ev)
	}
}

// ── Confidence predicates + caps ─────────────────────────────────────────────

func TestGenerate_VolumeAloneNeverHigh(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	for i := 0; i < 500; i++ { // huge volume, one subject, one day
		recFeed(t, e, clk, "solo@corp.example", []string{"eng"}, "code.example", "r1", "OK")
	}
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	r := mustGenerate(t, e, s.ID).Recommendations[0]
	if r.Confidence != ConfidenceLow {
		t.Fatalf("500 requests / 1 subject / 1 day scored %q, want low (volume alone must never rate)", r.Confidence)
	}
	joined := strings.Join(r.ConfidenceLimits, " ")
	if !strings.Contains(joined, "below_medium_subject_diversity") || !strings.Contains(joined, "below_medium_day_diversity") {
		t.Fatalf("limits must name the failed diversity predicates: %v", r.ConfidenceLimits)
	}
}

func TestGenerate_MediumPredicates(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	for d := 0; d < 2; d++ { // 2 subjects × 2 days × 2 = 8 allowed ≥ 5
		recFeed(t, e, clk, "a@corp.example", []string{"eng"}, "code.example", "r1", "OK")
		recFeed(t, e, clk, "b@corp.example", []string{"eng"}, "code.example", "r1", "OK")
		recFeed(t, e, clk, "a@corp.example", []string{"eng"}, "ci.example", "r1", "OK")
		recFeed(t, e, clk, "b@corp.example", []string{"eng"}, "ci.example", "r1", "OK")
		clk.advance(24 * time.Hour)
	}
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	r := mustGenerate(t, e, s.ID).Recommendations[0]
	if r.Confidence != ConfidenceMedium {
		t.Fatalf("confidence %q, want medium: reasons=%v limits=%v", r.Confidence, r.ConfidenceReasons, r.ConfidenceLimits)
	}
}

func TestGenerate_TransportLossCapsHigh(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock() // simulate a session window that dropped observations
	e.sessions[len(e.sessions)-1].Transport.Dropped = 7
	e.mu.Unlock()
	r := mustGenerate(t, e, s.ID).Recommendations[0]
	if r.Confidence != ConfidenceMedium {
		t.Fatalf("degraded transport still scored %q, want medium", r.Confidence)
	}
	if !strings.Contains(strings.Join(r.ConfidenceLimits, " "), "transport_loss:dropped=7") {
		t.Fatalf("loss not identified in limits: %v", r.ConfidenceLimits)
	}
	if !r.Coverage.TransportDegraded || r.Coverage.TransportLoss.Dropped != 7 {
		t.Fatalf("coverage must carry the loss facts: %+v", r.Coverage)
	}
}

func TestGenerate_CategoryChurnCapsHigh(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	sess := e.sessions[len(e.sessions)-1]
	sess.CategoryChurn = append(sess.CategoryChurn, EpochChurn{At: rfc3339(clk.now()), To: "epoch-2"})
	e.mu.Unlock()
	r := mustGenerate(t, e, s.ID).Recommendations[0]
	if r.Confidence != ConfidenceMedium {
		t.Fatalf("churned session still scored %q, want medium", r.Confidence)
	}
	if !strings.Contains(strings.Join(r.ConfidenceLimits, " "), "category_churn:changes=1") {
		t.Fatalf("churn not identified: %v", r.ConfidenceLimits)
	}
}

func TestGenerate_CommunityTierMajorityCapsHigh(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	// All 36 high-evidence observations resolve through the community tier.
	for d := 0; d < 6; d++ {
		for u := 0; u < 6; u++ {
			recFeed(t, e, clk, fmt.Sprintf("user%d@corp.example", u), []string{"eng"}, "ut1.example", "r1", "OK")
		}
		clk.advance(24 * time.Hour)
	}
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	r := mustGenerate(t, e, s.ID).Recommendations[0]
	if r.Confidence != ConfidenceMedium {
		t.Fatalf("community-majority cell scored %q, want medium", r.Confidence)
	}
	if !strings.Contains(strings.Join(r.ConfidenceLimits, " "), "community_tier_majority") {
		t.Fatalf("community majority not identified: %v", r.ConfidenceLimits)
	}
}

func TestGenerate_CommunityTierMinorityDoesNotCap(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)                                                          // 36 admin-tier
	recFeed(t, e, clk, "user0@corp.example", []string{"eng"}, "ut1.example", "r1", "OK") // 1 community-tier
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	r := mustGenerate(t, e, s.ID).Recommendations[0]
	if r.Confidence != ConfidenceHigh {
		t.Fatalf("minority community evidence capped HIGH: %q limits=%v", r.Confidence, r.ConfidenceLimits)
	}
}

func TestGenerate_SubjectKeyChangedIneligible(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	e.sessions[len(e.sessions)-1].Agg.SubjectKeyChanged = true
	e.mu.Unlock()
	if _, err := e.GenerateRecommendations(s.ID); !errors.Is(err, ErrSubjectKeyChanged) {
		t.Fatalf("key-changed session generated: %v", err)
	}
}

func TestGenerate_SubjectOverflowIsLowerBoundNotACap(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	e.sessions[len(e.sessions)-1].Agg.Cells[CellKey("g:eng", "Dev Tools")].SubjectOverflow = 3
	e.mu.Unlock()
	r := mustGenerate(t, e, s.ID).Recommendations[0]
	if r.Confidence != ConfidenceHigh {
		t.Fatalf("subject overflow capped confidence to %q — it is a lower bound, not a loss", r.Confidence)
	}
	if !r.Coverage.SubjectsIsLowerBound || !r.Evidence.SubjectsIsLowerBound || r.Evidence.SubjectOverflow != 3 {
		t.Fatalf("overflow must surface as lower-bound facts: cov=%+v ev=%+v", r.Coverage, r.Evidence)
	}
}

// ── Coverage honesty ─────────────────────────────────────────────────────────

func TestGenerate_NoFabricatedDenominatorsOrUserClaims(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	recFeed(t, e, clk, "user0@corp.example", []string{"eng"}, "code.example", "rb", "POLICY_BLOCK")
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	r := mustGenerate(t, e, s.ID).Recommendations[0]
	if r.Coverage.MembershipDenominatorKnown {
		t.Fatal("MembershipDenominatorKnown=true with no membership input — fabricated denominator")
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	// The serialized object must carry no percentage claims and no per-user
	// blocked-traffic vocabulary (blocked facts are request counts only).
	for _, forbidden := range []string{"%", "percent", "blocked_subjects", "blocked_users", "coverage_ratio"} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("recommendation serialization carries %q: %s", forbidden, doc)
		}
	}
	// feedHighEvidence spans 6 observation days and the stop lands on the 7th
	// calendar day — the window is the inclusive session span, not the
	// observation-day count (those live in AllowedObservationDays).
	if r.Coverage.SessionWindowDays != 7 {
		t.Fatalf("session window days = %d, want 7", r.Coverage.SessionWindowDays)
	}
}

// ── Attribution ──────────────────────────────────────────────────────────────

func TestGenerate_DefaultActionAttributionDistinguishable(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)                                                         // RuleID rule-ulid-1
	recFeed(t, e, clk, "user0@corp.example", []string{"eng"}, "code.example", "", "OK") // default action
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	r := mustGenerate(t, e, s.ID).Recommendations[0]
	var haveRule, haveDefault bool
	for _, a := range r.Evidence.RuleHits {
		switch a.Key {
		case "rule-ulid-1":
			haveRule = a.Count == 36
		case DefaultActionRuleKey:
			haveDefault = a.Count == 1
		}
	}
	if !haveRule || !haveDefault {
		t.Fatalf("rule attribution must keep real ULIDs and %q distinct: %+v", DefaultActionRuleKey, r.Evidence.RuleHits)
	}
}

// ── Determinism / idempotency / supersession ─────────────────────────────────

func TestBuildRecommendations_ByteIdenticalDeterminism(t *testing.T) {
	agg := newAggregate()
	// Multiple cells with multi-entry maps to exercise every sort path.
	for i := 0; i < 5; i++ {
		key := CellKey("g:team"+fmt.Sprint(i), "Dev Tools")
		c := &Cell{Allowed: int64(40 + i), Requests: int64(40 + i),
			Subjects: map[string]bool{"t1": true, "t2": true, "t3": true, "t4": true, "t5": true, "t6": true},
			Days:     map[string]bool{"2026-08-01": true, "2026-08-02": true, "2026-08-03": true, "2026-08-04": true, "2026-08-05": true},
			TopHosts: map[string]int64{"a.example": 3, "b.example": 3, "c.example": 9},
			RuleHits: map[string]int64{"r1": 20, "r2": 20, DefaultActionRuleKey: 2},
			TierHits: map[string]int64{"admin": 30, "saas": 10},
		}
		agg.Cells[key] = c
	}
	sess := &Session{ID: "fixed-session", State: StateCompleted,
		StartedAt: "2026-08-01T00:00:00Z", StoppedAt: "2026-08-05T00:00:00Z",
		Baseline:     Baseline{PolicyGeneration: 7, CategoryEpoch: "ep1", GuardrailsHash: "gh1"},
		SubjectKeyID: "sk1", Agg: agg}
	allow := map[string]bool{"Dev Tools": true}
	th := Thresholds{}.withDefaults()
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

	var res1, res2 GenerateResult
	b1, err := json.Marshal(buildRecommendations(sess, allow, th, now, &res1))
	if err != nil {
		t.Fatal(err)
	}
	b2, err := json.Marshal(buildRecommendations(sess, allow, th, now, &res2))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("same inputs produced different bytes:\n%s\n%s", b1, b2)
	}
	if fmt.Sprint(res1) != fmt.Sprint(res2) {
		t.Fatalf("result accounting diverged: %+v vs %+v", res1, res2)
	}
}

func TestGenerate_IdempotentAcrossCallsAndRestart(t *testing.T) {
	clk := newTestClock()
	dir := t.TempDir()
	e := newRecEngine(t, dir, clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	res1 := mustGenerate(t, e, s.ID)
	res2 := mustGenerate(t, e, s.ID)
	if res2.UnchangedCount != 1 || res2.SupersededCount != 0 {
		t.Fatalf("second generation not idempotent: %+v", res2)
	}
	b1, _ := json.Marshal(res1.Recommendations)
	b2, _ := json.Marshal(res2.Recommendations)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("regeneration changed content:\n%s\n%s", b1, b2)
	}
	if n := len(e.Recommendations()); n != 1 {
		t.Fatalf("store grew on idempotent regeneration: %d", n)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	// Restart: same store, same config ⇒ same bytes again (and still no growth).
	e2 := newRecEngine(t, dir, clk, nil)
	res3 := mustGenerate(t, e2, s.ID)
	b3, _ := json.Marshal(res3.Recommendations)
	if !bytes.Equal(b1, b3) {
		t.Fatalf("post-restart regeneration changed content:\n%s\n%s", b1, b3)
	}
	if n := len(e2.Recommendations()); n != 1 {
		t.Fatalf("store grew across restart: %d", n)
	}
}

func TestGenerate_ChangedContentSupersedes(t *testing.T) {
	clk := newTestClock()
	dir := t.TempDir()
	e := newRecEngine(t, dir, clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	mustGenerate(t, e, s.ID)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	// Same allowlist (guardrails unchanged) but different thresholds ⇒ the
	// confidence content changes ⇒ new object supersedes the old one.
	e2 := newRecEngine(t, dir, clk, func(c *Config) { c.Recommend = Thresholds{HighMinSubjects: 50} })
	res := mustGenerate(t, e2, s.ID)
	if res.SupersededCount != 1 || len(res.Recommendations) != 1 {
		t.Fatalf("supersession accounting: %+v", res)
	}
	if res.Recommendations[0].Confidence == ConfidenceHigh {
		t.Fatal("raised threshold still scored high")
	}
	all := e2.Recommendations()
	var generated, superseded int
	for _, r := range all {
		switch r.State {
		case RecStateGenerated:
			generated++
		case RecStateSuperseded:
			superseded++
		}
	}
	if generated != 1 || superseded != 1 {
		t.Fatalf("want exactly one generated + one superseded, got %d/%d", generated, superseded)
	}
}

func TestGenerate_GuardrailsChangeRefusesStaleEvidence(t *testing.T) {
	clk := newTestClock()
	dir := t.TempDir()
	e := newRecEngine(t, dir, clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen with a DIFFERENT allowlist: the pinned GuardrailsHash no longer
	// matches ⇒ generation refuses rather than silently reinterpreting.
	e2 := newRecEngine(t, dir, clk, func(c *Config) {
		c.RecommendableCategories = []string{"Dev Tools", "Finance", "AI"}
	})
	if _, err := e2.GenerateRecommendations(s.ID); !errors.Is(err, ErrGuardrailsChanged) {
		t.Fatalf("changed guardrails: %v, want ErrGuardrailsChanged", err)
	}
}

func TestGenerate_MissingGuardrailBaselineRefuses(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock() // simulate a pre-M4 (schema v2) session with no pinned hash
	e.sessions[len(e.sessions)-1].Baseline.GuardrailsHash = ""
	e.mu.Unlock()
	if _, err := e.GenerateRecommendations(s.ID); !errors.Is(err, ErrNoGuardrailBaseline) {
		t.Fatalf("unpinned session: %v, want ErrNoGuardrailBaseline", err)
	}
}

// ── ProposedRule shape ───────────────────────────────────────────────────────

func TestProposedRule_FixedBornSafeSemantics(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	pr := mustGenerate(t, e, s.ID).Recommendations[0].ProposedRule
	if pr.Action != "Allow" || pr.SSLAction != "Inspect" || pr.Enabled {
		t.Fatalf("proposed rule must be Allow+Inspect+disabled: %+v", pr)
	}
	if pr.SourceGroup != "eng" || pr.DestCategory != "Dev Tools" {
		t.Fatalf("proposed rule scope must be the exact observed pair: %+v", pr)
	}
}

// ── Bounds ───────────────────────────────────────────────────────────────────

func TestGenerate_PerGenerationTruncationIsCounted(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, "", clk, nil)
	s, _ := e.StartSession("op")
	for g := 0; g < maxRecommendationsPerGeneration+6; g++ {
		recFeed(t, e, clk, "a@corp.example", []string{fmt.Sprintf("team%03d", g)}, "code.example", "r1", "OK")
	}
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	res := mustGenerate(t, e, s.ID)
	if res.EligibleCells != maxRecommendationsPerGeneration+6 ||
		res.TruncatedCells != 6 ||
		len(res.Recommendations) != maxRecommendationsPerGeneration {
		t.Fatalf("truncation accounting: eligible=%d truncated=%d recs=%d",
			res.EligibleCells, res.TruncatedCells, len(res.Recommendations))
	}
}

func TestPruneRecommendations_SupersededFirstThenFIFO(t *testing.T) {
	var recs []*Recommendation
	for i := 0; i < maxRetainedRecommendations+40; i++ {
		state := RecStateGenerated
		if i%10 == 0 { // 30 superseded sprinkled through
			state = RecStateSuperseded
		}
		recs = append(recs, &Recommendation{ID: fmt.Sprintf("r%04d", i), SessionID: "s", State: state})
	}
	pruned := pruneRecommendations(recs)
	if len(pruned) != maxRetainedRecommendations {
		t.Fatalf("pruned to %d, want %d", len(pruned), maxRetainedRecommendations)
	}
	for _, r := range pruned { // all 30 superseded evicted first…
		if r.State == RecStateSuperseded {
			t.Fatalf("superseded %s survived while over cap", r.ID)
		}
	}
	// …then FIFO on the generated remainder: the first 10 generated
	// (r0001–r0009, r0011) are gone, so the first survivor is r0012.
	if pruned[0].ID != "r0012" {
		t.Fatalf("FIFO eviction order wrong: first survivor %s", pruned[0].ID)
	}
}

// ── Persistence v3 + privacy ─────────────────────────────────────────────────

func TestGenerate_PersistedV3RoundTripNoRawSubjects(t *testing.T) {
	clk := newTestClock()
	dir := t.TempDir()
	e := newRecEngine(t, dir, clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk) // subjects "userN@corp.example"
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	res := mustGenerate(t, e, s.ID)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "policy_learning.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	// Complete persisted-store privacy scan: raw subjects, source-qualified
	// identity, URLs/paths must be absent from the WHOLE document now that
	// recommendations exist.
	for _, forbidden := range []string{"user0@corp.example", "@corp.example", "idp\x1f", "http://", "https://"} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("persisted store carries %q", forbidden)
		}
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env["schema_version"] != float64(SchemaVersion) {
		t.Fatalf("schema_version = %v, want %d", env["schema_version"], SchemaVersion)
	}
	if _, ok := env["recommendations"]; !ok {
		t.Fatal("recommendations absent from the v3 envelope")
	}

	// Reload: evidence is by value and survives independently of live cells.
	e2 := newRecEngine(t, dir, clk, nil)
	got := e2.Recommendations()
	if len(got) != 1 {
		t.Fatalf("reloaded %d recommendations, want 1", len(got))
	}
	b1, _ := json.Marshal(res.Recommendations[0])
	b2, _ := json.Marshal(got[0])
	if !bytes.Equal(b1, b2) {
		t.Fatalf("recommendation changed across restart:\n%s\n%s", b1, b2)
	}
	if st := e2.Snapshot(); st.Recommendations != 1 {
		t.Fatalf("stats recommendations = %d", st.Recommendations)
	}
}

func TestGenerate_NewerSchemaStoreStaysReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy_learning.json")
	newer := `{"schema_version":7,"sessions":[],"future":true}`
	if err := os.WriteFile(path, []byte(newer), 0o600); err != nil {
		t.Fatal(err)
	}
	clk := newTestClock()
	e := newRecEngine(t, dir, clk, func(c *Config) { c.StorePath = path })
	if !e.ReadOnly() {
		t.Fatal("newer-schema store did not enter read-only")
	}
	if _, err := e.GenerateRecommendations("any"); !errors.Is(err, ErrStoreReadOnly) {
		t.Fatalf("generate on read-only store: %v, want ErrStoreReadOnly", err)
	}
}

// ── Guardrails canonicalization / staleness helper ───────────────────────────

func TestCanonicalizeAndGuardrailsHash(t *testing.T) {
	a := canonicalizeCategories([]string{" Dev Tools ", "Finance", "Dev Tools", "", "AI"})
	if want := []string{"AI", "Dev Tools", "Finance"}; fmt.Sprint(a) != fmt.Sprint(want) {
		t.Fatalf("canonicalize = %v, want %v", a, want)
	}
	h1 := guardrailsHashFor(canonicalizeCategories([]string{"B", "A"}))
	h2 := guardrailsHashFor(canonicalizeCategories([]string{"A", "B", " A "}))
	if h1 != h2 || h1 == "" {
		t.Fatalf("canonical hash must be order/spacing-insensitive: %q vs %q", h1, h2)
	}
	if h3 := guardrailsHashFor(canonicalizeCategories([]string{"A"})); h3 == h1 {
		t.Fatal("different allowlists share a hash")
	}
	// Framing ambiguity: ["AB"] vs ["A","B"] must differ.
	if guardrailsHashFor([]string{"AB"}) == guardrailsHashFor([]string{"A", "B"}) {
		t.Fatal("length framing failed — concatenation collision")
	}
}

func TestStaleReasons_PureComputedStaleness(t *testing.T) {
	r := &Recommendation{
		Baseline:     Baseline{PolicyGeneration: 5, CategoryEpoch: "ep1", GuardrailsHash: "gh1"},
		SubjectKeyID: "sk1",
	}
	fresh := StaleInputs{PolicyGeneration: 5, CategoryEpoch: "ep1", GuardrailsHash: "gh1", SubjectKeyID: "sk1"}
	if got := StaleReasons(r, fresh); len(got) != 0 {
		t.Fatalf("fresh pins reported stale: %v", got)
	}
	stale := StaleInputs{PolicyGeneration: 6, CategoryEpoch: "ep2", GuardrailsHash: "gh2", SubjectKeyID: "sk2"}
	got := StaleReasons(r, stale)
	want := []string{"policy_generation_changed", "category_epoch_changed", "guardrails_changed", "subject_key_changed"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("stale reasons = %v, want %v", got, want)
	}
	// Unknown current key identity must not claim a key change.
	if got := StaleReasons(r, StaleInputs{PolicyGeneration: 5, CategoryEpoch: "ep1", GuardrailsHash: "gh1"}); len(got) != 0 {
		t.Fatalf("empty current key id reported stale: %v", got)
	}
}

// ── Concurrency (race-detector coverage) ─────────────────────────────────────

func TestGenerate_ConcurrentWithObserveAndReads(t *testing.T) {
	clk := newTestClock()
	e := newRecEngine(t, t.TempDir(), clk, nil)
	s1, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.StartSession("op2"); err != nil { // new active session observing
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			e.Observe(Observation{Subject: "x@corp.example", AuthSource: "idp",
				Groups: []string{"eng"}, Host: "code.example", Method: "GET", Status: "OK"})
		}
	}()
	for i := 0; i < 20; i++ {
		if _, err := e.GenerateRecommendations(s1.ID); err != nil {
			t.Fatalf("generate under concurrency: %v", err)
		}
		_ = e.Recommendations()
		_ = e.Sessions()
	}
	<-done
}

// ── M4.1: recommendation-policy identity ─────────────────────────────────────

func TestRecommendationPolicyHash_OrderingIndependentAndDefaultEquivalent(t *testing.T) {
	// Incidental configuration ordering/spacing/duplication must not change the
	// identity.
	a := Thresholds{CommunityTiers: []string{"community", "ut1"}}.withDefaults()
	b := Thresholds{CommunityTiers: []string{"ut1", " community ", "ut1"}}.withDefaults()
	ha := recommendationPolicyHashFor(a.policySnapshot())
	hb := recommendationPolicyHashFor(b.policySnapshot())
	if ha != hb || ha == "" {
		t.Fatalf("ordering/spacing changed the policy hash: %q vs %q", ha, hb)
	}
	// Explicit values equal to the defaults are the SAME semantics ⇒ same hash.
	c := Thresholds{HighMinAllowedRequests: 30, HighMinSubjects: 5, HighMinDays: 5,
		MediumMinAllowedRequests: 5, MediumMinSubjects: 2, MediumMinDays: 2,
		CommunityTiers: []string{"community"}}.withDefaults()
	d := Thresholds{}.withDefaults()
	if recommendationPolicyHashFor(c.policySnapshot()) != recommendationPolicyHashFor(d.policySnapshot()) {
		t.Fatal("explicit-default configuration hashed differently from implicit defaults")
	}
}

func TestRecommendationPolicyHash_MaterialChangesChangeHash(t *testing.T) {
	base := recommendationPolicyHashFor(Thresholds{}.withDefaults().policySnapshot())
	mutations := map[string]Thresholds{
		"high_requests":   {HighMinAllowedRequests: 31},
		"high_subjects":   {HighMinSubjects: 6},
		"high_days":       {HighMinDays: 6},
		"medium_requests": {MediumMinAllowedRequests: 6},
		"medium_subjects": {MediumMinSubjects: 3},
		"medium_days":     {MediumMinDays: 3},
		"community_tiers": {CommunityTiers: []string{"community", "ut1"}},
	}
	seen := map[string]string{"": base}
	for name, th := range mutations {
		h := recommendationPolicyHashFor(th.withDefaults().policySnapshot())
		if h == base {
			t.Errorf("%s change did not change the policy hash", name)
		}
		for prev, ph := range seen {
			if ph == h {
				t.Errorf("%s collides with %q", name, prev)
			}
		}
		seen[name] = h
	}
}

func TestRecommendationPolicyHash_UnrelatedConfigCannotChangeIt(t *testing.T) {
	clk := newTestClock()
	e1 := newRecEngine(t, "", clk, nil)
	// Different store, retention, allowlist (guardrails), resolver — none of it
	// is recommendation-decision policy.
	e2 := newRecEngine(t, t.TempDir(), clk, func(c *Config) {
		c.RecommendableCategories = []string{"AI"}
		c.MaxRetainedSessions = 3
		c.Categories = nil
	})
	if e1.RecommendationPolicyHash() != e2.RecommendationPolicyHash() {
		t.Fatal("non-policy configuration changed the recommendation-policy hash")
	}
	if e1.GuardrailsHash() == e2.GuardrailsHash() {
		t.Fatal("allowlist change must still move GuardrailsHash (separate identities)")
	}
}

func TestGenerate_PinsPolicySnapshotAndSurvivesRestart(t *testing.T) {
	clk := newTestClock()
	dir := t.TempDir()
	e := newRecEngine(t, dir, clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	r := mustGenerate(t, e, s.ID).Recommendations[0]
	if r.PolicyHash != e.RecommendationPolicyHash() || r.PolicyHash == "" {
		t.Fatalf("policy hash not pinned: %q vs %q", r.PolicyHash, e.RecommendationPolicyHash())
	}
	want := e.CurrentRecommendationPolicy()
	if fmt.Sprint(r.Policy) != fmt.Sprint(want) {
		t.Fatalf("policy snapshot not embedded by value: %+v vs %+v", r.Policy, want)
	}
	if r.Policy.AlgorithmVersion != recommendAlgorithmVersion || r.Policy.HighMinSubjects != 5 {
		t.Fatalf("snapshot content: %+v", r.Policy)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	// Restart with the SAME config: identity identical, object byte-identical.
	e2 := newRecEngine(t, dir, clk, nil)
	if e2.RecommendationPolicyHash() != r.PolicyHash {
		t.Fatal("policy identity not stable across restart")
	}
	got := e2.Recommendations()[0]
	b1, _ := json.Marshal(r)
	b2, _ := json.Marshal(got)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("recommendation changed across restart:\n%s\n%s", b1, b2)
	}
}

func TestGenerate_PolicyChangeSupersedesNeverRewrites(t *testing.T) {
	clk := newTestClock()
	dir := t.TempDir()
	e := newRecEngine(t, dir, clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	orig := mustGenerate(t, e, s.ID).Recommendations[0]
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen under a changed decision policy (community tiers extended — a
	// semantic cap change even though this cell's confidence outcome may not
	// move).
	e2 := newRecEngine(t, dir, clk, func(c *Config) {
		c.Recommend = Thresholds{CommunityTiers: []string{"community", "ut1"}}
	})
	if e2.RecommendationPolicyHash() == orig.PolicyHash {
		t.Fatal("policy change did not move the engine identity")
	}
	res := mustGenerate(t, e2, s.ID)
	if res.SupersededCount != 1 || len(res.Recommendations) != 1 {
		t.Fatalf("policy change must supersede: %+v", res)
	}
	if res.Recommendations[0].PolicyHash != e2.RecommendationPolicyHash() {
		t.Fatal("new recommendation not pinned to the new policy identity")
	}
	// The historical object is preserved verbatim (state latch aside): its
	// evidence, snapshot, and hash still describe the ORIGINAL decision.
	var old Recommendation
	for _, r := range e2.Recommendations() {
		if r.ID == orig.ID {
			old = r
		}
	}
	if old.ID == "" || old.State != RecStateSuperseded {
		t.Fatalf("original object missing/not superseded: %+v", old)
	}
	old.State = orig.State // undo the one permitted mutation for the comparison
	b1, _ := json.Marshal(orig)
	b2, _ := json.Marshal(old)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("policy change rewrote historical evidence:\n%s\n%s", b1, b2)
	}
	// And the pure staleness helper flags the old object against the new
	// engine identity.
	reasons := StaleReasons(&old, StaleInputs{
		PolicyGeneration:         old.Baseline.PolicyGeneration,
		CategoryEpoch:            old.Baseline.CategoryEpoch,
		GuardrailsHash:           old.Baseline.GuardrailsHash,
		SubjectKeyID:             old.SubjectKeyID,
		RecommendationPolicyHash: e2.RecommendationPolicyHash(),
	})
	if fmt.Sprint(reasons) != fmt.Sprint([]string{"recommendation_policy_changed"}) {
		t.Fatalf("stale reasons = %v, want [recommendation_policy_changed]", reasons)
	}
}

func TestStaleReasons_RecommendationPolicyClaims(t *testing.T) {
	r := &Recommendation{PolicyHash: "p1"}
	if got := StaleReasons(r, StaleInputs{RecommendationPolicyHash: "p1"}); len(got) != 0 {
		t.Fatalf("matching policy hash reported stale: %v", got)
	}
	if got := StaleReasons(r, StaleInputs{RecommendationPolicyHash: "p2"}); fmt.Sprint(got) != fmt.Sprint([]string{"recommendation_policy_changed"}) {
		t.Fatalf("changed policy hash: %v", got)
	}
	// No current identity supplied ⇒ no claim.
	if got := StaleReasons(r, StaleInputs{}); len(got) != 0 {
		t.Fatalf("no-claim case reported stale: %v", got)
	}
	// Unpinned (pre-M4.1) object vs a current identity ⇒ stale, fail-closed.
	unpinned := &Recommendation{}
	if got := StaleReasons(unpinned, StaleInputs{RecommendationPolicyHash: "p1"}); fmt.Sprint(got) != fmt.Sprint([]string{"recommendation_policy_changed"}) {
		t.Fatalf("unpinned object not failed closed: %v", got)
	}
}
