package policylearn

// M5B engine tests — decision lifecycle (accepting/accepted/rejected):
// transition matrix, idempotency, persist-before-return rollback, regeneration
// protection, prune priority, and the policy-identity staleness precedence.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newDecisionFixture builds an engine with one generated recommendation and
// returns (engine, clock, recommendation ID).
func newDecisionFixture(t *testing.T, dir string) (*Engine, *testClock, string) {
	t.Helper()
	clk := newTestClock()
	e := newRecEngine(t, dir, clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	res := mustGenerate(t, e, s.ID)
	return e, clk, res.Recommendations[0].ID
}

func TestDecision_AcceptLifecycleAndIdempotency(t *testing.T) {
	e, _, recID := newDecisionFixture(t, t.TempDir())

	r, err := e.BeginAccept(recID, "01TARGETRULEIDAAAAAAAAAAAA")
	if err != nil || r.State != RecStateAccepting || r.TargetRuleID != "01TARGETRULEIDAAAAAAAAAAAA" {
		t.Fatalf("BeginAccept: %v %+v", err, r)
	}
	// Retry with a DIFFERENT freshly minted target: the persisted intent wins.
	r2, err := e.BeginAccept(recID, "01DIFFERENTTARGETBBBBBBBBB")
	if err != nil || r2.TargetRuleID != "01TARGETRULEIDAAAAAAAAAAAA" {
		t.Fatalf("BeginAccept retry must reuse the persisted intent: %v %+v", err, r2)
	}

	fin, err := e.FinalizeAccept(recID, "admin@198.51.100.9")
	if err != nil || fin.State != RecStateAccepted || fin.AcceptedBy != "admin@198.51.100.9" || fin.AcceptedAt == "" {
		t.Fatalf("FinalizeAccept: %v %+v", err, fin)
	}
	if fin.TargetRuleID != "01TARGETRULEIDAAAAAAAAAAAA" {
		t.Fatal("accepted recommendation lost its target rule linkage")
	}
	// Finalize is idempotent; BeginAccept and Reject now refuse.
	if again, err := e.FinalizeAccept(recID, "other"); err != nil || again.AcceptedBy != "admin@198.51.100.9" {
		t.Fatalf("FinalizeAccept idempotency: %v %+v", err, again)
	}
	if _, err := e.BeginAccept(recID, "01NEWTARGETCCCCCCCCCCCCCCC"); !errors.Is(err, ErrRecommendationAccepted) {
		t.Fatalf("BeginAccept on accepted: %v", err)
	}
	if _, err := e.Reject(recID, "op", "no"); !errors.Is(err, ErrRecommendationAccepted) {
		t.Fatalf("Reject on accepted: %v", err)
	}
	if _, err := e.AbortAccept(recID); !errors.Is(err, ErrRecommendationAccepted) {
		t.Fatalf("AbortAccept on accepted: %v", err)
	}
}

func TestDecision_AbortRevertsIntent(t *testing.T) {
	e, _, recID := newDecisionFixture(t, t.TempDir())
	if _, err := e.BeginAccept(recID, "01TARGETRULEIDAAAAAAAAAAAA"); err != nil {
		t.Fatal(err)
	}
	r, err := e.AbortAccept(recID)
	if err != nil || r.State != RecStateGenerated || r.TargetRuleID != "" {
		t.Fatalf("AbortAccept: %v %+v", err, r)
	}
	// Idempotent on generated.
	if _, err := e.AbortAccept(recID); err != nil {
		t.Fatalf("AbortAccept idempotency: %v", err)
	}
	// A later accept mints a fresh intent.
	r2, err := e.BeginAccept(recID, "01NEWTARGETCCCCCCCCCCCCCCC")
	if err != nil || r2.TargetRuleID != "01NEWTARGETCCCCCCCCCCCCCCC" {
		t.Fatalf("re-accept after abort: %v %+v", err, r2)
	}
}

func TestDecision_RejectLifecycle(t *testing.T) {
	e, _, recID := newDecisionFixture(t, t.TempDir())
	r, err := e.Reject(recID, "op@198.51.100.9", "not needed\x00\ncontrol")
	if err != nil || r.State != RecStateRejected || r.RejectedBy != "op@198.51.100.9" {
		t.Fatalf("Reject: %v %+v", err, r)
	}
	if strings.ContainsAny(r.RejectReason, "\x00\n") {
		t.Fatalf("reason not sanitized: %q", r.RejectReason)
	}
	// Idempotent retry keeps the ORIGINAL reason.
	again, err := e.Reject(recID, "other", "different reason")
	if err != nil || again.RejectReason != r.RejectReason || again.RejectedBy != "op@198.51.100.9" {
		t.Fatalf("Reject idempotency rewrote history: %v %+v", err, again)
	}
	// Accept on rejected refuses.
	if _, err := e.BeginAccept(recID, "01TARGETRULEIDAAAAAAAAAAAA"); !errors.Is(err, ErrRecommendationRejected) {
		t.Fatalf("BeginAccept on rejected: %v", err)
	}
	// Reject on accepting refuses.
	e2, _, recID2 := newDecisionFixture(t, t.TempDir())
	if _, err := e2.BeginAccept(recID2, "01TARGETRULEIDAAAAAAAAAAAA"); err != nil {
		t.Fatal(err)
	}
	if _, err := e2.Reject(recID2, "op", ""); !errors.Is(err, ErrRecommendationAccepting) {
		t.Fatalf("Reject on accepting: %v", err)
	}
	// Unknown ID.
	if _, err := e.Reject("nope", "op", ""); !errors.Is(err, ErrRecommendationNotFound) {
		t.Fatalf("Reject unknown: %v", err)
	}
	// Bounded reason.
	long := strings.Repeat("x", 1000)
	if got := sanitizeReason(long); len(got) != maxRejectReasonLen {
		t.Fatalf("reason bound: %d", len(got))
	}
}

func TestDecision_PersistFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "store")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	clk := newTestClock()
	e := newRecEngine(t, sub, clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	recID := mustGenerate(t, e, s.ID).Recommendations[0].ID

	// Destroy the store directory so AtomicWrite fails.
	if err := os.RemoveAll(sub); err != nil {
		t.Fatal(err)
	}
	if _, err := e.BeginAccept(recID, "01TARGETRULEIDAAAAAAAAAAAA"); err == nil {
		t.Fatal("BeginAccept succeeded with an unwritable store")
	}
	// Persist-before-return: the failed transition left NO trace.
	r, ok := e.RecommendationByID(recID)
	if !ok || r.State != RecStateGenerated || r.TargetRuleID != "" {
		t.Fatalf("failed BeginAccept leaked state: %+v", r)
	}

	// Restore the directory: the same accept now succeeds; finalize-failure
	// rollback follows the same contract.
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := e.BeginAccept(recID, "01TARGETRULEIDAAAAAAAAAAAA"); err != nil {
		t.Fatalf("BeginAccept after restore: %v", err)
	}
	if err := os.RemoveAll(sub); err != nil {
		t.Fatal(err)
	}
	if _, err := e.FinalizeAccept(recID, "admin"); err == nil {
		t.Fatal("FinalizeAccept succeeded with an unwritable store")
	}
	r, _ = e.RecommendationByID(recID)
	if r.State != RecStateAccepting {
		t.Fatalf("failed finalize leaked state: %+v", r)
	}
}

func TestDecision_RegenerationNeverClobbersDecisions(t *testing.T) {
	e, _, recID := newDecisionFixture(t, t.TempDir())
	sessID, _ := func() (string, bool) {
		r, ok := e.RecommendationByID(recID)
		return r.SessionID, ok
	}()
	if _, err := e.BeginAccept(recID, "01TARGETRULEIDAAAAAAAAAAAA"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.FinalizeAccept(recID, "admin"); err != nil {
		t.Fatal(err)
	}
	before, _ := e.RecommendationByID(recID)

	res, err := e.GenerateRecommendations(sessID) // identical content regeneration
	if err != nil {
		t.Fatal(err)
	}
	after, _ := e.RecommendationByID(recID)
	if after.State != RecStateAccepted || after.AcceptedBy != before.AcceptedBy || after.TargetRuleID != before.TargetRuleID {
		t.Fatalf("regeneration clobbered an accepted decision: %+v", after)
	}
	b1, _ := json.Marshal(before)
	b2, _ := json.Marshal(after)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("regeneration mutated an accepted object:\n%s\n%s", b1, b2)
	}
	_ = res
	if n := len(e.Recommendations()); n != 1 {
		t.Fatalf("regeneration duplicated a decided recommendation: %d", n)
	}
}

func TestDecision_PrunePriorityProtectsIntents(t *testing.T) {
	var recs []*Recommendation
	mk := func(state string, n int) {
		for i := 0; i < n; i++ {
			recs = append(recs, &Recommendation{
				ID: fmt.Sprintf("%s-%03d", state, i), SessionID: "s", State: state, TargetRuleID: "t"})
		}
	}
	mk(RecStateAccepting, 4)
	mk(RecStateAccepted, 100)
	mk(RecStateGenerated, 100)
	mk(RecStateRejected, 60)
	mk(RecStateSuperseded, 60) // total 324, cap 256 ⇒ evict 68
	pruned := pruneRecommendations(recs)
	if len(pruned) != maxRetainedRecommendations {
		t.Fatalf("pruned to %d, want %d", len(pruned), maxRetainedRecommendations)
	}
	counts := map[string]int{}
	for _, r := range pruned {
		counts[r.State]++
	}
	// 60 superseded + 8 rejected evicted; everything else intact.
	want := map[string]int{RecStateAccepting: 4, RecStateAccepted: 100, RecStateGenerated: 100, RecStateRejected: 52}
	for st, n := range want {
		if counts[st] != n {
			t.Fatalf("prune priority: %s = %d, want %d (all: %v)", st, counts[st], n, counts)
		}
	}
}

func TestDecision_PersistedV6RoundTripAndDowngradeSafety(t *testing.T) {
	dir := t.TempDir()
	e, _, recID := newDecisionFixture(t, dir)
	if _, err := e.BeginAccept(recID, "01TARGETRULEIDAAAAAAAAAAAA"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.FinalizeAccept(recID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	clk := newTestClock()
	e2 := newRecEngine(t, dir, clk, nil)
	r, ok := e2.RecommendationByID(recID)
	if !ok || r.State != RecStateAccepted || r.TargetRuleID != "01TARGETRULEIDAAAAAAAAAAAA" {
		t.Fatalf("decision state lost across restart: %+v", r)
	}

	// A decision-state record without its target linkage is corruption.
	bad := `{"schema_version":6,"sessions":[],"recommendations":[{"id":"x","session_id":"s","state":"accepting"}]}`
	if _, err := decodeEnvelope([]byte(bad)); err == nil {
		t.Fatal("accepting without target_rule_id decoded cleanly")
	}
}

// TestStaleReasons_ContentHashPrecedence pins the M5B §5 contract (see the
// StaleReasons doc for the numbered precedence).
func TestStaleReasons_ContentHashPrecedence(t *testing.T) {
	pinned := &Recommendation{Baseline: Baseline{PolicyGeneration: 5, PolicyContentHash: "content-A"}}

	// 1. Content asserted + pinned: generation-only change is NOT stale…
	got := StaleReasons(pinned, StaleInputs{PolicyGeneration: 99, PolicyContentHash: "content-A"})
	for _, r := range got {
		if r == "policy_generation_changed" || r == "policy_content_changed" {
			t.Fatalf("generation-only change reported stale for a content-pinned recommendation: %v", got)
		}
	}
	// …while an actual content difference IS.
	got = StaleReasons(pinned, StaleInputs{PolicyGeneration: 5, PolicyContentHash: "content-B"})
	if !strings.Contains(strings.Join(got, " "), "policy_content_changed") {
		t.Fatalf("content change not detected: %v", got)
	}

	// 2. Content asserted + UNPINNED (legacy) recommendation: fail-closed.
	legacy := &Recommendation{Baseline: Baseline{PolicyGeneration: 5}}
	got = StaleReasons(legacy, StaleInputs{PolicyGeneration: 5, PolicyContentHash: "content-A"})
	if !strings.Contains(strings.Join(got, " "), "policy_content_changed") {
		t.Fatalf("unpinned recommendation not failed closed: %v", got)
	}

	// 3. Content NOT asserted: generation is the fallback.
	got = StaleReasons(legacy, StaleInputs{PolicyGeneration: 6})
	if !strings.Contains(strings.Join(got, " "), "policy_generation_changed") {
		t.Fatalf("generation fallback missing: %v", got)
	}
	if got := StaleReasons(legacy, StaleInputs{PolicyGeneration: 5}); len(got) != 0 {
		t.Fatalf("fallback false positive: %v", got)
	}
}

func TestDecision_SupersededRefusesAcceptAndReject(t *testing.T) {
	clk := newTestClock()
	dir := t.TempDir()
	e := newRecEngine(t, dir, clk, nil)
	s, _ := e.StartSession("op")
	feedHighEvidence(t, e, clk)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	oldID := mustGenerate(t, e, s.ID).Recommendations[0].ID
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	// Changed thresholds ⇒ regeneration supersedes the original object.
	e2 := newRecEngine(t, dir, clk, func(c *Config) { c.Recommend = Thresholds{HighMinSubjects: 50} })
	if _, err := e2.GenerateRecommendations(s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e2.BeginAccept(oldID, "01TARGETRULEIDAAAAAAAAAAAA"); !errors.Is(err, ErrRecommendationSuperseded) {
		t.Fatalf("BeginAccept on superseded: %v", err)
	}
	if _, err := e2.Reject(oldID, "op", ""); !errors.Is(err, ErrRecommendationSuperseded) {
		t.Fatalf("Reject on superseded: %v", err)
	}
}
