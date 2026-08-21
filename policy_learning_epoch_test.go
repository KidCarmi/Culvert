package main

// QB-2 corrective slice — restart-stable CategoryEpoch (scheme v2). These
// tests pin the ROOT composition: learnCategoryEpoch must be invariant under
// a restart-equivalent rebuild/reload of an unchanged admin taxonomy (the old
// process-local revision counter was not, so every node restart staled every
// recommendation of any session that spanned it), must still change on a REAL
// taxonomy change, and must be scheme-tagged so old counter-scheme pins can
// never compare equal to the new semantic identity.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/policylearn"
)

// epochTestEngine builds a durable engine wired to the REAL production epoch
// composition (learnCategoryEpoch over the global catStore) with an injected
// category resolver so aggregation is hermetic.
func epochTestEngine(t *testing.T, dir string) *policylearn.Engine {
	t.Helper()
	e, err := policylearn.New(policylearn.Config{
		StorePath:               filepath.Join(dir, "policy_learning.json"),
		SubjectKeyPath:          filepath.Join(dir, "subject.key"),
		Now:                     time.Now,
		Categories:              func(string) (string, string) { return "EpochTestCat", "admin" },
		CategoryEpoch:           learnCategoryEpoch,
		RecommendableCategories: []string{"EpochTestCat"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func epochTestObserve(t *testing.T, e *policylearn.Engine, want int64) {
	t.Helper()
	e.Observe(policylearn.Observation{Subject: "alice", AuthSource: "oidc:lab",
		Groups: []string{"eng"}, Host: "epoch.example", Method: "GET", Status: "OK", Action: "Allow"})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && e.ObservationStats().Delivered < want {
		time.Sleep(time.Millisecond)
	}
	if e.ObservationStats().Delivered < want {
		t.Fatalf("observation not delivered: %+v", e.ObservationStats())
	}
}

// catStoreRestartEquivalentRebuild simulates the taxonomy half of a process
// restart: a full index rebuild over IDENTICAL content (what a fresh process's
// Load of the same persisted file produces). Under the retired counter scheme
// this changed the epoch; under scheme v2 it must not.
func catStoreRestartEquivalentRebuild() {
	catStore.ReplaceAll(catStore.All())
}

// (2) Restart with identical persisted taxonomy ⇒ identical CategoryEpoch.
func TestLearnCategoryEpoch_V2StableAcrossRestartEquivalentRebuild(t *testing.T) {
	if err := catStore.Set("epoch-v2-stable", []string{"epoch-v2.example"}, false); err != nil {
		t.Fatalf("Set: %v", err)
	}
	t.Cleanup(func() { _ = catStore.Delete("epoch-v2-stable") })
	before := learnCategoryEpoch()
	catStoreRestartEquivalentRebuild()
	if after := learnCategoryEpoch(); after != before {
		t.Fatalf("epoch changed across identical-content rebuild: %q -> %q", before, after)
	}
}

// Upgrade semantics: the v2 scheme is tagged so a value pinned under the old
// "saas:...|admin:<counter>" scheme can never compare equal to a v2 value.
func TestLearnCategoryEpoch_V2SchemeDistinguishableFromCounterScheme(t *testing.T) {
	epoch := learnCategoryEpoch()
	if !strings.HasPrefix(epoch, "v2|saas:") {
		t.Fatalf("epoch %q does not carry the v2 scheme tag", epoch)
	}
	if !strings.Contains(epoch, "|admin:") {
		t.Fatalf("epoch %q missing the admin component", epoch)
	}
	// The admin component is a hex content fingerprint, never a bare counter.
	adminPart := epoch[strings.LastIndex(epoch, "|admin:")+len("|admin:"):]
	if len(adminPart) != 32 {
		t.Fatalf("admin component %q is not the 32-hex content fingerprint", adminPart)
	}
}

// (8)+(9)+(10) through a real engine: restart during an active session
// records NO churn from the restart alone; complete → generate → restart
// leaves the recommendation non-stale on the category axis; a REAL taxonomy
// change then records churn-relevant staleness for the correct reason.
func TestLearnCategoryEpoch_EngineRestartDoesNotChurnOrStale(t *testing.T) {
	if err := catStore.Set("epoch-v2-engine", []string{"epoch-v2-engine.example"}, false); err != nil {
		t.Fatalf("Set: %v", err)
	}
	t.Cleanup(func() { _ = catStore.Delete("epoch-v2-engine") })
	dir := t.TempDir()

	e1 := epochTestEngine(t, dir)
	if _, err := e1.StartSession("qb2"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	epochTestObserve(t, e1, 1)
	if err := e1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// (8) Restart mid-Learning with unchanged taxonomy: session resumes with a
	// process_restart gap but NO category churn.
	catStoreRestartEquivalentRebuild()
	e2 := epochTestEngine(t, dir)
	epochTestObserve(t, e2, 1) // drain runs the epoch check against the resumed session
	sess := e2.Sessions()
	cur := sess[len(sess)-1]
	if cur.State != policylearn.StateLearning {
		t.Fatalf("session did not resume Learning: %s", cur.State)
	}
	if len(cur.CategoryChurn) != 0 {
		t.Fatalf("restart alone recorded category churn: %+v", cur.CategoryChurn)
	}
	gotRestartGap := false
	for _, g := range cur.Gaps {
		if g.Reason == "process_restart" {
			gotRestartGap = true
		}
		if strings.Contains(g.Reason, "churn") || strings.Contains(g.Reason, "category") {
			t.Fatalf("restart recorded a category gap: %+v", g)
		}
	}
	if !gotRestartGap {
		t.Fatalf("process_restart gap missing: %+v", cur.Gaps)
	}

	// (9) Complete → generate → restart again: the recommendation carries NO
	// category-related stale reason under the unchanged taxonomy.
	done, err := e2.StopSession("qb2")
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := e2.GenerateRecommendations(done.ID); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := e2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	catStoreRestartEquivalentRebuild()
	e3 := epochTestEngine(t, dir)
	defer func() { _ = e3.Close() }()
	recs := e3.Recommendations()
	if len(recs) == 0 {
		t.Fatal("no recommendations survived restart")
	}
	staleWith := func(r policylearn.Recommendation) []string {
		return policylearn.StaleReasons(&r, policylearn.StaleInputs{
			PolicyGeneration:         r.Baseline.PolicyGeneration,
			PolicyContentHash:        r.Baseline.PolicyContentHash,
			CategoryEpoch:            learnCategoryEpoch(),
			GuardrailsHash:           e3.GuardrailsHash(),
			SubjectKeyID:             e3.SubjectKeyID(),
			RecommendationPolicyHash: e3.RecommendationPolicyHash(),
		})
	}
	for _, reason := range staleWith(recs[0]) {
		if reason == "category_epoch_changed" {
			t.Fatalf("restart with unchanged taxonomy staled the recommendation: %v", staleWith(recs[0]))
		}
	}

	// (10) A REAL taxonomy change makes the same recommendation stale for the
	// correct reason.
	if err := catStore.AddHost("epoch-v2-engine", "added.example"); err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	t.Cleanup(func() { _ = catStore.RemoveHost("epoch-v2-engine", "added.example") })
	found := false
	for _, reason := range staleWith(recs[0]) {
		if reason == "category_epoch_changed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("real taxonomy change did not stale the recommendation: %v", staleWith(recs[0]))
	}
}
