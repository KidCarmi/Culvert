package main

// policy_fenced_read_test.go — policy fenced-read + draft-review coherency
// proofs (final 2D-B correction §§6–12, red families C/D/E).
//
// Every read surface that returns a rule list PLUS the version fence clients
// echo via ?ifVersion= must capture both from ONE store state. At the prior
// candidate each surface assembled them from independent reads —
// effectivePolicyList() then effectivePolicyVersion() (/api/policy),
// listAuthRules() then policyStore.policyVersion() (/api/authpolicy), and the
// draft GET's state/diff/version/shadows/baseStale pile — so a writer landing
// between the reads handed a client generation-P rules with a generation-P+1
// token: its stale later edit (or the commit of an unreviewed candidate)
// passed the optimistic fence against content it never saw.
//
// The stress proofs use the house directional invariant
// (coherent_read_2db_test.go): rows carry a generation marker, the mutator
// bumps the version exactly once per installed generation, and the version
// must never be AHEAD of the returned rows. The §12 proof is deterministic:
// the reviewed token must refuse to commit a candidate containing a rule the
// review response did not show.

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
)

// fencedPolicyState builds generation-tagged access-rule states: one stable
// rule plus one "gen-<n>" marker rule, so ReplaceAll (install + bumpVersion in
// ONE critical section) advances content and fence in lock-step.
func fencedPolicyState(n int64) []PolicyRule {
	return []PolicyRule{
		{Name: "alpha", Action: ActionAllow, Priority: 1},
		{Name: fmt.Sprintf("gen-%d", n), Action: ActionAllow, Priority: 2},
	}
}

// TestFencedRead_PolicyGETVersionDescribesReturnedRules is the §23-C proof:
// under a concurrent policy writer, GET /api/policy must never pair rules from
// one generation with a LATER generation's version fence.
func TestFencedRead_PolicyGETVersionDescribesReturnedRules(t *testing.T) {
	draftTestSetup(t) // RequireCommit off — the running store serves the GET

	policyStore.ReplaceAll(fencedPolicyState(0))
	base, _ := policyStore.policyVersion() // corresponds to generation 0

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var n int64
		for {
			select {
			case <-stop:
				return
			default:
			}
			n++
			policyStore.ReplaceAll(fencedPolicyState(n))
		}
	}()
	defer func() { close(stop); <-done }()

	const reads = 400
	for i := 0; i < reads; i++ {
		w := httptest.NewRecorder()
		apiPolicy(w, getReq("/api/policy"))
		if w.Code != 200 {
			t.Fatalf("read %d: status %d: %s", i, w.Code, w.Body.String())
		}
		var resp struct {
			Rules []struct {
				Name string `json:"name"`
			} `json:"rules"`
			Version int64 `json:"version"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("read %d: decode: %v", i, err)
		}
		names := make([]string, len(resp.Rules))
		for j, r := range resp.Rules {
			names[j] = r.Name
		}
		g := parseGenerationName(names)
		if g < 0 {
			t.Fatalf("read %d: no generation marker in rules %v", i, names)
		}
		if delta := resp.Version - base; delta > g {
			t.Fatalf("read %d: TORN POLICY READ: version %d (base %d, delta %d) is AHEAD of the returned rules (generation %d) — stale rules paired with a successor fence token pass the ifVersion fence against content the client never saw", i, resp.Version, base, delta, g)
		}
	}
}

// fencedAuthState builds generation-tagged states whose marker is a valid
// Stage-1 auth rule (the /api/authpolicy GET filters to the auth subset, so
// the marker must survive policyRulePersistable).
func fencedAuthState(n int64) []PolicyRule {
	return []PolicyRule{
		{Name: "alpha", Action: ActionAllow, Priority: 1},
		{
			Name: fmt.Sprintf("gen-%d", n), Priority: 2,
			RuleType: ruleTypeAuth,
			SubjectMatch: &SubjectMatch{
				SchemaVersion: 1,
				All:           []SubjectPredicate{{Type: "cidr", Values: []string{"10.0.0.0/8"}}},
			},
			Auth: &AuthRuleSpec{Outcome: OutcomeExempt, Owner: "ops", Reason: "lab", BroadExemption: true},
		},
	}
}

// TestFencedRead_AuthPolicyGETVersionDescribesReturnedRules is the §23-D
// proof: GET /api/authpolicy filters its auth views and reads its running
// version fence from ONE store snapshot — never stale auth rows with a
// successor token.
func TestFencedRead_AuthPolicyGETVersionDescribesReturnedRules(t *testing.T) {
	draftTestSetup(t)

	policyStore.ReplaceAll(fencedAuthState(0))
	base, _ := policyStore.policyVersion() // corresponds to generation 0

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var n int64
		for {
			select {
			case <-stop:
				return
			default:
			}
			n++
			policyStore.ReplaceAll(fencedAuthState(n))
		}
	}()
	defer func() { close(stop); <-done }()

	const reads = 400
	for i := 0; i < reads; i++ {
		w := httptest.NewRecorder()
		apiAuthPolicy(w, getReq("/api/authpolicy"))
		if w.Code != 200 {
			t.Fatalf("read %d: status %d: %s", i, w.Code, w.Body.String())
		}
		var resp struct {
			Rules []struct {
				Name string `json:"name"`
			} `json:"rules"`
			Version int64 `json:"version"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("read %d: decode: %v", i, err)
		}
		names := make([]string, len(resp.Rules))
		for j, r := range resp.Rules {
			names[j] = r.Name
		}
		g := parseGenerationName(names)
		if g < 0 {
			t.Fatalf("read %d: no generation marker in auth rules %v", i, names)
		}
		if delta := resp.Version - base; delta > g {
			t.Fatalf("read %d: TORN AUTH-POLICY READ: version %d (base %d, delta %d) is AHEAD of the returned auth rules (generation %d) — stale rows paired with a successor fence token", i, resp.Version, base, delta, g)
		}
	}
}

// getDraftReview GETs /api/policy/draft and decodes the review fields.
func getDraftReview(t *testing.T) (version int64, pendingCount int, added []string, active bool) {
	t.Helper()
	w := httptest.NewRecorder()
	apiPolicyDraft(w, getReq("/api/policy/draft"))
	if w.Code != 200 {
		t.Fatalf("draft GET: status %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Active       bool  `json:"active"`
		Version      int64 `json:"version"`
		PendingCount int   `json:"pendingCount"`
		Diff         struct {
			Added []string `json:"added"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("draft GET decode: %v", err)
	}
	return resp.Version, resp.PendingCount, resp.Diff.Added, resp.Active
}

// TestFencedRead_DraftReviewVersionDescribesReviewedCandidate is the §23-E
// stress proof: GET /api/policy/draft derives diff, pendingCount, and the
// commit token from ONE captured candidate state. Every staged create both
// adds one rule and bumps the candidate version once, so in any coherent
// response  version − forkBase == pendingCount ; a version AHEAD of the
// pending count is exactly the old-diff + new-token pair that commits a rule
// the operator never reviewed.
func TestFencedRead_DraftReviewVersionDescribesReviewedCandidate(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)

	// First staged create forks the draft; establish the fork base from the
	// first review: base = version − pendingCount (the candidate's generation
	// stream continues running's, so the absolute value is not 0).
	if w := createRuleViaAPI(t, "staged-0", ""); w.Code != 200 {
		t.Fatalf("open draft: %d %s", w.Code, w.Body.String())
	}
	v0, p0, _, active := getDraftReview(t)
	if !active || p0 < 1 {
		t.Fatalf("draft not active after first staged create (active=%t pending=%d)", active, p0)
	}
	base := v0 - int64(p0)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for n := 1; ; n++ {
			select {
			case <-stop:
				return
			default:
			}
			w := httptest.NewRecorder()
			apiPolicyCreate(w, jsonReq("POST", "/api/policy",
				map[string]any{"name": fmt.Sprintf("staged-%d", n), "action": "Allow"}))
			if w.Code != 200 {
				return // stop staging on any refusal; the reads keep asserting
			}
		}
	}()
	defer func() { close(stop); <-done }()

	const reads = 300
	for i := 0; i < reads; i++ {
		ver, pending, _, act := getDraftReview(t)
		if !act {
			t.Fatalf("read %d: draft went inactive under staging", i)
		}
		if delta := ver - base; delta > int64(pending) {
			t.Fatalf("read %d: TORN DRAFT REVIEW: commit token %d (fork base %d, delta %d) is AHEAD of the reviewed diff (pendingCount %d) — committing with this token activates staged rules the review response never showed", i, ver, base, delta, pending)
		}
	}
}

// TestFencedRead_CommitWithReviewedTokenRefusesUnseenRule is the §12
// deterministic proof (load-bearing 2B regression gate): an operator reviews
// candidate generation T whose diff shows only Rule-A; Rule-B is then staged;
// a commit echoing T must 409 and activate NOTHING.
func TestFencedRead_CommitWithReviewedTokenRefusesUnseenRule(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)

	if w := createRuleViaAPI(t, "rule-a", ""); w.Code != 200 {
		t.Fatalf("stage rule-a: %d %s", w.Code, w.Body.String())
	}
	reviewedVer, _, added, active := getDraftReview(t)
	if !active {
		t.Fatal("draft must be active")
	}
	if len(added) != 1 || added[0] != "rule-a" {
		t.Fatalf("review must show exactly rule-a, got %v", added)
	}

	// An unseen edit lands after the review.
	if w := createRuleViaAPI(t, "rule-b", ""); w.Code != 200 {
		t.Fatalf("stage rule-b: %d %s", w.Code, w.Body.String())
	}

	w := httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq("POST",
		fmt.Sprintf("/api/policy/draft/commit?ifVersion=%d", reviewedVer),
		map[string]any{"comment": "reviewed rule-a only"}))
	if w.Code != 409 {
		t.Fatalf("commit with the reviewed token after an unseen edit must 409, got %d: %s — the reviewed-version fence no longer guarantees 'commit exactly what was reviewed'", w.Code, w.Body.String())
	}
	// Nothing activated: running must contain neither rule.
	for _, r := range policyStore.List() {
		if r.Name == "rule-a" || r.Name == "rule-b" {
			t.Fatalf("refused commit must activate nothing, but running contains %q", r.Name)
		}
	}
	if !policyDraft.active() {
		t.Fatal("refused commit must retain the draft")
	}
}
