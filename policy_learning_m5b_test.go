package main

// M5B tests — the Accept/Reject trust boundary: draft-only enforcement,
// born-safe translation, crash-safe cross-store reconciliation, fencing, and
// the strongest invariant (§14): after ANY crash/retry sequence a
// recommendation has either zero matching draft rules (not Accepted) or
// exactly one matching DISABLED draft rule whose ID it records.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/policylearn"
)

// plDraftHarness layers draft-mode isolation over plHarness: RequireCommit
// restored, the shared draft candidate cleared, and any policy rules the test
// adds to the RUNNING store removed.
func plDraftHarness(t *testing.T) {
	t.Helper()
	plHarness(t)
	prevRC := requireCommitEnabled()
	runningBefore := policyStore.List()
	t.Cleanup(func() {
		setRequireCommit(prevRC)
		policyDraft.clear()
		policyStore.ReplaceAll(runningBefore)
	})
	policyDraft.clear()
	setRequireCommit(false)
}

// plSeedRecommendation drives the REAL product path to one generated
// recommendation and returns its ID.
func plSeedRecommendation(t *testing.T) string {
	t.Helper()
	if err := catStore.Set("m5b-cat", []string{"m5b.example"}, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = catStore.Delete("m5b-cat") })
	if w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin,
		`{"enabled":true,"recommendable_categories":["m5b-cat"]}`); w.Code != 200 {
		t.Fatalf("enable: %d %s", w.Code, w.Body.String())
	}
	plStartSession(t)
	plObserve(t, "m5b-user@corp.example", []string{"m5b-team"}, "m5b.example")
	sessID := plCompleteSession(t)
	if w := plDo(apiPolicyLearningGenerate, http.MethodPost, "/api/policy-learning/recommendations/generate", RoleOperator,
		`{"session_id":"`+sessID+`"}`); w.Code != 200 {
		t.Fatalf("generate: %d %s", w.Code, w.Body.String())
	}
	recs := plRecsGET(t)
	if len(recs.Recommendations) != 1 {
		t.Fatalf("seed: %d recommendations", len(recs.Recommendations))
	}
	return recs.Recommendations[0].ID
}

type plRecsResponse struct {
	Recommendations []plRecommendationDTO `json:"recommendations"`
	DraftModeArmed  bool                  `json:"draft_mode_armed"`
	PolicyVersion   int64                 `json:"policy_version"`
}

func plRecsGET(t *testing.T) plRecsResponse {
	t.Helper()
	w := plDo(apiPolicyLearningRecommendations, http.MethodGet, "/api/policy-learning/recommendations", RoleViewer, "")
	if w.Code != 200 {
		t.Fatalf("recommendations GET: %d %s", w.Code, w.Body.String())
	}
	var out plRecsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func plAcceptPost(t *testing.T, role UIRole, recID string, ifVersion int64) *plDoResult {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"id": recID, "action": "accept", "if_version": ifVersion})
	w := plDo(apiPolicyLearningRecommendations, http.MethodPost, "/api/policy-learning/recommendations", role, string(body))
	return &plDoResult{Code: w.Code, Body: w.Body.String()}
}

type plDoResult struct {
	Code int
	Body string
}

// plCountTargetRules counts rules carrying the ID across candidate + running.
func plCountTargetRules(targetID string) (candidate, running int) {
	if targetID == "" {
		return 0, 0
	}
	cand := policyDraft.candidateList()
	for i := range cand { // index-based: PolicyRule is a large struct (rangeValCopy)
		if cand[i].ID == targetID {
			candidate++
		}
	}
	if policyStore.findByIDCopy(targetID) != nil {
		running++
	}
	return candidate, running
}

// assertStrongestInvariant pins M5B §14 for one recommendation.
func assertStrongestInvariant(t *testing.T, recID string) {
	t.Helper()
	eng := policyLearnEngine.Load()
	rec, ok := eng.RecommendationByID(recID)
	if !ok {
		t.Fatalf("recommendation %s vanished", recID)
	}
	cand, running := plCountTargetRules(rec.TargetRuleID)
	switch rec.State {
	case policylearn.RecStateAccepted:
		if cand+running != 1 {
			t.Fatalf("accepted %s: %d matching rules (cand=%d running=%d), want exactly 1", recID, cand+running, cand, running)
		}
		found := plFindTargetRule(rec.TargetRuleID)
		if found == nil || !plRuleMatchesTranslation(found, &rec) || ruleIsEnabled(found) {
			t.Fatalf("accepted %s: target rule missing or not the disabled translation: %+v", recID, found)
		}
	default:
		if rec.State != policylearn.RecStateAccepting && cand+running != 0 {
			t.Fatalf("%s state=%s but %d target rules exist", recID, rec.State, cand+running)
		}
	}
	// A learning acceptance must NEVER create a running rule pre-commit in
	// these tests (no commit is ever issued here).
	if running != 0 {
		t.Fatalf("%s: rule reached the RUNNING store without a draft commit", recID)
	}
}

// ── §1 draft-only + happy path + idempotency ─────────────────────────────────

func TestM5B_AcceptIsDraftOnlyAndBornSafe(t *testing.T) {
	plDraftHarness(t)
	recID := plSeedRecommendation(t)

	// RequireCommit OFF ⇒ 409, nothing written anywhere.
	res := plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body, "Draft Mode") {
		t.Fatalf("accept without draft mode: %d %s", res.Code, res.Body)
	}
	assertStrongestInvariant(t, recID)

	setRequireCommit(true)
	// Wrong fence ⇒ 409.
	if res := plAcceptPost(t, RoleAdmin, recID, 999999); res.Code != http.StatusConflict {
		t.Fatalf("accept with wrong if_version: %d %s", res.Code, res.Body)
	}
	// Missing fence ⇒ 400.
	if w := plDo(apiPolicyLearningRecommendations, http.MethodPost, "/api/policy-learning/recommendations", RoleAdmin,
		`{"id":"`+recID+`","action":"accept"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("accept without if_version: %d", w.Code)
	}

	// Correct fence ⇒ ONE disabled draft rule, born-safe, linked.
	res = plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code != 200 {
		t.Fatalf("accept: %d %s", res.Code, res.Body)
	}
	eng := policyLearnEngine.Load()
	rec, _ := eng.RecommendationByID(recID)
	if rec.State != policylearn.RecStateAccepted || rec.TargetRuleID == "" {
		t.Fatalf("recommendation not accepted: %+v", rec)
	}
	assertStrongestInvariant(t, recID)
	rule := plFindTargetRule(rec.TargetRuleID)
	if rule.Action != ActionAllow || rule.SSLAction != SSLInspect || ruleIsEnabled(rule) ||
		rule.SourceGroup != "m5b-team" || string(rule.DestCategory) != "m5b-cat" {
		t.Fatalf("born-safe translation violated: %+v", rule)
	}
	if policyStore.findByIDCopy(rec.TargetRuleID) != nil {
		t.Fatal("accept wrote into the RUNNING rulebase")
	}

	// Idempotent re-accept: no duplicate, already_done.
	res = plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code != 200 || !strings.Contains(res.Body, `"already_done":true`) {
		t.Fatalf("re-accept: %d %s", res.Code, res.Body)
	}
	if cand, _ := plCountTargetRules(rec.TargetRuleID); cand != 1 {
		t.Fatalf("re-accept duplicated the rule: %d", cand)
	}
}

// ── RBAC + reject ────────────────────────────────────────────────────────────

func TestM5B_DecisionRBAC(t *testing.T) {
	plDraftHarness(t)
	recID := plSeedRecommendation(t)
	setRequireCommit(true)

	if res := plAcceptPost(t, RoleOperator, recID, plRecsGET(t).PolicyVersion); res.Code != http.StatusForbidden {
		t.Fatalf("operator accept: %d, want 403", res.Code)
	}
	if w := plDo(apiPolicyLearningRecommendations, http.MethodPost, "/api/policy-learning/recommendations", RoleViewer,
		`{"id":"`+recID+`","action":"reject"}`); w.Code != http.StatusForbidden {
		t.Fatalf("viewer reject: %d, want 403", w.Code)
	}
	if w := plDo(apiPolicyLearningRecommendations, http.MethodPost, "/api/policy-learning/recommendations", RoleOperator,
		`{"id":"`+recID+`","action":"reject","reason":"  not needed\r\n  "}`); w.Code != 200 {
		t.Fatalf("operator reject: %d %s", w.Code, w.Body.String())
	}
	rec, _ := policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State != policylearn.RecStateRejected || rec.RejectReason != "not needed" {
		t.Fatalf("reject state: %+v", rec)
	}
	// Idempotent reject; accept-after-reject 409; no rules anywhere.
	if w := plDo(apiPolicyLearningRecommendations, http.MethodPost, "/api/policy-learning/recommendations", RoleOperator,
		`{"id":"`+recID+`","action":"reject","reason":"different"}`); w.Code != 200 {
		t.Fatalf("reject retry: %d", w.Code)
	}
	rec2, _ := policyLearnEngine.Load().RecommendationByID(recID)
	if rec2.RejectReason != "not needed" {
		t.Fatal("reject retry rewrote the recorded reason")
	}
	if res := plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion); res.Code != http.StatusConflict {
		t.Fatalf("accept after reject: %d", res.Code)
	}
	assertStrongestInvariant(t, recID)
}

// ── §13 crash/failure matrix ─────────────────────────────────────────────────

// TestM5B_CrashAfterIntentBeforeMutation: the intent is durable, the draft
// mutation never happened (and the in-memory draft died with the "process").
// Retry under fresh fences redoes the mutation and converges on the SAME
// target rule ID.
func TestM5B_CrashAfterIntentBeforeMutation(t *testing.T) {
	plDraftHarness(t)
	recID := plSeedRecommendation(t)
	setRequireCommit(true)

	eng := policyLearnEngine.Load()
	begun, err := eng.BeginAccept(recID, newRuleID())
	if err != nil {
		t.Fatal(err)
	}
	target := begun.TargetRuleID

	// "Crash": reload the learning store; the never-persisted draft is gone.
	_ = eng.Close()
	policyLearnEngine.Store(nil)
	loadPolicyLearning(policyLearnPaths)
	policyDraft.clear()

	rec, _ := policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State != policylearn.RecStateAccepting || rec.TargetRuleID != target {
		t.Fatalf("intent not durable: %+v", rec)
	}

	// Admin retry: fences fresh ⇒ redo; SAME preallocated target ID.
	res := plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code != 200 {
		t.Fatalf("retry accept: %d %s", res.Code, res.Body)
	}
	rec, _ = policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State != policylearn.RecStateAccepted || rec.TargetRuleID != target {
		t.Fatalf("retry did not converge on the persisted target: %+v", rec)
	}
	assertStrongestInvariant(t, recID)
}

// TestM5B_CrashAfterMutationBeforeLatch: the rule exists, the latch does not.
// Retry finalizes idempotently — zero duplicates, even with the fences now
// STALE (the mutation already happened under valid fences).
func TestM5B_CrashAfterMutationBeforeLatch(t *testing.T) {
	plDraftHarness(t)
	recID := plSeedRecommendation(t)
	setRequireCommit(true)

	eng := policyLearnEngine.Load()
	begun, err := eng.BeginAccept(recID, newRuleID())
	if err != nil {
		t.Fatal(err)
	}
	rule := plTranslateRecommendation(&begun)
	stampRuleMetadataForWrite(&rule, nil, "crash-sim")
	if added := policyWriteStore("crash-sim").Add(rule); added.ID != begun.TargetRuleID {
		t.Fatalf("simulated mutation re-minted the ID: %s", added.ID)
	}

	// "Crash", then the policy content changes (fences go stale).
	_ = eng.Close()
	policyLearnEngine.Store(nil)
	loadPolicyLearning(policyLearnPaths)
	addedProbe := policyStore.Add(PolicyRule{Priority: 99881, Name: "m5b-stale-probe", DestFQDN: "probe.invalid", Action: ActionBlockPage})
	t.Cleanup(func() { policyStore.Delete(addedProbe.Priority) })

	res := plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code != 200 {
		t.Fatalf("finalize retry: %d %s", res.Code, res.Body)
	}
	rec, _ := policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State != policylearn.RecStateAccepted || rec.TargetRuleID != begun.TargetRuleID {
		t.Fatalf("finalize retry: %+v", rec)
	}
	if cand, _ := plCountTargetRules(rec.TargetRuleID); cand != 1 {
		t.Fatalf("duplicate rules after crash-retry: %d", cand)
	}
	assertStrongestInvariant(t, recID)
}

// TestM5B_IntegrityConflictNeverOverwrites: same TargetRuleID, different
// content ⇒ 409 + audit; the divergent rule is untouched and the
// recommendation stays accepting.
func TestM5B_IntegrityConflictNeverOverwrites(t *testing.T) {
	plDraftHarness(t)
	recID := plSeedRecommendation(t)
	setRequireCommit(true)

	eng := policyLearnEngine.Load()
	begun, err := eng.BeginAccept(recID, newRuleID())
	if err != nil {
		t.Fatal(err)
	}
	rule := plTranslateRecommendation(&begun)
	stampRuleMetadataForWrite(&rule, nil, "crash-sim")
	policyWriteStore("crash-sim").Add(rule)
	// An admin (or corruption) flips the rule to ENABLED before the retry.
	tampered := rule
	enabled := true
	tampered.Enabled = &enabled
	if !policyDraft.cand.UpdateByID(begun.TargetRuleID, tampered) {
		t.Fatal("tamper setup failed")
	}

	res := plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body, "DIFFERENT content") {
		t.Fatalf("integrity conflict: %d %s", res.Code, res.Body)
	}
	rec, _ := policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State != policylearn.RecStateAccepting {
		t.Fatalf("conflict changed the recommendation state: %+v", rec)
	}
	got := plFindTargetRule(begun.TargetRuleID)
	if got == nil || !ruleIsEnabled(got) {
		t.Fatal("conflicting rule was overwritten")
	}
	// Deterministic on retry.
	if res := plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion); res.Code != http.StatusConflict {
		t.Fatalf("conflict retry: %d", res.Code)
	}
}

// TestM5B_StaleIntentAbortsSafely: accepting + rule absent + fences stale ⇒
// the intent reverts to generated (evidence untouched) with a 409.
func TestM5B_StaleIntentAbortsSafely(t *testing.T) {
	plDraftHarness(t)
	recID := plSeedRecommendation(t)
	setRequireCommit(true)

	eng := policyLearnEngine.Load()
	if _, err := eng.BeginAccept(recID, newRuleID()); err != nil {
		t.Fatal(err)
	}
	// Fences go stale: the running policy content changes; no rule was created.
	addedProbe := policyStore.Add(PolicyRule{Priority: 99882, Name: "m5b-stale-probe-2", DestFQDN: "probe2.invalid", Action: ActionBlockPage})
	t.Cleanup(func() { policyStore.Delete(addedProbe.Priority) })

	res := plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body, "stale") {
		t.Fatalf("stale intent: %d %s", res.Code, res.Body)
	}
	rec, _ := policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State != policylearn.RecStateGenerated || rec.TargetRuleID != "" {
		t.Fatalf("stale intent not safely aborted: %+v", rec)
	}
	assertStrongestInvariant(t, recID)
}

// TestM5B_AcceptVersusDraftEditAndSupersession: concurrent draft edits move
// the fence (409, no silent retry); superseded recommendations refuse.
func TestM5B_AcceptVersusDraftEditAndSupersession(t *testing.T) {
	plDraftHarness(t)
	recID := plSeedRecommendation(t)
	setRequireCommit(true)

	fence := plRecsGET(t).PolicyVersion
	// Another admin edits the draft between fence read and accept.
	other := PolicyRule{Priority: 99883, Name: "m5b-other-admin", DestFQDN: "other.invalid", Action: ActionAllow}
	policyWriteStore("other-admin").Add(other)
	if res := plAcceptPost(t, RoleAdmin, recID, fence); res.Code != http.StatusConflict {
		t.Fatalf("accept across draft edit: %d %s", res.Code, res.Body)
	}
	assertStrongestInvariant(t, recID)

	// Supersession: a policy-thresholds change (engine rebuild) changes the
	// recommendation content on regeneration; the OLD object refuses accept.
	// (Simulated at the engine level: mark superseded directly is not exposed —
	// regenerate after a guardrail-neutral policy change is covered by the
	// stale tests, so here we drive supersession via the engine merge by
	// changing evidence-affecting state: reject-then-accept covers decided
	// states; superseded is exercised in the package suite. Accept on an
	// unknown ID is the remaining explicit case.)
	if res := plAcceptPost(t, RoleAdmin, "unknown-rec", plRecsGET(t).PolicyVersion); res.Code != http.StatusNotFound {
		t.Fatalf("accept unknown: %d", res.Code)
	}
}

// TestM5B_ConcurrentDoubleAccept: serialized by the lifecycle mutex; both
// callers converge on ONE rule, deterministically.
func TestM5B_ConcurrentDoubleAccept(t *testing.T) {
	plDraftHarness(t)
	recID := plSeedRecommendation(t)
	setRequireCommit(true)
	fence := plRecsGET(t).PolicyVersion

	results := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func() { results <- plAcceptPost(t, RoleAdmin, recID, fence).Code }()
	}
	a, b := <-results, <-results
	// First in wins; the loser sees idempotent success (state=accepted short-
	// circuits before the fence) — both deterministic, never a duplicate.
	if a != 200 || b != 200 {
		t.Fatalf("double accept: %d/%d", a, b)
	}
	rec, _ := policyLearnEngine.Load().RecommendationByID(recID)
	if cand, _ := plCountTargetRules(rec.TargetRuleID); cand != 1 {
		t.Fatalf("double accept duplicated: %d rules", cand)
	}
	assertStrongestInvariant(t, recID)
}

// ── §5 policy content vs generation precedence (root regression) ─────────────

func TestM5B_GenerationOnlyChangeIsNotStale(t *testing.T) {
	plDraftHarness(t)
	recID := plSeedRecommendation(t)

	if got := plRecsGET(t).Recommendations[0].StaleReasons; len(got) != 0 {
		t.Fatalf("fresh recommendation stale: %v", got)
	}
	// Generation-only change: add then delete a probe rule — the enforced
	// content returns to the original bytes while the generation counter
	// advances twice.
	probe := policyStore.Add(PolicyRule{Priority: 99884, Name: "m5b-gen-probe", DestFQDN: "gen.invalid", Action: ActionBlockPage})
	policyStore.Delete(probe.Priority)
	got := plRecsGET(t).Recommendations[0].StaleReasons
	for _, r := range got {
		if r == "policy_content_changed" || r == "policy_generation_changed" {
			t.Fatalf("generation-only change reported stale (content-pinned recommendation): %v", got)
		}
	}
	// An actual content change IS stale.
	probe2 := policyStore.Add(PolicyRule{Priority: 99885, Name: "m5b-content-probe", DestFQDN: "content.invalid", Action: ActionBlockPage})
	t.Cleanup(func() { policyStore.Delete(probe2.Priority) })
	got = plRecsGET(t).Recommendations[0].StaleReasons
	if !strings.Contains(strings.Join(got, " "), "policy_content_changed") {
		t.Fatalf("content change not stale: %v", got)
	}
	_ = recID
}

// ── audit ────────────────────────────────────────────────────────────────────

func TestM5B_DecisionAudit(t *testing.T) {
	plDraftHarness(t)
	recID := plSeedRecommendation(t)

	// Refused accept (no draft mode) audits the refusal.
	plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	setRequireCommit(true)
	res := plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code != 200 {
		t.Fatalf("accept: %d %s", res.Code, res.Body)
	}
	rec, _ := policyLearnEngine.Load().RecommendationByID(recID)

	var acceptOK, refusedOK bool
	for _, e := range auditGet() {
		if !strings.Contains(e.Actor, "198.51.100.77") {
			continue
		}
		switch e.Action {
		case "policy_learning.accept":
			if e.Object == recID && strings.Contains(e.Detail, rec.TargetRuleID) &&
				strings.Contains(e.Detail, "m5b-team") && strings.Contains(e.Detail, "m5b-cat") &&
				strings.Contains(e.Detail, "session=") {
				acceptOK = true
			}
			if strings.Contains(e.Detail, "m5b-user") {
				t.Fatalf("accept audit leaks subject data: %q", e.Detail)
			}
		case "policy_learning.accept.refused":
			refusedOK = true
		}
	}
	if !acceptOK || !refusedOK {
		t.Fatalf("audit trail incomplete: accept=%t refused=%t", acceptOK, refusedOK)
	}
}

// ── GUI source pins ──────────────────────────────────────────────────────────

func TestM5B_GUIDecisionWording(t *testing.T) {
	// The decision UX lives in the JS renderer — pin the whole document
	// (pkgSourceDir-anchored per the static-read wall).
	raw, err := os.ReadFile(filepath.Join(pkgSourceDir(), "static", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	full := string(raw)
	for _, required := range []string{
		"Accept to Draft",
		"Creates a disabled rule in Policy Draft. It does not change enforcement.",
		"Accept requires Draft Mode",
		"acceptance in progress (unresolved)",
		"plReject",
	} {
		if !strings.Contains(full, required) {
			t.Errorf("GUI missing required decision wording/control %q", required)
		}
	}
	for _, forbidden := range []string{"Accept + Enable", "Accept + Commit", "Accept and Enable", "Enable Rule"} {
		if strings.Contains(full, forbidden) {
			t.Errorf("GUI offers forbidden combined action %q", forbidden)
		}
	}
}

// TestM5B_AcceptVersusGuardrailChange: an admin guardrail change after
// generation makes the recommendation stale (guardrails_changed) — accept
// refuses 409 and creates nothing.
func TestM5B_AcceptVersusGuardrailChange(t *testing.T) {
	plDraftHarness(t)
	recID := plSeedRecommendation(t)
	setRequireCommit(true)
	if w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin,
		`{"recommendable_categories":["m5b-cat","AI"]}`); w.Code != 200 {
		t.Fatalf("guardrail change: %d %s", w.Code, w.Body.String())
	}
	stale := plRecsGET(t).Recommendations[0].StaleReasons
	if !strings.Contains(strings.Join(stale, " "), "guardrails_changed") {
		t.Fatalf("guardrail change not stale: %v", stale)
	}
	res := plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body, "stale") {
		t.Fatalf("accept of guardrail-stale recommendation: %d %s", res.Code, res.Body)
	}
	assertStrongestInvariant(t, recID)
}
