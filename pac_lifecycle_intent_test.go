package main

// pac_lifecycle_intent_test.go — 2F-B PAC trustable-publish matrix (R1–R10,
// R27–R29 of the approved 2F contract, docs/design/FRONTEND-MIGRATION-PLAN.md
// C1/C2/C8), plus the persistence-boundary and legacy-authorization proofs.
//
// RED-before evidence: every test was committed against the frozen 2F-A
// baseline (a632c69f) BEFORE the implementation and fails there, because the
// baseline (a) swaps store memory before the durable write, (b) reports a
// finalization failure after a proven active commit as a 500 "published
// but…", (c) has no operation intent, so a crash between the active write
// and history finalization loses the revision and a foreign active state is
// silently accepted, (d) has no operationId and re-commits a repeated
// operation, (e) authorizes DIRECT by the predictable profile id alone, so a
// changed draft/pool/active between challenge and retry still publishes and
// a publish challenge is accepted by a rollback, and (f) exposes no lifecycle
// state, so nothing distinguishes a committed profile whose pool later
// changed from an ambiguous one.
//
// Crash and fault injection are deterministic: the pacLifecycleStage /
// pacLifecyclePersist seams and on-disk snapshots, never sleeps.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/google/uuid"
)

const pacIntentIP = "198.51.100.91"

func pacIntentEnv(t *testing.T) {
	t.Helper()
	pacFenceEnv(t)
	sh, ph := pacLifecycleStageHook, pacLifecyclePersistHook
	t.Cleanup(func() { pacLifecycleStageHook, pacLifecyclePersistHook = sh, ph })
	pacLifecycleStageHook, pacLifecyclePersistHook = nil, nil
}

func pacIntentDraft(name string, direct bool) string {
	rules := `[]`
	if direct {
		rules = `[{"kind":"domain","pattern":"x.example","action":"direct"}]`
	}
	return fmt.Sprintf(`{"id":"branch-il","name":%q,"enabled":true,"poolId":"il","privateNetworks":"proxy","availabilityMode":"balanced","rules":%s}`, name, rules)
}

// pacIntentPublish posts a publish for branch-il; extra is appended inside the
// body object (e.g. `,"confirm":{…}`).
func pacIntentPublish(t *testing.T, opID string, expectedRev int64, draft, extra string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"action":"publish","operationId":%q,"expectedActiveRevision":%d,"draft":%s%s}`, opID, expectedRev, draft, extra)
	return pacFenceReq(t, "POST", "/api/pac/profiles/branch-il/lifecycle", body, pacIntentIP)
}

func pacIntentGet(t *testing.T) map[string]any {
	t.Helper()
	rec := pacFenceReq(t, "GET", "/api/pac/profiles/branch-il/lifecycle", "", pacIntentIP)
	if rec.Code != 200 {
		t.Fatalf("lifecycle GET: %d %s", rec.Code, rec.Body.String())
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func pacIntentJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not JSON: %q", rec.Body.String())
	}
	return m
}

// pacIntentChallenge asserts a structured confirm_required challenge and
// returns the `,"confirm":{…}` fragment that echoes it with the typed value.
func pacIntentChallenge(t *testing.T, rec *httptest.ResponseRecorder, wantAction string, wantTargetN int64) (confirm string, challenge map[string]any) {
	t.Helper()
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 challenge, got %d %s", rec.Code, rec.Body.String())
	}
	m := pacIntentJSON(t, rec)
	if m["code"] != "confirm_required" || m["confirmField"] != "confirm" {
		t.Fatalf("want code confirm_required/confirmField confirm, got %s", rec.Body.String())
	}
	ch, _ := m["challenge"].(string)
	val, _ := m["confirmValue"].(string)
	b, _ := m["binding"].(map[string]any)
	if !strings.HasPrefix(ch, "v1:") || !strings.HasPrefix(val, "branch-il:") || len(val) <= len("branch-il:") || b == nil {
		t.Fatalf("challenge must carry an opaque v1 token, a server-selected confirmValue and the binding: %s", rec.Body.String())
	}
	for _, k := range []string{"profileId", "action", "candidateSpecDigest", "expectedActiveRevision", "expectedActiveSpecDigest", "poolDigest", "artifactDigest", "newDirectPaths"} {
		if _, ok := b[k]; !ok {
			t.Fatalf("binding lacks %q: %v", k, b)
		}
	}
	if b["action"] != wantAction {
		t.Fatalf("binding.action = %v, want %s", b["action"], wantAction)
	}
	if tn, _ := b["targetN"].(float64); int64(tn) != wantTargetN {
		t.Fatalf("binding.targetN = %v, want %d", b["targetN"], wantTargetN)
	}
	bj, _ := json.Marshal(b)
	return fmt.Sprintf(`,"confirm":{"challenge":%q,"value":%q,"binding":%s}`, ch, val, bj), m
}

func pacIntentStale(t *testing.T, rec *httptest.ResponseRecorder, wantChanged ...string) {
	t.Helper()
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 challenge_stale, got %d %s", rec.Code, rec.Body.String())
	}
	m := pacIntentJSON(t, rec)
	if m["code"] != "challenge_stale" {
		t.Fatalf("want code challenge_stale, got %s", rec.Body.String())
	}
	changed, _ := m["changed"].([]any)
	for _, w := range wantChanged {
		found := false
		for _, c := range changed {
			if c == w {
				found = true
			}
		}
		if !found {
			t.Fatalf("challenge_stale must name %q among changed fields, got %v", w, changed)
		}
	}
	if _, ok := m["challenge"].(string); !ok {
		t.Fatalf("challenge_stale must carry a fresh challenge: %s", rec.Body.String())
	}
}

func pacIntentRevisions(t *testing.T) int {
	t.Helper()
	revs, _ := pacIntentGet(t)["revisions"].([]any)
	return len(revs)
}

func pacIntentActiveName(t *testing.T) string {
	t.Helper()
	p, ok := pacProfiles.ProfileByID("branch-il")
	if !ok {
		t.Fatal("branch-il vanished")
	}
	return p.Name
}

func pacIntentSnapshotFiles(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, p := range []string{pacFencePaths.profiles, pacFencePaths.lifecycle} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("snapshot %s: %v", p, err)
		}
		out[p] = b
	}
	return out
}

func pacIntentRestoreFiles(t *testing.T, snap map[string][]byte) {
	t.Helper()
	for p, b := range snap {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// pacIntentRestart reloads every PAC store from disk through the production
// startup loader (the same path a process restart takes).
func pacIntentRestart(t *testing.T) {
	t.Helper()
	pacProfiles.Restore(pac.ProfileState{})
	pacLifecycle.Restore(pac.LifecycleState{})
	if err := loadPAC(pacStartupConfig{
		ConfigPath: pacFencePaths.legacy, ProfilesPath: pacFencePaths.profiles,
		LifecyclePath: pacFencePaths.lifecycle, ExceptionsPath: pacFencePaths.exceptions, DefaultProxyPort: 8080,
	}); err != nil {
		t.Fatalf("restart load: %v", err)
	}
}

// ── R1: persist-before-swap ──

func TestPACIntent_R1_StoreWriteFailureLeavesMemoryUnchanged(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "missing-subdir")
	seed := pac.ProfilesConfig{
		Profiles: []pac.Profile{{ID: "a", Name: "A", Enabled: true, PoolID: "p", PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeSecure, Revision: 1}},
		Pools:    []pac.Pool{{ID: "p", Name: "P", Endpoints: []pac.PoolEndpoint{{Host: "x.example", Port: 8080}}}},
	}
	var ps pac.ProfileStore
	ps.Restore(pac.ProfileState{Cfg: seed, Path: filepath.Join(bad, "pac_profiles.json")})
	cand := seed
	cand.Profiles = []pac.Profile{{ID: "a", Name: "CANDIDATE", Enabled: true, PoolID: "p", PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeSecure, Revision: 2}}
	if err := ps.Set(cand); err == nil {
		t.Fatal("Set must fail on an unwritable path")
	}
	if got := ps.Get(); !reflect.DeepEqual(got, seed) {
		t.Fatalf("a failed durable write must leave memory unchanged; got %+v", got.Profiles[0])
	}
	var ls pac.LifecycleStore
	ls.Restore(pac.LifecycleState{ByID: map[string]*pac.ProfileLifecycle{}, Path: filepath.Join(bad, "lc.json")})
	if err := ls.Put(&pac.ProfileLifecycle{ProfileID: "a", ActiveN: 7}); err == nil {
		t.Fatal("Put must fail on an unwritable path")
	}
	if _, ok := ls.Get("a"); ok {
		t.Fatal("a failed lifecycle write must leave memory unchanged")
	}
}

// ── R2: finalization failure after a proven commit ──

func TestPACIntent_R2_FinalizeFailureIsPublishedPendingReconciliation(t *testing.T) {
	pacIntentEnv(t)
	pacLifecyclePersistHook = func(stage string) error {
		if stage == "finalize" {
			return fmt.Errorf("injected finalize failure")
		}
		return nil
	}
	op := uuid.NewString()
	rec := pacIntentPublish(t, op, 1, pacIntentDraft("Committed", false), "")
	if rec.Code != 200 {
		t.Fatalf("a proven active commit must never be reported as a failure: %d %s", rec.Code, rec.Body.String())
	}
	m := pacIntentJSON(t, rec)
	if m["published"] != true || m["historyState"] != "pending_reconciliation" || m["operationId"] != op {
		t.Fatalf("want published:true historyState:pending_reconciliation operationId echoed, got %s", rec.Body.String())
	}
	if pacIntentActiveName(t) != "Committed" {
		t.Fatal("active store must carry the committed spec")
	}
	// Reconciliation on the next lifecycle read finalizes history idempotently.
	pacLifecyclePersistHook = nil
	g := pacIntentGet(t)
	if g["state"] != "idle" || g["activeN"] != float64(1) || len(g["revisions"].([]any)) != 1 {
		t.Fatalf("GET must reconcile the pending op into exactly one recorded revision: state=%v activeN=%v", g["state"], g["activeN"])
	}
}

// ── R3 / R28: crash after the active write, before finalization ──

func pacIntentCrashAfterActiveCommit(t *testing.T) map[string][]byte {
	t.Helper()
	var snap map[string][]byte
	pacLifecycleStageHook = func(stage string) {
		if stage == "active_committed" {
			snap = pacIntentSnapshotFiles(t)
		}
	}
	if rec := pacIntentPublish(t, uuid.NewString(), 1, pacIntentDraft("Crashed", false), ""); rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	pacLifecycleStageHook = nil
	if snap == nil {
		t.Fatal("active_committed stage never observed")
	}
	return snap
}

func TestPACIntent_R3_CrashAfterActiveCommit_RestartRecordsHistory(t *testing.T) {
	pacIntentEnv(t)
	snap := pacIntentCrashAfterActiveCommit(t)
	pacIntentRestoreFiles(t, snap) // the on-disk state at the crash instant
	pacIntentRestart(t)
	g := pacIntentGet(t)
	if g["state"] != "idle" || g["activeN"] != float64(1) || len(g["revisions"].([]any)) != 1 {
		t.Fatalf("startup reconciliation must finalize the committed op: state=%v activeN=%v revisions=%v", g["state"], g["activeN"], g["revisions"])
	}
	if pacIntentActiveName(t) != "Crashed" {
		t.Fatal("active store must be the committed candidate after restart")
	}
}

func TestPACIntent_R28_ReconciliationIgnoresFileModTime(t *testing.T) {
	for _, order := range []string{"profiles-older", "lifecycle-older"} {
		t.Run(order, func(t *testing.T) {
			pacIntentEnv(t)
			snap := pacIntentCrashAfterActiveCommit(t)
			pacIntentRestoreFiles(t, snap)
			old := time.Now().Add(-2 * time.Hour)
			target := pacFencePaths.profiles
			if order == "lifecycle-older" {
				target = pacFencePaths.lifecycle
			}
			if err := os.Chtimes(target, old, old); err != nil {
				t.Fatal(err)
			}
			pacIntentRestart(t)
			if g := pacIntentGet(t); g["state"] != "idle" || g["activeN"] != float64(1) {
				t.Fatalf("outcome must be decided by revision+spec digest, never by mtime: state=%v activeN=%v", g["state"], g["activeN"])
			}
		})
	}
}

// ── R4: a foreign active state is ambiguous and refuses until repaired ──

func TestPACIntent_R4_ForeignActiveStateIsAmbiguousUntilRepair(t *testing.T) {
	pacIntentEnv(t)
	var snap map[string][]byte
	pacLifecycleStageHook = func(stage string) {
		if stage == "intent_persisted" {
			snap = pacIntentSnapshotFiles(t)
		}
	}
	if rec := pacIntentPublish(t, uuid.NewString(), 1, pacIntentDraft("Mine", false), ""); rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	pacLifecycleStageHook = nil
	if snap == nil {
		t.Fatal("intent_persisted stage never observed")
	}
	// The on-disk state at the crash instant (intent pending, active at
	// revision 1) plus a FOREIGN writer that installed a different spec at
	// revision 2 before this node came back.
	pacIntentRestoreFiles(t, snap)
	var foreign pac.ProfileStore
	foreign.Restore(pac.ProfileState{Path: pacFencePaths.profiles})
	if err := foreign.Load(pacFencePaths.profiles); err != nil {
		t.Fatal(err)
	}
	cfg := foreign.Get()
	for i := range cfg.Profiles {
		if cfg.Profiles[i].ID == "branch-il" {
			cfg.Profiles[i].Name, cfg.Profiles[i].Revision = "Foreign", 2
			cfg.Profiles[i].PrivateNetworks, cfg.Profiles[i].AvailabilityMode, cfg.Profiles[i].Rules = pac.PrivateProxy, pac.ModeSecure, nil
		}
	}
	if err := foreign.Set(cfg); err != nil {
		t.Fatal(err)
	}
	pacIntentRestart(t)
	g := pacIntentGet(t)
	if g["state"] != "ambiguous" || g["ambiguous"] == nil {
		t.Fatalf("neither-expected-nor-candidate active state must be ambiguous: %v", g["state"])
	}
	rec := pacIntentPublish(t, uuid.NewString(), 2, pacIntentDraft("Again", false), "")
	if rec.Code != http.StatusServiceUnavailable || pacIntentJSON(t, rec)["code"] != "lifecycle_ambiguous" {
		t.Fatalf("publish on an ambiguous lifecycle must be refused 503 lifecycle_ambiguous: %d %s", rec.Code, rec.Body.String())
	}
	if pacIntentActiveName(t) != "Foreign" {
		t.Fatal("refusal must not touch the active store")
	}
	rep := uuid.NewString()
	rec = pacFenceReq(t, "POST", "/api/pac/profiles/branch-il/lifecycle",
		fmt.Sprintf(`{"action":"repair","operationId":%q,"resolution":"accept_active"}`, rep), pacIntentIP)
	if rec.Code != 200 || pacIntentJSON(t, rec)["repaired"] != true {
		t.Fatalf("repair accept_active: %d %s", rec.Code, rec.Body.String())
	}
	g = pacIntentGet(t)
	revs := g["revisions"].([]any)
	last := revs[len(revs)-1].(map[string]any)
	if g["state"] != "idle" || last["repaired"] != true || last["spec"].(map[string]any)["name"] != "Foreign" {
		t.Fatalf("repair must record the OBSERVED active spec as a repaired revision and clear ambiguity: state=%v last=%v", g["state"], last)
	}
	if p, _ := pacProfiles.ProfileByID("branch-il"); p.Name != "Foreign" || p.Revision != 2 {
		t.Fatal("repair must never rewrite the active store")
	}
	if rec := pacIntentPublish(t, uuid.NewString(), 2, pacIntentDraft("After", false), ""); rec.Code != 200 {
		t.Fatalf("publish after repair: %d %s", rec.Code, rec.Body.String())
	}
}

// ── R5 / R9: at-most-once decisions ──

func TestPACIntent_R5_RepeatedOperationIDReturnsTheRecordedResult(t *testing.T) {
	pacIntentEnv(t)
	op := uuid.NewString()
	first := pacIntentPublish(t, op, 1, pacIntentDraft("One", false), "")
	if first.Code != 200 {
		t.Fatalf("publish: %d %s", first.Code, first.Body.String())
	}
	again := pacIntentPublish(t, op, 1, pacIntentDraft("Two", false), "")
	if again.Code != 200 || !reflect.DeepEqual(pacIntentJSON(t, first), pacIntentJSON(t, again)) {
		t.Fatalf("a repeated decided operationId must return the recorded result, got %d %s vs %s", again.Code, again.Body.String(), first.Body.String())
	}
	if pacIntentRevisions(t) != 1 || pacIntentActiveName(t) != "One" {
		t.Fatal("a repeated operationId must not commit twice")
	}
	if rec := pacIntentPublish(t, "not-a-uuid", 2, pacIntentDraft("Bad", false), ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("operationId must be a UUID: %d", rec.Code)
	}
	if rec := pacFenceReq(t, "POST", "/api/pac/profiles/branch-il/lifecycle", `{"action":"publish","expectedActiveRevision":2,"draft":`+pacIntentDraft("NoOp", false)+`}`, pacIntentIP); rec.Code != http.StatusBadRequest {
		t.Fatalf("operationId is required: %d", rec.Code)
	}
}

func TestPACIntent_R9_CommittedChallengeIsSingleUse(t *testing.T) {
	pacIntentEnv(t)
	op := uuid.NewString()
	confirm, _ := pacIntentChallenge(t, pacIntentPublish(t, op, 1, pacIntentDraft("Direct", true), ""), "publish", 0)
	first := pacIntentPublish(t, op, 1, pacIntentDraft("Direct", true), confirm)
	if first.Code != 200 {
		t.Fatalf("confirmed publish: %d %s", first.Code, first.Body.String())
	}
	replay := pacIntentPublish(t, op, 1, pacIntentDraft("Direct", true), confirm)
	if replay.Code != 200 || !reflect.DeepEqual(pacIntentJSON(t, first), pacIntentJSON(t, replay)) {
		t.Fatalf("replaying the committed operation must return the recorded result: %d %s", replay.Code, replay.Body.String())
	}
	if pacIntentRevisions(t) != 1 {
		t.Fatalf("exactly one revision after the replay, got %d", pacIntentRevisions(t))
	}
	// Withdraw the DIRECT path (a plain publish needs no confirmation), then
	// try to re-introduce it with a NEW operation that echoes the CONSUMED
	// challenge: the challenge is single-use, so it must be refused even
	// though the reviewed candidate is byte-identical.
	if rec := pacIntentPublish(t, uuid.NewString(), 2, pacIntentDraft("Plain", false), ""); rec.Code != 200 {
		t.Fatalf("plain publish: %d %s", rec.Code, rec.Body.String())
	}
	fresh := pacIntentPublish(t, uuid.NewString(), 3, pacIntentDraft("Direct", true), confirm)
	if fresh.Code == 200 {
		t.Fatal("a committed challenge must not authorize a second commit")
	}
	pacIntentStale(t, fresh)
	if pacIntentRevisions(t) != 2 {
		t.Fatalf("exactly two revisions, got %d", pacIntentRevisions(t))
	}
}

// ── R6 / R7 / R8 / R29: candidate-bound confirmation ──

func TestPACIntent_R6_DraftChangeBetweenChallengeAndRetryIsStale(t *testing.T) {
	pacIntentEnv(t)
	op := uuid.NewString()
	confirm, _ := pacIntentChallenge(t, pacIntentPublish(t, op, 1, pacIntentDraft("Direct", true), ""), "publish", 0)
	changed := strings.Replace(pacIntentDraft("Direct", true), "x.example", "y.example", 1)
	pacIntentStale(t, pacIntentPublish(t, op, 1, changed, confirm), "candidateSpecDigest")
	if pacIntentRevisions(t) != 0 || pacIntentActiveName(t) != "Branch IL" {
		t.Fatal("stale challenge must not publish")
	}
}

func TestPACIntent_R7_R29_PoolChangeBetweenChallengeAndRetryIsStaleNamingPoolDigest(t *testing.T) {
	pacIntentEnv(t)
	op := uuid.NewString()
	confirm, _ := pacIntentChallenge(t, pacIntentPublish(t, op, 1, pacIntentDraft("Direct", true), ""), "publish", 0)
	tk := pacFenceReadTokens(t)
	if rec := pacFenceReq(t, "PUT", "/api/pac/pools/il", `{"id":"il","name":"IL","endpoints":[{"host":"proxy-il2.example","port":8080}],"etag":"`+tk.poolEtags["il"]+`"}`, pacFenceWinnerIP); rec.Code != 200 {
		t.Fatalf("pool change: %d %s", rec.Code, rec.Body.String())
	}
	rec := pacIntentPublish(t, op, 1, pacIntentDraft("Direct", true), confirm)
	pacIntentStale(t, rec, "poolDigest")
	for _, c := range pacIntentJSON(t, rec)["changed"].([]any) {
		if c == "candidateSpecDigest" {
			t.Fatal("an unchanged profile spec must not be reported as changed")
		}
	}
	if pacIntentRevisions(t) != 0 {
		t.Fatal("stale challenge must not publish")
	}
}

func TestPACIntent_R8_ActiveChangeBetweenChallengeAndRetryIsStale(t *testing.T) {
	pacIntentEnv(t)
	op := uuid.NewString()
	confirm, _ := pacIntentChallenge(t, pacIntentPublish(t, op, 1, pacIntentDraft("Direct", true), ""), "publish", 0)
	// Another admin edits the active profile (revision 1 → 2).
	if rec := pacFenceReq(t, "PUT", "/api/pac/profiles/branch-il", pacFenceProfileJSON(`,"revision":1`), pacFenceWinnerIP); rec.Code != 200 {
		t.Fatalf("peer PUT: %d %s", rec.Code, rec.Body.String())
	}
	// The caller refreshes its fence token but echoes the OLD challenge.
	pacIntentStale(t, pacIntentPublish(t, op, 2, pacIntentDraft("Direct", true), confirm), "expectedActiveRevision")
	if pacIntentRevisions(t) != 0 || pacIntentActiveName(t) != "Renamed IL" {
		t.Fatal("stale challenge must not publish")
	}
}

// ── R10: rollback challenges bind action and target ──

func TestPACIntent_R10_RollbackChallengeBindsActionAndTarget(t *testing.T) {
	pacIntentEnv(t)
	op1 := uuid.NewString()
	c1, _ := pacIntentChallenge(t, pacIntentPublish(t, op1, 1, pacIntentDraft("Direct", true), ""), "publish", 0)
	if rec := pacIntentPublish(t, op1, 1, pacIntentDraft("Direct", true), c1); rec.Code != 200 {
		t.Fatalf("publish v1: %d %s", rec.Code, rec.Body.String())
	}
	if rec := pacIntentPublish(t, uuid.NewString(), 2, pacIntentDraft("Plain", false), ""); rec.Code != 200 {
		t.Fatalf("publish v2: %d %s", rec.Code, rec.Body.String())
	}
	// A PUBLISH challenge for the same DIRECT spec (not committed).
	pubConfirm, _ := pacIntentChallenge(t, pacIntentPublish(t, uuid.NewString(), 3, pacIntentDraft("Direct", true), ""), "publish", 0)
	rb := func(op, extra string) *httptest.ResponseRecorder {
		return pacFenceReq(t, "POST", "/api/pac/profiles/branch-il/lifecycle",
			fmt.Sprintf(`{"action":"rollback","operationId":%q,"targetN":1,"expectedActiveRevision":3%s}`, op, extra), pacIntentIP)
	}
	op := uuid.NewString()
	rbConfirm, _ := pacIntentChallenge(t, rb(op, ""), "rollback", 1)
	if rec := rb(op, pubConfirm); rec.Code == 200 {
		t.Fatal("a publish challenge must never authorize a rollback")
	}
	if pacIntentRevisions(t) != 2 {
		t.Fatal("mis-bound challenge must not roll back")
	}
	if rec := rb(op, rbConfirm); rec.Code != 200 || pacIntentJSON(t, rec)["rolledBack"] != true {
		t.Fatalf("correctly bound rollback: %d %s", rec.Code, rec.Body.String())
	}
	if pacIntentRevisions(t) != 3 {
		t.Fatalf("rollback must append exactly one revision, got %d", pacIntentRevisions(t))
	}
}

// ── R27: a later pool change never ambiguates a committed operation ──

func TestPACIntent_R27_PoolChangeAfterCommitStaysCommitted(t *testing.T) {
	pacIntentEnv(t)
	if rec := pacIntentPublish(t, uuid.NewString(), 1, pacIntentDraft("Committed", false), ""); rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	if g := pacIntentGet(t); g["poolChangedSince"] != false {
		t.Fatalf("poolChangedSince must be false right after publish: %v", g["poolChangedSince"])
	}
	tk := pacFenceReadTokens(t)
	if rec := pacFenceReq(t, "PUT", "/api/pac/pools/il", `{"id":"il","name":"IL","endpoints":[{"host":"proxy-il2.example","port":8080}],"etag":"`+tk.poolEtags["il"]+`"}`, pacFenceWinnerIP); rec.Code != 200 {
		t.Fatalf("pool change: %d %s", rec.Code, rec.Body.String())
	}
	g := pacIntentGet(t)
	if g["state"] != "idle" || g["poolChangedSince"] != true || g["activeN"] != float64(1) {
		t.Fatalf("a pool change after commit must stay committed and be surfaced separately: state=%v poolChangedSince=%v", g["state"], g["poolChangedSince"])
	}
	if rec := pacIntentPublish(t, uuid.NewString(), 2, pacIntentDraft("Next", false), ""); rec.Code != 200 {
		t.Fatalf("publish after pool change: %d %s", rec.Code, rec.Body.String())
	}
}

// ── Persistence boundaries: intent persist failure and proven active failure ──

func TestPACIntent_IntentPersistFailure_ChangesNothing(t *testing.T) {
	pacIntentEnv(t)
	pacLifecyclePersistHook = func(stage string) error {
		if stage == "intent" {
			return fmt.Errorf("injected intent failure")
		}
		return nil
	}
	before, since := pacFenceCapture(t), time.Now().UnixMilli()
	rec := pacIntentPublish(t, uuid.NewString(), 1, pacIntentDraft("Never", false), "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("intent persistence failure must be a 500 with nothing changed: %d %s", rec.Code, rec.Body.String())
	}
	pacFenceAssertUnchanged(t, before, since, "pac.profile_publish")
}

func TestPACIntent_ActiveWriteFailure_IsProvenFailureAndAborted(t *testing.T) {
	pacIntentEnv(t)
	pacProfiles.Restore(pac.ProfileState{Cfg: pacProfiles.Get(), Path: filepath.Join(t.TempDir(), "missing", "pac_profiles.json")})
	op := uuid.NewString()
	rec := pacIntentPublish(t, op, 1, pacIntentDraft("Never", false), "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a failed active write is a proven failure: %d %s", rec.Code, rec.Body.String())
	}
	if pacIntentActiveName(t) != "Branch IL" {
		t.Fatal("memory must not carry the candidate after a failed durable write")
	}
	g := pacIntentGet(t)
	if g["state"] != "idle" || g["pendingOp"] != nil {
		t.Fatalf("proven failure must abort the intent: state=%v pendingOp=%v", g["state"], g["pendingOp"])
	}
	aborted := false
	for _, o := range g["operations"].([]any) {
		om := o.(map[string]any)
		if om["operationId"] == op && om["state"] == "aborted" {
			aborted = true
		}
	}
	if !aborted {
		t.Fatalf("the aborted operation must be recorded: %v", g["operations"])
	}
}

// ── Legacy profile-id authorization is retired ──

func TestPACIntent_LegacyConfirmDirectNoLongerAuthorizes(t *testing.T) {
	pacIntentEnv(t)
	rec := pacIntentPublish(t, uuid.NewString(), 1, pacIntentDraft("Direct", true), `,"confirmDirect":"branch-il"`)
	if rec.Code == 200 {
		t.Fatal("the predictable profile id must not authorize a DIRECT publish")
	}
	if pacIntentRevisions(t) != 0 {
		t.Fatal("legacy confirmDirect must not publish")
	}
	// CRUD path: the same bound challenge, echoed in the body.
	tk := pacFenceReadTokens(t)
	create := `{"id":"byp","name":"Byp","enabled":true,"poolId":"il","privateNetworks":"proxy","availabilityMode":"balanced","rules":[{"kind":"domain","pattern":"z.example","action":"direct"}],"collectionEtag":"` + tk.collectionEtag + `"%s}`
	if rec := pacFenceReq(t, "POST", "/api/pac/profiles?confirmDirect=byp", fmt.Sprintf(create, ""), pacIntentIP); rec.Code == 200 {
		t.Fatal("legacy ?confirmDirect= must not authorize a DIRECT create")
	}
	rec = pacFenceReq(t, "POST", "/api/pac/profiles", fmt.Sprintf(create, ""), pacIntentIP)
	m := pacIntentJSON(t, rec)
	if rec.Code != http.StatusConflict || m["code"] != "confirm_required" || m["challenge"] == nil {
		t.Fatalf("CRUD DIRECT create must issue the bound challenge: %d %s", rec.Code, rec.Body.String())
	}
	bj, _ := json.Marshal(m["binding"])
	confirm := fmt.Sprintf(`,"confirm":{"challenge":%q,"value":%q,"binding":%s}`, m["challenge"], m["confirmValue"], bj)
	if rec := pacFenceReq(t, "POST", "/api/pac/profiles", fmt.Sprintf(create, confirm), pacIntentIP); rec.Code != 200 {
		t.Fatalf("confirmed CRUD create: %d %s", rec.Code, rec.Body.String())
	}
}
