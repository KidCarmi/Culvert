package main

// pac_lifecycle_correction_test.go — the 2F-B correction matrix (external
// review of candidate ae61ac78, docs/design/FRONTEND-MIGRATION-PLAN.md C1):
//
//   C-1  a corrupt lifecycle file is quarantined into a durable, visible
//        history_reset — never an ordinary idle lifecycle;
//   C-2  publish and rollback are refused until an admin acknowledges the
//        reset, and the acknowledgement is bound to the authoritative active
//        revision + ProfileSpecDigest;
//   C-3  an acknowledgement whose persistence fails stays fail-closed, across
//        a restart;
//   C-4  a crash after the authoritative active write completes, on restart,
//        exactly one success audit, one config version, one lifecycle
//        revision and the recorded result;
//   C-5  a crash after each individual post-commit boundary completes ONLY the
//        missing effects — nothing is duplicated;
//   C-6  reconciliation of an aborted or ambiguous operation produces zero
//        success audits and zero config versions (a committed control proves
//        the counters are live);
//   C-7  a replayed operationId after recovery returns the recorded response
//        and repeats no side effect;
//   C-8  the success audit pins the exact operationId and a truthful
//        historyState.
//
// RED-before evidence: every test fails at exactly ae61ac78, where (a) a
// corrupt lifecycle file is silently replaced by an empty store, (b)
// OpCommitted is a classification result only — the intent goes from durable
// pending straight to recorded, so a crash after the active write loses the
// success audit and the config version, which reconciliation never
// completes, and (c) the success audit carries neither operationId nor
// historyState. Crash and fault injection are deterministic (stage /
// persist seams + on-disk snapshots), never sleeps.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/google/uuid"
)

// pacIntentAudits counts audit entries of action that name operationId in
// their detail (a UUID is unique, so this is content-keyed, never a len()
// delta — see the CLAUDE.md audit-ring pitfall).
func pacIntentAudits(op, action string) int {
	n := 0
	ring := auditGet()
	for i := range ring {
		if ring[i].Action == action && strings.Contains(ring[i].Detail, "operationId="+op) {
			n++
		}
	}
	return n
}

// pacIntentVersionsFor counts config versions whose note names operationId.
func pacIntentVersionsFor(op string) int {
	n := 0
	for _, m := range configVersions.List() {
		if strings.Contains(m.Note, op) {
			n++
		}
	}
	return n
}

// pacIntentRestartComplete is a full process restart: the startup loader
// (settles intents against the authoritative active store) followed by the
// post-load reconciliation main.go runs once every store is loaded.
func pacIntentRestartComplete(t *testing.T) {
	t.Helper()
	pacIntentRestart(t)
	pacReconcileAllLifecycles()
}

func pacIntentCorruptLifecycle(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(pacFencePaths.lifecycle, []byte(`{"branch-il": {"profileId": "branch-il", "revisions": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	pacIntentRestartComplete(t)
}

func pacIntentAck(t *testing.T, op string, rev int64, digest string) *httptest.ResponseRecorder {
	t.Helper()
	return pacFenceReq(t, "POST", "/api/pac/profiles/branch-il/lifecycle",
		fmt.Sprintf(`{"action":"acknowledge_history_reset","operationId":%q,"expectedActiveRevision":%d,"expectedActiveSpecDigest":%q}`, op, rev, digest), pacIntentIP)
}

func pacIntentRollback(t *testing.T, op string, targetN, expectedRev int64) *httptest.ResponseRecorder {
	t.Helper()
	return pacFenceReq(t, "POST", "/api/pac/profiles/branch-il/lifecycle",
		fmt.Sprintf(`{"action":"rollback","operationId":%q,"targetN":%d,"expectedActiveRevision":%d}`, op, targetN, expectedRev), pacIntentIP)
}

func pacIntentAssertRecordedOnce(t *testing.T, op string, wantRevisions int) {
	t.Helper()
	if n := pacIntentAudits(op, "pac.profile_publish"); n != 1 {
		t.Fatalf("exactly one success audit for %s, got %d", op, n)
	}
	if n := pacIntentVersionsFor(op); n != 1 {
		t.Fatalf("exactly one config version for %s, got %d", op, n)
	}
	if n := pacIntentRevisions(t); n != wantRevisions {
		t.Fatalf("exactly %d lifecycle revision(s), got %d", wantRevisions, n)
	}
	g := pacIntentGet(t)
	if g["state"] != "idle" || g["historyState"] != "recorded" || g["pendingOp"] != nil {
		t.Fatalf("operation must be recorded: state=%v historyState=%v pendingOp=%v", g["state"], g["historyState"], g["pendingOp"])
	}
	found := false
	for _, o := range g["operations"].([]any) {
		om := o.(map[string]any)
		if om["operationId"] == op && om["state"] == "recorded" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the operation must be decided as recorded: %v", g["operations"])
	}
}

// ── C-1: corruption is a visible, durable history_reset ──

func TestPACCorrection_C1_CorruptLifecycleIsHistoryResetNotIdle(t *testing.T) {
	pacIntentEnv(t)
	if rec := pacIntentPublish(t, uuid.NewString(), 1, pacIntentDraft("Before", false), ""); rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	pacIntentCorruptLifecycle(t)
	g := pacIntentGet(t)
	if g["historyState"] != "history_reset" {
		t.Fatalf("a quarantined lifecycle file must be reported as history_reset, got historyState=%v (state=%v)", g["historyState"], g["state"])
	}
	hr, _ := g["historyReset"].(map[string]any)
	if hr == nil {
		t.Fatal("GET must carry the store-level historyReset record")
	}
	q, _ := hr["quarantinedTo"].(string)
	if q == "" {
		t.Fatalf("historyReset must name the quarantined file: %v", hr)
	}
	if _, err := os.Stat(q); err != nil {
		t.Fatalf("the corrupt file must be moved aside, never deleted: %v", err)
	}
	// The active store stays the sole authority and is untouched.
	if p, ok := pacProfiles.ProfileByID("branch-il"); !ok || p.Name != "Before" || p.Revision != 2 {
		t.Fatalf("active store must be untouched by a lifecycle reset: %+v", p)
	}
	if g["activeExists"] != true || g["activeRevision"] != float64(2) {
		t.Fatalf("GET must still report the authoritative active profile: %v %v", g["activeExists"], g["activeRevision"])
	}
	// The reset survives a further restart until acknowledged.
	pacIntentRestartComplete(t)
	if g := pacIntentGet(t); g["historyState"] != "history_reset" {
		t.Fatalf("history_reset must be durable across restarts: %v", g["historyState"])
	}
}

// ── C-2: publish/rollback refused until a bound acknowledgement ──

func TestPACCorrection_C2_MutationsRefusedUntilBoundAcknowledgement(t *testing.T) {
	pacIntentEnv(t)
	if rec := pacIntentPublish(t, uuid.NewString(), 1, pacIntentDraft("Before", false), ""); rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	pacIntentCorruptLifecycle(t)
	rec := pacIntentPublish(t, uuid.NewString(), 2, pacIntentDraft("Unacked", false), "")
	if rec.Code != http.StatusConflict || pacIntentJSON(t, rec)["code"] != "history_reset" {
		t.Fatalf("publish must be refused 409 history_reset until acknowledged: %d %s", rec.Code, rec.Body.String())
	}
	rec = pacIntentRollback(t, uuid.NewString(), 1, 2)
	if rec.Code != http.StatusConflict || pacIntentJSON(t, rec)["code"] != "history_reset" {
		t.Fatalf("rollback must be refused 409 history_reset until acknowledged: %d %s", rec.Code, rec.Body.String())
	}
	if pacIntentActiveName(t) != "Before" {
		t.Fatal("refusal must not touch the active store")
	}
	g := pacIntentGet(t)
	digest, _ := g["activeSpecDigest"].(string)
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("GET must expose the active ProfileSpecDigest: %v", g["activeSpecDigest"])
	}
	// A stale acknowledgement (wrong digest / wrong revision) authorizes nothing.
	rec = pacIntentAck(t, uuid.NewString(), 2, "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	if rec.Code != http.StatusConflict || pacIntentJSON(t, rec)["code"] != "history_reset_stale" {
		t.Fatalf("an acknowledgement for a different spec must be refused 409 history_reset_stale: %d %s", rec.Code, rec.Body.String())
	}
	rec = pacIntentAck(t, uuid.NewString(), 1, digest)
	if rec.Code == 200 {
		t.Fatal("an acknowledgement for a different active revision must be refused")
	}
	if g := pacIntentGet(t); g["historyState"] != "history_reset" {
		t.Fatalf("a refused acknowledgement must leave the reset in place: %v", g["historyState"])
	}
	// The correctly bound acknowledgement clears it; the active store is never rewritten.
	ack := uuid.NewString()
	rec = pacIntentAck(t, ack, 2, digest)
	if rec.Code != 200 || pacIntentJSON(t, rec)["acknowledged"] != true {
		t.Fatalf("bound acknowledgement: %d %s", rec.Code, rec.Body.String())
	}
	if p, _ := pacProfiles.ProfileByID("branch-il"); p.Name != "Before" || p.Revision != 2 {
		t.Fatal("acknowledgement must never rewrite the active store")
	}
	g = pacIntentGet(t)
	if g["historyState"] != "recorded" {
		t.Fatalf("after acknowledgement the lifecycle is ordinary again: %v", g["historyState"])
	}
	if pacIntentAudits(ack, "pac.profile_history_reset_ack") != 1 {
		t.Fatal("the acknowledgement must be audited once with its operationId")
	}
	// Replay of the acknowledgement is idempotent; publish now proceeds.
	if rec := pacIntentAck(t, ack, 2, digest); rec.Code != 200 {
		t.Fatalf("replayed acknowledgement: %d %s", rec.Code, rec.Body.String())
	}
	if rec := pacIntentPublish(t, uuid.NewString(), 2, pacIntentDraft("After", false), ""); rec.Code != 200 {
		t.Fatalf("publish after acknowledgement: %d %s", rec.Code, rec.Body.String())
	}
}

// ── C-3: acknowledgement persistence failure stays fail-closed ──

func TestPACCorrection_C3_AckPersistFailureStaysResetAcrossRestart(t *testing.T) {
	pacIntentEnv(t)
	if rec := pacIntentPublish(t, uuid.NewString(), 1, pacIntentDraft("Before", false), ""); rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	pacIntentCorruptLifecycle(t)
	digest, _ := pacIntentGet(t)["activeSpecDigest"].(string)
	pacLifecyclePersistHook = func(stage string) error {
		if stage == "ack" {
			return fmt.Errorf("injected ack persist failure")
		}
		return nil
	}
	rec := pacIntentAck(t, uuid.NewString(), 2, digest)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("an acknowledgement that could not be persisted must fail: %d %s", rec.Code, rec.Body.String())
	}
	if g := pacIntentGet(t); g["historyState"] != "history_reset" {
		t.Fatalf("a failed acknowledgement must leave history_reset active: %v", g["historyState"])
	}
	if rec := pacIntentPublish(t, uuid.NewString(), 2, pacIntentDraft("Still", false), ""); rec.Code != http.StatusConflict {
		t.Fatalf("publish must still be refused after a failed acknowledgement: %d %s", rec.Code, rec.Body.String())
	}
	pacIntentRestartComplete(t)
	if g := pacIntentGet(t); g["historyState"] != "history_reset" {
		t.Fatalf("the reset must survive a restart when the acknowledgement never became durable: %v", g["historyState"])
	}
	pacLifecyclePersistHook = nil
	if rec := pacIntentAck(t, uuid.NewString(), 2, digest); rec.Code != 200 {
		t.Fatalf("acknowledgement once persistence works: %d %s", rec.Code, rec.Body.String())
	}
	pacIntentRestartComplete(t)
	if g := pacIntentGet(t); g["historyState"] != "recorded" {
		t.Fatalf("a durable acknowledgement must survive a restart: %v", g["historyState"])
	}
}

// ── C-4: crash after the active write → restart completes every effect exactly once ──

func TestPACCorrection_C4_CrashAfterActiveWrite_RestartCompletesEffectsOnce(t *testing.T) {
	pacIntentEnv(t)
	op := uuid.NewString()
	var snap map[string][]byte
	pacLifecycleStageHook = func(stage string) {
		if stage == "active_committed" {
			snap = pacIntentSnapshotFiles(t)
			// Crash: nothing after the authoritative write ever lands.
			pacLifecyclePersistHook = func(string) error { return fmt.Errorf("crashed") }
		}
	}
	rec := pacIntentPublish(t, op, 1, pacIntentDraft("Crashed", false), "")
	pacLifecycleStageHook, pacLifecyclePersistHook = nil, nil
	if snap == nil {
		t.Fatal("active_committed stage never observed")
	}
	if rec.Code != 200 || pacIntentJSON(t, rec)["historyState"] != "pending_reconciliation" {
		t.Fatalf("a proven commit whose effects could not be persisted is published:true pending_reconciliation: %d %s", rec.Code, rec.Body.String())
	}
	if pacIntentAudits(op, "pac.profile_publish") != 0 || pacIntentVersionsFor(op) != 0 {
		t.Fatal("no post-commit effect may land before its committed progress is durable")
	}
	pacIntentRestoreFiles(t, snap)
	pacIntentRestartComplete(t)
	if pacIntentActiveName(t) != "Crashed" {
		t.Fatal("active store must be the committed candidate after restart")
	}
	pacIntentAssertRecordedOnce(t, op, 1)
	// Repeated reconciliation, GET and restart change nothing further.
	pacIntentGet(t)
	pacIntentRestartComplete(t)
	pacIntentAssertRecordedOnce(t, op, 1)
}

// ── C-5: crash after each post-commit boundary → only the missing effects ──

func TestPACCorrection_C5_CrashAfterEachPostCommitBoundary_CompletesOnlyMissingEffects(t *testing.T) {
	for _, boundary := range []string{"committed_persisted", "history_recorded", "version_recorded", "cluster_published", "finalized"} {
		t.Run(boundary, func(t *testing.T) {
			pacIntentEnv(t)
			op := uuid.NewString()
			observed := false
			pacLifecycleStageHook = func(stage string) {
				if stage == boundary {
					observed = true
					// Crash right after this durable boundary: every later
					// lifecycle write fails, so no later effect can land.
					pacLifecyclePersistHook = func(string) error { return fmt.Errorf("crashed after %s", boundary) }
				}
			}
			rec := pacIntentPublish(t, op, 1, pacIntentDraft("Boundary", false), "")
			pacLifecycleStageHook, pacLifecyclePersistHook = nil, nil
			if !observed {
				t.Fatalf("boundary %s never observed", boundary)
			}
			if rec.Code != 200 {
				t.Fatalf("a proven commit is always success: %d %s", rec.Code, rec.Body.String())
			}
			m := pacIntentJSON(t, rec)
			want := "pending_reconciliation"
			if boundary == "finalized" {
				want = "recorded"
			}
			if m["historyState"] != want {
				t.Fatalf("historyState after a crash at %s: got %v want %s", boundary, m["historyState"], want)
			}
			// Effects that landed before the crash are already there exactly once.
			if pacIntentAudits(op, "pac.profile_publish") > 1 || pacIntentVersionsFor(op) > 1 {
				t.Fatal("an effect landed twice within one operation")
			}
			pacIntentRestartComplete(t)
			pacIntentAssertRecordedOnce(t, op, 1)
			pacIntentGet(t)
			pacIntentRestartComplete(t)
			pacIntentAssertRecordedOnce(t, op, 1)
		})
	}
}

// ── C-6: aborted / ambiguous never produce a success audit or a version ──

func TestPACCorrection_C6_AbortedAndAmbiguousProduceNoSuccessEffects(t *testing.T) {
	t.Run("aborted", func(t *testing.T) {
		pacIntentEnv(t)
		pacProfiles.Restore(pac.ProfileState{Cfg: pacProfiles.Get(), Path: filepath.Join(t.TempDir(), "missing", "pac_profiles.json")})
		op := uuid.NewString()
		if rec := pacIntentPublish(t, op, 1, pacIntentDraft("Never", false), ""); rec.Code != http.StatusInternalServerError {
			t.Fatalf("aborted: %d %s", rec.Code, rec.Body.String())
		}
		pacIntentGet(t)
		if pacIntentAudits(op, "pac.profile_publish") != 0 || pacIntentVersionsFor(op) != 0 {
			t.Fatal("an aborted operation must never emit a success audit or a config version")
		}
	})
	t.Run("ambiguous", func(t *testing.T) {
		pacIntentEnv(t)
		op := uuid.NewString()
		var snap map[string][]byte
		pacLifecycleStageHook = func(stage string) {
			if stage == "intent_persisted" {
				snap = pacIntentSnapshotFiles(t)
			}
		}
		if rec := pacIntentPublish(t, op, 1, pacIntentDraft("Mine", false), ""); rec.Code != 200 {
			t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
		}
		pacLifecycleStageHook = nil
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
		// The original request completed in-process before the on-disk state
		// was rolled back to the intent boundary; what matters is that
		// reconciling the now-ambiguous intent adds NOTHING to those effects.
		before := pacIntentAudits(op, "pac.profile_publish")
		beforeV := pacIntentVersionsFor(op)
		pacIntentRestartComplete(t)
		pacIntentGet(t)
		if g := pacIntentGet(t); g["state"] != "ambiguous" {
			t.Fatalf("want ambiguous, got %v", g["state"])
		}
		if pacIntentAudits(op, "pac.profile_publish") != before || pacIntentVersionsFor(op) != beforeV {
			t.Fatal("reconciling an ambiguous operation must never emit a success audit or a config version")
		}
	})
	t.Run("committed-control", func(t *testing.T) {
		pacIntentEnv(t)
		snap := pacIntentCrashAfterActiveCommit(t)
		var op string
		for _, o := range pacIntentGet(t)["operations"].([]any) {
			op, _ = o.(map[string]any)["operationId"].(string)
		}
		pacIntentRestoreFiles(t, snap)
		if pacIntentAudits(op, "pac.profile_publish") != 1 || pacIntentVersionsFor(op) != 1 {
			t.Fatalf("control: the completed in-process operation must have exactly one audit and one version (audits=%d versions=%d)", pacIntentAudits(op, "pac.profile_publish"), pacIntentVersionsFor(op))
		}
		pacIntentRestartComplete(t)
		pacIntentAssertRecordedOnce(t, op, 1)
	})
}

// ── C-7: replay after recovery ──

func TestPACCorrection_C7_ReplayAfterRecoveryReturnsRecordedResultWithoutSideEffects(t *testing.T) {
	pacIntentEnv(t)
	op := uuid.NewString()
	var snap map[string][]byte
	pacLifecycleStageHook = func(stage string) {
		if stage == "active_committed" {
			snap = pacIntentSnapshotFiles(t)
			pacLifecyclePersistHook = func(string) error { return fmt.Errorf("crashed") }
		}
	}
	pacIntentPublish(t, op, 1, pacIntentDraft("Crashed", false), "")
	pacLifecycleStageHook, pacLifecyclePersistHook = nil, nil
	pacIntentRestoreFiles(t, snap)
	pacIntentRestartComplete(t)
	pacIntentAssertRecordedOnce(t, op, 1)
	replay := pacIntentPublish(t, op, 1, pacIntentDraft("Other", false), "")
	if replay.Code != 200 {
		t.Fatalf("replay: %d %s", replay.Code, replay.Body.String())
	}
	m := pacIntentJSON(t, replay)
	if m["published"] != true || m["operationId"] != op || m["historyState"] != "recorded" || m["revision"] != float64(1) {
		t.Fatalf("replay must return the recorded result: %s", replay.Body.String())
	}
	if pacIntentActiveName(t) != "Crashed" {
		t.Fatal("replay must not commit again")
	}
	pacIntentAssertRecordedOnce(t, op, 1)
	pacIntentRestartComplete(t)
	pacIntentAssertRecordedOnce(t, op, 1)
}

// ── C-8: audit content ──

func TestPACCorrection_C8_SuccessAuditPinsOperationIDAndHistoryState(t *testing.T) {
	pacIntentEnv(t)
	op := uuid.NewString()
	if rec := pacIntentPublish(t, op, 1, pacIntentDraft("Audited", false), ""); rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	var found *AuditEntry
	for _, e := range auditGet() {
		if e.Action == "pac.profile_publish" && strings.Contains(e.Detail, "operationId="+op) {
			e := e
			found = &e
		}
	}
	if found == nil {
		t.Fatal("the success audit must name the operationId")
	}
	if !strings.Contains(found.Detail, "historyState=recorded") {
		t.Fatalf("the success audit must carry the truthful historyState: %q", found.Detail)
	}
	if found.Object != "branch-il" || !strings.Contains(found.Actor, pacIntentIP) {
		t.Fatalf("audit object/actor: %q %q", found.Object, found.Actor)
	}
	// The same contract for a rollback, and no success audit for the refused
	// (aborted) path.
	rb := uuid.NewString()
	if rec := pacIntentRollback(t, rb, 1, 2); rec.Code != 200 {
		t.Fatalf("rollback: %d %s", rec.Code, rec.Body.String())
	}
	if pacIntentAudits(rb, "pac.profile_rollback") != 1 {
		t.Fatal("the rollback success audit must name its operationId")
	}
	var detail string
	for _, e := range auditGet() {
		if e.Action == "pac.profile_rollback" && strings.Contains(e.Detail, "operationId="+rb) {
			detail = e.Detail
		}
	}
	if !strings.Contains(detail, "historyState=recorded") {
		t.Fatalf("rollback audit historyState: %q", detail)
	}
	if pacIntentAudits(op, "pac.profile_publish") != 1 {
		t.Fatal("exactly one success audit per operation")
	}
}
