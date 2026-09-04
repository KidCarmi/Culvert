package main

// pac_lifecycle_round2_test.go — the 2F-B correction round-2 matrix
// (external review of candidate 16858885, docs/design/FRONTEND-MIGRATION-PLAN.md
// C1):
//
//   R2-1 an unreadable reset sidecar whose replacement write fails must still
//        yield history_reset after every restart — the last durable reset
//        evidence is never removed before its replacement is proven;
//   R2-2 a config-version write failure leaves Progress.ConfigVersion=false
//        and the operation in pending_reconciliation;
//   R2-3 reconciliation later creates exactly ONE config version and advances
//        the marker only afterwards; repeats add nothing;
//   R2-4 a cluster-publication failure leaves Progress.Cluster=false and the
//        operation in pending_reconciliation;
//   R2-5 reconciliation retries the publication and advances the marker only
//        after success; repeats produce no further effective transition;
//   R2-6 repeated reconciliation never duplicates a config version, a success
//        audit, a history revision, or a cluster transition (asserted inside
//        R2-3 and R2-5).
//
// RED-before evidence: every test fails at exactly 16858885, where (a)
// loadResetRecordLocked renames an unreadable sidecar aside BEFORE its
// replacement is durable and ignores the replacement write error, and (b)
// the config-version and cluster steps set + persist their progress marker
// regardless of the effect's result. Fault injection is deterministic
// (pac.ResetWriteHook, pacEffectHook, an unwritable version store); no
// sleeps.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/configver"
	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/google/uuid"
)

func pacRound2Env(t *testing.T) {
	t.Helper()
	pacIntentEnv(t)
	eh, rh := pacEffectHook, pac.ResetWriteHook
	t.Cleanup(func() { pacEffectHook, pac.ResetWriteHook = eh, rh })
	pacEffectHook, pac.ResetWriteHook = nil, nil
}

func pacRound2ResetPath() string {
	return strings.TrimSuffix(pacFencePaths.lifecycle, ".json") + ".reset.json"
}

func pacRound2Progress(t *testing.T) (state string, historyState string, progress map[string]any) {
	t.Helper()
	g := pacIntentGet(t)
	state, _ = g["state"].(string)
	historyState, _ = g["historyState"].(string)
	if po, ok := g["pendingOp"].(map[string]any); ok {
		progress, _ = po["progress"].(map[string]any)
	}
	return state, historyState, progress
}

// ── R2-1: the last durable reset evidence survives a failed replacement ──

func TestPACRound2_R1_UnreadableSidecarReplacementFailureKeepsResetAcrossRestart(t *testing.T) {
	pacRound2Env(t)
	if rec := pacIntentPublish(t, uuid.NewString(), 1, pacIntentDraft("Before", false), ""); rec.Code != 200 {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	pacIntentCorruptLifecycle(t)
	if g := pacIntentGet(t); g["historyState"] != "history_reset" {
		t.Fatalf("precondition: history_reset, got %v", g["historyState"])
	}
	// The durable reset record itself becomes unreadable, and the boot that
	// finds it cannot write its replacement.
	if err := os.WriteFile(pacRound2ResetPath(), []byte(`{"at": "x", "acknowledged": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	pac.ResetWriteHook = func(string) error { return fmt.Errorf("injected reset write failure") }
	pacIntentRestartComplete(t)
	if g := pacIntentGet(t); g["historyState"] != "history_reset" {
		t.Fatalf("a boot that cannot record the replacement must stay fail-closed in memory: %v", g["historyState"])
	}
	if rec := pacIntentPublish(t, uuid.NewString(), 2, pacIntentDraft("Never", false), ""); rec.Code != http.StatusConflict {
		t.Fatalf("publish must stay refused while the reset is unacknowledged: %d %s", rec.Code, rec.Body.String())
	}
	// The next boot (writes work again) must STILL find durable reset
	// evidence: the unreadable record may not have been moved away while no
	// replacement existed.
	pac.ResetWriteHook = nil
	pacIntentRestartComplete(t)
	if g := pacIntentGet(t); g["historyState"] != "history_reset" {
		t.Fatalf("the reset must survive a restart after a failed replacement write (durable evidence lost): %v", g["historyState"])
	}
	if rec := pacIntentPublish(t, uuid.NewString(), 2, pacIntentDraft("Never", false), ""); rec.Code != http.StatusConflict {
		t.Fatalf("publish must stay refused after the restart: %d %s", rec.Code, rec.Body.String())
	}
	// Once recorded durably, the acknowledgement ceremony works as before and
	// the corrupt evidence was preserved, not deleted.
	digest, _ := pacIntentGet(t)["activeSpecDigest"].(string)
	if rec := pacIntentAck(t, uuid.NewString(), 2, digest); rec.Code != 200 {
		t.Fatalf("ack after recovery: %d %s", rec.Code, rec.Body.String())
	}
	pacIntentRestartComplete(t)
	if g := pacIntentGet(t); g["historyState"] != "recorded" {
		t.Fatalf("durable acknowledgement must survive a restart: %v", g["historyState"])
	}
	evidence, _ := filepath.Glob(pacRound2ResetPath() + ".corrupt.*")
	if len(evidence) == 0 {
		t.Fatal("the unreadable reset record must be preserved as evidence, never deleted")
	}
}

// ── R2-2 / R2-3: config-version truth ──

func TestPACRound2_R2_R3_ConfigVersionFailureIsRetriedExactlyOnce(t *testing.T) {
	pacRound2Env(t)
	good := configVersions
	// An unwritable version store: the parent directory does not exist and
	// is never created, so every durable write fails while List stays empty.
	configVersions = configver.New(filepath.Join(t.TempDir(), "missing", "versions"), 0)
	op := uuid.NewString()
	rec := pacIntentPublish(t, op, 1, pacIntentDraft("Versioned", false), "")
	if rec.Code != 200 {
		t.Fatalf("a proven commit is always success: %d %s", rec.Code, rec.Body.String())
	}
	if m := pacIntentJSON(t, rec); m["historyState"] != "pending_reconciliation" {
		t.Fatalf("a failed config-version capture must leave the operation pending_reconciliation, got %v", m["historyState"])
	}
	state, hs, progress := pacRound2Progress(t)
	if state != "pending" || hs != "pending_reconciliation" || progress == nil || progress["configVersion"] != false || progress["history"] != true {
		t.Fatalf("Progress.ConfigVersion must stay false after a failed capture: state=%s historyState=%s progress=%v", state, hs, progress)
	}
	if pacIntentVersionsFor(op) != 0 {
		t.Fatal("no version exists yet")
	}
	// The store recovers; reconciliation creates exactly one version and only
	// then advances the marker. Repeats add nothing.
	configVersions = good
	for i := 0; i < 3; i++ {
		pacIntentGet(t)
	}
	pacIntentAssertRecordedOnce(t, op, 1)
	pacIntentRestartComplete(t)
	pacIntentGet(t)
	pacIntentAssertRecordedOnce(t, op, 1)
}

// ── R2-4 / R2-5: cluster-publication truth ──

func TestPACRound2_R4_R5_ClusterPublicationFailureIsRetriedExactlyOnce(t *testing.T) {
	pacRound2Env(t)
	pacEffectHook = func(effect string) error {
		if effect == "cluster" {
			return fmt.Errorf("injected cluster publication failure")
		}
		return nil
	}
	op := uuid.NewString()
	rec := pacIntentPublish(t, op, 1, pacIntentDraft("Fleet", false), "")
	if rec.Code != 200 {
		t.Fatalf("a proven commit is always success: %d %s", rec.Code, rec.Body.String())
	}
	if m := pacIntentJSON(t, rec); m["historyState"] != "pending_reconciliation" {
		t.Fatalf("a failed cluster publication must leave the operation pending_reconciliation, got %v", m["historyState"])
	}
	state, hs, progress := pacRound2Progress(t)
	if state != "pending" || hs != "pending_reconciliation" || progress == nil || progress["cluster"] != false || progress["configVersion"] != true {
		t.Fatalf("Progress.Cluster must stay false after a failed publication (config version already done): state=%s historyState=%s progress=%v", state, hs, progress)
	}
	if pacIntentVersionsFor(op) != 1 {
		t.Fatalf("the config version landed before the cluster step: want 1, got %d", pacIntentVersionsFor(op))
	}
	// A failed retry changes nothing.
	pacIntentGet(t)
	if _, hs, progress := pacRound2Progress(t); hs != "pending_reconciliation" || progress["cluster"] != false {
		t.Fatalf("a retry that fails again must not advance the marker: %s %v", hs, progress)
	}
	// Publication works again: exactly ONE effective cluster transition, then
	// the marker advances; further reconciliations/restarts publish nothing.
	pacEffectHook = nil
	before := globalConfigStore.Version()
	pacIntentGet(t)
	if got := globalConfigStore.Version(); got != before+1 {
		t.Fatalf("the retried publication must produce exactly one cluster transition: version %d -> %d", before, got)
	}
	pacIntentAssertRecordedOnce(t, op, 1)
	for i := 0; i < 3; i++ {
		pacIntentGet(t)
	}
	pacIntentRestartComplete(t)
	pacIntentGet(t)
	if got := globalConfigStore.Version(); got != before+1 {
		t.Fatalf("repeated reconciliation must not republish: version %d -> %d", before, got)
	}
	pacIntentAssertRecordedOnce(t, op, 1)
}
