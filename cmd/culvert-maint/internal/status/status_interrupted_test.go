package status

// status_interrupted_test.go — the journal-backed part of GET /v1/status. The
// end-to-end shape is pinned by the process-level tests in the main package;
// these cover the cases that need a live Manager or a broken journal.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/config"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

func providerWithJournal(t *testing.T) (*Provider, *journal.Journal) {
	t.Helper()
	p := newProvider(t, fakeBin(t), config.PrivilegeDockerGroupLab)
	p.cfg.ProxyRepo = "ghcr.io/kidcarmi/culvert"
	jnl, err := journal.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return p.WithJournal(jnl), jnl
}

func TestSnapshot_NoJournalRecordsAddsNoInterruptedOperation(t *testing.T) {
	p, _ := providerWithJournal(t)
	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.InterruptedOperations != nil || st.InterruptedOperationsError != "" {
		t.Errorf("clean journal must report no interrupted operation: %+v", st)
	}
	// pinned_tag does not depend on the journal. The fake docker prints
	// nothing, so the tag is unreadable here and must be reported as unknown,
	// not left out and not asserted to match.
	if st.PinnedTag == nil || st.PinnedTag.ImageID != "" || st.PinnedTag.MatchesRunning != nil || st.PinnedTag.Error == "" {
		t.Errorf("pinned_tag must be reported, as unknown, with a clean journal: %+v", st.PinnedTag)
	}
}

// TestSnapshot_OwnOperationsAreNotInterrupted: a record whose operation this
// process is running, or has just finished and not yet retired, is not an
// interruption. A record with no operation behind it is.
func TestSnapshot_OwnOperationsAreNotInterrupted(t *testing.T) {
	p, jnl := providerWithJournal(t)
	op, err := p.mgr.Begin(ops.KindUpgradeApply, "uid=0", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := jnl.Write(journal.Record{OpID: op.ID, Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarting, StartedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"running", "finished, record not yet removed"} {
		st, err := p.Snapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(st.InterruptedOperations) != 0 {
			t.Errorf("%s: this process's own op was reported as interrupted: %+v", stage, st.InterruptedOperations)
		}
		_ = p.mgr.Finish(op.ID, ops.StateSucceeded, "", nil)
	}

	// A record left by an earlier process, marked at startup.
	const orphan = "01HZZZZZZZZZZZZZZZZZZZZZZZ"
	if err := jnl.Write(journal.Record{OpID: orphan, Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarting, StartedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	p.mgr.MarkAllInterrupted([]ops.InterruptedOp{{OpID: orphan, Kind: ops.KindUpgradeApply, Actor: "uid=0"}})
	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(st.InterruptedOperations) != 1 || st.InterruptedOperations[0].OpID != orphan {
		t.Fatalf("interrupted_operations = %+v, want only the orphan", st.InterruptedOperations)
	}
	got := st.InterruptedOperations[0]
	// The fake docker prints nothing, so neither live fact could be read: both
	// must say so instead of asserting a match.
	if got.RunningImage != "unknown" {
		t.Errorf("running_image = %q, want unknown", got.RunningImage)
	}
	if st.PinnedTag == nil || st.PinnedTag.ImageID != "" || st.PinnedTag.MatchesRunning != nil || st.PinnedTag.Error == "" {
		t.Errorf("pinned_tag must report an unreadable tag as unknown: %+v", st.PinnedTag)
	}
}

// TestSnapshot_UnreadableJournalIsUnknownNotEmpty: status stays 200, says the
// list is unknown, and does not echo the file.
func TestSnapshot_UnreadableJournalIsUnknownNotEmpty(t *testing.T) {
	p, jnl := providerWithJournal(t)
	if err := os.WriteFile(filepath.Join(jnl.Dir(), "01HZZZZZZZZZZZZZZZZZZZZZZZ.json"), []byte(`{"phase":"SECRET-CONTENT`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot must not fail: %v", err)
	}
	if st.InterruptedOperationsError == "" || len(st.InterruptedOperations) != 0 {
		t.Errorf("want an error and no list: %+v", st)
	}
	if strings.Contains(st.InterruptedOperationsError, "SECRET-CONTENT") {
		t.Errorf("error repeats file content: %q", st.InterruptedOperationsError)
	}
}
