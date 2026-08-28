package main

// saas_feed_writer_domain_test.go — Blocker E proofs (2D-B final correction
// §§17–19): every runtime writer of the signed-feed configuration on an
// authoritative node shares ONE ordering domain (adminSettingsMu) for the
// read, the durable AdminSettings write, and the runtime-holder publish.
//
// At the prior frozen candidate, config import and config-version rollback
// called setSaaSFeedDurable directly (with the durable write happening later,
// outside any shared critical section), so a bulk install could land BETWEEN
// a fenced settings PUT's precondition and its apply — its install silently
// destroyed by the PUT's apply while its own save then persisted the PUT's
// state, leaving the runtime holder, the GET revision, and the durable file
// free to disagree about which writer won. These are the §22-E red-before
// proofs.
//
// Technique: writer A reproduces the PUT's exact transaction shape through
// saveAdminSettingsWithOverrides (precondition fence + saasFeed target +
// applyOnSuccess) and PAUSES inside the critical section via its
// precondition; the concurrent bulk writer must BLOCK until A's transaction
// completes (Gosched-loop + select, the established commit-boundary
// technique — no sleeps as synchronization), and after both finish exactly
// one serial order must hold, with holder, revision, and durable file in
// agreement on the winner.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// wdReadSettingsFile decodes the AdminSettings the settings file currently
// records (the durable half of the agreement proof).
func wdReadSettingsFile(t *testing.T, path string) AdminSettings {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("read settings file: %v", err)
	}
	var s AdminSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("decode settings file: %v", err)
	}
	return s
}

// wdAssertAgreement asserts the three surfaces agree on one winning feed
// configuration: the runtime holder, the GET view's revision, and the durable
// AdminSettings file.
func wdAssertAgreement(t *testing.T, path string, want saasFeedDurable) {
	t.Helper()
	got := getSaaSFeedDurable()
	if got.Managed != want.Managed || got.Enabled != want.Enabled || got.URL != want.URL ||
		got.Protocol != want.Protocol || got.RefreshSeconds != want.RefreshSeconds {
		t.Fatalf("runtime holder disagrees with the serialized winner: got %+v want %+v", got, want)
	}
	view := saasFeedSettingsView()
	if rev, _ := view["revision"].(string); rev != saasFeedSettingsRevision(want) {
		t.Fatalf("GET revision %q does not describe the winning configuration (want %q)", rev, saasFeedSettingsRevision(want))
	}
	s := wdReadSettingsFile(t, path)
	if s.SaaSFeedManaged != want.Managed || s.SaaSFeedEnabled != want.Enabled ||
		s.SaaSFeedURL != want.URL || s.SaaSFeedProtocol != want.Protocol ||
		s.SaaSFeedRefreshSeconds != want.RefreshSeconds {
		t.Fatalf("durable AdminSettings disagrees with the serialized winner: file {managed:%t enabled:%t url:%q proto:%q refresh:%d} want %+v",
			s.SaaSFeedManaged, s.SaaSFeedEnabled, s.SaaSFeedURL, s.SaaSFeedProtocol, s.SaaSFeedRefreshSeconds, want)
	}
}

// wdPausedPUTTransaction starts writer A — the PUT's transaction shape with a
// pause inside the critical section, after its precondition (revision fence)
// has passed. Returns the entered/release/done channels and the error slot.
func wdPausedPUTTransaction(t *testing.T, target saasFeedDurable, expectRev string) (entered, release, done chan struct{}, errSlot *error) {
	t.Helper()
	entered = make(chan struct{})
	release = make(chan struct{})
	done = make(chan struct{})
	errSlot = new(error)
	go func() {
		defer close(done)
		*errSlot = saveAdminSettingsWithOverrides(adminSaveOverrides{
			saasFeed: &target,
			precondition: func() error {
				if cur := saasFeedSettingsRevision(getSaaSFeedDurable()); cur != expectRev {
					return errSaaSSettingsRevisionConflict
				}
				close(entered)
				<-release
				return nil
			},
			applyOnSuccess: func() { setSaaSFeedDurable(target) },
		})
	}()
	return entered, release, done, errSlot
}

// wdAssertBlockedThenRelease asserts opDone has NOT closed while writer A is
// paused inside the domain, then releases A and waits for both to finish.
func wdAssertBlockedThenRelease(t *testing.T, what string, opDone, release, aDone chan struct{}, aErr *error) {
	t.Helper()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	escaped := false
	select {
	case <-opDone:
		escaped = true
	default:
	}
	// Release the paused transaction BEFORE any failure report, so a failing
	// run never leaves adminSettingsMu held (which would deadlock the rest of
	// the package).
	close(release)
	<-aDone
	<-opDone
	if escaped {
		t.Fatalf("%s completed while a fenced settings transaction held the writer domain — its install can be silently destroyed by the transaction's apply", what)
	}
	if *aErr != nil {
		t.Fatalf("fenced transaction must succeed: %v", *aErr)
	}
}

func TestSaaSWriterDomain_ImportSerializesAfterFencedPUTTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)
	f3a2IsolateConfigWriters(t)
	f3a2SwapRole(t, "standalone")
	f3a2ResetFeedDurable(t)

	d0 := getSaaSFeedDurable()
	targetA := d0
	targetA.Managed = true
	targetA.Enabled = false
	targetA.RefreshSeconds = 7200

	entered, release, aDone, aErr := wdPausedPUTTransaction(t, targetA, saasFeedSettingsRevision(d0))
	<-entered

	importDone := make(chan struct{})
	go func() {
		defer close(importDone)
		importSaaSFeedConfig(&configBackup{
			SaaSFeedManaged:        true,
			SaaSFeedEnabled:        true,
			SaaSFeedProtocol:       saasFeedProtocolV1,
			SaaSFeedRefreshSeconds: 3600,
		})
	}()
	wdAssertBlockedThenRelease(t, "config import's feed install", importDone, release, aDone, aErr)

	// One serial order: A applied, then the import — the import's
	// configuration is the final state on ALL THREE surfaces.
	want := d0
	want.Managed = true
	want.Enabled = true
	want.URL = ""
	want.Protocol = saasFeedProtocolV1
	want.RefreshSeconds = 3600
	wdAssertAgreement(t, path, want)
}

func TestSaaSWriterDomain_RollbackSerializesAfterFencedPUTTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)
	f3a2IsolateConfigWriters(t)
	f3a2SwapRole(t, "standalone")
	f3a2ResetFeedDurable(t)

	d0 := getSaaSFeedDurable()
	targetA := d0
	targetA.Managed = true
	targetA.Enabled = false
	targetA.RefreshSeconds = 7200

	entered, release, aDone, aErr := wdPausedPUTTransaction(t, targetA, saasFeedSettingsRevision(d0))
	<-entered

	rollbackDone := make(chan struct{})
	go func() {
		defer close(rollbackDone)
		// applyPACFromBackup is the rollback function that carries the feed
		// slice (called by applyConfigBackup under configRollbackMu); driven
		// directly with a feed-only backup, matching the existing direct
		// applyConfigBackup test convention.
		applyPACFromBackup(&configBackup{
			SaaSFeedManaged:        true,
			SaaSFeedEnabled:        true,
			SaaSFeedProtocol:       saasFeedProtocolV1,
			SaaSFeedRefreshSeconds: 1800,
		})
	}()
	wdAssertBlockedThenRelease(t, "config-version rollback's feed install", rollbackDone, release, aDone, aErr)

	want := d0
	want.Managed = true
	want.Enabled = true
	want.URL = ""
	want.Protocol = saasFeedProtocolV1
	want.RefreshSeconds = 1800
	wdAssertAgreement(t, path, want)
}

// TestSaaSWriterDomain_FencedPUTConflictsAfterConcurrentInstall is the §19
// reverse direction: a bulk install (the import/rollback transaction shape)
// holds the domain first; a fenced PUT loaded against the pre-install
// revision must WAIT for the domain and then CONFLICT (409) — it can never
// silently overwrite the install it did not see — and the install's
// configuration stays the agreed winner on all three surfaces.
func TestSaaSWriterDomain_FencedPUTConflictsAfterConcurrentInstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)
	f3a2IsolateConfigWriters(t)
	f3a2SwapRole(t, "standalone")
	f3a2ResetFeedDurable(t)

	d0 := getSaaSFeedDurable()
	rev0 := saasFeedSettingsRevision(d0)

	// Writer I: the bulk-install transaction, paused inside the domain.
	targetI := d0
	targetI.Managed = true
	targetI.Enabled = true
	targetI.Protocol = saasFeedProtocolV1
	targetI.RefreshSeconds = 1800
	iEntered := make(chan struct{})
	iRelease := make(chan struct{})
	iDone := make(chan struct{})
	var iErr error
	go func() {
		defer close(iDone)
		iErr = saveAdminSettingsWithOverrides(adminSaveOverrides{
			saasFeed: &targetI,
			precondition: func() error {
				close(iEntered)
				<-iRelease
				return nil
			},
			applyOnSuccess: func() { setSaaSFeedDurable(targetI) },
		})
	}()
	<-iEntered

	// The fenced PUT, loaded against the PRE-install revision.
	putDone := make(chan struct{})
	var putCode int
	var putBody string
	go func() {
		defer close(putDone)
		w := dispatchSettingsURL(RoleAdmin, http.MethodPut,
			"/api/saas-feed/settings?ifRevision="+rev0, `{"enabled":false,"refresh":"2h"}`)
		putCode, putBody = w.Code, w.Body.String()
	}()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	putEscaped := false
	select {
	case <-putDone:
		putEscaped = true
	default:
	}
	close(iRelease)
	<-iDone
	<-putDone
	if putEscaped {
		t.Fatal("fenced PUT completed while another writer held the domain")
	}
	if iErr != nil {
		t.Fatalf("install transaction must succeed: %v", iErr)
	}
	if putCode != http.StatusConflict {
		t.Fatalf("the fenced PUT must conflict against the install it did not see; got %d: %s", putCode, putBody)
	}
	wdAssertAgreement(t, path, targetI)
}
