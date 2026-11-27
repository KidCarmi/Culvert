package main

// support_upload_commit_order_chaos128_test.go — CHAOS-128: the support-evidence
// upload drain's COMMIT ORDER.
//
// THE DEFECT. finishUploadDrain persisted the post-attempt queue entry, treated
// a persist failure as log-only, did NOT return, and then performed the two
// IRREVERSIBLE side effects that are valid only if that write landed: it deleted
// the sealed blob (the only copy of the bytes BundleSHA256 was computed over)
// and wrote the support.bundle.upload audit record claiming delivery — whose own
// comment asserted "the receipt lives on the persisted queue entry", which is
// precisely the artifact that had just failed to persist.
//
// On a full, read-only or failing support volume one consented upload therefore
// lost BOTH the bytes and the gateway's signed receipt (the node's only proof of
// delivery) while the audit trail recorded a delivery it could no longer
// substantiate. The stale on-disk entry — still `queued, attempts=0,
// next_retry_at=0` — then sent the next attempt at the deleted blob, where a
// plain ENOENT is not a GatewayError and is classified TRANSIENT, burning the
// 6-attempt budget down to `deferred`. The operator surface and the audit trail
// ended up asserting opposite outcomes for the same bundle.
//
// The SAME lost write also broke the retry ladder for a non-terminal attempt: a
// transient failure increments Attempts and sets a backoff NextRetryAt, and if
// that write is lost the disk keeps attempts=0/next_retry_at=0, so the bounded
// ladder becomes an unbounded re-send every supportUploadTick that can never
// reach `deferred`.
//
// THE FIX, AND WHY IT IS A HOLD RATHER THAN AN EARLY RETURN. Returning before
// the side effects fixes the integrity half and introduces an availability one,
// because the retained entry is immediately due again and the 30 s worker would
// re-upload the whole bundle to the vendor on every tick for as long as the
// volume stayed unwritable — a local disk fault amplified into unbounded egress.
// So the outcome is held in RAM until its write lands: the receipt is not thrown
// away, and the bundle is not re-sent. The gates below pin BOTH halves, because
// each one alone has a cheap wrong implementation that the other catches.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/supportupload"
)

// errUnwritableVolume stands in for ENOSPC/EROFS/EIO from the durable-write
// chokepoint. It is deliberately NOT fileutil.ErrReplacedNotSynced: that
// sentinel means the bytes LANDED and durableSupportWrite reports it as
// committed, which is the opposite case (see support_replaced_notsynced_test.go).
var errUnwritableVolume = errors.New("chaos128: no space left on device")

// failSupportWritesAfterSetup makes every subsequent durable support write fail,
// so a test can fault the drain's persist WITHOUT faulting the enqueue and seal
// that set it up. Returns a func that restores the real writer, for the tests
// that then assert recovery.
func failSupportWritesAfterSetup(t *testing.T) (restore func()) {
	t.Helper()
	prev := supportDurableWriter
	supportDurableWriter = func(string, []byte, os.FileMode) error { return errUnwritableVolume }
	restored := false
	t.Cleanup(func() {
		if !restored {
			supportDurableWriter = prev
		}
	})
	return func() {
		supportDurableWriter = prev
		restored = true
	}
}

// resetUploadCommitHoldForTest clears the process-wide hold at test START and
// again on cleanup. uploadCommitHeld is a package global shared by every test in
// the binary, and a leaked hold would silently suppress another test's drain
// (uploadCommitIsHeld skips the entry), so it is restored both ways.
func resetUploadCommitHoldForTest(t *testing.T) {
	t.Helper()
	clearHold := func() {
		uploadCommitMu.Lock()
		uploadCommitHeld = map[string]uploadQueueEntry{}
		uploadCommitMu.Unlock()
	}
	clearHold()
	t.Cleanup(clearHold)
}

// queuedUploadForTest enqueues a sealed, consented bundle and returns its id and
// sealed bytes. Runs BEFORE any writer fault, so the queue entry and the blob are
// genuinely on disk.
func queuedUploadForTest(t *testing.T, seed, caseID string) (id string, sealed []byte) {
	t.Helper()
	id = csbID(seed)
	sealed = []byte("sealed-blob-bytes-" + seed)
	if err := writeSealedUpload(id, sealed); err != nil {
		t.Fatalf("write sealed: %v", err)
	}
	if _, err := enqueueUpload(id, caseID, "tac-1", sha256hex(sealed), time.Now()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return id, sealed
}

// countingUpload is an uploadFunc that succeeds with a receipt and counts calls,
// so a gate can tell one delivery from one delivery per tick.
func countingUpload(sig string, calls *int) uploadFunc {
	return func(_ context.Context, e uploadQueueEntry) (*supportupload.Receipt, string, error) {
		*calls++
		return &supportupload.Receipt{BundleSHA256: e.BundleSHA256, Sig: sig}, "sess-1", nil
	}
}

// ── 1. the integrity half ───────────────────────────────────────────────────

// A persist the volume refused must not authorize deleting the bytes or
// recording a delivery. Pre-fix this failed on all three assertions at once: the
// blob was gone, the audit claimed delivery, and nothing said otherwise.
func TestCHAOS128_FailedPersistKeepsTheBytesAndRecordsNoDelivery(t *testing.T) {
	withTempUploadDir(t)
	resetUploadCommitHoldForTest(t)
	enableUploadForTest(t)
	id, sealed := queuedUploadForTest(t, "kep", "CASE-128A")
	baseline := time.Now().UnixMilli()
	heldBefore := supportUploadCommitHeldTotal.Load()

	failSupportWritesAfterSetup(t)
	calls := 0
	drainDueUploads(context.Background(), countingUpload("SIG-A", &calls))

	if calls != 1 {
		t.Fatalf("upload attempts = %d, want 1 (the transfer itself must still happen)", calls)
	}
	// The bytes are the only thing that makes a retry possible at all.
	got, err := os.ReadFile(sealedUploadPath(id))
	if err != nil {
		t.Fatalf("sealed blob must survive a failed persist — the receipt is unrecorded, so the "+
			"bundle is still owed to the gateway and these bytes are the only copy: %v", err)
	}
	if !bytes.Equal(got, sealed) {
		t.Errorf("sealed blob changed: got %d bytes, want %d", len(got), len(sealed))
	}
	// Nothing may claim a delivery the node cannot prove.
	if hasMatchingAuditEntry(auditGet(), "system", "support.bundle.upload", id, baseline) {
		t.Error("support.bundle.upload was recorded although the queue entry (which carries the " +
			"receipt) never reached disk: the audit trail asserts a delivery with no proof behind it")
	}
	// And the failure is visible rather than silent.
	if n := uploadCommitsHeld(); n != 1 {
		t.Errorf("held outcomes gauge = %d, want 1 — an outcome stranded in RAM must be reportable", n)
	}
	if delta := supportUploadCommitHeldTotal.Load() - heldBefore; delta < 1 {
		t.Errorf("held counter delta = %d, want >= 1", delta)
	}
}

// ── 2. the availability half ────────────────────────────────────────────────

// The on-disk entry for a held bundle still reads `queued`, so dueUploadEntries
// keeps offering it. An early return alone would re-send the whole bundle to the
// vendor on every 30 s tick for the length of the disk incident.
func TestCHAOS128_HeldOutcomeIsNotResentWhileTheVolumeIsUnwritable(t *testing.T) {
	withTempUploadDir(t)
	resetUploadCommitHoldForTest(t)
	enableUploadForTest(t)
	id, _ := queuedUploadForTest(t, "res", "CASE-128B")

	failSupportWritesAfterSetup(t)
	calls := 0
	up := countingUpload("SIG-B", &calls)
	for tick := 0; tick < 5; tick++ {
		drainDueUploads(context.Background(), up)
	}

	if calls != 1 {
		t.Fatalf("upload attempts across 5 ticks = %d, want 1: a local write fault must not "+
			"amplify into one full bundle re-upload per tick", calls)
	}
	if !uploadCommitIsHeld(id) {
		t.Error("the outcome must stay held while the volume refuses the write")
	}
	if _, err := os.Stat(sealedUploadPath(id)); err != nil {
		t.Errorf("sealed blob must still be retained after repeated ticks: %v", err)
	}
}

// ── 3. recovery ─────────────────────────────────────────────────────────────

// Once the volume accepts writes, the held outcome commits: the entry lands with
// its receipt, the blob is released, the delivery is audited — and the bundle is
// NOT transferred a second time, because the receipt was never lost.
func TestCHAOS128_HeldOutcomeCommitsWhenTheWriteLands(t *testing.T) {
	withTempUploadDir(t)
	resetUploadCommitHoldForTest(t)
	enableUploadForTest(t)
	id, _ := queuedUploadForTest(t, "rec", "CASE-128C")
	baseline := time.Now().UnixMilli()

	restore := failSupportWritesAfterSetup(t)
	calls := 0
	up := countingUpload("SIG-C", &calls)
	drainDueUploads(context.Background(), up)
	if !uploadCommitIsHeld(id) {
		t.Fatalf("precondition: the outcome should be held after a failed persist")
	}

	restore() // the volume recovers
	drainDueUploads(context.Background(), up)

	if calls != 1 {
		t.Errorf("upload attempts = %d, want 1: the held receipt makes a re-transfer unnecessary", calls)
	}
	e, ok := loadUploadQueueEntry(id)
	if !ok {
		t.Fatal("queue entry missing after recovery")
	}
	if e.State != uploadStateUploaded {
		t.Errorf("state = %q, want %q", e.State, uploadStateUploaded)
	}
	if e.Receipt == nil || e.Receipt.Sig != "SIG-C" {
		t.Errorf("receipt = %+v, want the held receipt SIG-C to reach disk", e.Receipt)
	}
	if _, err := os.Stat(sealedUploadPath(id)); !os.IsNotExist(err) {
		t.Errorf("sealed blob should be released once the outcome is durable, stat err = %v", err)
	}
	if !hasMatchingAuditEntry(auditGet(), "system", "support.bundle.upload", id, baseline) {
		t.Error("the delivery must be audited once — and only once — its record is durable")
	}
	if n := uploadCommitsHeld(); n != 0 {
		t.Errorf("held outcomes gauge = %d, want 0 after the write landed", n)
	}
}

// Committing a held outcome is a local write plus an audit record for a transfer
// that ALREADY happened; it dials nothing. Disabling upload pauses egress, so it
// must not strand the record of a delivery the node already made. This pins the
// ordering of retryHeldUploadCommits against the uploadEnabled() gate.
func TestCHAOS128_HeldOutcomeCommitsEvenWhileUploadIsDisabled(t *testing.T) {
	withTempUploadDir(t)
	resetUploadCommitHoldForTest(t)
	enableUploadForTest(t)
	id, _ := queuedUploadForTest(t, "dis", "CASE-128D")
	baseline := time.Now().UnixMilli()

	restore := failSupportWritesAfterSetup(t)
	calls := 0
	drainDueUploads(context.Background(), countingUpload("SIG-D", &calls))
	if !uploadCommitIsHeld(id) {
		t.Fatalf("precondition: the outcome should be held after a failed persist")
	}
	restore()

	// The operator switches upload off while the hold is outstanding.
	uploadConfigMu.Lock()
	err := saveUploadConfigLocked(uploadConfig{Enabled: false})
	uploadConfigMu.Unlock()
	if err != nil {
		t.Fatalf("disable upload: %v", err)
	}
	if uploadEnabled() {
		t.Fatal("precondition: upload should be disabled")
	}

	dialed := false
	drainDueUploads(context.Background(), func(context.Context, uploadQueueEntry) (*supportupload.Receipt, string, error) {
		dialed = true
		return nil, "", errors.New("must not dial")
	})

	if dialed {
		t.Error("no transfer may be attempted while upload is disabled")
	}
	if e, ok := loadUploadQueueEntry(id); !ok || e.State != uploadStateUploaded || e.Receipt == nil {
		t.Errorf("held outcome = %+v (found=%v), want it persisted as uploaded with its receipt "+
			"even though egress is paused", e, ok)
	}
	if !hasMatchingAuditEntry(auditGet(), "system", "support.bundle.upload", id, baseline) {
		t.Error("the already-completed delivery must still be audited once its record is durable")
	}
}

// ── 4. the retry ladder ─────────────────────────────────────────────────────

// A TRANSIENT failure's bookkeeping is the attempt counter and the backoff. If
// that write is lost and the attempt is repeated from the stale entry, the
// bounded 6-attempt ladder becomes an unbounded re-send that can never reach
// `deferred`. The hold covers every state, not only terminal ones, for exactly
// this reason.
func TestCHAOS128_LostAttemptBookkeepingDoesNotUnboundTheRetryLadder(t *testing.T) {
	withTempUploadDir(t)
	resetUploadCommitHoldForTest(t)
	enableUploadForTest(t)
	id, _ := queuedUploadForTest(t, "lad", "CASE-128E")

	failSupportWritesAfterSetup(t)
	calls := 0
	transient := func(context.Context, uploadQueueEntry) (*supportupload.Receipt, string, error) {
		calls++
		return nil, "", errors.New("connection reset by peer")
	}
	for tick := 0; tick < 8; tick++ { // more ticks than maxUploadAttempts
		drainDueUploads(context.Background(), transient)
	}

	if calls != 1 {
		t.Fatalf("transfer attempts across 8 ticks = %d, want 1: with attempts++ unpersisted the "+
			"entry stays due at attempts=0 forever, so the attempt cap (%d) can never trip",
			calls, maxUploadAttempts)
	}
	held, ok := heldUploadOutcomeForTest(id)
	if !ok {
		t.Fatal("the transient outcome must be held, so its attempt count is not lost")
	}
	if held.Attempts != 1 {
		t.Errorf("held attempts = %d, want 1", held.Attempts)
	}
	if held.NextRetryAt == 0 {
		t.Error("held outcome carries no backoff deadline: the ladder's own bookkeeping is what " +
			"must survive, not just the state name")
	}
}

// heldUploadOutcomeForTest returns the in-RAM outcome for bundleID. Test support:
// the gates above assert on the bookkeeping the hold exists to preserve, which is
// not observable from disk precisely because the write failed.
func heldUploadOutcomeForTest(bundleID string) (uploadQueueEntry, bool) {
	uploadCommitMu.Lock()
	defer uploadCommitMu.Unlock()
	e, ok := uploadCommitHeld[bundleID]
	return e, ok
}

// ── 5. the control ──────────────────────────────────────────────────────────

// The cheapest way to pass every gate above is to stop deleting the blob and
// stop auditing deliveries at all. This control fails against that, and against
// any hold that forgets to release: a healthy drain must still release the bytes,
// audit the delivery once, and leave nothing held.
func TestCHAOS128_ControlHealthyDrainStillReleasesTheBytesAndAudits(t *testing.T) {
	withTempUploadDir(t)
	resetUploadCommitHoldForTest(t)
	enableUploadForTest(t)
	id, _ := queuedUploadForTest(t, "ctl", "CASE-128F")
	baseline := time.Now().UnixMilli()

	calls := 0
	drainDueUploads(context.Background(), countingUpload("SIG-F", &calls))

	if calls != 1 {
		t.Fatalf("upload attempts = %d, want 1", calls)
	}
	e, ok := loadUploadQueueEntry(id)
	if !ok || e.State != uploadStateUploaded || e.Receipt == nil || e.Receipt.Sig != "SIG-F" {
		t.Fatalf("entry after a healthy drain = %+v (found=%v)", e, ok)
	}
	if _, err := os.Stat(sealedUploadPath(id)); !os.IsNotExist(err) {
		t.Errorf("a healthy drain must still remove the sealed blob, stat err = %v", err)
	}
	if !hasMatchingAuditEntry(auditGet(), "system", "support.bundle.upload", id, baseline) {
		t.Error("a healthy drain must still record support.bundle.upload")
	}
	if n := uploadCommitsHeld(); n != 0 {
		t.Errorf("held outcomes gauge = %d, want 0 — a healthy drain holds nothing", n)
	}
}

// ── 6. the exposition ───────────────────────────────────────────────────────

// Both series are what an operator alerts on, so their names and types are
// pinned here rather than left to drift with the Prometheus block.
func TestCHAOS128_HeldOutcomesAreScrapeable(t *testing.T) {
	withTempUploadDir(t)
	resetUploadCommitHoldForTest(t)
	enableUploadForTest(t)
	id, _ := queuedUploadForTest(t, "met", "CASE-128G")

	failSupportWritesAfterSetup(t)
	calls := 0
	drainDueUploads(context.Background(), countingUpload("SIG-G", &calls))
	if !uploadCommitIsHeld(id) {
		t.Fatalf("precondition: the outcome should be held")
	}

	var sb strings.Builder
	supportWritePrometheus(&sb)
	out := sb.String()
	for _, want := range []string{
		"# TYPE culvert_support_upload_commit_held_total counter",
		"# TYPE culvert_support_upload_commit_held gauge",
		"culvert_support_upload_commit_held 1\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Prometheus output missing %q", want)
		}
	}
}
