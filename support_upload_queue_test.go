package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/supportupload"
)

// csbID builds a valid support-bundle id (csb_ + 26 base32 chars) from a short
// seed — supportBundleIDRe rejects anything else, which the queue relies on to
// keep filenames traversal-safe.
func csbID(seed string) string {
	return "csb_" + seed + strings.Repeat("a", 26-len(seed))
}

func TestEnqueueUpload_PersistAndList(t *testing.T) {
	withTempUploadDir(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	id := csbID("one")
	e, err := enqueueUpload(id, "CASE-1", "tac-2026", "deadbeef", now)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if e.State != uploadStateQueued {
		t.Fatalf("new entry state = %q, want queued", e.State)
	}
	// Survives a "restart": read back from disk.
	list := listUploadQueue()
	if len(list) != 1 || list[0].BundleID != id || list[0].CaseID != "CASE-1" {
		t.Fatalf("listUploadQueue = %+v", list)
	}
	if list[0].State != uploadStateQueued {
		t.Fatalf("persisted state = %q, want queued", list[0].State)
	}
}

func TestEnqueueUpload_IdempotentAndReArm(t *testing.T) {
	withTempUploadDir(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	id := csbID("two")
	if _, err := enqueueUpload(id, "C", "", "h", now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// Re-enqueue while queued → no duplicate.
	if _, err := enqueueUpload(id, "C", "", "h", now); err != nil {
		t.Fatalf("re-enqueue: %v", err)
	}
	if n := len(listUploadQueue()); n != 1 {
		t.Fatalf("re-enqueue created %d entries, want 1", n)
	}
	// Move it to deferred, then re-enqueue → re-armed to queued, attempts reset.
	e, _ := loadQueueEntryForTest(t, id)
	e.State = uploadStateDeferred
	e.Attempts = maxUploadAttempts
	e.LastError = "boom"
	if err := saveUploadQueueEntry(e); err != nil {
		t.Fatalf("save: %v", err)
	}
	rearmed, err := enqueueUpload(id, "C", "", "h", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("re-arm: %v", err)
	}
	if rearmed.State != uploadStateQueued || rearmed.Attempts != 0 || rearmed.LastError != "" {
		t.Fatalf("re-arm did not reset: %+v", rearmed)
	}
}

func TestEnqueueUpload_CapEnforced(t *testing.T) {
	withTempUploadDir(t)
	prev := maxUploadQueue
	maxUploadQueue = 2
	defer func() { maxUploadQueue = prev }()
	now := time.Unix(1_700_000_000, 0).UTC()
	if _, err := enqueueUpload(csbID("a"), "C", "", "h", now); err != nil {
		t.Fatalf("enqueue 1: %v", err)
	}
	if _, err := enqueueUpload(csbID("b"), "C", "", "h", now); err != nil {
		t.Fatalf("enqueue 2: %v", err)
	}
	if _, err := enqueueUpload(csbID("c"), "C", "", "h", now); err == nil {
		t.Fatal("enqueue past the cap must be refused")
	}
}

func TestEnqueueUpload_RejectedReArmRespectsCapacity(t *testing.T) {
	withTempUploadDir(t)
	prev := maxUploadQueue
	maxUploadQueue = 2
	defer func() { maxUploadQueue = prev }()
	now := time.Unix(1_700_000_000, 0).UTC()

	// A rejected (terminal) entry, plus a full non-terminal queue.
	rj := csbID("rjx")
	e, err := enqueueUpload(rj, "C", "", "h", now)
	if err != nil {
		t.Fatalf("enqueue rejected seed: %v", err)
	}
	e.State = uploadStateRejected
	if err := saveUploadQueueEntry(e); err != nil {
		t.Fatalf("save rejected: %v", err)
	}
	if _, err := enqueueUpload(csbID("pxa"), "C", "", "h", now); err != nil {
		t.Fatalf("enqueue pxa: %v", err)
	}
	if _, err := enqueueUpload(csbID("pxb"), "C", "", "h", now); err != nil {
		t.Fatalf("enqueue pxb: %v", err)
	}
	// Re-arming the rejected entry now would make 3 non-terminal entries > cap 2.
	if _, err := enqueueUpload(rj, "C", "", "h", now); err == nil {
		t.Fatal("re-arming a rejected entry past the capacity bound must be refused")
	}
	// A deferred re-arm (already counted as pending) is NOT blocked by the cap.
	df := csbID("pxa")
	d, _ := loadQueueEntryForTest(t, df)
	d.State = uploadStateDeferred
	if err := saveUploadQueueEntry(d); err != nil {
		t.Fatalf("save deferred: %v", err)
	}
	if _, err := enqueueUpload(df, "C", "", "h", now); err != nil {
		t.Fatalf("deferred re-arm should not be capacity-blocked: %v", err)
	}
}

func TestLoadUploadQueueEntry_RejectsBundleIDMismatch(t *testing.T) {
	withTempUploadDir(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	good := csbID("good")
	if _, err := enqueueUpload(good, "C", "", "h", now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// Tamper the on-disk record so its BundleID points at a DIFFERENT valid id,
	// keeping the file valid JSON. The loader must reject it rather than hand back
	// an entry whose BundleID would delete the wrong path on prune.
	e, ok := loadQueueEntryForTest(t, good)
	if !ok {
		t.Fatal("seed entry missing")
	}
	e.BundleID = csbID("evil")
	b, _ := json.MarshalIndent(e, "", "  ")
	if err := os.WriteFile(uploadQueuePath(good), b, 0o600); err != nil {
		t.Fatalf("tamper write: %v", err)
	}
	// The mismatched record is skipped, so the queue is empty (not returning a
	// record keyed to "evil").
	if list := listUploadQueue(); len(list) != 0 {
		t.Fatalf("mismatched entry not skipped: %+v", list)
	}
}

func TestEnqueueUpload_TerminalRetentionBounded(t *testing.T) {
	withTempUploadDir(t)
	prev := maxUploadTerminal
	maxUploadTerminal = 2
	defer func() { maxUploadTerminal = prev }()
	base := time.Unix(1_700_000_000, 0).UTC()

	// Create 4 terminal (uploaded) records with increasing CreatedAt, then a
	// fresh enqueue triggers the prune down to the newest 2 terminal.
	for i := 0; i < 4; i++ {
		id := csbID(strings.Repeat("t", 1) + string(rune('a'+i)))
		e, err := enqueueUpload(id, "C", "", "h", base.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
		e.State = uploadStateUploaded
		if err := saveUploadQueueEntry(e); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	// A new enqueue prunes oldest terminal beyond the cap.
	if _, err := enqueueUpload(csbID("live"), "C", "", "h", base.Add(10*time.Second)); err != nil {
		t.Fatalf("enqueue live: %v", err)
	}
	terminal := 0
	for _, e := range listUploadQueue() {
		if e.State == uploadStateUploaded || e.State == uploadStateRejected {
			terminal++
		}
	}
	if terminal != 2 {
		t.Fatalf("terminal records = %d, want capped at 2", terminal)
	}
}

func TestDrainUploadEntry_Success(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	e := uploadQueueEntry{BundleID: csbID("ok"), State: uploadStateQueued, BundleSHA256: "h"}
	up := func(_ context.Context, _ uploadQueueEntry) (*supportupload.Receipt, string, error) {
		return &supportupload.Receipt{BundleSHA256: "h", Sig: "sig"}, "up-123", nil
	}
	got := drainUploadEntry(context.Background(), e, up, now)
	if got.State != uploadStateUploaded || got.Receipt == nil || got.Receipt.Sig != "sig" {
		t.Fatalf("success drain = %+v", got)
	}
	if got.UploadID != "up-123" {
		t.Fatalf("success drain did not capture upload id: %q", got.UploadID)
	}
}

func TestDrainUploadEntry_TransientCapturesUploadID(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	e := uploadQueueEntry{BundleID: csbID("rid"), State: uploadStateQueued}
	// The uploader reaches init (gets a session id) then hits a transient error.
	up := func(_ context.Context, _ uploadQueueEntry) (*supportupload.Receipt, string, error) {
		return nil, "sess-9", errors.New("connection reset after init")
	}
	got := drainUploadEntry(context.Background(), e, up, now)
	if got.State != uploadStateQueued {
		t.Fatalf("transient state = %q, want queued", got.State)
	}
	if got.UploadID != "sess-9" {
		t.Fatalf("transient drain must persist the gateway session id, got %q", got.UploadID)
	}
}

func TestDrainUploadEntry_TransientRetryThenDeferred(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	e := uploadQueueEntry{BundleID: csbID("rt"), State: uploadStateQueued}
	up := func(_ context.Context, _ uploadQueueEntry) (*supportupload.Receipt, string, error) {
		return nil, "", errors.New("connection refused")
	}
	// Each transient failure re-queues with a backoff until the cap → deferred.
	for i := 1; i < maxUploadAttempts; i++ {
		e = drainUploadEntry(context.Background(), e, up, now)
		if e.State != uploadStateQueued {
			t.Fatalf("attempt %d state = %q, want queued", i, e.State)
		}
		if e.Attempts != i {
			t.Fatalf("attempt count = %d, want %d", e.Attempts, i)
		}
		if e.NextRetryAt <= now.Unix() {
			t.Fatalf("attempt %d did not schedule a future retry", i)
		}
	}
	// The cap-th failure defers.
	e = drainUploadEntry(context.Background(), e, up, now)
	if e.State != uploadStateDeferred {
		t.Fatalf("final state = %q, want deferred", e.State)
	}
	if e.NextRetryAt != 0 {
		t.Errorf("deferred entry should carry no retry time")
	}
	if e.LastError == "" {
		t.Errorf("deferred entry should record the last error")
	}
}

func TestDrainUploadEntry_GatewayRejectTerminal(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	e := uploadQueueEntry{BundleID: csbID("rj"), State: uploadStateQueued}
	up := func(_ context.Context, _ uploadQueueEntry) (*supportupload.Receipt, string, error) {
		return nil, "", &supportupload.GatewayError{Status: 403, Body: "not entitled"}
	}
	got := drainUploadEntry(context.Background(), e, up, now)
	if got.State != uploadStateRejected {
		t.Fatalf("4xx gateway rejection state = %q, want rejected", got.State)
	}
	if got.NextRetryAt != 0 {
		t.Error("a rejected entry must not schedule a retry")
	}
	// A 5xx is transient (retried), not terminal.
	e5 := uploadQueueEntry{BundleID: csbID("g5"), State: uploadStateQueued}
	up5 := func(_ context.Context, _ uploadQueueEntry) (*supportupload.Receipt, string, error) {
		return nil, "", &supportupload.GatewayError{Status: 503, Body: "unavailable"}
	}
	got5 := drainUploadEntry(context.Background(), e5, up5, now)
	if got5.State != uploadStateQueued {
		t.Fatalf("5xx state = %q, want queued (transient)", got5.State)
	}
}

func TestUploadRetryBackoff(t *testing.T) {
	cases := map[int]time.Duration{
		1:  2 * time.Second,
		2:  4 * time.Second,
		3:  8 * time.Second,
		4:  16 * time.Second,
		30: uploadRetryCap, // overflow guard → cap
	}
	for attempts, want := range cases {
		if got := uploadRetryBackoff(attempts); got != want {
			t.Errorf("backoff(%d) = %s, want %s", attempts, got, want)
		}
	}
	if uploadRetryBackoff(20) > uploadRetryCap {
		t.Error("backoff must never exceed the cap")
	}
}

func TestDueUploadEntries(t *testing.T) {
	withTempUploadDir(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	// Queued + due (no NextRetryAt).
	dueID := csbID("due")
	if _, err := enqueueUpload(dueID, "C", "", "h", now); err != nil {
		t.Fatalf("enqueue due: %v", err)
	}
	// Queued but scheduled in the future.
	futID := csbID("fut")
	fut, _ := enqueueUpload(futID, "C", "", "h", now)
	fut.NextRetryAt = now.Add(time.Hour).Unix()
	_ = saveUploadQueueEntry(fut)
	// Deferred is never due.
	defID := csbID("def")
	def, _ := enqueueUpload(defID, "C", "", "h", now)
	def.State = uploadStateDeferred
	_ = saveUploadQueueEntry(def)

	due := dueUploadEntries(now)
	if len(due) != 1 || due[0].BundleID != dueID {
		t.Fatalf("dueUploadEntries = %+v, want only %s", due, dueID)
	}
}

// loadQueueEntryForTest reads one entry back through the exported list (there is
// no exported single-entry getter — the worker loads via the list/due paths).
func loadQueueEntryForTest(t *testing.T, bundleID string) (uploadQueueEntry, bool) {
	t.Helper()
	list := listUploadQueue()
	for i := range list {
		if list[i].BundleID == bundleID {
			return list[i], true
		}
	}
	return uploadQueueEntry{}, false
}
