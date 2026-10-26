package alerts

// retry_durability_chaos93_test.go — CHAOS-93 regression gates for the alert
// retry queue's three defects: a pass that lost its unattempted entries on an
// ordinary restart (RT-1), a pass with no duration bound and no cancellation
// (RT-2), and a re-delivery recorded as if it were a first attempt (RT-5).
//
// All are whitebox on the package-level retry queue, so each one snapshots and
// restores that state (snapshotRetryQueue + snapshotRetryIDs) and redirects the
// persisted queue into a temp dir.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// snapshotRetryIDs restores the package's id issuer, which the pass and
// enqueueRetry both advance. Without it a test that enqueues entries leaks ids
// into the next test's expectations.
func snapshotRetryIDs(t *testing.T) {
	t.Helper()
	retryMu.Lock()
	orig := retryNextID
	retryMu.Unlock()
	t.Cleanup(func() {
		retryMu.Lock()
		retryNextID = orig
		retryMu.Unlock()
	})
}

// snapshotRetryDeliver restores the delivery seam.
func snapshotRetryDeliver(t *testing.T) {
	t.Helper()
	orig := retryDeliver
	t.Cleanup(func() { retryDeliver = orig })
}

// retryQueueInTempDir points the persisted queue at a temp file and returns its
// path. Mirrors the existing tests' use of SetRetryQueuePath.
func retryQueueInTempDir(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "alert_retry_queue.json")
	orig := RetryQueuePath()
	SetRetryQueuePath(path)
	t.Cleanup(func() { SetRetryQueuePath(orig) })
	return path
}

// readPersistedQueue is the restart oracle: it reads ONLY the file, the way a
// fresh process would, with no access to the dying process's memory.
func readPersistedQueue(t *testing.T, path string) []retryEntry {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test-owned temp path
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read persisted queue: %v", err)
	}
	var q []retryEntry
	if err := json.Unmarshal(data, &q); err != nil {
		t.Fatalf("unmarshal persisted queue: %v", err)
	}
	return q
}

// seedDueRetries puts n entries for hookID in the queue, all already due, and
// persists them — the state a node is in when a webhook origin has been
// blackholing deliveries for a while.
func seedDueRetries(t *testing.T, hookID string, n int) {
	t.Helper()
	retryMu.Lock()
	for i := 0; i < n; i++ {
		retryNextID++
		retryQueue = append(retryQueue, retryEntry{
			ID:        retryNextID,
			WebhookID: hookID,
			Payload:   Payload{Event: "policy_block", Detail: "host-" + itoa(i)},
			Attempt:   1,
			NextRetry: time.Now().Add(-time.Minute),
		})
	}
	saveRetryQueueLocked()
	retryMu.Unlock()
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func storeWithHook(id string, url string) *Store {
	return &Store{hooks: []Webhook{{ID: id, Name: "gate", URL: url, Enabled: true, Events: []string{"*"}}}}
}

// TestProcessRetryQueue_UnattemptedEntriesSurviveRestartMidPass is the RT-1
// gate. It runs a pass whose first delivery blocks, then asks the only question
// a restart asks: what is on disk?
//
// Pre-fix the answer was "nothing": the pass had already moved every due entry
// out of retryQueue and persisted the truncated queue before delivering any of
// them, so all nine unattempted alerts existed solely in a local slice and died
// with the process — with no counter, no delivery record and no log line.
func TestProcessRetryQueue_UnattemptedEntriesSurviveRestartMidPass(t *testing.T) {
	snapshotRetryQueue(t)
	snapshotRetryIDs(t)
	snapshotRetryDeliver(t)
	path := retryQueueInTempDir(t)

	const total = 10
	seedDueRetries(t, "hook-rt1", total)

	inFlight := make(chan struct{})
	release := make(chan struct{})
	var first bool
	retryDeliver = func(_ context.Context, _ *Store, _ Webhook, _ retryEntry) bool {
		if !first {
			first = true
			close(inFlight)
			<-release // hold the pass inside its first attempt
		}
		return false
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		processRetryQueue(context.Background(), storeWithHook("hook-rt1", "https://example.invalid/hook"))
	}()

	select {
	case <-inFlight:
	case <-time.After(5 * time.Second):
		t.Fatal("pass never reached a delivery")
	}

	// The process dies here. Everything the operator still expects to be
	// retried has to be in the file.
	persisted := readPersistedQueue(t, path)
	if len(persisted) != total {
		t.Fatalf("restart mid-pass lost queued alerts: persisted %d of %d entries", len(persisted), total)
	}

	// The claimed entry is held out of the ready set by the lease, but it is
	// still queued and still on its ORIGINAL attempt count — an attempt that
	// did not complete must not be charged.
	var claimedSeen int
	for i := range persisted {
		if persisted[i].Attempt != 1 {
			t.Errorf("entry %d: attempt charged to %d for an attempt that never resolved", persisted[i].ID, persisted[i].Attempt)
		}
		if persisted[i].NextRetry.After(time.Now()) {
			claimedSeen++
		}
	}
	if claimedSeen != 1 {
		t.Errorf("expected exactly 1 leased (claimed) entry, got %d", claimedSeen)
	}

	close(release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("pass did not finish after release")
	}
}

// TestProcessRetryQueue_PassIsCancellable is the RT-2 gate. processRetryQueue
// took no context and each delivery built its own from context.Background(), so
// a cancelled lifecycle could not stop a pass; against a blackholing webhook a
// full queue occupied the loop for ~42 minutes. The pass must now return
// promptly on cancellation and leave the remaining work durable.
func TestProcessRetryQueue_PassIsCancellable(t *testing.T) {
	snapshotRetryQueue(t)
	snapshotRetryIDs(t)
	snapshotRetryDeliver(t)
	path := retryQueueInTempDir(t)

	const total = 8
	seedDueRetries(t, "hook-rt2", total)

	ctx, cancel := context.WithCancel(context.Background())
	attempts := make(chan struct{}, total)
	retryDeliver = func(ctx context.Context, _ *Store, _ Webhook, _ retryEntry) bool {
		attempts <- struct{}{}
		<-ctx.Done() // a blackholing origin: nothing comes back until the deadline
		return false
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		processRetryQueue(ctx, storeWithHook("hook-rt2", "https://example.invalid/hook"))
	}()

	select {
	case <-attempts:
	case <-time.After(5 * time.Second):
		t.Fatal("pass never reached a delivery")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled pass did not return: a shutdown cannot interrupt the retry queue")
	}

	// Cancellation is not loss: one entry was attempted (and failed, so it is
	// re-armed), the rest are untouched and all of them are still on disk.
	if persisted := readPersistedQueue(t, path); len(persisted) != total {
		t.Errorf("cancelled pass lost entries: persisted %d of %d", len(persisted), total)
	}
	if n := len(attempts); n != 0 {
		t.Errorf("cancelled pass kept delivering: %d further attempts", n)
	}
}

// TestProcessRetryQueue_PassIsBoundedByBudget is the other half of RT-2: a pass
// stops at retryPassBudget rather than running until the queue is empty, so one
// pass can never become an unbounded stretch of uninterruptible work. Recovery
// is unaffected because the next tick resumes from the durable queue.
func TestProcessRetryQueue_PassIsBoundedByBudget(t *testing.T) {
	snapshotRetryQueue(t)
	snapshotRetryIDs(t)
	snapshotRetryDeliver(t)
	retryQueueInTempDir(t)

	origBudget := retryPassBudget
	retryPassBudget = 500 * time.Millisecond
	t.Cleanup(func() { retryPassBudget = origBudget })

	const total = 12
	seedDueRetries(t, "hook-budget", total)

	// Each attempt costs a fifth of the budget, so the pass must stop before it
	// has worked through all twelve.
	spend := retryPassBudget / 5
	var attempts int
	retryDeliver = func(_ context.Context, _ *Store, _ Webhook, _ retryEntry) bool {
		attempts++
		time.Sleep(spend)
		return false
	}

	start := time.Now()
	processRetryQueue(context.Background(), storeWithHook("hook-budget", "https://example.invalid/hook"))
	elapsed := time.Since(start)

	if attempts >= total {
		t.Errorf("pass ignored its budget: made %d attempts of %d queued", attempts, total)
	}
	if elapsed > retryPassBudget+2*spend {
		t.Errorf("pass overran its budget: %v > %v", elapsed, retryPassBudget)
	}
	if depth := RetryQueueDepth(); depth == 0 {
		t.Error("budgeted pass emptied the queue; the unattempted entries must stay queued")
	}
}

// TestProcessRetryQueue_RecordsRealAttemptNumber is the RT-5 gate. The pass
// delivered through Deliver, which hardcodes attempt 1, so the delivery history
// the admin surface renders could not tell a third attempt from a first.
func TestProcessRetryQueue_RecordsRealAttemptNumber(t *testing.T) {
	snapshotRetryQueue(t)
	snapshotRetryIDs(t)
	snapshotRetryCounters(t)
	retryQueueInTempDir(t)

	retryMu.Lock()
	retryNextID++
	retryQueue = append(retryQueue, retryEntry{
		ID:        retryNextID,
		WebhookID: "hook-rt5",
		Payload:   Payload{Event: "policy_block", Detail: "third attempt"},
		Attempt:   2,
		NextRetry: time.Now().Add(-time.Minute),
	})
	saveRetryQueueLocked()
	retryMu.Unlock()

	// An unparseable URL fails at the regexp barrier, so this exercises the real
	// delivery path (and its record) without any network or SSRF dependency.
	store := storeWithHook("hook-rt5", "not-a-url")
	processRetryQueue(context.Background(), store)

	hist := store.DeliveryHistory()
	if len(hist) == 0 {
		t.Fatal("no delivery recorded")
	}
	if hist[0].Attempt != 2 {
		t.Errorf("delivery recorded as attempt %d, want the entry's real attempt 2", hist[0].Attempt)
	}
}

// TestAssignRetryIDs_RenumbersQueuePersistedBeforeIDsExisted pins the wire
// compatibility of adding retryEntry.ID: a queue written by an older build has
// no `id` field, so every entry loads as 0 — and an id of 0 matches nothing in
// removeRetryLocked, which would leave such entries claimable but never
// removable. Load renumbers them, and seeds the issuer past the file's maximum
// so a restart cannot reissue a live id.
func TestAssignRetryIDs_RenumbersQueuePersistedBeforeIDsExisted(t *testing.T) {
	snapshotRetryQueue(t)
	snapshotRetryIDs(t)

	retryMu.Lock()
	retryNextID = 0
	retryQueue = []retryEntry{
		{WebhookID: "legacy-a", Attempt: 1},         // no id: pre-upgrade entry
		{ID: 7, WebhookID: "current-b", Attempt: 1}, // written by this build
		{WebhookID: "legacy-c", Attempt: 2},
	}
	assignRetryIDsLocked()
	queue := append([]retryEntry(nil), retryQueue...)
	issuer := retryNextID
	retryMu.Unlock()

	seen := map[uint64]string{}
	for i := range queue {
		if queue[i].ID == 0 {
			t.Errorf("%s kept id 0 after load: it could be claimed but never removed", queue[i].WebhookID)
		}
		if prev, dup := seen[queue[i].ID]; dup {
			t.Errorf("id %d assigned to both %s and %s", queue[i].ID, prev, queue[i].WebhookID)
		}
		seen[queue[i].ID] = queue[i].WebhookID
	}
	if issuer < 7 {
		t.Errorf("issuer seeded to %d, below the id 7 already in the file", issuer)
	}
	for id := range seen {
		if id > issuer {
			t.Errorf("issuer %d is behind live id %d; a restart would reissue it", issuer, id)
		}
	}
}

// TestResolveRetry_FailedAttemptIsRearmedNotLost pins the resolve half: a failed
// delivery leaves exactly one entry queued for the next attempt, with the
// attempt count advanced, and the claimed entry gone — never both, never
// neither.
func TestResolveRetry_FailedAttemptIsRearmedNotLost(t *testing.T) {
	snapshotRetryQueue(t)
	snapshotRetryIDs(t)
	snapshotRetryCounters(t)
	path := retryQueueInTempDir(t)

	seedDueRetries(t, "hook-resolve", 1)
	claimed, ok := claimNextRetry(time.Now())
	if !ok {
		t.Fatal("nothing claimable")
	}

	resolveRetry(claimed, false)

	persisted := readPersistedQueue(t, path)
	if len(persisted) != 1 {
		t.Fatalf("expected exactly 1 re-armed entry, got %d", len(persisted))
	}
	if persisted[0].ID == claimed.ID {
		t.Error("resolved entry kept its claim id: the claim was never closed out")
	}
	if persisted[0].Attempt != claimed.Attempt+1 {
		t.Errorf("re-armed at attempt %d, want %d", persisted[0].Attempt, claimed.Attempt+1)
	}

	// And a successful one leaves nothing behind.
	claimed2, ok := claimNextRetry(persisted[0].NextRetry.Add(time.Second))
	if !ok {
		t.Fatal("re-armed entry not claimable after its backoff")
	}
	resolveRetry(claimed2, true)
	if got := readPersistedQueue(t, path); len(got) != 0 {
		t.Errorf("delivered entry stayed queued: %d entries", len(got))
	}
}
