package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/session"
)

// CHAOS-68 AU-40/AU-41 — the HA state bundle stays inside the CP↔DP frame, and
// the leader repairs its own revocations file.
//
// Codex raised AU-40 as a P1 on PR #1437: this sweep put an UNBOUNDED list
// (`Revoke` has no cap, the CP aggregates the fleet, entries live to their
// session expiry) into a bundle whose headroom is maxClusterGRPCMsgSize minus a
// published config that may itself be at maxSnapshotWireBytes. gRPC rejects the
// whole over-size message, so the standby loses config, CA material, cluster
// state AND revocations — failover readiness gone until entries expire.
//
// Every DEFECT gate here was verified failing against the pre-fix shape (a bare
// `json.Marshal(bundle)` with no budget). The CONTROLS matter as much: the
// cheapest way to pass every defect gate is to trim always, or to stop carrying
// revocations at all, either of which silently deletes the replication AU-24
// added — so a healthy bundle must be proven to carry everything.

// haTestBundle builds a bundle whose non-revocation members are small and
// fixed, so a byte budget in the test is about the revocations and nothing else.
func haTestBundle(entries []RevocationEntry) HAStateBundle {
	return HAStateBundle{
		ClusterState: json.RawMessage(`{"nodes":[]}`),
		CACertPEM:    "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
		Version:      7,
		Revocations:  entries,
	}
}

// haTokenEntries returns n token revocations in DESCENDING token order.
//
// Descending is deliberate, not incidental: ExportRevocations walks Go maps, so
// its output is unordered, and a fixture that happens to arrive already sorted
// makes an in-place sort of the caller's slice invisible — the no-mutation
// assertion then passes against a fitRevocationsToBudget that dropped its
// defensive copy (measured).
func haTokenEntries(n int, expiry int64) []RevocationEntry {
	out := make([]RevocationEntry, 0, n)
	for i := n - 1; i >= 0; i-- {
		out = append(out, RevocationEntry{Token: fmt.Sprintf("tok-%04d-payload", i), Expiry: expiry})
	}
	return out
}

// DEFECT: an over-budget bundle is brought back inside the frame.
//
// Pre-fix this returned the full marshal, which gRPC rejects wholesale — the
// standby then gets nothing at all, which is why trimming is the fail-SAFER
// answer rather than a convenience.
func TestChaos68_AU40_OverBudgetBundleIsTrimmedToFit(t *testing.T) {
	withChaos68Revocations(t)

	bundle := haTestBundle(haTokenEntries(200, 9_000_000_000))
	full, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	budget := len(full) / 2

	got, err := marshalHABundleWithinFrame(bundle, budget)
	if err != nil {
		t.Fatalf("marshalHABundleWithinFrame: %v", err)
	}
	if len(got) > budget {
		t.Fatalf("bundle is %d bytes, over the %d byte budget — the standby's sync would be rejected", len(got), budget)
	}
	if dropped := haBundleRevocationsDropped.Load(); dropped == 0 {
		t.Fatal("trimmed the bundle without counting a single dropped revocation — the operator has no signal that the standby holds a subset")
	}

	// The caller's slice must come back untouched — same length AND same order.
	// Length alone is not enough: fitRevocationsToBudget sorts, so dropping its
	// defensive copy reorders the caller's backing array in place while every
	// length assertion still passes.
	want := haTokenEntries(200, 9_000_000_000)
	if len(bundle.Revocations) != len(want) {
		t.Fatalf("the caller's revocation slice was shortened: %d entries left of %d", len(bundle.Revocations), len(want))
	}
	for i := range want {
		if bundle.Revocations[i] != want[i] {
			t.Fatalf("the caller's revocation slice was reordered at %d: got %+v, want %+v", i, bundle.Revocations[i], want[i])
		}
	}

	var out HAStateBundle
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("trimmed bundle does not parse: %v", err)
	}
	if out.Version != 7 || len(out.ClusterState) == 0 || out.CACertPEM == "" {
		t.Fatal("the trim dropped a non-revocation member — config, CA and cluster state are exactly what must survive")
	}
	if len(out.Revocations) == 0 {
		t.Fatal("trimmed to nothing: half the bundle was revocations, so some must still fit")
	}
}

// CONTROL: a bundle inside the budget carries EVERY revocation.
//
// Trimming unconditionally passes the defect gate above while silently
// replicating a subset on every healthy cluster in the fleet.
func TestChaos68_AU40_ControlHealthyBundleCarriesEveryRevocation(t *testing.T) {
	withChaos68Revocations(t)

	entries := haTokenEntries(50, 9_000_000_000)
	got, err := marshalHABundleWithinFrame(haTestBundle(entries), maxHABundleWireBytes)
	if err != nil {
		t.Fatalf("marshalHABundleWithinFrame: %v", err)
	}
	var out HAStateBundle
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out.Revocations) != len(entries) {
		t.Fatalf("carried %d of %d revocations on a bundle that fits — the standby must receive the leader's whole list", len(out.Revocations), len(entries))
	}
	if dropped := haBundleRevocationsDropped.Load(); dropped != 0 {
		t.Fatalf("counted %d dropped revocations on a bundle that fits", dropped)
	}
	// Entering the trim path at all is a defect even when it drops nothing: it
	// re-marshals the revocations on every poll and emits the "over the frame
	// budget" line, a standing false alarm about the one condition this whole
	// mechanism exists to report. Removing the `len(resp) <= budget` early
	// return passes every other assertion here, so the log gate's stamp is what
	// makes this a control rather than a restatement of the defect gate.
	if haBundleOverBudgetLogged.Load() != 0 {
		t.Fatal("a bundle that fits reported itself over the frame budget — the over-budget line must name a real overflow or operators will learn to ignore it")
	}
}

// DEFECT: the kept set is the highest-value prefix, not an arbitrary one.
//
// ExportRevocations walks Go maps, so without an explicit order the trim would
// carry a different arbitrary subset on every poll.
func TestChaos68_AU40_TrimKeepsAccountRevocationsAndLongestLivedFirst(t *testing.T) {
	entries := []RevocationEntry{
		{Token: "tok-short", Expiry: 100},
		{Token: "tok-long", Expiry: 9_000},
		{Token: "user:alice", User: "alice", Expiry: 100},
	}
	// Budget for exactly two of the three.
	var two int
	for _, e := range []RevocationEntry{entries[2], entries[1]} {
		b, _ := json.Marshal(e)
		two += len(b)
	}
	kept, dropped := fitRevocationsToBudget(entries, two+len("[],"))
	if dropped != 1 || len(kept) != 2 {
		t.Fatalf("kept %d dropped %d, want 2/1", len(kept), dropped)
	}
	if kept[0].User != "alice" {
		t.Fatalf("first kept is %+v — an account revocation withdraws every session that identity holds and must outrank a single token", kept[0])
	}
	if kept[1].Token != "tok-long" {
		t.Fatalf("second kept is %+v — a revocation expiring sooner protects for less time and must be dropped first", kept[1])
	}
}

// DEFECT: the kept set is deterministic across map-iteration order.
func TestChaos68_AU40_TrimIsDeterministic(t *testing.T) {
	base := haTokenEntries(40, 9_000_000_000)
	shuffled := make([]RevocationEntry, len(base))
	for i := range base {
		shuffled[len(base)-1-i] = base[i]
	}
	budget := 600

	a, da := fitRevocationsToBudget(base, budget)
	b, db := fitRevocationsToBudget(shuffled, budget)
	if da != db || len(a) != len(b) {
		t.Fatalf("input order changed the outcome: %d/%d vs %d/%d", len(a), da, len(b), db)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("entry %d differs by input order: %+v vs %+v", i, a[i], b[i])
		}
	}
	if da == 0 {
		t.Fatal("budget did not force a trim — the gate proves nothing")
	}
}

// DEFECT: a bundle over budget with no revocations to give back is REPORTED,
// not silently shipped and not turned into a second failure.
//
// The overflow belongs to the config or the cluster state, so no trim here can
// repair it. Refusing would replace one failed sync with another while losing
// the only line that names which member is too big.
func TestChaos68_AU40_OverBudgetWithoutRevocationsIsReportedNotRefused(t *testing.T) {
	withChaos68Revocations(t)

	bundle := haTestBundle(nil)
	got, err := marshalHABundleWithinFrame(bundle, 8)
	if err != nil {
		t.Fatalf("an unrepairable overflow must not become an error: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("returned an empty body — the standby would apply an EMPTY bundle and record the sync as successful")
	}
	if dropped := haBundleRevocationsDropped.Load(); dropped != 0 {
		t.Fatalf("charged %d dropped revocations when there were none to drop", dropped)
	}
}

// CONTROL: the frame budget really is below the frame it protects.
//
// A budget at or above maxClusterGRPCMsgSize passes every gate above while
// leaving gRPC to reject the bundle exactly as before.
func TestChaos68_AU40_ControlBudgetIsBelowTheFrame(t *testing.T) {
	if maxHABundleWireBytes >= maxClusterGRPCMsgSize {
		t.Fatalf("maxHABundleWireBytes=%d must leave gRPC framing slack below maxClusterGRPCMsgSize=%d", maxHABundleWireBytes, maxClusterGRPCMsgSize)
	}
	if maxHABundleWireBytes < maxSnapshotWireBytes {
		t.Fatalf("maxHABundleWireBytes=%d is below the config budget %d it must contain — every published config would trim", maxHABundleWireBytes, maxSnapshotWireBytes)
	}
}

// DEFECT (AU-41): the CP leader repairs its OWN revocations file.
//
// mergeAndPersistRevocations rewrites a vanished file, and all three of its
// call sites are RECEIVERS — the CP's SyncRevocations handler (a Data Plane
// must call in), the DP sync loop, and the standby applying the bundle. A CP
// leader with an HA standby and no connected Data Planes receives nothing, so
// its file could vanish and its revocations would stay memory-only until the
// next logout, with a restart before that accepting the sessions again — while
// the contract row told the operator a sync would rewrite it.
//
// Verified failing against the pre-fix handler (no repair call): the file
// stayed absent across the poll.
func TestChaos68_AU41_LeaderRepairsItsOwnRevocationsFileOnHASync(t *testing.T) {
	withChaos68Revocations(t)
	defer swapGlobalHA(t)()

	path := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(path)
	sessionRevoked.RevokeUser("departing-admin")
	if err := sessionRevoked.SaveRevocations(); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	// The file is carried off — a deleted file, or a replaced mount. No write
	// was attempted, so nothing observes it on its own.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	globalHA.mu.Lock()
	globalHA.role = "leader"
	globalHA.token = "leader-token"
	globalHA.mu.Unlock()

	svc := &controlPlaneServer{}
	reqBytes, _ := json.Marshal(map[string]string{"token": "leader-token"})
	if _, err := svc.HASync(context.Background(), json.RawMessage(reqBytes)); err != nil {
		t.Fatalf("HASync: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the leader did not rewrite its vanished revocations file: %v", err)
	}
	if !strings.Contains(string(data), "departing-admin") {
		t.Fatalf("the rewritten file does not carry the live revocation: %s", data)
	}
}

// CONTROL: the repair is SELF-LIMITING — a leader whose file is present does
// not rewrite it on every poll.
//
// The standby polls every few seconds, so an unconditional save would be a
// write per poll for the life of the cluster: a mitigation for a durability
// defect must not become a write-amplification one.
func TestChaos68_AU41_ControlHealthyLeaderDoesNotRewriteEveryPoll(t *testing.T) {
	withChaos68Revocations(t)
	defer swapGlobalHA(t)()

	path := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(path)
	sessionRevoked.RevokeUser("departing-admin")
	if err := sessionRevoked.SaveRevocations(); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	// A sentinel the real file format would never produce. It survives exactly
	// as long as nothing writes. os.Remove is NOT the instrument here: a
	// missing file is itself a reason to write, so removing it would create the
	// condition this control exists to rule out.
	if err := os.WriteFile(path, []byte("SENTINEL-NOT-REWRITTEN"), 0o600); err != nil {
		t.Fatalf("scribble: %v", err)
	}

	globalHA.mu.Lock()
	globalHA.role = "leader"
	globalHA.token = "leader-token"
	globalHA.mu.Unlock()

	svc := &controlPlaneServer{}
	reqBytes, _ := json.Marshal(map[string]string{"token": "leader-token"})
	for range 3 {
		if _, err := svc.HASync(context.Background(), json.RawMessage(reqBytes)); err != nil {
			t.Fatalf("HASync: %v", err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "SENTINEL-NOT-REWRITTEN" {
		t.Fatalf("a healthy leader rewrote its revocations file on an ordinary poll: %s", data)
	}
}

// DEFECT (AU-42): the persist-failure row must not render SAVE ATTEMPTS as a
// count of revocations.
//
// The observer fires once per failed SaveRevocations call, and two callers make
// the two numbers diverge by orders of magnitude: the AU-31 boot probe attempts
// a save on an EMPTY list, and the cluster sync loop retries every 3-5s while a
// volume is broken. The row said "N session revocation(s) could not be written"
// and the metric help agreed, so one fault appeared as hundreds of affected
// sessions and overstated the operator's re-apply job by that factor.
//
// The true scope is the LIVE list, because SaveRevocations writes it whole.
func TestChaos68_AU42_PersistRowReportsAttemptsAndScopeSeparately(t *testing.T) {
	withChaos68Revocations(t)

	// One revocation in force, many failed attempts against it — the shape the
	// retry loop produces.
	sessionRevoked.RevokeUser("departing-admin")
	for range 120 {
		noteRevocationPersistFailure(errRevocationTestWrite)
	}

	row := checkSessionRevocation()
	if row.Status != diagFail {
		t.Fatalf("status %v, want fail while writes are failing", row.Status)
	}
	if strings.Contains(row.Message, "120 session revocation") {
		t.Fatalf("the row reports 120 revocations when one is in force — that is the attempt count, and it is the operator's re-apply job it misstates:\n%s", row.Message)
	}
	if !strings.Contains(row.Message, "120 failed save attempt") {
		t.Fatalf("the row drops the attempt count, which is the magnitude of the incident:\n%s", row.Message)
	}
	if !strings.Contains(row.Message, "1 account revocation") {
		t.Fatalf("the row does not name the live scope — what a restart actually loses:\n%s", row.Message)
	}
}

// CONTROL: the attempt counter is still reported.
//
// The cheapest way to pass the gate above is to stop printing the count
// altogether, which deletes the operator's only measure of how long the volume
// has been failing.
func TestChaos68_AU42_ControlAttemptCountIsStillVisible(t *testing.T) {
	withChaos68Revocations(t)
	noteRevocationPersistFailure(errRevocationTestWrite)

	row := checkSessionRevocation()
	if !strings.Contains(row.Message, "1 failed save attempt") {
		t.Fatalf("the incident's magnitude is gone from the row:\n%s", row.Message)
	}
}

var errRevocationTestWrite = errors.New("no space left on device")

// DEFECT: a bundle still over budget AFTER surrendering every revocation is
// both COUNTED and EXPLAINED.
//
// This is the worst of the two overflow cases — every revocation dropped and
// the sync still rejected — and the first shape of the fix reported only the
// other one, so it was counted and never explained.
func TestChaos68_AU40_TrimmedToNothingAndStillOverBudgetIsReported(t *testing.T) {
	withChaos68Revocations(t)

	bundle := haTestBundle(haTokenEntries(20, 9_000_000_000))
	// Smaller than the bundle's non-revocation members, so surrendering every
	// revocation still cannot bring it inside.
	got, err := marshalHABundleWithinFrame(bundle, 40)
	if err != nil {
		t.Fatalf("marshalHABundleWithinFrame: %v", err)
	}
	if dropped := haBundleRevocationsDropped.Load(); dropped != 20 {
		t.Fatalf("dropped %d of 20 revocations — every one had to go and each must be counted", dropped)
	}
	if haBundleOverBudgetLogged.Load() == 0 {
		t.Fatal("gave up every revocation and stayed over budget without saying so — the operator sees a subset counted and no reason the sync is still failing")
	}
	if len(got) == 0 {
		t.Fatal("returned an empty body")
	}
}

// The drop count reaches /healthz, and ONLY when non-zero.
//
// A counter nobody reads is not a surface. HA sync keeps working through a
// trim, so every other signal stays green — this is the one place an operator
// who is not scraping /metrics can see that the standby holds a subset. The
// non-zero condition follows the CHAOS-61 precedent beside it: a flat zero on
// every healthy leader in the fleet is noise, and noise is how a real signal
// gets ignored.
func TestChaos68_AU40_DropCountReachesHealthzOnlyWhenNonZero(t *testing.T) {
	withChaos68Revocations(t)
	defer swapGlobalHA(t)()

	resp := map[string]any{}
	addRequestLogHealth(resp)
	if _, present := resp["haBundleRevocationsDropped"]; present {
		t.Fatal("a healthy leader reports a drop field — a flat zero on every appliance is how a real signal gets ignored")
	}

	noteHABundleRevocations(3)
	resp = map[string]any{}
	addRequestLogHealth(resp)
	got, present := resp["haBundleRevocationsDropped"]
	if !present {
		t.Fatal("the standby is holding a subset of this leader's revocations and /healthz does not say so")
	}
	if n, _ := got.(int64); n != 3 {
		t.Fatalf("reported %v, want 3", got)
	}
}

// haHealthzHeldSubset reports the /healthz drop field, or -1 when the field is
// absent. Absent is the healthy answer, and the distinction is the whole of
// AU-43: a leader that has recovered must stop making the claim, not report a
// stale number.
func haHealthzHeldSubset(t *testing.T) int64 {
	t.Helper()
	resp := map[string]any{}
	addRequestLogHealth(resp)
	v, present := resp["haBundleRevocationsDropped"]
	if !present {
		return -1
	}
	n, ok := v.(int64)
	if !ok {
		t.Fatalf("/healthz drop field is %T, want int64", v)
	}
	return n
}

// DEFECT (AU-43): the present-tense surfaces clear when a later bundle carries
// the complete set.
//
// Codex raised this as a P2 on PR #1437, and it is the THIRD instance of one
// rule in this tree — `ca_health.go` fixed it for the CA rotation persist
// warning, AU-25 fixed it for `revocationsAreDurable` in this same sweep, and
// AU-40 then keyed /healthz and the documented alert rule on the cumulative
// counter a hundred lines from the note recording the rule.
//
// The condition genuinely recovers: `ExportRevocations` returns only
// non-expired entries so the backlog drains by itself, the trim's priority
// order makes the dropped tail self-clearing, and the published config sharing
// the frame can shrink. Pre-fix, one transient trim pinned "a promotion would
// admit sessions this leader currently rejects" for the life of the process.
func TestChaos68_AU43_SubsetSurfacesClearWhenAFullBundleGoesOut(t *testing.T) {
	withChaos68Revocations(t)
	defer swapGlobalHA(t)()

	bundle := haTestBundle(haTokenEntries(40, 9_000_000_000))
	full, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}

	// A frame too tight for the backlog: the standby is replicated a subset.
	if _, err := marshalHABundleWithinFrame(bundle, len(full)/2); err != nil {
		t.Fatalf("marshalHABundleWithinFrame (trimmed): %v", err)
	}
	dropped := haHealthzHeldSubset(t)
	if dropped <= 0 {
		t.Fatalf("/healthz reported %d after a trim — the fixture did not exercise the trim, so this gate proves nothing", dropped)
	}

	// Entries expire, or the config shrinks, and the very next bundle carries
	// everything. THIS is the assertion the counter-driven shape fails.
	if _, err := marshalHABundleWithinFrame(bundle, len(full)); err != nil {
		t.Fatalf("marshalHABundleWithinFrame (complete): %v", err)
	}
	if got := haHealthzHeldSubset(t); got != -1 {
		t.Fatalf("a bundle that carried every revocation left /healthz still reporting %d dropped: a present-tense claim keyed on a value that never decreases (AU-43)", got)
	}
	if n := haBundleRevocationsSubset.Load(); n != 0 {
		t.Fatalf("the current-state gauge reads %d after a complete bundle, want 0", n)
	}
}

// CONTROL: recovery must not erase the MAGNITUDE.
//
// The cheapest way to pass the gate above is to zero the cumulative counter
// when a full bundle goes out — which would delete the only record that this
// leader has been running against its frame at all, and with it any `increase`
// or rate alert built on the _total series.
func TestChaos68_AU43_ControlCumulativeTotalSurvivesRecovery(t *testing.T) {
	withChaos68Revocations(t)
	defer swapGlobalHA(t)()

	bundle := haTestBundle(haTokenEntries(40, 9_000_000_000))
	full, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if _, err := marshalHABundleWithinFrame(bundle, len(full)/2); err != nil {
		t.Fatalf("marshalHABundleWithinFrame (trimmed): %v", err)
	}
	afterTrim := haBundleRevocationsDropped.Load()
	if afterTrim == 0 {
		t.Fatal("the trim charged nothing to the cumulative counter")
	}
	if _, err := marshalHABundleWithinFrame(bundle, len(full)); err != nil {
		t.Fatalf("marshalHABundleWithinFrame (complete): %v", err)
	}
	if got := haBundleRevocationsDropped.Load(); got != afterTrim {
		t.Fatalf("the cumulative total moved from %d to %d when a full bundle went out — recovery clears the CURRENT state, never the magnitude", afterTrim, got)
	}
}

// CONTROL: the claim must still be made while it is true.
//
// The cheapest way to pass the recovery gate is to stop reporting the subset
// at all, which silently deletes AU-40's only signal — and it must survive
// REPEATED trims, because the standby polls every few seconds and a field that
// reported once and then went quiet is the same blind spot.
func TestChaos68_AU43_ControlSubsetIsReportedForAsLongAsItHolds(t *testing.T) {
	withChaos68Revocations(t)
	defer swapGlobalHA(t)()

	bundle := haTestBundle(haTokenEntries(40, 9_000_000_000))
	full, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	for poll := 1; poll <= 3; poll++ {
		if _, err := marshalHABundleWithinFrame(bundle, len(full)/2); err != nil {
			t.Fatalf("poll %d: marshalHABundleWithinFrame: %v", poll, err)
		}
		if got := haHealthzHeldSubset(t); got <= 0 {
			t.Fatalf("poll %d: /healthz reported %d while the bundle was still being trimmed", poll, got)
		}
	}
}

// DEFECT (AU-43): a bundle that never reached the standby reports nothing.
//
// The recovery signal is "a bundle carrying everything went out". A marshal
// failure produces no bundle, so the standby's view is whatever the last
// successful sync left it — recording 0 on that path would announce a recovery
// that did not happen, which is the same class of wrong answer as the latch
// this gate's sibling fixes, in the opposite direction.
func TestChaos68_AU43_AFailedMarshalDoesNotReportRecovery(t *testing.T) {
	withChaos68Revocations(t)
	defer swapGlobalHA(t)()

	bundle := haTestBundle(haTokenEntries(40, 9_000_000_000))
	full, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if _, err := marshalHABundleWithinFrame(bundle, len(full)/2); err != nil {
		t.Fatalf("marshalHABundleWithinFrame (trimmed): %v", err)
	}
	held := haHealthzHeldSubset(t)
	if held <= 0 {
		t.Fatalf("/healthz reported %d after a trim — the fixture did not exercise the trim", held)
	}

	// json.RawMessage is validated at marshal time, so this is the real error
	// path of the real entry point, not a stub.
	broken := haTestBundle(haTokenEntries(40, 9_000_000_000))
	broken.ClusterState = json.RawMessage(`{not json`)
	if _, err := marshalHABundleWithinFrame(broken, len(full)); err == nil {
		t.Fatal("a bundle carrying invalid JSON marshalled without error — the fixture no longer reaches the error path")
	}
	if got := haHealthzHeldSubset(t); got != held {
		t.Fatalf("/healthz moved from %d to %d on a bundle that was never sent: a failed marshal is not evidence the standby caught up", held, got)
	}
}
