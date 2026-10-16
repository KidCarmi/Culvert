package main

// cp_addr_publish_chaos_test.go — CHAOS-71: a failed CP address-list
// republish on an HA transition is pending, loud and retried, and never rolls
// the transition back (Codex P1 4295648192 on #1556).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// cpAddrPublishHarness isolates the retry loop: a spawned loop reports itself
// on the returned channel and exits at once (so nothing outlives the test),
// and alerts are captured. The test then drives retryCPAddrPublish
// synchronously.
func cpAddrPublishHarness(t *testing.T) (spawned chan struct{}, alerts func() []string) {
	t.Helper()
	cpStartupAlertsLoaded(t, true) // steady state: pages fire, they do not queue
	spawned = make(chan struct{}, 16)
	prevSleep := cpAddrRetrySleep
	cpAddrRetrySleep = func(context.Context, time.Duration) bool {
		spawned <- struct{}{}
		return false
	}
	t.Cleanup(func() { cpAddrRetrySleep = prevSleep })

	var mu sync.Mutex
	var fired []string
	prevAlert := fireAlert
	fireAlert = func(event string, _ AlertPayload) {
		mu.Lock()
		fired = append(fired, event)
		mu.Unlock()
	}
	t.Cleanup(func() { fireAlert = prevAlert })
	return spawned, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), fired...)
	}
}

// cpAddrActiveCP brings up an owned, published store with a snapshot of
// controllable size, activated at myAddr with HA still off.
func cpAddrActiveCP(t *testing.T, myAddr string) {
	t.Helper()
	big := ConfigSnapshot{BlockedHosts: make([]string, 200)}
	for i := range big.BlockedHosts {
		big.BlockedHosts[i] = fmt.Sprintf("blocked-%04d.example", i)
	}
	globalConfigStore.setCPAddressSource(buildCPAddressList)
	if err := globalConfigStore.Update(big); err != nil {
		t.Fatalf("seed publish: %v", err)
	}
	s := &cpListenerSupervisor{cfg: cpListenerConfig{addr: myAddr}, stopping: make(chan struct{})}
	if outcome, _, err := s.commitActivation(); outcome != cpCommitted || err != nil {
		t.Fatalf("activation: outcome=%d err=%v", outcome, err)
	}
}

// cpAddrSetBudgetExcluding sets the wire budget one byte below the committed
// snapshot carrying addrs, so publishing exactly that list is rejected.
func cpAddrSetBudgetExcluding(t *testing.T, addrs []string) {
	t.Helper()
	snap := globalConfigStore.Get()
	snap.CPAddresses = addrs
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	prev := snapshotWireBudget
	snapshotWireBudget = len(b) - 1
	t.Cleanup(func() { snapshotWireBudget = prev })
}

func cpAddrAwaitSpawn(t *testing.T, spawned chan struct{}) {
	t.Helper()
	select {
	case <-spawned:
	case <-time.After(10 * time.Second):
		t.Fatal("a failed republish did not start the retry loop")
	}
}

func cpAddrContains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// cpAddrAssertPending checks the latched state and its diagnostics row.
func cpAddrAssertPending(t *testing.T, trigger string, alerts func() []string) {
	t.Helper()
	st := globalConfigStore.cpAddrPublishSnapshot()
	if !st.pending || st.trigger != trigger || st.reason != "publish_rejected" || st.attempts < 1 {
		t.Fatalf("pending state = %+v, want pending on %q (publish_rejected)", st, trigger)
	}
	if row := checkCPAddressList(); row.Status != diagFail || row.OperatorAction == "" {
		t.Errorf("cp_address_list row = %+v, want FAIL with an operator action", row)
	}
	if !cpAddrContains(alerts(), "config_snapshot_rejected") {
		t.Errorf("no config_snapshot_rejected alert for the rejected republish (fired: %v)", alerts())
	}
}

// cpAddrAssertRecovered restores the budget, drives the retry loop
// synchronously, and checks the list caught up with the HA topology.
func cpAddrAssertRecovered(t *testing.T, want []string) {
	t.Helper()
	snapshotWireBudget = maxSnapshotWireBytes
	rounds := 0
	cpAddrRetrySleep = func(context.Context, time.Duration) bool { rounds++; return rounds <= 3 } // bounded: a broken loop fails, not hangs
	globalConfigStore.retryCPAddrPublish(context.Background())
	if st := globalConfigStore.cpAddrPublishSnapshot(); st.pending {
		t.Fatalf("the retry loop returned with the publish still pending: %+v", st)
	}
	got := globalConfigStore.Get().CPAddresses
	if !slicesEqual(got, buildCPAddressList()) || !slicesEqual(got, want) {
		t.Errorf("after the retry the published list = %v, derived %v, want %v", got, buildCPAddressList(), want)
	}
	if row := checkCPAddressList(); row.Status != diagOK {
		t.Errorf("cp_address_list row after recovery = %+v, want OK", row)
	}
}

func cpAddrTopologyFixture(t *testing.T) *HAState {
	t.Helper()
	tempHADir(t)
	_ = cpIsolateActivation(t)
	cpChaosSetup(t)
	h := &HAState{}
	cpUseTopologySource(t, h)
	t.Cleanup(h.Stop)
	return h
}

// TestChaos71_AuthorityGainingTransitionWithARejectedRepublishStaysLeaderAndRetries:
// enable and resume (the Codex path) against a snapshot that cannot carry the
// new list. The transition succeeds — authority is the fence's, the list is a
// failover hint (ADR-0005) — and the failure is pending, alerted, reported FAIL
// and retried until the list matches buildCPAddressList().
func TestChaos71_AuthorityGainingTransitionWithARejectedRepublishStaysLeaderAndRetries(t *testing.T) {
	const (
		myAddr = "10.0.0.2:50051"
		peer   = "standby-with-a-long-enough-hostname.example.internal:50051"
	)
	for _, tc := range []struct {
		name, trigger string
		do            func(h *HAState) error
	}{
		{"enable", haTransitionEnable, func(h *HAState) error { _, err := h.EnableAsLeader(peer, false); return err }},
		{"resume_after_delayed_bind", haTransitionResume, func(h *HAState) error {
			h.ResumeAsLeader(&haConfig{Enabled: true, Role: "leader", PeerAddr: peer, Token: "tok"})
			return nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := cpAddrTopologyFixture(t)
			spawned, alerts := cpAddrPublishHarness(t)
			cpAddrActiveCP(t, myAddr)
			want := []string{peer, myAddr}
			cpAddrSetBudgetExcluding(t, want)

			if err := tc.do(h); err != nil {
				t.Fatalf("%s failed on a rejected address publish: %v — the role must stand (ADR-0005)", tc.name, err)
			}
			if st := h.Status(); st.Role != "leader" || st.PeerAddr != peer {
				t.Fatalf("after %s: role=%q peer=%q, want leader/%q", tc.name, st.Role, st.PeerAddr, peer)
			}
			if got := globalConfigStore.Get().CPAddresses; len(got) != 0 {
				t.Fatalf("precondition: the over-budget list was committed: %v", got)
			}
			cpAddrAwaitSpawn(t, spawned)
			cpAddrAssertPending(t, tc.trigger, alerts)
			cpAddrAssertRecovered(t, want)
		})
	}
}

// TestChaos71_SafetyTransitionWithARejectedRepublishIsNeverRolledBack: a
// standby entry against a new leader whose list cannot be published still
// demotes — fencing is the safety property — and the list is pending and
// retried.
func TestChaos71_SafetyTransitionWithARejectedRepublishIsNeverRolledBack(t *testing.T) {
	const (
		myAddr    = "10.0.0.2:50051"
		peer      = "10.0.0.9:50051"
		newLeader = "new-leader-with-a-much-longer-hostname.example.internal:50051"
	)
	h := cpAddrTopologyFixture(t)
	spawned, alerts := cpAddrPublishHarness(t)
	cpAddrActiveCP(t, myAddr)
	if _, err := h.EnableAsLeader(peer, false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if got := globalConfigStore.Get().CPAddresses; !slicesEqual(got, []string{peer, myAddr}) {
		t.Fatalf("precondition: list after enable = %v", got)
	}
	want := []string{newLeader, myAddr}
	cpAddrSetBudgetExcluding(t, want)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the sync loop exits at once
	h.StartAsStandby(ctx, newLeader, "tok", myAddr, "", "", "", false, func() error { return nil })
	if st := h.Status(); st.Role != "standby" || st.PeerAddr != newLeader {
		t.Fatalf("standby entry rolled back on a rejected publish: role=%q peer=%q", st.Role, st.PeerAddr)
	}
	if got := globalConfigStore.Get().CPAddresses; !slicesEqual(got, []string{peer, myAddr}) {
		t.Fatalf("precondition: the over-budget list was committed: %v", got)
	}
	cpAddrAwaitSpawn(t, spawned)
	cpAddrAssertPending(t, haTransitionStandby, alerts)
	cpAddrAssertRecovered(t, want)
}

// TestChaos71_CPAddrCommitRaceIsPendingAndWarned: losing the commit race every
// attempt is a transient class — pending and reported WARN, not FAIL.
func TestChaos71_CPAddrCommitRaceIsPendingAndWarned(t *testing.T) {
	_ = cpIsolateActivation(t)
	spawned, _ := cpAddrPublishHarness(t)
	s := globalConfigStore
	s.setCPAddressSource(func() []string { return []string{"10.0.0.9:50051"} })
	if err := s.Update(ConfigSnapshot{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if st := s.cpAddrPublishSnapshot(); st.pending {
		t.Fatalf("precondition: pending after a clean seed: %+v", st)
	}

	prev := cpAddrMergeBeforeCommit
	cpAddrMergeBeforeCommit = func() { // a competing commit every attempt
		s.mu.Lock()
		s.version++
		s.mu.Unlock()
	}
	t.Cleanup(func() { cpAddrMergeBeforeCommit = prev })

	err := s.reconcileCPAddressesFrom("test", func() []string { return []string{"10.0.0.8:50051"} })
	if !errors.Is(err, errCPAddrCommitRace) {
		t.Fatalf("err = %v, want errCPAddrCommitRace", err)
	}
	cpAddrAwaitSpawn(t, spawned)
	if st := s.cpAddrPublishSnapshot(); !st.pending || st.reason != "commit_race" {
		t.Fatalf("pending state = %+v, want pending commit_race", st)
	}
	if row := checkCPAddressList(); row.Status != diagWarn {
		t.Errorf("cp_address_list row = %+v, want WARN for a transient commit race", row)
	}
}

// TestChaos71_Wall_OwnedCPAddressPublishesAreRecorded: UpdateCPAddressesFrom
// is called only from the recording path, its retry loop, and the activation
// publish (whose failure refuses the activation), so no new caller can drop
// a failed republish on the floor.
func TestChaos71_Wall_OwnedCPAddressPublishesAreRecorded(t *testing.T) {
	allowed := map[string]bool{"publishOwnedCPAddresses": true, "retryCPAddrPublish": true, "cpPublishCPAddresses": true}
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	found := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			owner := cpTopLevelName(decl)
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "UpdateCPAddressesFrom" {
					found++
					if !allowed[owner] {
						t.Errorf("%s: %s calls UpdateCPAddressesFrom directly — use publishOwnedCPAddresses so a failure is latched pending and retried",
							fset.Position(call.Pos()), owner)
					}
				}
				return true
			})
		}
	}
	if found < 3 {
		t.Fatalf("the wall found only %d calls — its selector has gone stale", found)
	}
}

// cpTopLevelName names a top-level declaration: a function, or the first
// variable of a var block.
func cpTopLevelName(decl ast.Decl) string {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		return d.Name.Name
	case *ast.GenDecl:
		for _, sp := range d.Specs {
			if vs, ok := sp.(*ast.ValueSpec); ok && len(vs.Names) > 0 {
				return vs.Names[0].Name
			}
		}
	}
	return ""
}

// cpTimeoutErr is a net.Error that timed out.
type cpTimeoutErr struct{}

func (cpTimeoutErr) Error() string   { return "i/o timeout" }
func (cpTimeoutErr) Timeout() bool   { return true }
func (cpTimeoutErr) Temporary() bool { return true }

var _ net.Error = cpTimeoutErr{}

// TestChaos71_CPGRPCReasonTable — Codex P2 4295648199: explicit stage tags win
// over the generic errno they wrap. Every class is covered, and each tag is
// checked wrapping EVERY errno the table knows (plus a timeout), the shape a
// real unreadable cert/key/CA file produces.
func TestChaos71_CPGRPCReasonTable(t *testing.T) {
	sysErr := func(e syscall.Errno) error {
		return &net.OpError{Op: "listen", Net: "tcp", Err: &os.SyscallError{Syscall: "bind", Err: e}}
	}
	fileErr := func(e syscall.Errno) error { return &os.PathError{Op: "open", Path: "/etc/culvert/cp.key", Err: e} }
	errnos := map[syscall.Errno]string{
		syscall.EADDRINUSE: "port_in_use", syscall.EACCES: "permission_denied", syscall.EPERM: "permission_denied",
		syscall.EADDRNOTAVAIL: "address_unavailable", syscall.EMFILE: "descriptors_exhausted", syscall.ENFILE: "descriptors_exhausted",
	}
	covered := map[string]bool{}
	check := func(err error, want string) {
		t.Helper()
		got := classifyCPGRPCBindError(err)
		if got != want {
			t.Errorf("classify(%v) = %q, want %q", err, got, want)
		}
		covered[got] = true
	}
	for e, want := range errnos {
		check(sysErr(e), want)
	}
	check(&net.OpError{Op: "accept", Net: "tcp", Err: cpTimeoutErr{}}, "network_error")
	check(sysErr(syscall.EINVAL), "listen_failed")
	check(nil, "none")

	tags := map[error]string{errCPGRPCTLSMaterial: "tls_certificate", errCPGRPCAddressPublish: "address_publish_rejected"}
	for tag, want := range tags {
		check(tag, want)
		for e := range errnos {
			check(fmt.Errorf("%w: %w", tag, fileErr(e)), want)
			check(fmt.Errorf("load: %w", fmt.Errorf("%w: %w", tag, sysErr(e))), want)
		}
		check(fmt.Errorf("%w: %w", tag, cpTimeoutErr{}), want)
	}

	for _, r := range cpGRPCReasonRules {
		if !covered[r.reason] {
			t.Errorf("classifier rule %q has no case in this table", r.reason)
		}
	}
}
