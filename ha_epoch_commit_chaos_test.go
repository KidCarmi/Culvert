package main

// ha_epoch_commit_chaos_test.go — CHAOS-71: a fencing epoch is advertised only
// once a snapshot stamped with it has committed (Codex P1 4299814297 on
// #1556). See ha_epoch_commit.go.

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// cpEpochPage is one captured config_snapshot_rejected page.
type cpEpochPage struct{ source, detail string }

// cpEpochHarness is an HA topology source with a fake lease backend, a store
// owned by an active Control Plane at myAddr, retry loops parked, and every
// config_snapshot_rejected page captured (webhooks loaded).
func cpEpochHarness(t *testing.T, myAddr string) (h *HAState, f *halease.Fake, pages func() []cpEpochPage) {
	t.Helper()
	h = cpAddrTopologyFixture(t)
	f = halease.NewFake(time.Minute)
	h.SetLeaseProvider(f, "cp-a")
	_, _ = cpAddrPublishHarness(t) // pages fire (webhooks loaded)
	var mu sync.Mutex
	var got []cpEpochPage
	prev := fireAlert
	fireAlert = func(event string, p AlertPayload) {
		if event == "config_snapshot_rejected" {
			mu.Lock()
			got = append(got, cpEpochPage{p.Source, p.Detail})
			mu.Unlock()
		}
	}
	t.Cleanup(func() { fireAlert = prev })
	cpAddrActiveCP(t, myAddr)
	// No background address-retry loop: the test asserts the pending state
	// itself, and a spawned loop would outlive the seams it reads.
	globalConfigStore.addrPubMu.Lock()
	globalConfigStore.addrPub.retrying = true
	globalConfigStore.addrPubMu.Unlock()
	t.Cleanup(resetDPLastSeenEpochForTest())
	return h, f, func() []cpEpochPage { mu.Lock(); defer mu.Unlock(); return append([]cpEpochPage(nil), got...) }
}

// cpEpochPagesFrom counts the pages a given producer sent.
func cpEpochPagesFrom(pages []cpEpochPage, source string) int {
	n := 0
	for _, p := range pages {
		if p.source == source {
			n++
		}
	}
	return n
}

// cpNextGrantEpoch is the epoch the fake backend grants next.
func cpNextGrantEpoch(t *testing.T, f *halease.Fake) int64 {
	t.Helper()
	st, err := f.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return st.Epoch + 1
}

// cpRejectEpochStamp sets the wire budget one byte below the COMMITTED
// snapshot restamped with e, so the E-stamped commit itself is refused.
func cpRejectEpochStamp(t *testing.T, e int64) {
	t.Helper()
	snap := globalConfigStore.Get()
	snap.Epoch = e
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	prev := snapshotWireBudget
	snapshotWireBudget = len(b) - 1
	t.Cleanup(func() { snapshotWireBudget = prev })
}

// cpAssertEpochServable: the advertised epoch is committed, and a DP that
// learns it on a heartbeat accepts the committed snapshot.
func cpAssertEpochServable(t *testing.T, h *HAState, want int64) {
	t.Helper()
	advertised := h.CurrentEpoch()
	if advertised != want {
		t.Fatalf("advertised epoch = %d, want the new grant %d", advertised, want)
	}
	snap := globalConfigStore.Get()
	if snap.Epoch != advertised {
		t.Fatalf("heartbeats advertise epoch %d but the committed snapshot carries %d — every DP would reject it", advertised, snap.Epoch)
	}
	restore := resetDPLastSeenEpochForTest()
	defer restore()
	if !dpObserveEpoch("heartbeat reply", advertised) || !dpObserveEpoch("config snapshot", snap.Epoch) {
		t.Fatalf("a DP that heard epoch %d on a heartbeat rejected the snapshot stamped %d", advertised, snap.Epoch)
	}
	if !h.WriteAllowed() {
		t.Error("the installed grant conferred no write authority")
	}
}

// cpAssertEpochNotAdvertised: the refused epoch reached no surface, and the
// stamp mirror is back on the installed grant.
func cpAssertEpochNotAdvertised(t *testing.T, h *HAState, refused, wantAdvertised int64) {
	t.Helper()
	if got := h.CurrentEpoch(); got != wantAdvertised {
		t.Errorf("advertised epoch = %d after the refused commit, want %d (the refused epoch is %d)", got, wantAdvertised, refused)
	}
	if got := h.PublishedFenceEpoch(); got != wantAdvertised {
		t.Errorf("publishes still stamp epoch %d after the refused commit, want %d", got, wantAdvertised)
	}
	if got := globalConfigStore.Get().Epoch; got == refused {
		t.Errorf("the committed snapshot carries the refused epoch %d", got)
	}
	if _, _, epoch := h.leaseHealth(); epoch == refused {
		t.Errorf("/healthz reports the refused epoch %d", epoch)
	}
	if h.WriteAllowed() {
		t.Error("the refused grant conferred write authority")
	}
}

// TestChaos71_EpochCommitsBeforeTheAddressList_AddressesOverBudget — case (a).
// Enable and resume add HA addresses that push the snapshot over the wire
// budget. The epoch commit is separate and fits, so the new epoch is committed
// and only then advertised; the node leads; DPs accept the snapshot; the
// address list alone is pending and paged once.
func TestChaos71_EpochCommitsBeforeTheAddressList_AddressesOverBudget(t *testing.T) {
	const (
		myAddr = "10.0.0.2:50051"
		peer   = "standby-with-a-long-enough-hostname.example.internal:50051"
	)
	for _, tc := range []struct {
		name, trigger string
		do            func(h *HAState) error
	}{
		{"enable", haTransitionEnable, func(h *HAState) error { _, err := h.EnableAsLeader(peer, false); return err }},
		{"resume", haTransitionResume, func(h *HAState) error {
			h.ResumeAsLeader(&haConfig{Enabled: true, Role: "leader", PeerAddr: peer, Token: "tok"})
			return nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, f, pages := cpEpochHarness(t, myAddr)
			want := cpNextGrantEpoch(t, f)
			cpAddrSetBudgetExcluding(t, []string{peer, myAddr})

			if err := tc.do(h); err != nil {
				t.Fatalf("%s refused over the address list: %v — the list is only a failover hint", tc.name, err)
			}
			if st := h.Status(); st.Role != "leader" {
				t.Fatalf("role = %q, want leader", st.Role)
			}
			cpAssertEpochServable(t, h, want)
			if got := globalConfigStore.Get().CPAddresses; len(got) != 0 {
				t.Fatalf("precondition: the over-budget list committed: %v", got)
			}
			if st := globalConfigStore.cpAddrPublishSnapshot(); !st.pending || st.trigger != tc.trigger {
				t.Errorf("address publish state = %+v, want pending on %q", st, tc.trigger)
			}
			p := pages()
			if n := cpEpochPagesFrom(p, "cluster"); n != 1 || len(p) != 1 {
				t.Errorf("pages = %+v, want exactly the address rejection, once", p)
			}
		})
	}
}

// TestChaos71_PromoteAndRecoveryCommitTheEpochBeforeAdvertisingIt: the two
// transitions that do not change the list. Neither has a topology republish
// to carry the epoch, so the separate commit is the only thing that stamps it
// (lease recovery, whose role does not change, never restamped before).
func TestChaos71_PromoteAndRecoveryCommitTheEpochBeforeAdvertisingIt(t *testing.T) {
	const myAddr = "10.0.0.2:50051"
	t.Run("promote", func(t *testing.T) {
		h, f, pages := cpEpochHarness(t, myAddr)
		cpEnterStandby(t, h, myAddr)
		want := cpNextGrantEpoch(t, f)
		if err := h.PromoteManually(); err != nil {
			t.Fatalf("promote: %v", err)
		}
		cpAssertEpochServable(t, h, want)
		if p := pages(); len(p) != 0 {
			t.Errorf("a clean promote paged: %+v", p)
		}
	})
	t.Run("lease_recovery", func(t *testing.T) {
		h, f, _ := cpEpochHarness(t, myAddr)
		cpReadOnlyLeader(t, h, f)
		f.ExpireForTest() // the unkept grant lapses; recovery acquires afresh
		want := cpNextGrantEpoch(t, f)
		if !cpRecoveryRound(h) {
			t.Fatal("the recovery round did not complete")
		}
		cpAssertEpochServable(t, h, want)
	})
}

// TestChaos71_RefusedEpochCommitNeverAdvertisesTheEpoch — case (b). The
// E-stamped commit itself is rejected. E reaches no surface, the stamp mirror
// reverts, the transition fails closed on leadership (enable: no role;
// promote: standby; resume: the ADR-0005 S2 read-only leader; recovery: still
// read-only) and the refusal pages once.
func TestChaos71_RefusedEpochCommitNeverAdvertisesTheEpoch(t *testing.T) {
	const (
		myAddr = "10.0.0.2:50051"
		peer   = "10.0.0.9:50051"
	)
	t.Run("enable", func(t *testing.T) {
		h, f, pages := cpEpochHarness(t, myAddr)
		e := cpNextGrantEpoch(t, f)
		cpRejectEpochStamp(t, e)
		if _, err := h.EnableAsLeader(peer, false); err == nil {
			t.Fatal("enable succeeded although its epoch could not be committed")
		}
		cpAssertEpochNotAdvertised(t, h, e, 0)
		if st := h.Status(); st.Role != "" {
			t.Errorf("a refused enable took role %q", st.Role)
		}
		if cfg, err := loadHAConfig(); err == nil && cfg.Enabled {
			t.Errorf("a refused enable persisted HA config %+v", cfg)
		}
		cpAssertRefusalPagedOnce(t, pages)
	})
	t.Run("promote", func(t *testing.T) {
		h, f, pages := cpEpochHarness(t, myAddr)
		cpEnterStandby(t, h, myAddr)
		e := cpNextGrantEpoch(t, f)
		cpRejectEpochStamp(t, e)
		if err := h.PromoteManually(); err == nil {
			t.Fatal("promote succeeded although its epoch could not be committed")
		}
		cpAssertEpochNotAdvertised(t, h, e, 0)
		if st := h.Status(); st.Role != "standby" {
			t.Errorf("a refused promote left role %q, want standby", st.Role)
		}
		if h.promoted.Load() {
			t.Error("a refused promote kept the once-guard: no later promote could retry")
		}
		cpAssertRefusalPagedOnce(t, pages)
	})
	t.Run("resume_takes_the_read_only_leader_stance", func(t *testing.T) {
		h, f, pages := cpEpochHarness(t, myAddr)
		e := cpNextGrantEpoch(t, f)
		cpRejectEpochStamp(t, e)
		h.ResumeAsLeader(&haConfig{Enabled: true, Role: "leader", PeerAddr: peer, Token: "tok"})
		cpAssertEpochNotAdvertised(t, h, e, 0)
		if st := h.Status(); st.Role != "leader" {
			t.Errorf("a refused resume left role %q, want the ADR-0005 S2 read-only leader (a roleless node issues unfenced)", st.Role)
		}
		// haIssuanceAllowed's inputs: an HA role, so the standalone branch is
		// closed, and no write authority (asserted above), so issuance refuses.
		if !h.Status().Enabled {
			t.Error("the refused resume left HA disabled — the standalone issuance branch would be open")
		}
		if h.leaseRecoveryActive() {
			t.Error("the refused resume armed an auto-retry (ADR-0005 S2: none; S4 follow-up)")
		}
		cpAssertRefusalPagedOnce(t, pages)
	})
	t.Run("lease_recovery_stays_read_only_and_does_not_page_again", func(t *testing.T) {
		h, f, pages := cpEpochHarness(t, myAddr)
		cpReadOnlyLeader(t, h, f) // the resume refusal: episode open, paged once
		f.ExpireForTest()
		e := cpNextGrantEpoch(t, f)
		cpRejectEpochStamp(t, e)
		if cpRecoveryRound(h) {
			t.Fatal("the recovery round reported done although its epoch could not be committed — the loop would stop retrying and leave the node read-only for good")
		}
		cpAssertEpochNotAdvertised(t, h, e, 0)
		if st := h.Status(); st.Role != "leader" {
			t.Errorf("role = %q, want the read-only leader", st.Role)
		}
		cpAssertRefusalPagedOnce(t, pages) // same episode as the resume's
	})
}

// TestChaos71_RefusedBootResumePagesOnceAfterTheWebhooksLoad: a boot resume
// runs before the webhooks load. Its refusal page is queued and delivered
// exactly once at the flush; a later successful install ends the episode.
func TestChaos71_RefusedBootResumePagesOnceAfterTheWebhooksLoad(t *testing.T) {
	const (
		myAddr = "10.0.0.2:50051"
		peer   = "10.0.0.9:50051"
	)
	h, f, direct := cpEpochHarness(t, myAddr)
	cpStartupAlertsLoaded(t, false) // boot: the webhooks are not loaded yet
	var mu sync.Mutex
	var flushed []cpEpochPage
	prev := startupAlertFire
	startupAlertFire = func(event string, p AlertPayload) {
		if event == "config_snapshot_rejected" {
			mu.Lock()
			flushed = append(flushed, cpEpochPage{p.Source, p.Detail})
			mu.Unlock()
		}
	}
	t.Cleanup(func() { startupAlertFire = prev })

	e := cpNextGrantEpoch(t, f)
	cpRejectEpochStamp(t, e)
	h.ResumeAsLeader(&haConfig{Enabled: true, Role: "leader", PeerAddr: peer, Token: "tok"})
	if d := direct(); len(d) != 0 {
		t.Fatalf("page(s) fired before the webhooks loaded, into an empty store: %+v", d)
	}
	flushStartupAlerts()
	mu.Lock()
	got := cpEpochPagesFrom(flushed, "ha")
	mu.Unlock()
	if got != 1 {
		t.Fatalf("the startup flush delivered %d epoch-refusal page(s), want exactly 1", got)
	}
}

// cpAssertRefusalPagedOnce: exactly one page from the HA producer.
func cpAssertRefusalPagedOnce(t *testing.T, pages func() []cpEpochPage) {
	t.Helper()
	p := pages()
	if n := cpEpochPagesFrom(p, "ha"); n != 1 {
		t.Errorf("the epoch refusal paged %d time(s), want exactly 1 (pages: %+v)", n, p)
	}
}

// cpEnterStandby makes h a standby (the sync loop exits at once) whose
// onPromote succeeds.
func cpEnterStandby(t *testing.T, h *HAState, myAddr string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.StartAsStandby(ctx, "10.0.0.7:50051", "tok", myAddr, "", "", "", false, func() error { return nil })
	if st := h.Status(); st.Role != "standby" {
		t.Fatalf("precondition: role %q", st.Role)
	}
}

// cpReadOnlyLeader makes h a read-only leader: a resume whose epoch commit is
// refused (one refusal page), with the budget restored afterwards.
func cpReadOnlyLeader(t *testing.T, h *HAState, f *halease.Fake) {
	t.Helper()
	prev := snapshotWireBudget
	cpRejectEpochStamp(t, cpNextGrantEpoch(t, f))
	h.ResumeAsLeader(&haConfig{Enabled: true, Role: "leader", PeerAddr: "10.0.0.9:50051", Token: "tok"})
	snapshotWireBudget = prev
	if st := h.Status(); st.Role != "leader" || h.CurrentEpoch() != 0 {
		t.Fatalf("precondition: role=%q epoch=%d, want a read-only leader", st.Role, h.CurrentEpoch())
	}
}

// cpRecoveryRound runs one CHAOS-55 recovery round synchronously and returns
// its "done" verdict: false keeps the loop retrying.
func cpRecoveryRound(h *HAState) bool {
	var lastLog time.Time
	suppressed := 0
	return h.leaseRecoveryAttempt(time.Now(), &lastLog, &suppressed)
}

// TestChaos71_Wall_FencingEpochIsAdvertisedOnlyAfterItsCommit: no surface that
// publishes a fencing epoch (CurrentEpoch → heartbeat, issuance, deltas,
// /healthz, write authority; the leader role) is reachable from a grant before
// the snapshot stamped with it commits, and renewal never waits on that
// commit.
//
//   - leaseEpoch takes a non-zero value only in exposeGrantLocked, and every
//     caller of exposeGrantLocked commits (commitGrant) first;
//   - the acquisition never reaches the commit, the exposure, a role or the
//     keepalive;
//   - every authority-gaining transition starts the keepalive on the staged
//     grant before the commit, commits before it starts the Control Plane
//     listener (onPromote), and exposes before it takes the leader role;
//   - the staged and in-flight epochs are read only by the install halves and
//     the stamp mirror, and the stamp mirror is read only by the publish stamp.
//
// TestChaos71_Wall_NoSnapshotPublishUnderTheHALock separately pins that the
// commit itself never runs under HAState.mu.
func TestChaos71_Wall_FencingEpochIsAdvertisedOnlyAfterItsCommit(t *testing.T) {
	funcs, _ := cpParseFuncsAndGateHolders(t)
	cpWallNonZeroEpochOnlyAfterCommit(t, funcs)
	for _, start := range []string{"acquireLeaseAttempt", "acquireLeaseForLeadership", "acquireLeaseForResume", "resumeAcquireRound"} {
		forbidden := map[string]bool{
			"setLeaseEpochLocked": true, "setTopologyLocked": true, "startLeaseKeepalive": true,
			"commitGrant": true, "exposeGrantLocked": true,
		}
		if path, bad := cpReaches(funcs, start, forbidden, 8); bad {
			t.Errorf("%s reaches %s — a grant would be advertised or acted on before its epoch commits", start, strings.Join(path, " → "))
		}
	}
	for _, fn := range []string{"EnableAsLeader", "resumeAsLeader", "promote", "completeLeaseRecovery"} {
		cpWallInstallsFirst(t, funcs, fn)
	}
	cpWallFieldUse(t, "grantEpoch", map[string]bool{
		"acquireLeaseAttempt": true, "commitGrant": true, "exposeGrantLocked": true, "abandonGrantLocked": true, "heldEpochLocked": true,
	})
	cpWallFieldUse(t, "stampEpoch", map[string]bool{
		"commitGrant": true, "syncFenceEpochLocked": true, "exposeGrantLocked": true, "abandonGrantLocked": true,
	})
	cpWallFieldUse(t, "PublishedFenceEpoch", map[string]bool{"publishFenceEpoch": true})
}

// cpCommitCallers are the calls that run commitGrant: itself, and the
// resume's wrapper (which must call it).
var cpCommitCallers = []string{"commitGrant", "commitResumeGrant"}

// cpWallNonZeroEpochOnlyAfterCommit: every setLeaseEpochLocked call outside
// exposeGrantLocked passes a literal 0, and every function that calls
// exposeGrantLocked commits before it.
func cpWallNonZeroEpochOnlyAfterCommit(t *testing.T, funcs map[string][]*ast.FuncDecl) {
	t.Helper()
	if w := funcs["commitResumeGrant"]; len(w) != 1 || len(cpCallsNamed(w[0], "commitGrant")) == 0 {
		t.Fatal("commitResumeGrant no longer calls commitGrant — the wall's selector has gone stale")
	}
	installs, exposers := 0, 0
	for name, decls := range funcs {
		for _, fn := range decls {
			for _, call := range cpCallsNamed(fn, "setLeaseEpochLocked") {
				if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Value == "0" {
					continue
				}
				if name != "exposeGrantLocked" {
					t.Errorf("%s installs a non-zero fencing epoch — only exposeGrantLocked may, after the stamped commit", name)
					continue
				}
				installs++
			}
			for _, call := range cpCallsNamed(fn, "exposeGrantLocked") {
				exposers++
				if commit := cpFirstCallPos(fn, cpCommitCallers...); commit == token.NoPos || commit > call.Pos() {
					t.Errorf("%s exposes a fencing epoch before committing the snapshot stamped with it", name)
				}
			}
		}
	}
	if installs != 1 || exposers == 0 {
		t.Errorf("exposeGrantLocked installs the epoch %d time(s) and has %d caller(s), want 1 and at least 1 — the wall's selector has gone stale", installs, exposers)
	}
}

// cpWallInstallsFirst: in fn, the keepalive starts before the commit (in fn,
// or in the resume's wrapper), the commit precedes the Control Plane listener
// (onPromote), and the exposure precedes every leader-role write.
func cpWallInstallsFirst(t *testing.T, funcs map[string][]*ast.FuncDecl, fn string) {
	t.Helper()
	decls := funcs[fn]
	if len(decls) != 1 {
		t.Fatalf("%s: %d declarations — the wall's selector has gone stale", fn, len(decls))
	}
	commit := cpFirstCallPos(decls[0], cpCommitCallers...)
	expose := cpFirstCallPos(decls[0], "exposeGrantLocked")
	if commit == token.NoPos || expose == token.NoPos {
		t.Errorf("%s takes authority without committing and exposing its grant", fn)
		return
	}
	keepaliveIn, commitIn := decls[0], commit
	if direct := cpFirstCallPos(decls[0], "commitGrant"); direct == token.NoPos {
		keepaliveIn = funcs["commitResumeGrant"][0] // the commit runs in the wrapper
		commitIn = cpFirstCallPos(keepaliveIn, "commitGrant")
	}
	if ka := cpFirstCallPos(keepaliveIn, "startLeaseKeepalive"); ka == token.NoPos || ka > commitIn {
		t.Errorf("%s commits its epoch before the keepalive starts on the staged grant — renewal would wait on the commit", fn)
	}
	for _, call := range append(cpCallsNamed(decls[0], "runOnPromote"), cpCallsNamed(decls[0], "onPromote")...) {
		if call.Pos() < commit {
			t.Errorf("%s starts the Control Plane listener before the new epoch is committed — a refused commit would leave it running", fn)
		}
	}
	for _, call := range cpCallsNamed(decls[0], "setTopologyLocked") {
		if lit, ok := cpFirstStringArg(call); ok && lit != "leader" {
			continue // a non-leader role (a resume's standby re-entry) is not authority
		}
		if call.Pos() < expose {
			t.Errorf("%s takes the leader role before the new epoch is exposed", fn)
		}
	}
}

// cpFirstCallPos is the position of fn's first call to any of names.
func cpFirstCallPos(fn *ast.FuncDecl, names ...string) token.Pos {
	first := token.NoPos
	for _, name := range names {
		for _, call := range cpCallsNamed(fn, name) {
			if first == token.NoPos || call.Pos() < first {
				first = call.Pos()
			}
		}
	}
	return first
}

// cpWallFieldUse: the selector name appears only in the allowed top-level
// declarations (functions, or a package var such as publishFenceEpoch).
func cpWallFieldUse(t *testing.T, field string, allowed map[string]bool) {
	t.Helper()
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seen := 0
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
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == field {
					seen++
					if !allowed[owner] {
						t.Errorf("%s: %s uses %s — only %v may (a staged or in-flight epoch must reach no advertised surface)",
							fset.Position(sel.Pos()), owner, field, allowed)
					}
				}
				return true
			})
		}
	}
	if seen == 0 {
		t.Errorf("the wall saw no use of %s — its selector has gone stale", field)
	}
}

// cpCallsNamed lists fn's calls to name, in source order.
func cpCallsNamed(fn *ast.FuncDecl, name string) []*ast.CallExpr {
	var out []*ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			if f.Name == name {
				out = append(out, call)
			}
		case *ast.SelectorExpr:
			if f.Sel.Name == name {
				out = append(out, call)
			}
		}
		return true
	})
	return out
}

// cpFirstStringArg returns a call's first argument when it is a string literal.
func cpFirstStringArg(call *ast.CallExpr) (string, bool) {
	if len(call.Args) == 0 {
		return "", false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	return strings.Trim(lit.Value, `"`), true
}

// TestChaos71_EpochCommittedByAConcurrentPublishIsInstalled: the restamp
// fails, but a concurrent publish committed while the stamp mirror read the
// new epoch — so the epoch IS committed and distributable. The install must
// proceed (reverting the mirror would leave a committed epoch that nothing
// advertises, and the next publish would stamp the old one over it).
func TestChaos71_EpochCommittedByAConcurrentPublishIsInstalled(t *testing.T) {
	const peer = "10.0.0.9:50051"
	h, f, _ := cpEpochHarness(t, "10.0.0.2:50051")
	want := cpNextGrantEpoch(t, f)
	prev := haRestampFenceEpoch
	haRestampFenceEpoch = func() error {
		// A concurrent commit landing in the install's window (its build must
		// not need HAState.mu, which the install holds): stamped with the mirror.
		if _, err := globalConfigStore.UpdateCPAddressesFrom(func() []string { return []string{"10.0.0.8:50051"} }); err != nil {
			t.Errorf("concurrent publish: %v", err)
		}
		return errors.New("injected: the restamp lost the commit race")
	}
	t.Cleanup(func() { haRestampFenceEpoch = prev })
	if _, err := h.EnableAsLeader(peer, false); err != nil {
		t.Fatalf("enable refused although its epoch was committed by a concurrent publish: %v", err)
	}
	cpAssertEpochServable(t, h, want)
}

// cpStatefulOnPromote models the production onPromote (enableControlPlane): a
// second call after a successful first one fails "already running as
// control-plane". It counts the listener starts.
func cpStatefulOnPromote(fail *bool) (onPromote func() error, starts func() int) {
	var mu sync.Mutex
	started := 0
	return func() error {
			mu.Lock()
			defer mu.Unlock()
			if fail != nil && *fail {
				return errors.New("injected: listener failed to start")
			}
			if started > 0 {
				return errors.New("already running as control-plane")
			}
			started++
			return nil
		}, func() int {
			mu.Lock()
			defer mu.Unlock()
			return started
		}
}

// TestChaos71_RefusedPromoteCommitNeverStartsTheListener — Codex P1 4300948604.
// A fresh standby's promote whose epoch commit is refused must not start the
// Control Plane listener: the once-guard reset alone would leave the listener
// and role up, and every later promote would fail "already running as
// control-plane" before reaching another commit. Once the config fits again,
// the next promote must succeed.
func TestChaos71_RefusedPromoteCommitNeverStartsTheListener(t *testing.T) {
	const myAddr = "10.0.0.2:50051"
	h, f, pages := cpEpochHarness(t, myAddr)
	onPromote, starts := cpStatefulOnPromote(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.StartAsStandby(ctx, "10.0.0.7:50051", "tok", myAddr, "", "", "", false, onPromote)

	e := cpNextGrantEpoch(t, f)
	prev := snapshotWireBudget
	cpRejectEpochStamp(t, e)
	if err := h.PromoteManually(); err == nil {
		t.Fatal("promote succeeded although its epoch could not be committed")
	}
	if n := starts(); n != 0 {
		t.Fatalf("a promote whose epoch commit was refused started the Control Plane listener %d time(s)", n)
	}
	cpAssertEpochNotAdvertised(t, h, e, 0)
	cpAssertRefusalPagedOnce(t, pages)

	snapshotWireBudget = prev // the operator reduced the config
	f.ExpireForTest()         // the refused grant lapses unkept
	want := cpNextGrantEpoch(t, f)
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("the retry after the config fits again failed: %v — the refused promote left the node unpromotable", err)
	}
	if n := starts(); n != 1 {
		t.Errorf("the listener was started %d time(s), want exactly once (by the successful promote)", n)
	}
	cpAssertEpochServable(t, h, want)
}

// TestChaos71_PromoteListenerFailureAbandonsTheCommittedEpoch: the epoch is
// committed, then onPromote fails. The node stays a retryable standby, the
// committed epoch is never advertised, and publishes stop stamping it.
func TestChaos71_PromoteListenerFailureAbandonsTheCommittedEpoch(t *testing.T) {
	const myAddr = "10.0.0.2:50051"
	h, f, _ := cpEpochHarness(t, myAddr)
	fail := true
	onPromote, _ := cpStatefulOnPromote(&fail)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.StartAsStandby(ctx, "10.0.0.7:50051", "tok", myAddr, "", "", "", false, onPromote)

	if err := h.PromoteManually(); err == nil {
		t.Fatal("promote succeeded although onPromote failed")
	}
	if st := h.Status(); st.Role != "standby" || h.promoted.Load() {
		t.Fatalf("after a failed onPromote: role=%q promoted=%v, want a retryable standby", st.Role, h.promoted.Load())
	}
	if got := h.CurrentEpoch(); got != 0 {
		t.Errorf("a promote whose listener failed advertises epoch %d", got)
	}
	if got := h.PublishedFenceEpoch(); got != 0 {
		t.Errorf("publishes still stamp the abandoned epoch %d (want 0)", got)
	}
	fail = false
	f.ExpireForTest()
	want := cpNextGrantEpoch(t, f)
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("the retry failed: %v", err)
	}
	cpAssertEpochServable(t, h, want)
}

// TestChaos71_SlowEpochCommitDoesNotCostTheLease — the class rule of Codex P1
// 4301857115, for the stamped commit: an enable whose epoch commit takes
// longer than a 3 s TTL keeps its lease. The keepalive renews the staged grant
// while the commit runs outside HAState.mu, so when the commit returns the
// lease is still held and renewed, the epoch is installed and committed, and
// the node has not self-fenced.
func TestChaos71_SlowEpochCommitDoesNotCostTheLease(t *testing.T) {
	const ttl = 3 * time.Second
	h, _, _ := cpEpochHarness(t, "10.0.0.2:50051")
	f := halease.NewFake(ttl)
	h.SetLeaseProvider(f, "cp-a")
	want := cpNextGrantEpoch(t, f)
	var slowed atomic.Int32
	prev := haRestampFenceEpoch
	haRestampFenceEpoch = func() error {
		if slowed.Add(1) == 1 {
			time.Sleep(ttl + 700*time.Millisecond) // longer than the TTL, let alone the trusted window
		}
		return prev()
	}
	t.Cleanup(func() { haRestampFenceEpoch = prev })

	if _, err := h.EnableAsLeader("10.0.0.9:50051", false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if slowed.Load() == 0 {
		t.Fatal("precondition: the enable never reached the slow epoch commit")
	}
	cpAssertEpochServable(t, h, want)
	st, err := f.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Holder != "cp-a" || st.Epoch != want || st.ValidFor <= 0 {
		t.Fatalf("lease holder=%q epoch=%d valid_for=%s — the staged grant was not renewed during the commit", st.Holder, st.Epoch, st.ValidFor)
	}
}

// TestChaos71_GrantLostDuringTheEpochCommitIsNotExposed: the exposure
// re-checks that the grant is still held. A grant superseded while its epoch
// commit runs is dropped by the keepalive, and the enable is refused: no
// role, no advertised epoch, the stamp mirror back on the installed grant,
// and no keepalive left renewing anything.
func TestChaos71_GrantLostDuringTheEpochCommitIsNotExposed(t *testing.T) {
	h, _, _ := cpEpochHarness(t, "10.0.0.2:50051")
	f := halease.NewFake(300 * time.Millisecond)
	h.SetLeaseProvider(f, "cp-a")
	e := cpNextGrantEpoch(t, f)
	prev := haRestampFenceEpoch
	haRestampFenceEpoch = func() error {
		f.ExpireForTest()
		if granted, _, err := f.Acquire(context.Background(), "cp-b"); !granted || err != nil {
			t.Errorf("precondition: the peer could not take the lease (granted=%v err=%v)", granted, err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) { // the keepalive's next renewal sees the loss
			h.mu.RLock()
			lost := h.grantEpoch == 0
			h.mu.RUnlock()
			if lost {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		return prev()
	}
	t.Cleanup(func() { haRestampFenceEpoch = prev })

	if _, err := h.EnableAsLeader("10.0.0.9:50051", false); err == nil {
		t.Fatal("enable succeeded although its grant was lost before the epoch could be installed")
	}
	if st := h.Status(); st.Role != "" {
		t.Errorf("role = %q, want none", st.Role)
	}
	cpAssertEpochNotAdvertised(t, h, e, 0)
	h.mu.RLock()
	keepalive := h.leaseStopCh != nil
	h.mu.RUnlock()
	if keepalive {
		t.Error("a keepalive is still running for the lost grant")
	}
}

// TestChaos71_RefusedEpochCommitRevertsTheStampAtomically: the keep-or-revert
// decision reverts the stamp mirror under the store lock, in the same step as
// the check. A publish that lands right after the decision (here, inside the
// seam, with HAState.mu still held by the caller) must stamp the installed
// epoch, never the refused one, which nothing advertises.
func TestChaos71_RefusedEpochCommitRevertsTheStampAtomically(t *testing.T) {
	h, f, _ := cpEpochHarness(t, "10.0.0.2:50051")
	e := cpNextGrantEpoch(t, f)
	cpRejectEpochStamp(t, e)
	prevKeep := haKeepEpochStampIfCommitted
	haKeepEpochStampIfCommitted = func(epoch int64, revert func()) bool {
		kept := prevKeep(epoch, revert)
		snapshotWireBudget = maxSnapshotWireBytes // the concurrent publish itself fits
		if _, err := globalConfigStore.UpdateCPAddressesFrom(func() []string { return []string{"10.0.0.8:50051"} }); err != nil {
			t.Errorf("concurrent publish: %v", err)
		}
		return kept
	}
	t.Cleanup(func() { haKeepEpochStampIfCommitted = prevKeep })

	if _, err := h.EnableAsLeader("10.0.0.9:50051", false); err == nil {
		t.Fatal("enable succeeded although its epoch commit was refused")
	}
	if got := globalConfigStore.Get().Epoch; got == e {
		t.Errorf("a publish landing after the refusal committed the refused epoch %d — DPs would learn an epoch nothing advertises", got)
	}
	cpAssertEpochNotAdvertised(t, h, e, 0)
}
