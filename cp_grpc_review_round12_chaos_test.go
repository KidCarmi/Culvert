package main

// cp_grpc_review_round12_chaos_test.go — CHAOS-71 gates for the twelfth review
// round on #1556: the HA resume runs outside the activation gate and aborts on
// shutdown (Codex P1 4298247416), and role_conflict pages with its own text
// (P2 4298247430).

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// cpSignallingLease wraps the fake fencing backend and reports every Acquire.
type cpSignallingLease struct {
	*halease.Fake
	acquired chan struct{}
}

func (l *cpSignallingLease) Acquire(ctx context.Context, id string) (bool, halease.Status, error) {
	granted, st, err := l.Fake.Acquire(ctx, id)
	select {
	case l.acquired <- struct{}{}:
	default:
	}
	return granted, st, err
}

func cpLeaderConfig(t *testing.T) *haConfig {
	t.Helper()
	if err := saveHAConfig(&haConfig{Enabled: true, Role: "leader", PeerAddr: "10.0.0.9:50051", Token: "tok", Term: 3}); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadHAConfig()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestChaos71_ShutdownInsideTheGhostWaitAbortsTheResume — Codex P1 4298247416.
// A restarted leader finds its OWN ghost lease from the previous process and
// waits it out (up to haResumeGhostWait, 45 s). SIGTERM lands inside that wait
// (the ha-stop hook's BeginShutdown). The resume must return well within the
// shutdown watchdog, take no HA role, start no keepalive and acquire no lease
// of its own — the only key is the previous process's ghost, untouched.
func TestChaos71_ShutdownInsideTheGhostWaitAbortsTheResume(t *testing.T) {
	tempHADir(t)
	cfg := cpLeaderConfig(t)
	fake := halease.NewFake(time.Minute)
	if granted, _, _ := fake.Acquire(context.Background(), "cp-a"); !granted {
		t.Fatal("precondition: the previous process's ghost lease")
	}
	ghost, _ := fake.Read(context.Background())
	lease := &cpSignallingLease{Fake: fake, acquired: make(chan struct{}, 4)}
	h := &HAState{}
	h.SetLeaseProvider(lease, "cp-a")
	t.Cleanup(h.Stop)

	done := make(chan bool, 1)
	go func() { done <- h.ResumeAsLeaderIfUnclaimed(cfg, func() bool { return true }) }()
	select {
	case <-lease.acquired: // the first round saw our own ghost; the loop now waits it out
	case <-time.After(10 * time.Second):
		t.Fatal("the resume never tried the lease")
	}

	start := time.Now()
	h.BeginShutdown() // SIGTERM: the ha-stop hook
	var applied bool
	select {
	case applied = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the resume was still waiting on its ghost lease 5 s after shutdown began — the ha-stop watchdog (≈11 s) would abandon it")
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("the resume took %s to notice shutdown", took)
	}
	if applied {
		t.Error("the resume applied after shutdown began")
	}
	if st := h.Status(); st.Role != "" {
		t.Errorf("role after the aborted resume = %q, want none", st.Role)
	}
	h.mu.RLock()
	epoch, keepalive := h.leaseEpoch, h.leaseStopCh != nil
	h.mu.RUnlock()
	if epoch != 0 || keepalive {
		t.Errorf("after the aborted resume: leaseEpoch=%d keepalive=%v, want neither", epoch, keepalive)
	}
	if now, _ := fake.Read(context.Background()); now.Epoch != ghost.Epoch || now.Holder != ghost.Holder {
		t.Errorf("lease after the aborted resume = %+v, want the untouched ghost %+v — the resume must not acquire after shutdown", now, ghost)
	}
}

// TestChaos71_ShutdownAfterTheGrantTakesNoRole: shutdown lands right after the
// resume's acquisition was GRANTED. The re-check under HAState.mu must refuse
// the role and start no keepalive. The just-granted lease is left unkept and
// expires after its TTL: ADR-0005 S1 gives the Provider no Release primitive
// (a grant whose follow-up fails is the documented bounded stall).
func TestChaos71_ShutdownAfterTheGrantTakesNoRole(t *testing.T) {
	tempHADir(t)
	cfg := cpLeaderConfig(t)
	fake := halease.NewFake(time.Minute)
	h := &HAState{}
	h.SetLeaseProvider(fake, "cp-a")
	t.Cleanup(h.Stop)
	prev := haResumeAfterAcquire
	haResumeAfterAcquire = h.BeginShutdown
	t.Cleanup(func() { haResumeAfterAcquire = prev })

	if h.ResumeAsLeaderIfUnclaimed(cfg, func() bool { return true }) {
		t.Error("the resume applied although shutdown began right after its grant")
	}
	if st := h.Status(); st.Role != "" {
		t.Errorf("role = %q, want none", st.Role)
	}
	h.mu.RLock()
	keepalive := h.leaseStopCh != nil
	h.mu.RUnlock()
	if keepalive {
		t.Error("a keepalive was started after shutdown began")
	}
	// The unguarded resume obeys the same latch.
	h2 := &HAState{}
	h2.BeginShutdown()
	h2.ResumeAsLeader(cfg)
	if st := h2.Status(); st.Role != "" {
		t.Errorf("an unguarded resume after shutdown took role %q", st.Role)
	}
}

// TestChaos71_Wall_NoHALeaseAcquisitionUnderTheActivationGate: no function
// that takes cpActivationGateMu can reach — directly or through package
// functions — onActivated, a leadership resume or a lease acquisition. The
// ha-stop hook takes that gate, and the shutdown watchdog abandons it after
// ≈11 s; a fencing-backend wait (up to 45 s) under it is the defect.
func TestChaos71_Wall_NoHALeaseAcquisitionUnderTheActivationGate(t *testing.T) {
	funcs, holders := cpParseFuncsAndGateHolders(t)
	if len(holders) == 0 {
		t.Fatal("no function takes cpActivationGateMu — the wall's selector has gone stale")
	}
	forbidden := map[string]bool{
		"runOnActivated": true, "onActivated": true, "ResumeAsLeader": true, "ResumeAsLeaderIfUnclaimed": true,
		"resumeAsLeader": true, "acquireLeaseForResume": true, "acquireLeaseForLeadership": true,
		"acquireLeaseAttempt": true, "resumeAcquireRound": true, "Acquire": true,
	}
	for _, h := range holders {
		if path, bad := cpReaches(funcs, h, forbidden, 8); bad {
			t.Errorf("%s takes cpActivationGateMu and reaches %s — a fencing-backend wait would hold the gate the ha-stop hook needs",
				h, strings.Join(path, " → "))
		}
	}
}

// cpParseFuncsAndGateHolders maps every production function name to its
// declarations and lists the functions whose body takes cpActivationGateMu.
func cpParseFuncsAndGateHolders(t *testing.T) (funcs map[string][]*ast.FuncDecl, holders []string) {
	t.Helper()
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	funcs = map[string][]*ast.FuncDecl{}
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
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			funcs[fn.Name.Name] = append(funcs[fn.Name.Name], fn)
			if cpTakesGate(fn) {
				holders = append(holders, fn.Name.Name)
			}
		}
	}
	return funcs, holders
}

func cpTakesGate(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Lock" {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "cpActivationGateMu" {
				found = true
			}
		}
		return !found
	})
	return found
}

// cpCallees lists the names fn calls (plain and selector calls).
func cpCallees(fn *ast.FuncDecl) []string {
	var out []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			out = append(out, f.Name)
		case *ast.SelectorExpr:
			out = append(out, f.Sel.Name)
		}
		return true
	})
	return out
}

// cpReaches walks the by-name call graph from start (conservative: a name
// stands for every declaration with it) and reports a path to a forbidden
// name within depth.
func cpReaches(funcs map[string][]*ast.FuncDecl, start string, forbidden map[string]bool, depth int) ([]string, bool) {
	type node struct {
		name string
		path []string
	}
	seen := map[string]bool{start: true}
	queue := []node{{start, []string{start}}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if len(cur.path) > depth {
			continue
		}
		for _, decl := range funcs[cur.name] {
			for _, callee := range cpCallees(decl) {
				if forbidden[callee] {
					return append(append([]string(nil), cur.path...), callee), true
				}
				if !seen[callee] {
					seen[callee] = true
					queue = append(queue, node{callee, append(append([]string(nil), cur.path...), callee)})
				}
			}
		}
	}
	return nil, false
}

// TestChaos71_RoleConflictPagesAsALocalConfigConflict — Codex P2 4298247430.
// role_conflict is not a fleet outage: its page and its contract row name the
// contradictory local wiring and the config fix, never a fleet-wide outage or
// a restart. Any other terminal exit keeps the generic text.
func TestChaos71_RoleConflictPagesAsALocalConfigConflict(t *testing.T) {
	alerts := cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCSupervisorDown(cpGRPCRoleConflictReason)
	got := alerts()
	if len(got) != 1 {
		t.Fatalf("role_conflict paged %d time(s), want 1", len(got))
	}
	for _, want := range []string{"both Control Plane and Data Plane wiring", "Data Plane claimed", "not a fleet outage", "configuration"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("role_conflict page does not say %q: %q", want, got[0])
		}
	}
	for _, bad := range []string{"fleet-wide", "until this node is restarted"} {
		if strings.Contains(got[0], bad) {
			t.Errorf("role_conflict page says %q — it is a local config conflict, not an outage a restart fixes: %q", bad, got[0])
		}
	}
	row := checkCPGRPCListener()
	if row.Status != diagFail || strings.Contains(row.OperatorAction, "Restart this node") || strings.Contains(row.Message, "fleet-wide") ||
		!strings.Contains(row.OperatorAction, "configuration") {
		t.Errorf("role_conflict contract row = %+v", row)
	}

	// The panic exit keeps the generic terminal text.
	resetCPGRPCListenerHealthForTest()
	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCSupervisorDown("bind loop panicked")
	got = alerts()
	if last := got[len(got)-1]; !strings.Contains(last, "will NOT rebind") || !strings.Contains(last, "fleet-wide") {
		t.Errorf("the panic exit lost the generic terminal text: %q", last)
	}
	if row := checkCPGRPCListener(); !strings.Contains(row.OperatorAction, "Restart this node") {
		t.Errorf("the panic exit's row lost its restart remedy: %+v", row)
	}
}

// TestChaos71_NoLeaseIsAcquiredOnceShutdownBegan: a resume that starts after
// shutdown began never tries the fencing backend — no grant is taken that an
// abort would then leave to its TTL — and keepalive, the one HA loop a resume
// would start, refuses to spawn after the latch.
func TestChaos71_NoLeaseIsAcquiredOnceShutdownBegan(t *testing.T) {
	tempHADir(t)
	cfg := cpLeaderConfig(t)
	fake := halease.NewFake(time.Minute)
	lease := &cpSignallingLease{Fake: fake, acquired: make(chan struct{}, 4)}
	h := &HAState{}
	h.SetLeaseProvider(lease, "cp-a")
	t.Cleanup(h.Stop)
	h.BeginShutdown()

	if h.ResumeAsLeaderIfUnclaimed(cfg, func() bool { return true }) {
		t.Error("a resume applied after shutdown began")
	}
	select {
	case <-lease.acquired:
		t.Error("the resume called Acquire after shutdown began")
	default:
	}
	if st, _ := fake.Read(context.Background()); st.Holder != "" {
		t.Errorf("a lease key exists after a post-shutdown resume: %+v", st)
	}

	h.mu.Lock()
	h.setLeaseEpochLocked(7) // as if a grant were held
	h.mu.Unlock()
	h.startLeaseKeepalive()
	h.mu.RLock()
	started := h.leaseStopCh != nil
	h.mu.RUnlock()
	if started {
		t.Error("a lease keepalive started after shutdown began")
	}
}

// TestChaos71_WallTheHAStopHookLatchesShutdownBeforeStop: the ha-stop hook
// closes the activation gate, latches HA shutdown, and only then joins.
func TestChaos71_WallTheHAStopHookLatchesShutdownBeforeStop(t *testing.T) {
	body := cpReadSource(t, "main_shutdown.go")
	i := strings.Index(body, `reg.Register("ha-stop"`)
	if i < 0 {
		t.Fatal("could not locate the ha-stop hook")
	}
	hook := body[i:]
	if j := strings.Index(hook, "\n\t})"); j > 0 {
		hook = hook[:j]
	}
	gate, latch, stop := strings.Index(hook, "beginCPActivationShutdown()"), strings.Index(hook, "globalHA.BeginShutdown()"), strings.Index(hook, "globalHA.Stop()")
	if gate < 0 || latch < 0 || stop < 0 || gate > latch || latch > stop {
		t.Errorf("the ha-stop hook must close the gate, latch HA shutdown, then Stop (positions gate=%d latch=%d stop=%d)", gate, latch, stop)
	}
}
