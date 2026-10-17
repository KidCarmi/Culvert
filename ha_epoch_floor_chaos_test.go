package main

// ha_epoch_floor_chaos_test.go — CHAOS-71, Codex P1 4302435329 on #1645: a
// grant lost after its epoch committed but before it was exposed. The owner
// chose the narrow rule (ADR-0005 implementation note): with NO HA role the
// published stamp never drops below the highest epoch this node committed (the
// role-less floor), so an HA-off node's Data Planes keep accepting config;
// under an HA role S3's zombie-0 rule is unchanged, and Data Planes that
// ratcheted to the committed epoch wait, fail closed, for the real leader.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// cpFloorHarness is cpEpochHarness with a short-TTL fake, so the keepalive
// notices a lost grant within a few hundred milliseconds.
func cpFloorHarness(t *testing.T, myAddr string) (*HAState, *halease.Fake) {
	t.Helper()
	h, _, _ := cpEpochHarness(t, myAddr)
	f := halease.NewFake(300 * time.Millisecond)
	h.SetLeaseProvider(f, "cp-a")
	return h, f
}

// cpLoseGrantAfterItsCommit wraps the stamped commit: the commit runs, a Data
// Plane fetches the E-stamped snapshot and ratchets to E, and then the peer
// takes the lease and the keepalive drops the staged grant — all before the
// transition reaches its exposure.
func cpLoseGrantAfterItsCommit(t *testing.T, h *HAState, f *halease.Fake, e int64) {
	t.Helper()
	prev := haRestampFenceEpoch
	haRestampFenceEpoch = func() error {
		err := prev()
		if got := globalConfigStore.Get().Epoch; err != nil || got != e {
			t.Errorf("precondition: the stamped commit err=%v committed epoch %d, want %d", err, got, e)
		}
		if !dpObserveEpoch("config snapshot", globalConfigStore.Get().Epoch) {
			t.Error("precondition: the Data Plane rejected the E-stamped snapshot")
		}
		f.ExpireForTest()
		if granted, _, aerr := f.Acquire(context.Background(), "cp-b"); !granted || aerr != nil {
			t.Errorf("precondition: the peer could not take the lease (granted=%v err=%v)", granted, aerr)
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			h.mu.RLock()
			lost := h.grantEpoch == 0
			h.mu.RUnlock()
			if lost {
				return err
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("precondition: the keepalive never dropped the lost grant")
		return err
	}
	t.Cleanup(func() { haRestampFenceEpoch = prev })
}

// cpNextPublishVerdict makes the next publish (a CP address list change, so
// something commits) and reports the epoch it carried, whether the Data Plane
// (ratcheted to the committed epoch) accepted it, and the same for the delta
// reply a polling Data Plane would receive.
func cpNextPublishVerdict(t *testing.T, ip string) (stamp int64, accepted bool, deltaEpoch int64, deltaAccepted bool) {
	t.Helper()
	before := globalConfigStore.Version()
	changed, err := globalConfigStore.UpdateCPAddressesFrom(func() []string { return []string{"10.0.0.8:50051"} })
	if err != nil || !changed {
		t.Fatalf("the next publish: changed=%v err=%v", changed, err)
	}
	stamp = globalConfigStore.Get().Epoch
	accepted = dpObserveEpoch("config snapshot", stamp)
	clearUnenrolledPull(ip)
	t.Cleanup(func() { clearUnenrolledPull(ip) })
	reply := callDelta(t, &controlPlaneServer{}, deltaCtx(ip), before)
	return stamp, accepted, reply.Epoch, dpObserveEpoch("config delta", reply.Epoch)
}

// TestChaos71_FailedEnableAfterItsCommitKeepsTheRoleLessFloor — the Codex
// interleaving. The enable commits E, a Data Plane ratchets to E, and the
// grant is lost before exposure. The enable is refused: no HA role, no
// advertised epoch, no write authority. But the node is HA-off and still
// serving, so its next publish (and delta reply) carries E, and the Data
// Plane that ratcheted to E accepts it instead of freezing.
func TestChaos71_FailedEnableAfterItsCommitKeepsTheRoleLessFloor(t *testing.T) {
	h, f := cpFloorHarness(t, "10.0.0.2:50051")
	e := cpNextGrantEpoch(t, f)
	cpLoseGrantAfterItsCommit(t, h, f, e)

	if _, err := h.EnableAsLeader("10.0.0.9:50051", false); err == nil {
		t.Fatal("enable succeeded although its grant was lost before exposure")
	}
	if st := h.Status(); st.Role != "" || st.Enabled {
		t.Fatalf("role=%q enabled=%v after the failed enable, want HA off", st.Role, st.Enabled)
	}
	if got := h.CurrentEpoch(); got != 0 {
		t.Errorf("the lost grant's epoch %d is advertised", got)
	}
	if _, _, epoch := h.leaseHealth(); epoch != 0 {
		t.Errorf("/healthz reports epoch %d for a grant that was never installed", epoch)
	}
	if h.WriteAllowed() {
		t.Error("the lost grant conferred write authority")
	}
	if got := h.PublishedFenceEpoch(); got != e {
		t.Errorf("publishes stamp %d, want the committed epoch %d (the role-less floor)", got, e)
	}
	stamp, ok, deltaEpoch, deltaOK := cpNextPublishVerdict(t, "203.0.113.71")
	if stamp != e || !ok {
		t.Errorf("the next publish carried epoch %d (accepted=%v), want %d accepted — the HA-off node's Data Planes freeze", stamp, ok, e)
	}
	if deltaEpoch != e || !deltaOK {
		t.Errorf("the delta reply carried epoch %d (accepted=%v), want %d accepted", deltaEpoch, deltaOK, e)
	}
}

// TestChaos71_HARoleLosingACommittedGrantStampsZero — the same loss under an
// HA role: a promote (standby) and a lease recovery (read-only leader). The
// role is kept, the stamp is 0 (ADR-0005 S3's zombie shape) and the Data
// Plane that ratcheted to E rejects it, waiting for the real leader's higher
// epoch. The floor IS recorded; the role decides that it is not applied.
func TestChaos71_HARoleLosingACommittedGrantStampsZero(t *testing.T) {
	const myAddr = "10.0.0.2:50051"
	for _, tc := range []struct {
		name, role string
		setup      func(t *testing.T, h *HAState, f *halease.Fake)
		do         func(t *testing.T, h *HAState)
		ip         string
	}{
		{"promote", "standby",
			func(t *testing.T, h *HAState, _ *halease.Fake) { cpEnterStandby(t, h, myAddr) },
			func(t *testing.T, h *HAState) {
				if err := h.PromoteManually(); err == nil {
					t.Fatal("promote succeeded although its grant was lost before exposure")
				}
			}, "203.0.113.72"},
		{"lease_recovery", "leader",
			func(t *testing.T, h *HAState, f *halease.Fake) {
				cpReadOnlyLeader(t, h, f)
				f.ExpireForTest() // the refused resume's grant lapses; recovery acquires afresh
			},
			func(t *testing.T, h *HAState) {
				if cpRecoveryRound(h) {
					t.Fatal("the recovery round reported done although its grant was lost before exposure")
				}
			}, "203.0.113.73"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, f := cpFloorHarness(t, myAddr)
			tc.setup(t, h, f)
			e := cpNextGrantEpoch(t, f)
			cpLoseGrantAfterItsCommit(t, h, f, e)
			tc.do(t, h)

			if st := h.Status(); st.Role != tc.role {
				t.Fatalf("role = %q, want %q", st.Role, tc.role)
			}
			if got := h.CurrentEpoch(); got != 0 {
				t.Errorf("the lost grant's epoch %d is advertised", got)
			}
			if h.WriteAllowed() {
				t.Error("the lost grant conferred write authority")
			}
			h.mu.RLock()
			floor := h.committedEpoch
			h.mu.RUnlock()
			if floor != e {
				t.Errorf("committedEpoch = %d, want %d — the commit was not recorded, so this test no longer isolates the role gate", floor, e)
			}
			if got := h.PublishedFenceEpoch(); got != 0 {
				t.Errorf("an HA-role node that lost its lease stamps %d, want 0 (ADR-0005 S3)", got)
			}
			stamp, ok, deltaEpoch, deltaOK := cpNextPublishVerdict(t, tc.ip)
			if stamp != 0 || ok {
				t.Errorf("the next publish carried epoch %d (accepted=%v), want 0 rejected — a fenced node's writes reach the fleet", stamp, ok)
			}
			if deltaEpoch != 0 || deltaOK {
				t.Errorf("the delta reply carried epoch %d (accepted=%v), want 0 rejected", deltaEpoch, deltaOK)
			}
		})
	}
}

// TestChaos71_Wall_RoleLessEpochFloorAppliesOnlyWithoutAnHARole: the floor
// reaches the stamp mirror and the config reply epoch only while no HA role is
// held; taking a role drops it at once (setTopologyLocked re-derives the
// mirror); an installed grant wins under every role. committedEpoch is
// written only by noteCommittedEpochLocked and read only by
// configEpochLocked, inside its no-role branch.
func TestChaos71_Wall_RoleLessEpochFloorAppliesOnlyWithoutAnHARole(t *testing.T) {
	tempHADir(t)
	h := &HAState{}
	t.Cleanup(h.Stop)
	h.SetLeaseProvider(halease.NewFake(time.Minute), "cp-a")
	const floor, installed = int64(7), int64(9)
	check := func(step string, want int64) {
		t.Helper()
		if got := h.PublishedFenceEpoch(); got != want {
			t.Errorf("%s: publishes stamp %d, want %d", step, got, want)
		}
		if got := h.ConfigReplyEpoch(); got != want {
			t.Errorf("%s: config replies carry %d, want %d", step, got, want)
		}
	}
	h.mu.Lock()
	h.noteCommittedEpochLocked(floor)
	h.noteCommittedEpochLocked(floor - 2) // the floor only rises
	h.syncFenceEpochLocked()
	h.mu.Unlock()
	check("no role", floor)
	for _, role := range []string{"standby", "leader", ""} {
		h.mu.Lock()
		h.setTopologyLocked(role, "10.0.0.9:50051", haTransitionStandby)
		h.mu.Unlock()
		want := int64(0)
		if role == "" {
			want = floor
		}
		check("role "+role, want)
		h.mu.Lock()
		h.setLeaseEpochLocked(installed)
		h.mu.Unlock()
		check("role "+role+" with an installed grant", installed)
		h.mu.Lock()
		h.setLeaseEpochLocked(0)
		h.mu.Unlock()
	}
	h.SetLeaseProvider(nil, "")
	check("legacy mode", 0)

	cpWallFieldUse(t, "committedEpoch", map[string]bool{"configEpochLocked": true, "noteCommittedEpochLocked": true})
	cpWallFloorReadIsRoleGated(t)
}

// cpWallFloorReadIsRoleGated: every committedEpoch read in configEpochLocked
// sits inside an `if h.role == ""` branch.
func cpWallFloorReadIsRoleGated(t *testing.T) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(pkgSourceDir(), "ha_fencing.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "configEpochLocked" {
			fn = fd
		}
	}
	if fn == nil {
		t.Fatal("configEpochLocked not found in ha_fencing.go — the wall's selector has gone stale")
	}
	var gated []*ast.BlockStmt
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if is, ok := n.(*ast.IfStmt); ok && cpIsNoRoleTest(is.Cond) {
			gated = append(gated, is.Body)
		}
		return true
	})
	reads := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "committedEpoch" {
			return true
		}
		reads++
		inside := false
		for _, b := range gated {
			inside = inside || (sel.Pos() >= b.Pos() && sel.End() <= b.End())
		}
		if !inside {
			t.Errorf("%s: configEpochLocked reads committedEpoch outside its no-role branch — the floor would apply under an HA role", fset.Position(sel.Pos()))
		}
		return true
	})
	if reads == 0 {
		t.Error("configEpochLocked never reads committedEpoch — the wall's selector has gone stale")
	}
}

// cpIsNoRoleTest reports whether cond is `<x>.role == ""`.
func cpIsNoRoleTest(cond ast.Expr) bool {
	be, ok := cond.(*ast.BinaryExpr)
	if !ok || be.Op != token.EQL {
		return false
	}
	sel, ok := be.X.(*ast.SelectorExpr)
	lit, isLit := be.Y.(*ast.BasicLit)
	return ok && sel.Sel.Name == "role" && isLit && lit.Kind == token.STRING && lit.Value == `""`
}
