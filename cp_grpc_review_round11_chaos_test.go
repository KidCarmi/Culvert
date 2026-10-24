package main

// cp_grpc_review_round11_chaos_test.go — CHAOS-71 gates for the eleventh
// review round on #1556: the boot resume vs a live HA enable (Codex P2
// 4297464190), terminal exits releasing CP address ownership (P2 4297464174;
// the per-row column lives in the exit-edge table) and the backoff gauge while
// serving (P3 4297464200).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestChaos71_BootResumeLosesToAnAdminHAEnableDuringAcquisition: an admin HA
// enable lands inside the resume's lease-acquisition window and persists a new
// peer and token. The resume must abort rather than overwrite and re-persist
// the older config — via the persisted-config revalidation, and independently
// via the role check made atomically under HAState.mu.
func TestChaos71_BootResumeLosesToAnAdminHAEnableDuringAcquisition(t *testing.T) {
	const (
		oldPeer = "10.0.0.9:50051"
		newPeer = "10.0.0.5:50051"
	)
	for _, tc := range []struct {
		name  string
		guard func(cfg *haConfig) func() bool
	}{
		{"persisted_config_revalidated", func(cfg *haConfig) func() bool {
			return func() bool { return haConfigStillResumable(cfg) }
		}},
		{"live_role_check_alone", func(*haConfig) func() bool { return func() bool { return true } }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tempHADir(t)
			if err := saveHAConfig(&haConfig{Enabled: true, Role: "leader", PeerAddr: oldPeer, Token: "old-token", Term: 3}); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadHAConfig()
			if err != nil {
				t.Fatal(err)
			}
			h := &HAState{}
			t.Cleanup(h.Stop)
			fired := false
			prev := haResumeAfterAcquire
			haResumeAfterAcquire = func() {
				if !fired {
					fired = true
					if _, err := h.EnableAsLeader(newPeer, false); err != nil {
						t.Errorf("admin enable: %v", err)
					}
				}
			}
			t.Cleanup(func() { haResumeAfterAcquire = prev })

			if applied := h.ResumeAsLeaderIfUnclaimed(cfg, tc.guard(cfg)); applied {
				t.Error("the resume applied over an HA enable that landed during its lease acquisition")
			}
			if got := h.Status().PeerAddr; got != newPeer {
				t.Errorf("live peer = %q, want the admin's %q", got, newPeer)
			}
			persisted, err := loadHAConfig()
			if err != nil {
				t.Fatal(err)
			}
			if persisted.PeerAddr != newPeer || persisted.Token == "old-token" {
				t.Errorf("persisted config = peer %q token %q — the resume overwrote the admin's decision", persisted.PeerAddr, persisted.Token)
			}
		})
	}
}

// TestChaos71_BootResumeRevalidatesThePersistedConfig: the persisted config
// alone changes during the acquisition (flipped to standby, no live
// transition). The persisted revalidation must abort the resume.
func TestChaos71_BootResumeRevalidatesThePersistedConfig(t *testing.T) {
	tempHADir(t)
	if err := saveHAConfig(&haConfig{Enabled: true, Role: "leader", PeerAddr: "10.0.0.9:50051", Token: "tok", Term: 3}); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadHAConfig()
	if err != nil {
		t.Fatal(err)
	}
	h := &HAState{}
	t.Cleanup(h.Stop)
	prev := haResumeAfterAcquire
	haResumeAfterAcquire = func() {
		_ = saveHAConfig(&haConfig{Enabled: true, Role: "standby", PeerAddr: "10.0.0.7:50051", Token: "tok"})
	}
	t.Cleanup(func() { haResumeAfterAcquire = prev })

	if h.ResumeAsLeaderIfUnclaimed(cfg, func() bool { return haConfigStillResumable(cfg) }) {
		t.Error("the resume applied after the persisted config stopped saying this node leads")
	}
	if role := h.Status().Role; role != "" {
		t.Errorf("role after the aborted resume = %q, want none", role)
	}
}

// TestChaos71_BootResumeAppliesWhenNothingRaced is the positive control.
func TestChaos71_BootResumeAppliesWhenNothingRaced(t *testing.T) {
	tempHADir(t)
	if err := saveHAConfig(&haConfig{Enabled: true, Role: "leader", PeerAddr: "10.0.0.9:50051", Token: "tok", Term: 3}); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadHAConfig()
	if err != nil {
		t.Fatal(err)
	}
	h := &HAState{}
	t.Cleanup(h.Stop)
	if !h.ResumeAsLeaderIfUnclaimed(cfg, func() bool { return haConfigStillResumable(cfg) }) {
		t.Fatal("an uncontested resume did not apply")
	}
	if st := h.Status(); st.Role != "leader" || st.PeerAddr != "10.0.0.9:50051" || st.Term != 3 {
		t.Errorf("resumed state = %+v", st)
	}
}

// TestChaos71_Wall_TerminalExitsGoThroughExitTerminal: the terminal-state
// recorder is called only by exitTerminal, so every terminal exit releases CP
// address ownership.
func TestChaos71_Wall_TerminalExitsGoThroughExitTerminal(t *testing.T) {
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	callers := map[string]int{}
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
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "noteCPGRPCSupervisorDown" {
						callers[owner]++
					}
				}
				return true
			})
		}
	}
	if len(callers) != 1 || callers["exitTerminal"] == 0 {
		t.Errorf("noteCPGRPCSupervisorDown callers = %v, want only exitTerminal", callers)
	}
}

// TestChaos71_BackoffGaugeReadsZeroWhileServing — Codex P3 4297464200: the
// gauge's contract is "0 while serving", stabilizing included; the internal
// backoff the episode keeps is not what it reports.
func TestChaos71_BackoffGaugeReadsZeroWhileServing(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCListenFailure("port_in_use", 8*time.Second, cpGRPCHealthNow())
	if got := cpGRPCListenerState().Backoff; got != 8*time.Second {
		t.Fatalf("precondition: backoff while rebinding = %s", got)
	}
	noteCPGRPCBound()
	snap := cpGRPCListenerState()
	if !snap.Stabilizing || snap.Backoff != 0 {
		t.Errorf("while serving (stabilizing=%v) the reported backoff = %s, want 0", snap.Stabilizing, snap.Backoff)
	}
	var b strings.Builder
	writeCPGRPCMetrics(&b)
	if !strings.Contains(b.String(), "culvert_cp_grpc_bind_backoff_seconds 0\n") {
		t.Errorf("metric while serving:\n%s", b.String())
	}
	cpGRPCListener.mu.Lock()
	internal := cpGRPCListener.backoff
	cpGRPCListener.mu.Unlock()
	if internal != 8*time.Second {
		t.Errorf("the internal backoff was reset to %s — the episode keeps it", internal)
	}
}
