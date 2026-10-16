package main

// cp_grpc_exit_edges_chaos_test.go — CHAOS-71: the supervisor's state machine
// as ONE table. Every exit edge of bind → adopt → claim → publish →
// onActivated → serve is driven deterministically, and every row asserts both
// columns of the table on cpListenerSupervisor.run: what must be RELEASED
// (server handle, bound socket, CP role, address publication) and what must be
// SIGNALLED (stopped / recoverable / terminal, and the alert).
//
// Determinism: the edge is opened by a seam or a pre-set flag, never by a
// sleep. The supervisor's backoff sleep is replaced (cpGRPCSleep) by a probe
// that captures the state at the moment the loop would sleep and then ends
// the loop, so recoverable rows are observed exactly where the edge left them.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type cpEdgeSignal int

const (
	cpEdgeStopped cpEdgeSignal = iota
	cpEdgeRecoverable
	cpEdgeTerminal
)

// cpEdgeObservation is what the probe captured when the loop went to sleep.
type cpEdgeObservation struct {
	snap   cpGRPCListenerSnapshot
	role   string
	handle bool
}

// cpEdgeEnv is what a row's setup hands the harness.
type cpEdgeEnv struct {
	t           *testing.T
	cfg         cpListenerConfig
	onActivated func()
	// drive runs after the supervisor started (it is already resolved on the
	// first attempt); nil means "nothing more to do".
	drive func(sup *cpListenerSupervisor)
	// sleeper overrides the default probe (capture once, then end the loop).
	sleeper func(stop <-chan struct{}, d time.Duration) bool
}

type cpEdgeRow struct {
	name string
	// setup prepares seams/state for the edge.
	setup func(e *cpEdgeEnv)
	// released column
	ownPort  bool   // the row's own address must be bindable afterwards
	wantRole string // the role after the edge (at the probe for recoverable rows)
	// signalled column
	signal     cpEdgeSignal
	wantReason string // recoverable/terminal reason class
	// extra per-row assertions
	check func(t *testing.T, sup *cpListenerSupervisor, obs *cpEdgeObservation)
}

// TestChaos71_SupervisorExitEdgeTable drives every exit edge of the CP
// listener supervisor (the table on cpListenerSupervisor.run).
func TestChaos71_SupervisorExitEdgeTable(t *testing.T) {
	boom := errors.New("injected commit-time rejection")
	var publishes atomic.Int32
	countingPublish := func(changed bool, err error) func() (bool, error) {
		return func() (bool, error) {
			publishes.Add(1)
			return changed, err
		}
	}
	var lnMu sync.Mutex
	var lns []net.Listener
	captureListeners := func(t *testing.T) {
		prev := cpWrapListener
		cpWrapListener = func(ln net.Listener) net.Listener {
			lnMu.Lock()
			lns = append(lns, ln)
			lnMu.Unlock()
			return ln
		}
		t.Cleanup(func() { cpWrapListener = prev })
	}
	firstListener := func() net.Listener {
		lnMu.Lock()
		defer lnMu.Unlock()
		return lns[0]
	}
	waitServing := func(t *testing.T) {
		cpWaitFor(t, 10*time.Second, "the listener to serve", func() bool { return cpGRPCListenerState().Serving })
	}

	rows := []cpEdgeRow{
		{
			name: "bind_failure",
			setup: func(e *cpEdgeEnv) {
				port, release := occupyPort(e.t)
				e.t.Cleanup(release)
				e.cfg.addr = fmt.Sprintf("127.0.0.1:%d", port)
			},
			wantRole: "standalone", signal: cpEdgeRecoverable, wantReason: "port_in_use",
		},
		{
			name: "tls_reload_failure",
			setup: func(e *cpEdgeEnv) {
				dir := e.t.TempDir()
				_ = os.WriteFile(dir+"/cp.crt", []byte("not a cert"), 0o600)
				_ = os.WriteFile(dir+"/cp.key", nil, 0o600)
				e.cfg.certFile, e.cfg.keyFile = dir+"/cp.crt", dir+"/cp.key"
			},
			ownPort: true, wantRole: "standalone", signal: cpEdgeRecoverable, wantReason: "tls_certificate",
		},
		{
			name:    "shutdown_at_the_claim",
			setup:   func(*cpEdgeEnv) { beginCPActivationShutdown() },
			ownPort: true, wantRole: "standalone", signal: cpEdgeStopped,
		},
		{
			name: "role_conflict",
			setup: func(*cpEdgeEnv) {
				clusterRoleMu.Lock()
				clusterRole.role = "data-plane"
				clusterRoleMu.Unlock()
			},
			ownPort: true, wantRole: "data-plane", signal: cpEdgeTerminal, wantReason: "role_conflict",
		},
		{
			name: "shutdown_after_the_claim",
			setup: func(e *cpEdgeEnv) {
				cpInjectPublish(e.t, countingPublish(true, nil))
				cpActivationAfterClaim = beginCPActivationShutdown
				e.t.Cleanup(func() { cpActivationAfterClaim = nil })
			},
			ownPort: true, wantRole: "standalone", signal: cpEdgeStopped,
			check: func(t *testing.T, _ *cpListenerSupervisor, _ *cpEdgeObservation) {
				if publishes.Load() != 0 {
					t.Error("the address list was published after shutdown began")
				}
			},
		},
		{
			name:    "address_publish_rejected",
			setup:   func(e *cpEdgeEnv) { cpInjectPublish(e.t, countingPublish(false, boom)) },
			ownPort: true, wantRole: "standalone", signal: cpEdgeRecoverable, wantReason: "address_publish_rejected",
		},
		{
			name: "panic_after_the_claim",
			setup: func(e *cpEdgeEnv) {
				cpActivationAfterClaim = func() { panic("injected: after claim") }
				e.t.Cleanup(func() { cpActivationAfterClaim = nil })
			},
			ownPort: true, wantRole: "standalone", signal: cpEdgeTerminal, wantReason: "bind loop panicked",
		},
		{
			name: "panic_in_onActivated",
			setup: func(e *cpEdgeEnv) {
				cpInjectPublish(e.t, countingPublish(true, nil))
				e.onActivated = func() { panic("injected: onActivated") }
			},
			ownPort: true, wantRole: "standalone", signal: cpEdgeTerminal, wantReason: "bind loop panicked",
			check: func(t *testing.T, _ *cpListenerSupervisor, _ *cpEdgeObservation) {
				if publishes.Load() < 2 {
					t.Errorf("the address list naming this node was published but never republished after the "+
						"panic (%d publish call(s)) — the fleet keeps a Control Plane that is gone", publishes.Load())
				}
			},
		},
		{
			name: "stop_while_serving",
			setup: func(e *cpEdgeEnv) {
				e.drive = func(sup *cpListenerSupervisor) {
					waitServing(e.t)
					_ = sup.Stop(e.t.Context())
				}
			},
			ownPort: true, wantRole: "control-plane", signal: cpEdgeStopped,
		},
		{
			name: "serve_ends_on_its_own",
			setup: func(e *cpEdgeEnv) {
				captureListeners(e.t)
				e.drive = func(*cpListenerSupervisor) {
					waitServing(e.t)
					_ = firstListener().Close()
				}
			},
			ownPort: true, wantRole: "control-plane", signal: cpEdgeRecoverable, wantReason: "listen_failed",
		},
		{
			name: "panic_after_a_serve_ended",
			setup: func(e *cpEdgeEnv) {
				captureListeners(e.t)
				cpInjectPublish(e.t, countingPublish(true, nil))
				e.sleeper = func(<-chan struct{}, time.Duration) bool { panic("injected: in the backoff after a serve") }
				e.drive = func(*cpListenerSupervisor) {
					waitServing(e.t)
					_ = firstListener().Close()
				}
			},
			ownPort: true, wantRole: "standalone", signal: cpEdgeTerminal, wantReason: "bind loop panicked",
			check: func(t *testing.T, _ *cpListenerSupervisor, _ *cpEdgeObservation) {
				if publishes.Load() < 2 {
					t.Errorf("no republish after the terminal exit (%d publish call(s))", publishes.Load())
				}
			},
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			publishes.Store(0)
			lnMu.Lock()
			lns = nil
			lnMu.Unlock()
			cpRunEdgeRow(t, row)
		})
	}
}

// cpRunEdgeRow runs one row: setup, start, drive, wait for the loop to end,
// then assert the released and signalled columns.
func cpRunEdgeRow(t *testing.T, row cpEdgeRow) {
	t.Helper()
	_ = cpIsolateActivation(t)
	alerts := cpChaosSetup(t)
	cpInsecure(t)
	clusterRoleMu.Lock()
	clusterRole.role = "standalone"
	clusterRoleMu.Unlock()

	e := &cpEdgeEnv{t: t, cfg: cpListenerConfig{addr: fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))}}
	row.setup(e)

	var obs *cpEdgeObservation
	var sup *cpListenerSupervisor
	var supMu sync.Mutex
	probe := func(_ <-chan struct{}, _ time.Duration) bool {
		if obs == nil {
			supMu.Lock()
			s := sup
			supMu.Unlock()
			o := &cpEdgeObservation{snap: cpGRPCListenerState(), role: cpRoleNow()}
			if s != nil {
				o.handle = s.currentServer() != nil
			}
			obs = o
		}
		return false // end the loop exactly here
	}
	if e.sleeper == nil {
		e.sleeper = probe
	}
	prevSleep := cpGRPCSleep
	cpGRPCSleep = e.sleeper
	t.Cleanup(func() { cpGRPCSleep = prevSleep })

	started, _ := cpStartSupervised(t, e.cfg, true, e.onActivated)
	if started == nil {
		t.Fatal("the boot path returned no supervisor")
	}
	supMu.Lock()
	sup = started
	supMu.Unlock()
	if e.drive != nil {
		e.drive(started)
	}
	select {
	case <-started.done:
	case <-time.After(15 * time.Second):
		t.Fatal("the supervisor loop did not end at the edge")
	}

	final := cpGRPCListenerState()
	role := cpRoleNow()

	// ---- released column
	if started.currentServer() != nil {
		t.Error("a server handle is still published after the edge")
	}
	if row.ownPort {
		cpRequirePortReleased(t, e.cfg.addr)
	}
	gotRole := role
	if row.signal == cpEdgeRecoverable {
		if obs == nil {
			t.Fatal("the loop never reached its backoff after a recoverable edge")
		}
		gotRole = obs.role
		if obs.handle {
			t.Error("a server handle was still published while the loop backed off")
		}
	}
	if gotRole != row.wantRole {
		t.Errorf("role after the edge = %q, want %q", gotRole, row.wantRole)
	}

	// ---- signalled column
	switch row.signal {
	case cpEdgeStopped:
		if !final.Stopped || final.SupervisorDown {
			t.Errorf("signal: want stopped, got stopped=%v supervisorDown=%v", final.Stopped, final.SupervisorDown)
		}
	case cpEdgeRecoverable:
		if !obs.snap.Failing || obs.snap.SupervisorDown || obs.snap.LastReason != row.wantReason {
			t.Errorf("signal: want recoverable %q, got failing=%v supervisorDown=%v reason=%q",
				row.wantReason, obs.snap.Failing, obs.snap.SupervisorDown, obs.snap.LastReason)
		}
	case cpEdgeTerminal:
		if !final.SupervisorDown || !final.Unavailable || final.LastReason != row.wantReason {
			t.Errorf("signal: want TERMINAL %q, got supervisorDown=%v unavailable=%v reason=%q",
				row.wantReason, final.SupervisorDown, final.Unavailable, final.LastReason)
		}
		if len(alerts()) == 0 {
			t.Error("a terminal edge raised no cp_grpc_listener_down alert")
		}
	}
	if row.check != nil {
		row.check(t, started, obs)
	}
}

// TestChaos71_TerminalEscalationPagesAgain — Codex P2 (4294641548). A
// recoverable episode that already paged ("the listener keeps retrying") and
// then turns terminal must page AGAIN: the one alert subscribers hold carries
// the opposite operator action. The terminal state has its own latch.
func TestChaos71_TerminalEscalationPagesAgain(t *testing.T) {
	alerts := cpChaosSetup(t)
	base := cpGRPCHealthNow()
	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCBindFailure("port_in_use", time.Second, base)
	later := base.Add(cpGRPCUnavailableAfter + time.Second)
	cpSwapHealthClock(t, func() time.Time { return later })
	noteCPGRPCBindFailure("port_in_use", 2*time.Second, later)
	if n := len(alerts()); n != 1 {
		t.Fatalf("precondition: the recoverable episode paged %d time(s), want 1", n)
	}

	noteCPGRPCSupervisorDown("role_conflict")
	got := alerts()
	if len(got) != 2 {
		t.Fatalf("the terminal escalation paged %d time(s) in total, want 2 — subscribers keep the 'keeps retrying' instruction", len(got))
	}
	if !strings.Contains(got[1], "will NOT rebind") {
		t.Errorf("the escalation alert does not carry the terminal instruction: %q", got[1])
	}
	// And the terminal latch is fire-once per episode.
	noteCPGRPCSupervisorDown("role_conflict")
	if n := len(alerts()); n != 2 {
		t.Errorf("a repeated terminal record paged again (%d alerts)", n)
	}
}

// TestChaos71_FullPublishRejectsWhenTheRetryBudgetRunsOut — CodeRabbit
// (4294902254). If the owned CP address list changes after EVERY validation,
// the full publish must give up through the rejection path — never fall
// through and commit a list it did not validate. Deterministic: the seam
// commits a different address list inside each validate→commit window.
func TestChaos71_FullPublishRejectsWhenTheRetryBudgetRunsOut(t *testing.T) {
	s := &ConfigStore{}
	var n atomic.Int32
	src := func() []string { return []string{fmt.Sprintf("10.0.0.%d:50051", n.Load())} }
	s.setCPAddressSource(src)
	if err := s.Update(ConfigSnapshot{CPAddresses: src()}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before := s.Version()

	var windows atomic.Int32
	configPublishBeforeCommit = func() {
		windows.Add(1)
		n.Add(1)
		if _, err := s.UpdateCPAddressesFrom(src); err != nil {
			t.Errorf("competing address publish: %v", err)
		}
	}
	t.Cleanup(func() { configPublishBeforeCommit = nil })

	err := s.Update(ConfigSnapshot{BlockedHosts: []string{"never-validated-with-this-list.example"}})
	if err == nil {
		t.Fatal("the full publish committed after exhausting its retry budget — with a CP address list it never validated")
	}
	if got := int(windows.Load()); got != cpAddrMergeAttempts {
		t.Errorf("the publish retried %d time(s), want exactly the budget (%d)", got, cpAddrMergeAttempts)
	}
	if cpListNames(s.Get().BlockedHosts, "never-validated-with-this-list.example") {
		t.Error("the unvalidated full publish was committed")
	}
	if msg, _ := s.LastPublishError(); msg == "" {
		t.Error("the exhausted publish did not go through the rejection path (no LastPublishError)")
	}
	// Only the competing address publishes committed.
	if got := s.Version() - before; got != int64(cpAddrMergeAttempts) {
		t.Errorf("%d commit(s) after the seed, want %d (the competing address publishes only)", got, cpAddrMergeAttempts)
	}
}

// TestChaos71_FullPublishValidatesTheListItCommits — Codex P1 (4294641541).
// The owned-list substitution used to run AFTER validation, so a near-limit
// snapshot validated with its own short list could be committed with a longer
// committed list — past the wire budget, rejected by every DP. Substitution now
// precedes validation and the commit is exactly what was validated.
func TestChaos71_FullPublishValidatesTheListItCommits(t *testing.T) {
	short := []string{"10.0.0.1:50051"}
	long := make([]string, 50)
	for i := range long {
		long[i] = fmt.Sprintf("cp-%02d.a-rather-long-control-plane-hostname.example.internal:50051", i)
	}
	big := ConfigSnapshot{BlockedHosts: make([]string, 200)}
	for i := range big.BlockedHosts {
		big.BlockedHosts[i] = fmt.Sprintf("blocked-%04d.example", i)
	}
	big.CPAddresses = long
	withLong, err := json.Marshal(big)
	if err != nil {
		t.Fatal(err)
	}
	big.CPAddresses = short

	prevBudget := snapshotWireBudget
	snapshotWireBudget = len(withLong) - 1 // big fits with the short list, not with the long one
	t.Cleanup(func() { snapshotWireBudget = prevBudget })

	s := &ConfigStore{}
	src := func() []string { return long }
	s.setCPAddressSource(src)
	if err := s.Update(ConfigSnapshot{CPAddresses: short}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := s.Get().CPAddresses; len(got) != len(long) {
		t.Fatalf("precondition: the owned long list was not committed (%d entries)", len(got))
	}

	if err := s.Update(big); err == nil {
		t.Fatal("a snapshot that exceeds the wire budget once it carries the committed CP address list was published")
	}
	if got := s.Get(); len(got.BlockedHosts) != 0 {
		t.Errorf("the oversized snapshot was committed (%d blocked hosts) — every DP would reject it", len(got.BlockedHosts))
	}
}
