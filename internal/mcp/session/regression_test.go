package session

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// TestConcurrentRequestPathVersusDirectory races the request hot paths
// (RegisterRequest / CorrelateResponse / Cancel, which take only the session
// lock) against the directory operations (Sweep / Close / Open, which take the
// manager lock then a session lock). Before the fix the request paths took the
// manager lock WHILE holding the session lock, the opposite order from Sweep, so
// this exercised an ABBA cycle. It must run cleanly under -race with no deadlock;
// the value assertions matter less than the absence of a hang / race report.
func TestConcurrentRequestPathVersusDirectory(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	m := newManager(t, clk)

	const sessions = 8
	for i := 0; i < sessions; i++ {
		_ = initialized(t, m, fmt.Sprintf("s%d", i))
	}

	var wg sync.WaitGroup
	// Request-path workers: register then correlate/cancel on the session lock.
	for i := 0; i < sessions; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, ok := m.Get(fmt.Sprintf("s%d", i))
			if !ok {
				return
			}
			for j := int64(0); j < 200; j++ {
				id := intID(j)
				if err := s.RegisterRequest(protocol.ClientOriginated, "c", id, "tools/call"); err != nil {
					continue
				}
				if j%2 == 0 {
					_, _ = s.CorrelateResponse(protocol.ClientOriginated, id)
				} else {
					_ = s.Cancel(protocol.ClientOriginated, "c", id)
				}
			}
		}(i)
	}
	// Directory workers: repeatedly sweep and count, taking the manager lock.
	for k := 0; k < 4; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				m.Sweep()
				_ = m.SessionCount()
				_ = m.TotalOutstanding()
			}
		}()
	}
	// Open/Close churn on distinct ids, also manager-locked.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 200; j++ {
			id := fmt.Sprintf("churn%d", j)
			if _, err := m.Open(id, protocol.Management, protocol.ClientFacing); err == nil {
				m.Close(id)
			}
		}
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("deadlock: workers did not finish within 30s (ABBA lock-order regression)")
	}
}

// TestCapabilityOutstandingIsolation proves the fleet-wide outstanding budget is
// tracked INDEPENDENTLY per capability: saturating the Gateway total across its
// sessions must not consume any of Management's budget, and vice versa. A single
// shared counter (the pre-fix behavior) would let Gateway load starve Management.
// Two sessions per capability make this a genuine FLEET-counter test (the fleet
// cap binds ACROSS sessions, not the per-session cap).
func TestCapabilityOutstandingIsolation(t *testing.T) {
	// Fleet cap 2, per-session cap 2 (the validator requires per-session ≤ total).
	// With two sessions each registering one request, the fleet cap — not the
	// per-session cap — is the binding constraint on the third registration.
	cfg := limits.Config{
		MaxFrameBytes: 4096, MaxDepth: 16, MaxObjectMembers: 64, MaxArrayElements: 64,
		MaxStringBytes: 1024, MaxMethodBytes: 64, MaxIDBytes: 64, MaxErrorDataBytes: 1024,
		MaxSessions: 8, MaxOutstandingPerSession: 2, MaxTotalOutstanding: 2, SessionTTL: time.Minute,
	}
	lim, err := limits.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(lim, lim, (&clock{t: time.Unix(1000, 0)}).now)

	gwA := initializedCap(t, m, "gwA", protocol.Gateway)
	gwB := initializedCap(t, m, "gwB", protocol.Gateway)
	mgA := initializedCap(t, m, "mgA", protocol.Management)
	mgB := initializedCap(t, m, "mgB", protocol.Management)

	// Saturate Gateway's FLEET budget (2) across its two sessions, one each.
	if err := gwA.RegisterRequest(protocol.ClientOriginated, "c", intID(1), "tools/call"); err != nil {
		t.Fatalf("gwA: %v", err)
	}
	if err := gwB.RegisterRequest(protocol.ClientOriginated, "c", intID(1), "tools/call"); err != nil {
		t.Fatalf("gwB: %v", err)
	}
	// A third Gateway registration (either session) must hit the FLEET cap, even
	// though each session is under its own per-session cap of 2.
	if err := gwA.RegisterRequest(protocol.ClientOriginated, "c", intID(2), "tools/call"); mcperr.ReasonOf(err) != mcperr.ReasonResourceLimit {
		t.Fatalf("gwA fleet: reason = %v, want resource_limit", mcperr.ReasonOf(err))
	}
	// Management must still have its FULL independent fleet budget.
	if err := mgA.RegisterRequest(protocol.ClientOriginated, "c", intID(1), "tools/call"); err != nil {
		t.Fatalf("mgmt not isolated from gateway saturation: %v", err)
	}
	if err := mgB.RegisterRequest(protocol.ClientOriginated, "c", intID(1), "tools/call"); err != nil {
		t.Fatalf("mgB: %v", err)
	}
	if err := mgA.RegisterRequest(protocol.ClientOriginated, "c", intID(2), "tools/call"); mcperr.ReasonOf(err) != mcperr.ReasonResourceLimit {
		t.Fatalf("mgmt fleet: reason = %v, want resource_limit", mcperr.ReasonOf(err))
	}
	if got := m.OutstandingFor(protocol.Gateway); got != 2 {
		t.Fatalf("gateway outstanding = %d, want 2", got)
	}
	if got := m.OutstandingFor(protocol.Management); got != 2 {
		t.Fatalf("management outstanding = %d, want 2", got)
	}
}

// TestSessionCountIsolation proves the per-capability SESSION cap is independent:
// filling Gateway's session cap must not block Management from opening sessions.
func TestSessionCountIsolation(t *testing.T) {
	cfg := limits.Config{
		MaxFrameBytes: 4096, MaxDepth: 16, MaxObjectMembers: 64, MaxArrayElements: 64,
		MaxStringBytes: 1024, MaxMethodBytes: 64, MaxIDBytes: 64, MaxErrorDataBytes: 1024,
		MaxSessions: 2, MaxOutstandingPerSession: 4, MaxTotalOutstanding: 16, SessionTTL: time.Minute,
	}
	lim, err := limits.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(lim, lim, (&clock{t: time.Unix(1000, 0)}).now)

	if _, err := m.Open("gw1", protocol.Gateway, protocol.ClientFacing); err != nil {
		t.Fatalf("gw1: %v", err)
	}
	if _, err := m.Open("gw2", protocol.Gateway, protocol.ClientFacing); err != nil {
		t.Fatalf("gw2: %v", err)
	}
	// Gateway is full.
	if _, err := m.Open("gw3", protocol.Gateway, protocol.ClientFacing); mcperr.ReasonOf(err) != mcperr.ReasonResourceLimit {
		t.Fatalf("gw3: reason = %v, want resource_limit", mcperr.ReasonOf(err))
	}
	// Management still has its full session budget.
	if _, err := m.Open("mg1", protocol.Management, protocol.ClientFacing); err != nil {
		t.Fatalf("mgmt session blocked by gateway saturation: %v", err)
	}
	if _, err := m.Open("mg2", protocol.Management, protocol.ClientFacing); err != nil {
		t.Fatalf("mg2: %v", err)
	}
	if _, err := m.Open("mg3", protocol.Management, protocol.ClientFacing); mcperr.ReasonOf(err) != mcperr.ReasonResourceLimit {
		t.Fatalf("mg3: reason = %v, want resource_limit", mcperr.ReasonOf(err))
	}
}

// TestHandshakeCompletionRequiresVersion proves the version gate: a session must
// not complete the handshake (notifications/initialized) — and thus reach
// steady-state admission — without a negotiated version. A kernel weakened to
// drop this gate would run the whole session outside the version allowlist.
func TestHandshakeCompletionRequiresVersion(t *testing.T) {
	m := newManager(t, &clock{t: time.Unix(1000, 0)})
	s, err := m.Open("s1", protocol.Gateway, protocol.ClientFacing)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := s.Admit(protocol.ClientOriginated, jsonrpc.ClassRequest, "initialize"); err != nil {
		t.Fatalf("admit initialize: %v", err)
	}
	// Skip SetNegotiatedVersion — completion must be refused.
	if _, err := s.Admit(protocol.ClientOriginated, jsonrpc.ClassNotification, "notifications/initialized"); mcperr.ReasonOf(err) != mcperr.ReasonInvalidLifecycle {
		t.Fatalf("initialized without version: reason = %v, want invalid_lifecycle", mcperr.ReasonOf(err))
	}
	if s.State() == protocol.StateInitialized {
		t.Fatal("session reached steady state without a negotiated version")
	}
	// After negotiation the same completion succeeds.
	if err := s.SetNegotiatedVersion(protocol.VersionPrimary); err != nil {
		t.Fatalf("set version: %v", err)
	}
	if _, err := s.Admit(protocol.ClientOriginated, jsonrpc.ClassNotification, "notifications/initialized"); err != nil {
		t.Fatalf("initialized after version: %v", err)
	}
	if s.State() != protocol.StateInitialized {
		t.Fatalf("state = %v, want initialized", s.State())
	}
}

// TestStalePendingExpiredOnActiveSession proves the outstanding-budget leak fix:
// a peer that keeps a session active (its lastActive keeps advancing) while
// withholding responses must not pin the outstanding budget forever. Sweep
// expires individual pending entries older than the TTL even on a live session.
func TestStalePendingExpiredOnActiveSession(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	m := newManager(t, clk)
	s := initialized(t, m, "s1")
	ttl := limits.DefaultGateway().SessionTTL()

	// Register a request that will be left outstanding.
	if err := s.RegisterRequest(protocol.ClientOriginated, "c", intID(1), "tools/call"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if m.TotalOutstanding() != 1 {
		t.Fatalf("outstanding = %d, want 1", m.TotalOutstanding())
	}

	// Advance past the TTL but keep the session active with a fresh admit so the
	// session itself is NOT swept — only the stale entry should be reclaimed.
	clk.t = clk.t.Add(ttl + time.Second)
	if _, err := s.Admit(protocol.ClientOriginated, jsonrpc.ClassRequest, "ping"); err != nil {
		t.Fatalf("ping to keep session active: %v", err)
	}

	if n := m.Sweep(); n != 0 {
		t.Fatalf("sweep reclaimed %d SESSIONS, want 0 (session is active)", n)
	}
	if m.SessionCount() != 1 {
		t.Fatal("active session was wrongly expired")
	}
	if got := s.PendingCount(); got != 0 {
		t.Fatalf("stale pending entry not reclaimed: pending = %d", got)
	}
	if got := m.TotalOutstanding(); got != 0 {
		t.Fatalf("outstanding budget leaked: %d, want 0", got)
	}
}

// initializedCap is initialized() for an explicit capability.
func initializedCap(t *testing.T, m *Manager, id string, capb protocol.Capability) *Session {
	t.Helper()
	s, err := m.Open(id, capb, protocol.ClientFacing)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := s.Admit(protocol.ClientOriginated, jsonrpc.ClassRequest, "initialize"); err != nil {
		t.Fatalf("admit initialize: %v", err)
	}
	if err := s.SetNegotiatedVersion(protocol.VersionPrimary); err != nil {
		t.Fatalf("set version: %v", err)
	}
	if _, err := s.Admit(protocol.ClientOriginated, jsonrpc.ClassNotification, "notifications/initialized"); err != nil {
		t.Fatalf("admit initialized: %v", err)
	}
	return s
}
