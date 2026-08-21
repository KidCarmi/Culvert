package session

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// clock is an injectable, advanceable test clock.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newManager(t *testing.T, clk *clock) *Manager {
	t.Helper()
	return NewManager(limits.DefaultGateway(), limits.DefaultManagement(), clk.now)
}

func intID(n int64) jsonrpc.ID { return jsonrpc.ID{Kind: jsonrpc.IDInt, Int: n} }

// register + advance a session into StateInitialized so business methods are legal.
func initialized(t *testing.T, m *Manager, id string) *Session {
	t.Helper()
	s, err := m.Open(id, protocol.Gateway, protocol.ClientFacing)
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
	if s.State() != protocol.StateInitialized {
		t.Fatalf("state = %v, want initialized", s.State())
	}
	return s
}

// Fixture 1 (#925): a same-session opposite-direction cancellation is rejected
// and the owning entry is retained.
func TestFixtureOppositeDirectionCancellationRejected(t *testing.T) {
	m := newManager(t, &clock{t: time.Unix(1000, 0)})
	s := initialized(t, m, "s1")
	if err := s.RegisterRequest(protocol.ClientOriginated, "client", intID(5), "tools/call"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if r := s.Cancel(protocol.ServerOriginated, "server", intID(5)); r != CancelRejectedOppositeDirection {
		t.Fatalf("cancel result = %v, want opposite-direction rejection", r)
	}
	if s.PendingCount() != 1 {
		t.Fatalf("owning entry not retained: pending = %d", s.PendingCount())
	}
}

// Fixture 2 (#925): the same id may be outstanding concurrently in both
// directions with no cross-correlation.
func TestFixtureSameIDBothDirections(t *testing.T) {
	m := newManager(t, &clock{t: time.Unix(1000, 0)})
	s := initialized(t, m, "s1")
	if err := s.RegisterRequest(protocol.ClientOriginated, "client", intID(7), "tools/call"); err != nil {
		t.Fatalf("register c: %v", err)
	}
	if err := s.RegisterRequest(protocol.ServerOriginated, "server", intID(7), "ping"); err != nil {
		t.Fatalf("register s: %v", err)
	}
	if s.PendingCount() != 2 {
		t.Fatalf("pending = %d, want 2", s.PendingCount())
	}
	// Cancelling in one direction resolves only that direction.
	if r := s.Cancel(protocol.ClientOriginated, "client", intID(7)); r != CancelApplied {
		t.Fatalf("cancel = %v, want applied", r)
	}
	if s.PendingCount() != 1 {
		t.Fatalf("cross-direction deletion: pending = %d, want 1", s.PendingCount())
	}
	// The server-direction entry still resolves cleanly.
	if got, err := s.CorrelateResponse(protocol.ServerOriginated, intID(7)); err != nil || got != Completed {
		t.Fatalf("correlate server = %v/%v, want Completed", got, err)
	}
}

// Fixture 3 (#925): cancellation of the initialize request is rejected.
func TestFixtureInitializeNotCancellable(t *testing.T) {
	m := newManager(t, &clock{t: time.Unix(1000, 0)})
	s, _ := m.Open("s1", protocol.Gateway, protocol.ClientFacing)
	if _, err := s.Admit(protocol.ClientOriginated, jsonrpc.ClassRequest, "initialize"); err != nil {
		t.Fatalf("admit: %v", err)
	}
	if err := s.RegisterRequest(protocol.ClientOriginated, "client", intID(1), "initialize"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if r := s.Cancel(protocol.ClientOriginated, "client", intID(1)); r != CancelRejectedInitialize {
		t.Fatalf("cancel = %v, want initialize-rejected", r)
	}
	if s.PendingCount() != 1 {
		t.Fatalf("initialize entry not retained")
	}
}

// Fixture 4 (#925): a late post-response cancellation is tolerated, not a
// duplicate-completion fault; and a second response IS a duplicate completion.
func TestFixtureLateCancellationTolerated(t *testing.T) {
	m := newManager(t, &clock{t: time.Unix(1000, 0)})
	s := initialized(t, m, "s1")
	_ = s.RegisterRequest(protocol.ClientOriginated, "client", intID(9), "tools/call")
	if got, err := s.CorrelateResponse(protocol.ClientOriginated, intID(9)); err != nil || got != Completed {
		t.Fatalf("first response = %v/%v", got, err)
	}
	if r := s.Cancel(protocol.ClientOriginated, "client", intID(9)); r != CancelLate {
		t.Fatalf("late cancel = %v, want CancelLate", r)
	}
	// A second response for the completed request is a duplicate completion.
	if _, err := s.CorrelateResponse(protocol.ClientOriginated, intID(9)); mcperr.ReasonOf(err) != mcperr.ReasonDuplicateCompletion {
		t.Fatalf("second response reason = %v, want duplicate_completion", mcperr.ReasonOf(err))
	}
}

// Fixture 5 (#925): a wrong-requestor cancellation (right direction, wrong
// owner) is rejected and the entry retained.
func TestFixtureWrongOwnerCancellationRejected(t *testing.T) {
	m := newManager(t, &clock{t: time.Unix(1000, 0)})
	s := initialized(t, m, "s1")
	_ = s.RegisterRequest(protocol.ClientOriginated, "owner-a", intID(11), "tools/call")
	if r := s.Cancel(protocol.ClientOriginated, "owner-b", intID(11)); r != CancelRejectedWrongOwner {
		t.Fatalf("cancel = %v, want wrong-owner rejection", r)
	}
	if s.PendingCount() != 1 {
		t.Fatalf("entry not retained after wrong-owner cancel")
	}
}

// Fixture 6 (#925): a server-originated reverse-channel request is rejected.
func TestFixtureReverseChannelRequestRejected(t *testing.T) {
	m := newManager(t, &clock{t: time.Unix(1000, 0)})
	s := initialized(t, m, "s1")
	for _, method := range []string{"sampling/createMessage", "elicitation/create", "roots/list"} {
		adm, err := s.Admit(protocol.ServerOriginated, jsonrpc.ClassRequest, method)
		if adm.Handling != protocol.HandlingRejected || mcperr.ReasonOf(err) != mcperr.ReasonUnsupportedMethod {
			t.Fatalf("%s admitted (handling=%v err=%v)", method, adm.Handling, err)
		}
	}
}

// Fixture 7 (#925): tasks/* (incl tasks/cancel) is rejected under admission.
func TestFixtureTasksRejected(t *testing.T) {
	m := newManager(t, &clock{t: time.Unix(1000, 0)})
	s := initialized(t, m, "s1")
	for _, method := range []string{"tasks/cancel", "tasks/create", "tasks/list", "tasks/get", "tasks/result"} {
		adm, err := s.Admit(protocol.ClientOriginated, jsonrpc.ClassRequest, method)
		if adm.Handling != protocol.HandlingRejected || mcperr.ReasonOf(err) != mcperr.ReasonUnsupportedMethod {
			t.Fatalf("%s not rejected (handling=%v err=%v)", method, adm.Handling, err)
		}
	}
}

// Anti-weakening guard (MCP-PROTO-013): an uncorrelated or malformed response must
// NOT delete a legitimate in-flight request's state — the remote-state-deletion
// primitive. A decoder/session weakened to release on any named id would fail this.
func TestUncorrelatedResponseDeletesNothing(t *testing.T) {
	m := newManager(t, &clock{t: time.Unix(1000, 0)})
	s := initialized(t, m, "s1")
	_ = s.RegisterRequest(protocol.ClientOriginated, "client", intID(13), "tools/call")
	if _, err := s.CorrelateResponse(protocol.ClientOriginated, intID(999)); mcperr.ReasonOf(err) != mcperr.ReasonUncorrelatedResponse {
		t.Fatalf("reason = %v, want uncorrelated_response", mcperr.ReasonOf(err))
	}
	if s.PendingCount() != 1 {
		t.Fatalf("uncorrelated response deleted state: pending = %d", s.PendingCount())
	}
	// The real entry still resolves normally.
	if got, err := s.CorrelateResponse(protocol.ClientOriginated, intID(13)); err != nil || got != Completed {
		t.Fatalf("legit correlate = %v/%v", got, err)
	}
}

func TestLifecycleBootstrap(t *testing.T) {
	m := newManager(t, &clock{t: time.Unix(1000, 0)})
	s, _ := m.Open("s1", protocol.Gateway, protocol.ClientFacing)
	// Pre-negotiation, only initialize is admissible.
	if _, err := s.Admit(protocol.ClientOriginated, jsonrpc.ClassRequest, "tools/call"); mcperr.ReasonOf(err) != mcperr.ReasonInvalidLifecycle {
		t.Fatalf("tools/call before initialize: reason = %v, want invalid_lifecycle", mcperr.ReasonOf(err))
	}
	if _, err := s.Admit(protocol.ClientOriginated, jsonrpc.ClassRequest, "ping"); mcperr.ReasonOf(err) != mcperr.ReasonInvalidLifecycle {
		t.Fatalf("ping before initialize should be invalid_lifecycle, got %v", mcperr.ReasonOf(err))
	}
	if _, err := s.Admit(protocol.ClientOriginated, jsonrpc.ClassRequest, "initialize"); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	// A duplicate initialize is now an invalid-lifecycle error, not a silent no-op.
	if _, err := s.Admit(protocol.ClientOriginated, jsonrpc.ClassRequest, "initialize"); mcperr.ReasonOf(err) != mcperr.ReasonInvalidLifecycle {
		t.Fatalf("duplicate initialize: reason = %v, want invalid_lifecycle", mcperr.ReasonOf(err))
	}
}

func TestRegisterBounds(t *testing.T) {
	// Small per-session cap via a custom limits set.
	small, err := limits.New(limits.Config{
		MaxFrameBytes: 4096, MaxDepth: 16, MaxObjectMembers: 64, MaxArrayElements: 64,
		MaxStringBytes: 1024, MaxMethodBytes: 64, MaxIDBytes: 64, MaxErrorDataBytes: 1024,
		MaxSessions: 4, MaxOutstandingPerSession: 2, MaxTotalOutstanding: 3, SessionTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	m2 := NewManager(small, small, (&clock{t: time.Unix(1000, 0)}).now)
	s := initializedOn(t, m2, "s1")
	if err := s.RegisterRequest(protocol.ClientOriginated, "c", intID(1), "tools/call"); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterRequest(protocol.ClientOriginated, "c", intID(2), "tools/call"); err != nil {
		t.Fatal(err)
	}
	// Third exceeds the per-session cap of 2.
	if err := s.RegisterRequest(protocol.ClientOriginated, "c", intID(3), "tools/call"); mcperr.ReasonOf(err) != mcperr.ReasonResourceLimit {
		t.Fatalf("expected per-session resource limit, got %v", err)
	}
	// Duplicate id in the same direction is rejected.
	if err := s.RegisterRequest(protocol.ClientOriginated, "c", intID(1), "tools/call"); mcperr.ReasonOf(err) != mcperr.ReasonInvalidJSONRPC {
		t.Fatalf("duplicate id: got %v", err)
	}
}

func TestSessionExpiration(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	m := newManager(t, clk)
	_ = initialized(t, m, "s1")
	if m.SessionCount() != 1 {
		t.Fatalf("session count = %d", m.SessionCount())
	}
	clk.t = clk.t.Add(2 * limits.DefaultGateway().SessionTTL())
	if n := m.Sweep(); n != 1 {
		t.Fatalf("sweep reclaimed %d, want 1", n)
	}
	if m.SessionCount() != 0 {
		t.Fatalf("session not expired")
	}
}

// initializedOn is like initialized but for an arbitrary manager.
func initializedOn(t *testing.T, m *Manager, id string) *Session {
	t.Helper()
	s, err := m.Open(id, protocol.Gateway, protocol.ClientFacing)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, _ = s.Admit(protocol.ClientOriginated, jsonrpc.ClassRequest, "initialize")
	_ = s.SetNegotiatedVersion(protocol.VersionPrimary)
	_, _ = s.Admit(protocol.ClientOriginated, jsonrpc.ClassNotification, "notifications/initialized")
	return s
}
