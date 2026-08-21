package session

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// FuzzCorrelationStateMachine drives a random sequence of register / correlate /
// cancel operations across both directions and asserts the state-machine
// invariants hold for every sequence: no panic, the pending count never exceeds
// the configured bounds, and — the security-critical one — an operation in one
// direction never changes the OTHER direction's pending set. It fuzzes the op
// stream via the input bytes.
func FuzzCorrelationStateMachine(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	f.Add([]byte{2, 2, 2, 2, 5, 5, 5, 5})
	f.Add([]byte{1, 3, 1, 3, 1, 3})
	f.Fuzz(func(t *testing.T, ops []byte) {
		lim, err := limits.New(limits.Config{
			MaxFrameBytes: 4096, MaxDepth: 16, MaxObjectMembers: 64, MaxArrayElements: 64,
			MaxStringBytes: 1024, MaxMethodBytes: 64, MaxIDBytes: 64, MaxErrorDataBytes: 1024,
			MaxSessions: 8, MaxOutstandingPerSession: 16, MaxTotalOutstanding: 32, SessionTTL: time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		clk := &clock{t: time.Unix(1000, 0)}
		m := NewManager(lim, lim, clk.now)
		s, err := m.Open("f", protocol.Gateway, protocol.ClientFacing)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = s.Admit(protocol.ClientOriginated, jsonrpc.ClassRequest, "initialize")
		_ = s.SetNegotiatedVersion(protocol.VersionPrimary)
		_, _ = s.Admit(protocol.ClientOriginated, jsonrpc.ClassNotification, "notifications/initialized")

		for i := 0; i+1 < len(ops); i += 2 {
			op := ops[i] % 3
			dir := protocol.ClientOriginated
			if ops[i]&0x80 != 0 {
				dir = protocol.ServerOriginated
			}
			id := jsonrpc.ID{Kind: jsonrpc.IDInt, Int: int64(ops[i+1] % 8)}
			other := oppositeDir(dir)

			// Snapshot the OTHER direction's pending keys before the op.
			beforeOther := snapshotDir(s, other)

			switch op {
			case 0:
				_ = s.RegisterRequest(dir, "owner", id, "tools/call")
			case 1:
				_, _ = s.CorrelateResponse(dir, id)
			case 2:
				_ = s.Cancel(dir, "owner", id)
			}

			// Invariant: the op never mutated the other direction's pending set.
			afterOther := snapshotDir(s, other)
			if !sameKeys(beforeOther, afterOther) {
				t.Fatalf("op in %v mutated %v pending set", dir, other)
			}
			// Invariant: pending never exceeds the per-session bound (both directions).
			if s.PendingCount() > 2*lim.MaxOutstandingPerSession() {
				t.Fatalf("pending exceeded bound: %d", s.PendingCount())
			}
		}
	})
}

func snapshotDir(s *Session, dir protocol.Direction) map[string]struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]struct{})
	if ds := s.dirs[dir]; ds != nil {
		for k := range ds.pending {
			out[k] = struct{}{}
		}
	}
	return out
}

func sameKeys(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}
