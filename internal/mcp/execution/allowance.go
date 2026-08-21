package execution

import (
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// Allowance bounds.
const (
	maxAllowanceEntries = 65536
	sessionCallCap      = 128
	sessionTTL          = 8 * time.Hour
)

// allowanceStore tracks ALLOW_ONCE (single consumption) and ALLOW_FOR_SESSION
// (bounded call count + TTL) grants. Consumption is atomic under the mutex so
// concurrent calls cannot over-consume a grant. It is bounded (a new grant is
// refused — fail closed — when at capacity).
type allowanceStore struct {
	mu   sync.Mutex
	once map[string]struct{}
	sess map[string]*sessGrant
}

type sessGrant struct {
	calls  int
	expiry time.Time
}

func newAllowanceStore() *allowanceStore {
	return &allowanceStore{once: map[string]struct{}{}, sess: map[string]*sessGrant{}}
}

// consume atomically consumes a unit of the allowance for this request. It returns
// true only when the grant is valid and not exhausted. A failed pre-execution hard
// control never reaches here (the caller consumes only when it will execute).
func (s *allowanceStore) consume(in runtime.ExecInput, action rollout.ActionKind, now time.Time) bool {
	key := allowanceKey(in)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.once)+len(s.sess) >= maxAllowanceEntries {
		// At capacity: refuse a NEW grant (fail closed). Existing grants still resolve.
		if _, known := s.once[key]; !known {
			if _, kn := s.sess[key]; !kn {
				return false
			}
		}
	}
	switch action {
	case rollout.ActionKindAllowOnce:
		if _, used := s.once[key]; used {
			return false // already consumed — never replayed
		}
		s.once[key] = struct{}{}
		return true
	case rollout.ActionKindAllowSession:
		g := s.sess[key]
		if g == nil || now.After(g.expiry) {
			g = &sessGrant{expiry: now.Add(sessionTTL)}
			s.sess[key] = g
		}
		if g.calls >= sessionCallCap {
			return false // session call cap exceeded
		}
		g.calls++
		return true
	default:
		return true
	}
}

// allowanceKey binds a grant to the exact session + tool + principal.
func allowanceKey(in runtime.ExecInput) string {
	sess := in.Input.Session.Fingerprint
	tool := ""
	if in.Input.Tool != nil {
		tool = in.Input.Tool.FingerprintHash
	}
	return sess + "\x1f" + tool + "\x1f" + in.Input.Principal.SubjectID
}
