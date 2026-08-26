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
//
// OVN-10 — EXPIRED SESSION grants are reclaimed at capacity; ALLOW_ONCE records
// are NEVER expired. The asymmetry is the whole point and must not be "tidied up"
// into a uniform TTL.
//
// allowanceKey is built from identity.ResolvedContext.Fingerprint, which despite
// the `Session` field name is computeFingerprint() over (capability, tenant,
// subject kind+id, client id, agent id, canonical resource, server, tool). It
// carries NO time, session id or nonce: the same principal invoking the same tool
// produces the SAME key on every request, for the life of the deployment.
//
// Therefore an ALLOW_ONCE record is the only thing standing between a one-shot
// grant and unlimited replay, and expiring it would silently redefine ALLOW_ONCE
// as "allow once per retention window" — a weakening of the control disguised as
// garbage collection. An expired ALLOW_FOR_SESSION grant is different: the lookup
// below already discards and recreates it, so deleting it is provably
// behaviour-neutral and is pure reclamation.
//
// The residual growth is therefore bounded by the number of DISTINCT principals
// that have ever consumed an ALLOW_ONCE grant on this node, which is a property of
// the estate rather than something a caller can inflate: subject and client come
// from verified token claims, agent is never populated on the live path, and
// server/tool come from the registry and catalog.
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

// sweepExpiredSessionsLocked drops session grants that have passed their TTL. It
// runs under the caller's lock and only at capacity, so the ordinary path stays
// O(1) and the scan is paid exactly when it buys something.
//
// This is reclamation, not policy: consume() already treats an expired grant as
// absent, so removing it cannot change any decision.
func (s *allowanceStore) sweepExpiredSessionsLocked(now time.Time) {
	for k, g := range s.sess {
		if now.After(g.expiry) {
			delete(s.sess, k)
		}
	}
}

// consume atomically consumes a unit of the allowance for this request. It returns
// true only when the grant is valid and not exhausted. A failed pre-execution hard
// control never reaches here (the caller consumes only when it will execute).
func (s *allowanceStore) consume(in runtime.ExecInput, action rollout.ActionKind, now time.Time) bool {
	key := allowanceKey(in)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.once)+len(s.sess) >= maxAllowanceEntries {
		// At capacity: reclaim session grants that can no longer be used BEFORE
		// refusing, so timed-out grants cannot crowd out live ones (OVN-10).
		s.sweepExpiredSessionsLocked(now)
	}
	if len(s.once)+len(s.sess) >= maxAllowanceEntries {
		// Still at capacity: refuse a NEW grant (fail closed). Existing grants still
		// resolve, so a full table never converts a single-use record into a replay.
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

// wouldSatisfy reports whether the allowance WOULD be satisfied for this request
// WITHOUT consuming it — the non-destructive prediction a Shadow evaluation needs to
// tell WOULD_EXECUTE from WOULD_BLOCK for an ALLOW_ONCE/ALLOW_FOR_SESSION. It never
// mutates state (no consume, no grant creation, no sweep): a Shadow evaluation must be
// side-effect-free even against in-memory allowance state. A non-allowance action is
// trivially satisfied.
func (s *allowanceStore) wouldSatisfy(in runtime.ExecInput, action rollout.ActionKind, now time.Time) bool {
	if !needsAllowance(action) {
		return true
	}
	key := allowanceKey(in)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, onceKnown := s.once[key]
	g, sessKnown := s.sess[key]
	// Capacity gate — mirror consume WITHOUT mutating (Codex P2). A request whose key is
	// not already present needs a NEW entry, and consume refuses that (fail closed) once
	// the store is at capacity AFTER reclaiming expired session grants. Counting live
	// entries (expired sessions excluded, since consume sweeps them first) reproduces
	// consume's post-sweep refusal without deleting anything.
	//
	// SR-01. Only a slot that SURVIVES that sweep exempts the request from the gate. An
	// EXPIRED session slot does not: consume's sweep deletes it and the capacity check
	// that follows then finds the key ABSENT and refuses. Treating any present key as
	// reusable (the first form of this check) therefore predicted a satisfied allowance
	// for exactly the request live enforcement blocks with allowance_consumed — a Shadow
	// prediction more permissive than the enforcement it exists to predict. ALLOW_ONCE
	// records are never swept, so they always survive.
	//
	// The pre-sweep count is checked FIRST, exactly as consume does: below capacity
	// consume never refuses, and the post-sweep count can only be smaller, so the answer
	// is already known. That keeps the O(len(sess)) live-entry scan off the ordinary path
	// — it is paid only when the store is actually full, which is when it buys something.
	slotSurvivesSweep := onceKnown || (sessKnown && g != nil && !now.After(g.expiry))
	if !slotSurvivesSweep && len(s.once)+len(s.sess) >= maxAllowanceEntries &&
		s.liveEntryCountLocked(now) >= maxAllowanceEntries {
		return false
	}
	switch action {
	case rollout.ActionKindAllowOnce:
		return !onceKnown // a fresh single-use would be granted; an already-used one would not
	case rollout.ActionKindAllowSession:
		if g == nil || now.After(g.expiry) {
			return true // a new (or renewed) session grant would be created
		}
		return g.calls < sessionCallCap
	default:
		return true
	}
}

// liveEntryCountLocked counts entries that consume would still see AFTER reclaiming
// expired session grants: all ALLOW_ONCE records plus the non-expired sessions. It is the
// post-sweep count consume's capacity check uses, computed here without mutating.
func (s *allowanceStore) liveEntryCountLocked(now time.Time) int {
	n := len(s.once)
	for _, g := range s.sess {
		if !now.After(g.expiry) {
			n++
		}
	}
	return n
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
