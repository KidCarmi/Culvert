package identity

import (
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// BindingStore binds exactly one resolved identity to one protocol session,
// keyed by session id. It is deliberately DECOUPLED from the PR-1 session.Manager:
// it holds its own leaf lock and never calls into the session manager while
// holding it (and the manager never calls into this store), so no ABBA lock cycle
// with the session manager is possible. The caller wires session lifecycle by
// calling Unbind when a session closes/expires — this keeps the store
// listener-independent.
//
// Invariants (all tested):
//   - a binding is created only after successful authentication (the caller passes
//     a validated *ResolvedContext);
//   - the binding is immutable once set;
//   - re-binding the SAME identity (equal Fingerprint) is idempotent;
//   - binding a DIFFERENT identity to the same session is rejected and the existing
//     binding retained (covers subject/tenant/client/agent/capability/server-resource
//     change — all of which change the fingerprint);
//   - one session can never read another session's identity (keyed by id);
//   - a rejected bind never deletes or alters an existing valid binding;
//   - Unbind removes the binding (session close/expiry).
type BindingStore struct {
	mu    sync.RWMutex // leaf lock; never held across a call into another subsystem
	bound map[string]*ResolvedContext
}

// NewBindingStore returns an empty binding store.
func NewBindingStore() *BindingStore {
	return &BindingStore{bound: make(map[string]*ResolvedContext)}
}

// Bind associates ctx with sessionID. First bind sets it. A subsequent bind with
// an identity whose Fingerprint equals the existing one is idempotent (returns the
// existing binding, nil error). A bind with a DIFFERENT fingerprint is rejected
// with ReasonSessionIdentityRebind and the existing binding is retained unchanged.
func (s *BindingStore) Bind(sessionID string, ctx *ResolvedContext) (*ResolvedContext, error) {
	if sessionID == "" {
		return nil, mcperr.New(mcperr.ReasonSessionIdentityRebind, "identity.bind", "empty session id")
	}
	if ctx == nil {
		return nil, mcperr.New(mcperr.ReasonSessionIdentityRebind, "identity.bind", "cannot bind a nil identity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.bound[sessionID]; ok {
		if cur.fingerprint == ctx.fingerprint {
			return cur, nil // idempotent equivalent re-bind
		}
		return cur, mcperr.New(mcperr.ReasonSessionIdentityRebind, "identity.bind", "a different identity is already bound to this session")
	}
	s.bound[sessionID] = ctx
	return ctx, nil
}

// Get returns the identity bound to sessionID, if any. A session can only ever
// observe its own binding.
func (s *BindingStore) Get(sessionID string) (*ResolvedContext, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ctx, ok := s.bound[sessionID]
	return ctx, ok
}

// Unbind removes the binding for sessionID (idempotent). Callers invoke it when
// the protocol session closes or expires. A malformed or rejected authentication
// must NOT call Unbind — only a genuine session-close does — so a failed auth can
// never delete a valid binding.
func (s *BindingStore) Unbind(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.bound, sessionID)
}

// Len returns the number of bound sessions.
func (s *BindingStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.bound)
}
