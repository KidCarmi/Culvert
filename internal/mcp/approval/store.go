package approval

import (
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Committer durably records an approval decision through PR-8 BEFORE the store
// changes state. Its CommitDecision returns a safe evidence digest on success,
// or a classified error on failure — on which the store performs NO state
// change (fail closed). The adminapi service supplies an implementation backed
// by events.Manager.CommitDecision; tests supply a fake.
type Committer interface {
	CommitDecision(r *Request, decision State, approver PrincipalID) (evidenceDigest string, err error)
}

// Receipt is an unforgeable record that a request was approved. Its fields are
// unexported and there is no public constructor that manufactures a valid
// receipt — only Store.Approve produces one, after a durable commit. A receipt
// is not a secret and carries no credential material; it is evidence a future
// stage MAY proceed.
type Receipt struct {
	valid            bool
	id               ID
	kind             Kind
	tenant           string
	capability       string
	approver         PrincipalID
	decisionDigest   string
	candidateHash    string
	proposedRevision uint64
	evidenceDigest   string
	grantedAt        time.Time
}

// Valid reports whether the receipt was produced by a real approval.
func (r Receipt) Valid() bool { return r.valid }

// ID returns the approved request's identifier.
func (r Receipt) ID() ID { return r.id }

// Kind returns the approved request's family.
func (r Receipt) Kind() Kind { return r.kind }

// Tenant returns the bound tenant.
func (r Receipt) Tenant() string { return r.tenant }

// Capability returns the bound capability.
func (r Receipt) Capability() string { return r.capability }

// Approver returns the deciding principal.
func (r Receipt) Approver() PrincipalID { return r.approver }

// DecisionDigest returns the bound decision digest (operational).
func (r Receipt) DecisionDigest() string { return r.decisionDigest }

// CandidateHash returns the bound candidate hash (publication).
func (r Receipt) CandidateHash() string { return r.candidateHash }

// ProposedRevision returns the bound proposed revision (publication).
func (r Receipt) ProposedRevision() uint64 { return r.proposedRevision }

// GrantedAt returns the grant time.
func (r Receipt) GrantedAt() time.Time { return r.grantedAt }

// Matches reports whether the receipt is bound to the given publication facts.
// A receipt for one tenant/capability/candidate cannot authorize another.
func (r Receipt) Matches(tenant, capability, candidateHash string, proposedRevision uint64) bool {
	return r.valid && r.tenant == tenant && r.capability == capability &&
		r.candidateHash == candidateHash && r.proposedRevision == proposedRevision
}

// Store is a bounded, in-memory, rebuildable projection of approval requests. It
// is the authoritative in-process view; the durable evidence is the PR-8 event
// stream (a Store can be rebuilt from committed approval events). All state
// transitions happen under the store lock, and only AFTER a durable commit.
type Store struct {
	mu           sync.Mutex
	clock        func() time.Time
	byID         map[ID]*Request
	perTenant    map[string]int
	maxPending   int
	maxPerTenant int
	ttl          time.Duration
}

// Config configures a Store. maxPending/maxPerTenant/ttl come from the adminapi
// limits (passed as plain values to keep this package a leaf — no import cycle).
type Config struct {
	Clock        func() time.Time
	MaxPending   int
	MaxPerTenant int
	TTL          time.Duration
}

// NewStore returns a bounded approval store.
func NewStore(cfg Config) *Store {
	clk := cfg.Clock
	if clk == nil {
		clk = time.Now
	}
	return &Store{
		clock:        clk,
		byID:         make(map[ID]*Request),
		perTenant:    make(map[string]int),
		maxPending:   cfg.MaxPending,
		maxPerTenant: cfg.MaxPerTenant,
		ttl:          cfg.TTL,
	}
}

// Create records a new pending request bound to the given facts. The caller
// supplies an unpredictable, unique ID (adminapi generates it from crypto/rand).
// Four-eyes is not checked here — only at decision time.
func (s *Store) Create(id ID, kind Kind, requester PrincipalID, b Binding) (*Request, error) {
	if id == "" || kind == KindUnset || requester == "" || b.Tenant == "" || b.Capability == "" {
		return nil, mcperr.New(mcperr.ReasonAdminRequestInvalid, "approval.create", "missing required binding field")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byID[id]; exists {
		return nil, mcperr.New(mcperr.ReasonAdminRequestInvalid, "approval.create", "duplicate approval id")
	}
	s.sweepLocked()
	if s.pendingCountLocked() >= s.maxPending {
		return nil, mcperr.New(mcperr.ReasonAdminRangeExceeded, "approval.create", "pending approval capacity reached")
	}
	if s.perTenant[b.Tenant] >= s.maxPerTenant {
		return nil, mcperr.New(mcperr.ReasonAdminRangeExceeded, "approval.create", "tenant pending approval capacity reached")
	}
	now := s.clock()
	r := &Request{
		id: id, kind: kind, requester: requester, binding: b,
		created: now, expiry: now.Add(s.ttl), state: StatePending,
	}
	s.byID[id] = r
	s.perTenant[b.Tenant]++
	return r, nil
}

// Get returns the request iff it exists within the caller's tenant scope. A
// tenant mismatch returns not-found (uniform) so existence never leaks across
// tenants. A pending request past its TTL is lazily expired first.
func (s *Store) Get(id ID, tenant string) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok || r.binding.Tenant != tenant {
		return nil, mcperr.New(mcperr.ReasonApprovalNotFound, "approval.get", "not found")
	}
	s.lazyExpireLocked(r)
	cp := *r
	return &cp, nil
}

// List returns a bounded, tenant-scoped view filtered by optional state. A zero
// stateFilter (StateUnknown) returns all states. Results are copies.
func (s *Store) List(tenant string, stateFilter State, limit int) []*Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Request, 0, limit)
	for _, r := range s.byID {
		if r.binding.Tenant != tenant {
			continue
		}
		s.lazyExpireLocked(r)
		if stateFilter != StateUnknown && r.state != stateFilter {
			continue
		}
		cp := *r
		out = append(out, &cp)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// Approve decides a pending request as approved. It enforces four-eyes, expiry,
// terminal-state immutability and the TOCTOU revision binding, then durably
// commits the decision through commit BEFORE changing state. A repeated approve
// by the same approver is idempotent (returns the same receipt); any conflicting
// terminal action is rejected.
func (s *Store) Approve(id ID, approver PrincipalID, live Revisions, commit Committer) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok {
		return Receipt{}, mcperr.New(mcperr.ReasonApprovalNotFound, "approval.approve", "not found")
	}
	s.lazyExpireLocked(r)
	if r.state == StateExpired {
		return Receipt{}, mcperr.New(mcperr.ReasonApprovalExpired, "approval.approve", "expired")
	}
	if r.state.terminal() {
		// Idempotent only when identical: same terminal action + same approver.
		if r.state == StateApproved && r.approver == approver {
			return r.receipt(), nil
		}
		return Receipt{}, mcperr.New(mcperr.ReasonApprovalTerminalState, "approval.approve", "already "+r.state.String())
	}
	if approver == r.requester {
		return Receipt{}, mcperr.New(mcperr.ReasonApprovalSelfApproval, "approval.approve", "requester may not approve own request")
	}
	if !r.bindingCurrent(live) {
		return Receipt{}, mcperr.New(mcperr.ReasonApprovalStaleRevision, "approval.approve", "bound revision changed")
	}
	// Durably commit BEFORE any state change. On failure, fail closed.
	digest, err := commit.CommitDecision(r, StateApproved, approver)
	if err != nil {
		return Receipt{}, err
	}
	now := s.clock()
	r.state = StateApproved
	r.approver = approver
	r.decidedAt = now
	rc := Receipt{
		valid: true, id: r.id, kind: r.kind, tenant: r.binding.Tenant,
		capability: r.binding.Capability, approver: approver,
		decisionDigest: r.binding.DecisionDigest, candidateHash: r.binding.CandidateHash,
		proposedRevision: r.binding.ProposedRevision, evidenceDigest: digest, grantedAt: now,
	}
	r.storeReceipt(rc)
	s.decPendingLocked(r.binding.Tenant)
	return rc, nil
}

// Reject decides a pending request as rejected. It commits the decision durably
// before changing state. A repeated identical rejection is idempotent; a
// conflicting terminal action is rejected.
func (s *Store) Reject(id ID, approver PrincipalID, reason string, commit Committer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok {
		return mcperr.New(mcperr.ReasonApprovalNotFound, "approval.reject", "not found")
	}
	s.lazyExpireLocked(r)
	if r.state == StateExpired {
		return mcperr.New(mcperr.ReasonApprovalExpired, "approval.reject", "expired")
	}
	if r.state.terminal() {
		if r.state == StateRejected && r.approver == approver {
			return nil // idempotent identical rejection
		}
		return mcperr.New(mcperr.ReasonApprovalTerminalState, "approval.reject", "already "+r.state.String())
	}
	if _, err := commit.CommitDecision(r, StateRejected, approver); err != nil {
		return err
	}
	r.state = StateRejected
	r.approver = approver
	r.decidedAt = s.clock()
	r.reason = mcperr.Sanitize(reason, 256)
	s.decPendingLocked(r.binding.Tenant)
	return nil
}

// bindingCurrent reports whether every bound revision still matches live. For a
// publication request the base revision must equal the live policy revision.
func (r *Request) bindingCurrent(live Revisions) bool {
	b := r.binding.Revisions
	if b.Policy != live.Policy || b.Catalog != live.Catalog ||
		b.Registry != live.Registry || b.Inspection != live.Inspection {
		return false
	}
	if r.kind == KindPublication && r.binding.BaseRevision != live.Policy {
		return false
	}
	return true
}

// --- receipt persistence on the request (for idempotent approve) ---

func (r *Request) storeReceipt(rc Receipt) { r.grantedReceipt = &rc }
func (r *Request) receipt() Receipt {
	if r.grantedReceipt == nil {
		return Receipt{}
	}
	return *r.grantedReceipt
}

// --- locked helpers ---

func (s *Store) lazyExpireLocked(r *Request) {
	if r.state == StatePending && r.expiredAt(s.clock()) {
		r.state = StateExpired
		r.decidedAt = s.clock()
		s.decPendingLocked(r.binding.Tenant)
	}
}

func (s *Store) sweepLocked() {
	for _, r := range s.byID {
		s.lazyExpireLocked(r)
	}
}

func (s *Store) pendingCountLocked() int {
	n := 0
	for _, r := range s.byID {
		if r.state == StatePending {
			n++
		}
	}
	return n
}

func (s *Store) decPendingLocked(tenant string) {
	if s.perTenant[tenant] > 0 {
		s.perTenant[tenant]--
	}
}
