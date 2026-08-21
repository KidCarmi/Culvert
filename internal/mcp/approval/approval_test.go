package approval

import (
	"errors"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// fakeCommitter records commits and can be forced to fail, so tests can prove
// the store commits durably BEFORE any state change and fails closed otherwise.
type fakeCommitter struct {
	calls int
	fail  bool
	last  State
}

func (f *fakeCommitter) CommitDecision(_ *Request, decision State, _ PrincipalID) (string, error) {
	f.calls++
	if f.fail {
		return "", mcperr.New(mcperr.ReasonEventDurabilityDegraded, "fake", "injected commit failure")
	}
	f.last = decision
	return "digest-" + decision.String(), nil
}

func newStore(t *testing.T, clk func() time.Time) *Store {
	t.Helper()
	return NewStore(Config{Clock: clk, MaxPending: 100, MaxPerTenant: 10, TTL: time.Hour})
}

func baseBinding() Binding {
	return Binding{
		Tenant: "acme", Capability: "gateway", DecisionEventID: "evt_1",
		DecisionDigest: "dd1", Action: "write", OperationClass: "write",
		Revisions: Revisions{Policy: 5, Catalog: 3, Registry: 2, Inspection: 1},
	}
}

func mustCreate(t *testing.T, s *Store, id ID, requester PrincipalID) *Request {
	t.Helper()
	r, err := s.Create(id, KindOperational, requester, baseBinding())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return r
}

func TestApprove_HappyPath(t *testing.T) {
	s := newStore(t, nil)
	mustCreate(t, s, "a1", "alice")
	c := &fakeCommitter{}
	rc, err := s.Approve("a1", "bob", Revisions{5, 3, 2, 1}, c)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if !rc.Valid() || rc.Approver() != "bob" || rc.Tenant() != "acme" {
		t.Fatalf("bad receipt: %+v", rc)
	}
	if c.calls != 1 || c.last != StateApproved {
		t.Fatalf("commit not invoked once with StateApproved: %+v", c)
	}
}

func TestApprove_SelfApprovalDenied(t *testing.T) {
	s := newStore(t, nil)
	mustCreate(t, s, "a1", "alice")
	c := &fakeCommitter{}
	_, err := s.Approve("a1", "alice", Revisions{5, 3, 2, 1}, c)
	if mcperr.ReasonOf(err) != mcperr.ReasonApprovalSelfApproval {
		t.Fatalf("want self_approval, got %v", err)
	}
	if c.calls != 0 {
		t.Fatal("commit must not run for a self-approval")
	}
}

func TestApprove_StaleRevisionDenied(t *testing.T) {
	s := newStore(t, nil)
	mustCreate(t, s, "a1", "alice")
	c := &fakeCommitter{}
	// Catalog revision moved from 3 -> 4 since the request was created.
	_, err := s.Approve("a1", "bob", Revisions{5, 4, 2, 1}, c)
	if mcperr.ReasonOf(err) != mcperr.ReasonApprovalStaleRevision {
		t.Fatalf("want stale_revision, got %v", err)
	}
	if c.calls != 0 {
		t.Fatal("commit must not run for a stale request")
	}
}

func TestApprove_CommitFailureFailsClosed(t *testing.T) {
	s := newStore(t, nil)
	mustCreate(t, s, "a1", "alice")
	c := &fakeCommitter{fail: true}
	_, err := s.Approve("a1", "bob", Revisions{5, 3, 2, 1}, c)
	if err == nil {
		t.Fatal("expected the injected commit failure to surface")
	}
	// State must be unchanged (still pending) — no state change before durable commit.
	r, gerr := s.Get("a1", "acme")
	if gerr != nil {
		t.Fatalf("Get: %v", gerr)
	}
	if r.State() != StatePending {
		t.Fatalf("state changed despite commit failure: %s", r.State())
	}
}

func TestApprove_ExpiredDenied(t *testing.T) {
	now := time.Unix(1000, 0)
	clk := func() time.Time { return now }
	s := NewStore(Config{Clock: clk, MaxPending: 10, MaxPerTenant: 10, TTL: time.Minute})
	mustCreate(t, s, "a1", "alice")
	now = now.Add(2 * time.Minute) // past TTL
	c := &fakeCommitter{}
	_, err := s.Approve("a1", "bob", Revisions{5, 3, 2, 1}, c)
	if mcperr.ReasonOf(err) != mcperr.ReasonApprovalExpired {
		t.Fatalf("want expired, got %v", err)
	}
	if c.calls != 0 {
		t.Fatal("commit must not run for an expired request")
	}
}

func TestApprove_TerminalImmutable_ConflictRejected(t *testing.T) {
	s := newStore(t, nil)
	mustCreate(t, s, "a1", "alice")
	c := &fakeCommitter{}
	if _, err := s.Approve("a1", "bob", Revisions{5, 3, 2, 1}, c); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	// A later reject on an approved request is a conflicting terminal transition.
	if err := s.Reject("a1", "carol", "no", c); mcperr.ReasonOf(err) != mcperr.ReasonApprovalTerminalState {
		t.Fatalf("want terminal_state, got %v", err)
	}
}

func TestApprove_IdempotentSameApprover(t *testing.T) {
	s := newStore(t, nil)
	mustCreate(t, s, "a1", "alice")
	c := &fakeCommitter{}
	rc1, err := s.Approve("a1", "bob", Revisions{5, 3, 2, 1}, c)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	rc2, err := s.Approve("a1", "bob", Revisions{5, 3, 2, 1}, c)
	if err != nil {
		t.Fatalf("idempotent Approve: %v", err)
	}
	if c.calls != 1 {
		t.Fatalf("idempotent approve must not re-commit: calls=%d", c.calls)
	}
	if rc1.ID() != rc2.ID() || rc2.Approver() != "bob" {
		t.Fatal("idempotent approve returned a different receipt")
	}
}

func TestGet_TenantIsolation(t *testing.T) {
	s := newStore(t, nil)
	mustCreate(t, s, "a1", "alice") // tenant acme
	// A different tenant must get uniform not-found (no existence leak).
	if _, err := s.Get("a1", "globex"); mcperr.ReasonOf(err) != mcperr.ReasonApprovalNotFound {
		t.Fatalf("cross-tenant Get should be not_found, got %v", err)
	}
}

func TestList_TenantScopedAndBounded(t *testing.T) {
	s := newStore(t, nil)
	mustCreate(t, s, "a1", "alice")
	mustCreate(t, s, "a2", "alice")
	if got := s.List("acme", StateUnknown, 100); len(got) != 2 {
		t.Fatalf("want 2 acme requests, got %d", len(got))
	}
	if got := s.List("globex", StateUnknown, 100); len(got) != 0 {
		t.Fatalf("cross-tenant list leaked %d", len(got))
	}
	if got := s.List("acme", StateUnknown, 1); len(got) != 1 {
		t.Fatalf("limit not honored: %d", len(got))
	}
}

func TestCreate_PerTenantBound(t *testing.T) {
	s := NewStore(Config{MaxPending: 100, MaxPerTenant: 2, TTL: time.Hour})
	mustCreate(t, s, "a1", "alice")
	mustCreate(t, s, "a2", "alice")
	if _, err := s.Create("a3", KindOperational, "alice", baseBinding()); mcperr.ReasonOf(err) != mcperr.ReasonAdminRangeExceeded {
		t.Fatalf("want range_exceeded at per-tenant cap, got %v", err)
	}
}

func TestReject_IdempotentAndCommits(t *testing.T) {
	s := newStore(t, nil)
	mustCreate(t, s, "a1", "alice")
	c := &fakeCommitter{}
	if err := s.Reject("a1", "bob", "not now", c); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if c.calls != 1 || c.last != StateRejected {
		t.Fatalf("reject did not commit once as rejected: %+v", c)
	}
	if err := s.Reject("a1", "bob", "not now", c); err != nil {
		t.Fatalf("idempotent Reject: %v", err)
	}
	if c.calls != 1 {
		t.Fatalf("idempotent reject re-committed: %d", c.calls)
	}
}

func TestPublicationBinding_BaseRevisionStale(t *testing.T) {
	s := newStore(t, nil)
	b := baseBinding()
	b.Capability = "gateway"
	b.CandidateHash = "cand1"
	b.BaseRevision = 5
	b.ProposedRevision = 6
	if _, err := s.Create("p1", KindPublication, "alice", b); err != nil {
		t.Fatalf("Create: %v", err)
	}
	c := &fakeCommitter{}
	// Base revision 5 but live policy is now 6 → stale.
	_, err := s.Approve("p1", "bob", Revisions{6, 3, 2, 1}, c)
	if mcperr.ReasonOf(err) != mcperr.ReasonApprovalStaleRevision {
		t.Fatalf("want stale on base-revision drift, got %v", err)
	}
}

func TestReceipt_MatchesBinding(t *testing.T) {
	s := newStore(t, nil)
	b := baseBinding()
	b.CandidateHash = "cand1"
	b.BaseRevision = 5
	b.ProposedRevision = 6
	if _, err := s.Create("p1", KindPublication, "alice", b); err != nil {
		t.Fatalf("Create: %v", err)
	}
	c := &fakeCommitter{}
	rc, err := s.Approve("p1", "bob", Revisions{5, 3, 2, 1}, c)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if !rc.Matches("acme", "gateway", "cand1", 6) {
		t.Fatal("receipt should match its bound publication facts")
	}
	if rc.Matches("globex", "gateway", "cand1", 6) {
		t.Fatal("receipt must not match another tenant")
	}
	if rc.Matches("acme", "gateway", "cand-other", 6) {
		t.Fatal("receipt must not match another candidate")
	}
}

// TestZeroReceiptInvalid proves a zero-value receipt (external construction)
// is never valid — receipts are unforgeable.
func TestZeroReceiptInvalid(t *testing.T) {
	var rc Receipt
	if rc.Valid() {
		t.Fatal("zero-value receipt must not be valid")
	}
	if rc.Matches("acme", "gateway", "x", 1) {
		t.Fatal("zero-value receipt must not match anything")
	}
}

var _ = errors.New // keep errors imported for future negative cases
