package tooltrust

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Separation of duties on the ADR-0034 tool-trust plane (SEC-MCP-4E-2), and the
// address-blind principal comparison that makes it non-bypassable (SEC-MCP-4E-1).
//
// internal/mcp/approval has enforced four-eyes on an OPERATIONAL approval since it
// shipped (ReasonApprovalSelfApproval). The tool-trust plane — which promotes an exact
// tool fingerprint to catalog.Usable — shipped with no such check, so one principal could
// request and grant its own supply-chain trust decision. These tests pin the refusal, its
// exact reason, that it leaves the record undecided, and that it cannot be evaded by the
// address a principal happens to carry.

// selfApprovalStore builds a store whose durable file lives in t.TempDir.
func selfApprovalStore(t *testing.T, clk func() time.Time) *Store {
	t.Helper()
	s, err := NewStore(Config{Path: filepath.Join(t.TempDir(), "approvals.json"), Clock: clk})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

// selfApprovalRequest creates one pending request attributed to requestedBy.
func selfApprovalRequest(t *testing.T, s *Store, requestedBy string) (*ToolApproval, RequestInput) {
	t.Helper()
	in := RequestInput{
		Tenant:                   "acme",
		ServerID:                 "controlled",
		ToolName:                 "echo",
		Fingerprint:              FingerprintDigest{1, 2, 3},
		FingerprintFormatVersion: 1,
		Purpose:                  PurposeShadowEvaluation,
		CatalogRevision:          7,
		RequestedBy:              requestedBy,
		Reason:                   "reviewed for shadow eval",
	}
	req, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	return req, in
}

// selfApprovalTarget is the matching CurrentTarget for selfApprovalRequest's input, so a
// refusal can only ever come from the four-eyes gate and never from a target mismatch.
func selfApprovalTarget(in RequestInput) CurrentTarget {
	return CurrentTarget{
		ServerExists: true, ServerUsable: true, Tenant: in.Tenant,
		ToolExists: true, Approvable: true,
		Fingerprint: in.Fingerprint, FingerprintFormatVersion: in.FingerprintFormatVersion,
		CatalogRevision: in.CatalogRevision, ServerRevision: in.ServerRevision,
	}
}

// TestApprove_SelfApprovalDenied is the core NEGATIVE test: the requester may not approve
// their own tool-trust request, and the refusal carries the same reason the operational
// approval plane uses.
func TestApprove_SelfApprovalDenied(t *testing.T) {
	s := selfApprovalStore(t, nil)
	req, in := selfApprovalRequest(t, s, "alice")
	_, err := s.Approve(req.ApprovalID, "alice", selfApprovalTarget(in))
	if got := mcperr.ReasonOf(err); got != mcperr.ReasonApprovalSelfApproval {
		t.Fatalf("self-approve reason = %v, want approval_self_approval", got)
	}
}

// TestApprove_DistinctApproverSucceeds is the POSITIVE control: the gate refuses only the
// requester, never a second human. Without it a passing negative test could mean Approve
// stopped working entirely.
func TestApprove_DistinctApproverSucceeds(t *testing.T) {
	s := selfApprovalStore(t, nil)
	req, in := selfApprovalRequest(t, s, "alice")
	got, err := s.Approve(req.ApprovalID, "bob", selfApprovalTarget(in))
	if err != nil {
		t.Fatalf("Approve by a distinct principal: %v", err)
	}
	if got.Status != StatusActive || got.ApprovedBy != "bob" {
		t.Fatalf("approved record = status %v by %q, want active by bob", got.Status, got.ApprovedBy)
	}
}

// TestApprove_SelfApprovalLeavesRecordUndecided proves the refusal is fail-closed and
// side-effect-free: the in-memory record stays Pending with no approval evidence, the
// durable file is byte-unchanged, and a LATER approve by a second human still works (the
// refusal must not poison the request).
func TestApprove_SelfApprovalLeavesRecordUndecided(t *testing.T) {
	s := selfApprovalStore(t, nil)
	req, in := selfApprovalRequest(t, s, "alice")
	before, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	if _, err := s.Approve(req.ApprovalID, "alice", selfApprovalTarget(in)); err == nil {
		t.Fatal("self-approve must fail")
	}
	cur, err := s.Get(req.ApprovalID, "acme")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cur.Status != StatusPending || cur.ApprovedBy != "" || !cur.ApprovedAt.IsZero() {
		t.Fatalf("record after refusal = status %v approvedBy %q at %v, want pending with no evidence",
			cur.Status, cur.ApprovedBy, cur.ApprovedAt)
	}
	after, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatalf("re-read store: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("a refused self-approval must not rewrite the durable store")
	}
	if _, err := s.Approve(req.ApprovalID, "bob", selfApprovalTarget(in)); err != nil {
		t.Fatalf("approve by a second human after a refusal: %v", err)
	}
}

// TestApprove_SelfApprovalNotEvadedByClientAddress is the REGRESSION test for SEC-MCP-4E-1
// at the store layer: a durable record written by an older build recorded the IP-bearing
// audit string as its requester. Comparing raw strings would let that same human approve
// it from any other address (or under the new identity-only principal), so the comparison
// normalizes an "@<IP>" suffix off BOTH sides.
func TestApprove_SelfApprovalNotEvadedByClientAddress(t *testing.T) {
	for _, tc := range []struct {
		name        string
		requestedBy string
		approver    string
	}{
		{"legacy requester vs identity approver", "alice@10.0.0.5", "alice"},
		{"identity requester vs legacy approver", "alice", "alice@10.0.0.5"},
		{"same human, two addresses", "alice@10.0.0.5", "alice@203.0.113.9"},
		{"same human, IPv6 address", "alice@10.0.0.5", "alice@2001:db8::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := selfApprovalStore(t, nil)
			req, in := selfApprovalRequest(t, s, tc.requestedBy)
			_, err := s.Approve(req.ApprovalID, tc.approver, selfApprovalTarget(in))
			if got := mcperr.ReasonOf(err); got != mcperr.ReasonApprovalSelfApproval {
				t.Fatalf("approve(%q → %q) reason = %v, want approval_self_approval", tc.requestedBy, tc.approver, got)
			}
		})
	}
}

// TestNormalizePrincipal_Boundaries pins the normalization's exact edges. Over-stripping
// would merge two DIFFERENT humans into one principal (a false self-approval refusal);
// under-stripping would re-open the address bypass. Both directions are pinned here,
// including the malformed shapes a hand-edited durable record can carry.
func TestNormalizePrincipal_Boundaries(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"alice", "alice"},                                 // bare identity: untouched
		{"alice@10.0.0.5", "alice"},                        // IPv4 suffix: stripped
		{"alice@2001:db8::1", "alice"},                     // IPv6 suffix: stripped
		{"alice@example.com", "alice@example.com"},         // an email domain is not an address
		{"alice@corp", "alice@corp"},                       // a bare realm is not an address
		{"alice@user@10.0.0.5", "alice@user"},              // only the LAST separator is considered
		{"10.0.0.5", "10.0.0.5"},                           // bare address (no identity): untouched
		{"@10.0.0.5", "@10.0.0.5"},                         // empty identity half: never yields ""
		{"alice@", "alice@"},                               // empty suffix: nothing to parse
		{"", ""},                                           // empty principal
		{"alice@999.999.999.999", "alice@999.999.999.999"}, // not a valid address
	} {
		if got := normalizePrincipal(tc.in); got != tc.want {
			t.Errorf("normalizePrincipal(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestNormalizePrincipal_KeepsDistinctHumansDistinct is the anti-over-stripping control:
// normalization must never collapse two different identities onto one another, which would
// refuse a legitimate four-eyes approval.
func TestNormalizePrincipal_KeepsDistinctHumansDistinct(t *testing.T) {
	if samePrincipal("alice@10.0.0.5", "bob@10.0.0.5") {
		t.Fatal("two humans behind ONE address must stay distinct principals")
	}
	if samePrincipal("alice@example.com", "alice@example.org") {
		t.Fatal("two email identities must stay distinct principals")
	}
}

// TestApprove_ConcurrentSelfApprovalRacesNeverGrant is the CONCURRENCY test: many
// simultaneous self-approvals plus one legitimate approval must end with exactly one active
// grant, approved by the second human — never by the requester. It pins that the gate is
// inside the store lock, not a check-then-act around it.
func TestApprove_ConcurrentSelfApprovalRacesNeverGrant(t *testing.T) {
	s := selfApprovalStore(t, nil)
	req, in := selfApprovalRequest(t, s, "alice")
	target := selfApprovalTarget(in)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _ = s.Approve(req.ApprovalID, "alice", target)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_, _ = s.Approve(req.ApprovalID, "bob", target)
	}()
	close(start)
	wg.Wait()

	got, err := s.Get(req.ApprovalID, "acme")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusActive {
		t.Fatalf("status after the race = %v, want active (bob's approval must land)", got.Status)
	}
	if got.ApprovedBy != "bob" {
		t.Fatalf("approvedBy = %q, want bob — the requester must never appear as approver", got.ApprovedBy)
	}
}

// TestApprove_SelfApprovalRefusalSurvivesReload proves the refusal is not merely an
// in-memory nicety: a store reloaded from disk after a refused self-approval still holds a
// PENDING record, so a restart cannot launder the refusal into a grant.
func TestApprove_SelfApprovalRefusalSurvivesReload(t *testing.T) {
	s := selfApprovalStore(t, nil)
	req, in := selfApprovalRequest(t, s, "alice")
	if _, err := s.Approve(req.ApprovalID, "alice", selfApprovalTarget(in)); err == nil {
		t.Fatal("self-approve must fail")
	}
	reloaded, err := NewStore(Config{Path: s.path})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, err := reloaded.Get(req.ApprovalID, "acme")
	if err != nil {
		t.Fatalf("Get after reload: %v", err)
	}
	if got.Status != StatusPending {
		t.Fatalf("status after reload = %v, want pending", got.Status)
	}
}

// TestApprove_IdempotentReapproveOfActiveGrantIsUnaffected pins the deliberate scope of the
// gate: it guards the pending→active TRANSITION only. Re-approving an already-active grant
// re-verifies the target and changes nothing, so it must stay idempotent — including for a
// principal that matches the requester, which can no longer be how the grant was made.
func TestApprove_IdempotentReapproveOfActiveGrantIsUnaffected(t *testing.T) {
	s := selfApprovalStore(t, nil)
	req, in := selfApprovalRequest(t, s, "alice")
	target := selfApprovalTarget(in)
	if _, err := s.Approve(req.ApprovalID, "bob", target); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	got, err := s.Approve(req.ApprovalID, "alice", target)
	if err != nil {
		t.Fatalf("idempotent re-approve of an ACTIVE grant must not be refused: %v", err)
	}
	if got.ApprovedBy != "bob" {
		t.Fatalf("approvedBy = %q, want bob — a re-approve must never re-attribute the grant", got.ApprovedBy)
	}
}
