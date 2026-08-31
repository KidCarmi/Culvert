package tooltrust

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Four-eyes (separation of duties) at the tool-trust approve boundary.
//
// A tool-trust grant promotes a tool to catalog.Usable — a supply-chain trust decision.
// internal/mcp/approval has always refused `approver == requester` for operational and
// publication approvals, and canary.EvaluateTrust already REQUIRES the same of this
// record (TrustNoFourEyes). Before this suite the store did not enforce it: a
// self-approved grant became durably active and promoted the tool immediately, and the
// Canary gate only noticed afterwards. These tests pin the enforcement.

// --- negative: the self-approval is refused --------------------------------

func TestApprove_RefusesSelfApproval(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := newTestStore(t, clk)
	in := goodRequest()
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	_, err = s.Approve(a.ApprovalID, in.RequestedBy, matchingTarget(in))
	mustReason(t, err, mcperr.ReasonApprovalSelfApproval)

	// Fail CLOSED: the record must be untouched — still pending, no approver, and the
	// coordinator must have nothing to promote.
	got, gerr := s.Get(a.ApprovalID, in.Tenant)
	if gerr != nil {
		t.Fatalf("Get: %v", gerr)
	}
	if got.Status != StatusPending {
		t.Fatalf("status = %s, want pending (a refused approve must not transition)", got.Status)
	}
	if got.ApprovedBy != "" || !got.ApprovedAt.IsZero() {
		t.Fatalf("refused approve recorded an approver: by=%q at=%v", got.ApprovedBy, got.ApprovedAt)
	}
	for _, ref := range s.ActiveApprovals(clk.t) {
		if ref.ApprovalID == a.ApprovalID {
			t.Fatal("a self-approved request became an ACTIVE grant")
		}
	}
}

// --- positive: a distinct approver still succeeds --------------------------

func TestApprove_DistinctApproverSucceeds(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := newTestStore(t, clk)
	in := goodRequest()
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	granted, err := s.Approve(a.ApprovalID, "security-lead@corp", matchingTarget(in))
	if err != nil {
		t.Fatalf("four-eyes approve must succeed: %v", err)
	}
	if granted.Status != StatusActive {
		t.Fatalf("status = %s, want active", granted.Status)
	}
	if granted.ApprovedBy != "security-lead@corp" {
		t.Fatalf("approved_by = %q", granted.ApprovedBy)
	}
	if granted.RequestedBy == granted.ApprovedBy {
		t.Fatal("requester and approver must differ on an active grant")
	}
}

// --- boundary: the comparison is EXACT, never normalised -------------------
//
// Deliberately pinned as a limitation, not a claim: the check is exact string equality
// on the authenticated subject, which is what the admin plane issues. It does not
// case-fold or canonicalise — an identity provider that emits two spellings for one
// human is a provisioning problem the store cannot see, and inventing a normalisation
// here would be a guess that could also MERGE two distinct principals.
func TestApprove_SelfApprovalComparisonIsExact(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	for name, approver := range map[string]string{
		"different case":    "Operator@corp",
		"trailing space":    "operator@corp ",
		"different subject": "operator2@corp",
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestStore(t, clk)
			in := goodRequest()
			a, err := s.CreateRequest(in)
			if err != nil {
				t.Fatalf("CreateRequest: %v", err)
			}
			if _, err := s.Approve(a.ApprovalID, approver, matchingTarget(in)); err != nil {
				t.Fatalf("approver %q is not byte-equal to the requester, so it must be admitted: %v", approver, err)
			}
		})
	}
}

// --- malformed / boundary input -------------------------------------------

func TestApprove_EmptyApproverStillRefusedBeforeFourEyes(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := newTestStore(t, clk)
	in := goodRequest()
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	// An empty approver is rejected at entry, so an empty RequestedBy could never
	// collapse the four-eyes check into "" == "" and read as satisfied.
	_, err = s.Approve(a.ApprovalID, "", matchingTarget(in))
	mustReason(t, err, mcperr.ReasonApprovalNotAuthorized)
}

func TestCreateRequest_RejectsEmptyRequester(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := newTestStore(t, clk)
	in := goodRequest()
	in.RequestedBy = ""
	if _, err := s.CreateRequest(in); err == nil {
		t.Fatal("a request with no requester must be refused: it can never be four-eyes approved")
	}
}

// --- regression: the ORDER of the gates ------------------------------------
//
// Self-approval must be refused as self-approval, not masked by an unrelated later
// gate, so the operator sees the real reason. And it must NOT displace the gates that
// run BEFORE it (expiry, terminal state), whose refusals are equally load-bearing.

func TestApprove_SelfApprovalOutranksTargetMismatch(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := newTestStore(t, clk)
	in := goodRequest()
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	drifted := matchingTarget(in)
	drifted.Fingerprint = fp(0x99) // ALSO drifted
	_, err = s.Approve(a.ApprovalID, in.RequestedBy, drifted)
	mustReason(t, err, mcperr.ReasonApprovalSelfApproval)
}

func TestApprove_ExpiryStillOutranksSelfApproval(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := newTestStore(t, clk)
	in := goodRequest()
	exp := clk.t.Add(time.Minute)
	in.ExpiresAt = &exp
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	clk.t = clk.t.Add(2 * time.Minute)
	_, err = s.Approve(a.ApprovalID, in.RequestedBy, matchingTarget(in))
	mustReason(t, err, mcperr.ReasonApprovalExpired)
}

// An already-active grant passed four-eyes when it was granted, so the idempotent
// re-approve path must stay reachable — including when the CALLER is the requester,
// who is entitled to re-read the outcome of a decision somebody else made.
func TestApprove_IdempotentReapproveByRequesterIsNotSelfApproval(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := newTestStore(t, clk)
	in := goodRequest()
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if _, err := s.Approve(a.ApprovalID, "security-lead@corp", matchingTarget(in)); err != nil {
		t.Fatalf("initial four-eyes approve: %v", err)
	}
	again, err := s.Approve(a.ApprovalID, in.RequestedBy, matchingTarget(in))
	if err != nil {
		t.Fatalf("idempotent re-approve of an already-active grant must not be refused: %v", err)
	}
	if again.ApprovedBy != "security-lead@corp" {
		t.Fatalf("re-approve rewrote the approver to %q — the original decision must stand", again.ApprovedBy)
	}
	if again.Status != StatusActive {
		t.Fatalf("status = %s, want active", again.Status)
	}
}

// --- concurrency -----------------------------------------------------------
//
// The requester racing ONLY herself: every attempt must be refused and the record must
// stay pending. This half is DETERMINISTIC — there is no peer to win the race, so it
// cannot pass by scheduling luck.
func TestApprove_ConcurrentSelfApprovalsAllRefused(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := newTestStore(t, clk)
	in := goodRequest()
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	const n = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	var refused, admitted int
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := s.Approve(a.ApprovalID, in.RequestedBy, matchingTarget(in))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				admitted++
			case mcperr.ReasonOf(err) == mcperr.ReasonApprovalSelfApproval:
				refused++
			}
		}()
	}
	wg.Wait()

	if admitted != 0 {
		t.Fatalf("%d concurrent self-approvals were ADMITTED", admitted)
	}
	if refused != n {
		t.Fatalf("refused %d of %d self-approvals; the rest failed for another reason", refused, n)
	}
	got, gerr := s.Get(a.ApprovalID, in.Tenant)
	if gerr != nil {
		t.Fatalf("Get: %v", gerr)
	}
	if got.Status != StatusPending || got.ApprovedBy != "" {
		t.Fatalf("record after 32 refused self-approvals: status=%s approved_by=%q, want pending/\"\"",
			got.Status, got.ApprovedBy)
	}
}

// The requester racing a legitimate PEER approver. Exactly one decision must land, and
// the invariant asserted is the one that holds under every interleaving: the recorded
// approver is never the requester. (Which goroutine wins is genuinely racy — if the peer
// lands first the requester's later calls reach the idempotent already-active branch and
// return success, which is correct and is why "some call returned an error" is NOT the
// property under test here; the deterministic gate above owns that half.)
func TestApprove_ConcurrentSelfAndPeerApprovals(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := newTestStore(t, clk)
	in := goodRequest()
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	const n = 32
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		approver := "security-lead@corp"
		if i%2 == 0 {
			approver = in.RequestedBy // the requester racing her own approval
		}
		go func(approver string) {
			defer wg.Done()
			_, _ = s.Approve(a.ApprovalID, approver, matchingTarget(in))
		}(approver)
	}
	wg.Wait()

	got, gerr := s.Get(a.ApprovalID, in.Tenant)
	if gerr != nil {
		t.Fatalf("Get: %v", gerr)
	}
	if got.ApprovedBy == in.RequestedBy {
		t.Fatalf("a concurrent self-approval won the race: approved_by = %q", got.ApprovedBy)
	}
	if got.Status != StatusActive || got.ApprovedBy != "security-lead@corp" {
		t.Fatalf("final record: status=%s approved_by=%q, want active/security-lead@corp", got.Status, got.ApprovedBy)
	}
}

// --- durability ------------------------------------------------------------
//
// A refused self-approval must leave nothing behind for a later Load to recover as an
// active grant.
func TestApprove_SelfApprovalLeavesNoDurableGrant(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	dir := t.TempDir()
	cfg := Config{Path: dir + "/approvals.json", Clock: clk.now, MaxRecords: 64, MaxPerTenant: 8}

	s, err := NewStore(cfg)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	in := goodRequest()
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if _, err := s.Approve(a.ApprovalID, in.RequestedBy, matchingTarget(in)); err == nil {
		t.Fatal("self-approval must be refused")
	}

	reloaded, err := NewStore(cfg)
	if err != nil {
		t.Fatalf("NewStore(reload): %v", err)
	}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("Load(reload): %v", err)
	}
	if n := len(reloaded.ActiveApprovals(clk.t)); n != 0 {
		t.Fatalf("recovered %d active grants after a refused self-approval, want 0", n)
	}
}

// --- pre-upgrade records cannot slip past the new gate ---------------------
//
// Up to SchemaVersion 1, RequestedBy/ApprovedBy were written from the admin plane's AUDIT
// actor, "<identity>@<clientIP>". The new Approve gate compares approver == RequestedBy,
// and that comparison is only meaningful between values in the same coordinate-free
// format: a v1 pending record naming "alice@198.51.100.1" compares unequal to the very
// same human approving as "alice", so she would walk straight through the gate this suite
// exists to enforce (Codex P2). The envelope bump closes it by refusing to load such a
// store at all.

func TestLoad_PreFourEyesPrincipalStoreFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")

	// A v1 record exactly as the previous build would have written it: a pending request
	// whose requester carries the client coordinate.
	legacy := `{"schema_version":1,"approvals":[{` +
		`"schema_version":1,"approval_id":"a1","tenant":"tenant-a","server_id":"srv-1",` +
		`"tool_name":"search","fingerprint_format_version":1,"catalog_revision":7,` +
		`"purpose":1,"status":1,"requested_by":"alice@198.51.100.1",` +
		`"requested_at":"2026-08-30T00:00:00Z"}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := NewStore(Config{Path: path, Clock: clk.now, MaxRecords: 64, MaxPerTenant: 8})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	err = s.Load()
	if err == nil {
		t.Fatal("a pre-four-eyes-principal store must fail closed, not load")
	}
	// The operator must be able to tell this from a damaged file — the two call for
	// opposite responses (re-decide vs. investigate corruption).
	if !strings.Contains(err.Error(), "predates the four-eyes principal change") {
		t.Fatalf("error must name the cause precisely, got: %v", err)
	}
	// Fail CLOSED: nothing is recovered, so no legacy grant can be approved or promoted.
	if n := len(s.ActiveApprovals(clk.t)); n != 0 {
		t.Fatalf("recovered %d grants from a refused load, want 0", n)
	}
	if _, gerr := s.Get("a1", "tenant-a"); gerr == nil {
		t.Fatal("a record from a refused load must not be reachable")
	}
}

// The bump must be a real forward step, not a silent no-op, and the version it supersedes
// must stay named so the message above can never go stale.
func TestSchemaVersion_IsPastThePreFourEyesPrincipalVersion(t *testing.T) {
	if SchemaVersion <= schemaVersionPreFourEyesPrincipal {
		t.Fatalf("SchemaVersion = %d must be greater than the pre-change version %d",
			SchemaVersion, schemaVersionPreFourEyesPrincipal)
	}
}

// A store written by THIS build round-trips, so the bump did not break ordinary recovery.
func TestLoad_CurrentSchemaRoundTripsAfterBump(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	dir := t.TempDir()
	cfg := Config{Path: filepath.Join(dir, "approvals.json"), Clock: clk.now, MaxRecords: 64, MaxPerTenant: 8}

	s, err := NewStore(cfg)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Load(); err != nil {
		t.Fatalf("Load fresh: %v", err)
	}
	in := goodRequest()
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if _, err := s.Approve(a.ApprovalID, "security-lead@corp", matchingTarget(in)); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	reloaded, err := NewStore(cfg)
	if err != nil {
		t.Fatalf("NewStore(reload): %v", err)
	}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("a store written by this build must reload: %v", err)
	}
	if n := len(reloaded.ActiveApprovals(clk.t)); n != 1 {
		t.Fatalf("recovered %d active grants, want 1", n)
	}
}
