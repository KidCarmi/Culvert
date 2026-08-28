package tooltrust

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// --- helpers --------------------------------------------------------------

func fp(b byte) FingerprintDigest {
	var d FingerprintDigest
	for i := range d {
		d[i] = b
	}
	return d
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestStore(t *testing.T, clk *fakeClock) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := NewStore(Config{
		Path:         filepath.Join(dir, "mcp_tooltrust", "approvals.json"),
		Clock:        clk.now,
		MaxRecords:   64,
		MaxPerTenant: 8,
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Load(); err != nil {
		t.Fatalf("Load fresh: %v", err)
	}
	return s
}

func goodRequest() RequestInput {
	return RequestInput{
		Tenant:                   "tenant-a",
		ServerID:                 "srv-1",
		ToolName:                 "search",
		Fingerprint:              fp(0x11),
		FingerprintFormatVersion: 1,
		Purpose:                  PurposeShadowEvaluation,
		CatalogRevision:          7,
		ServerRevision:           3,
		RequestedBy:              "operator@corp",
		Reason:                   "reviewed for shadow eval",
		TicketRef:                "TICKET-1",
	}
}

func matchingTarget(in RequestInput) CurrentTarget {
	return CurrentTarget{
		ServerExists:             true,
		ServerUsable:             true,
		Tenant:                   in.Tenant,
		ToolExists:               true,
		Approvable:               true,
		Fingerprint:              in.Fingerprint,
		FingerprintFormatVersion: in.FingerprintFormatVersion,
		CatalogRevision:          in.CatalogRevision,
		ServerRevision:           in.ServerRevision,
	}
}

func mustReason(t *testing.T, err error, want mcperr.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %s, got nil", want.Code())
	}
	if got := mcperr.ReasonOf(err); got != want {
		t.Fatalf("reason = %s, want %s", got.Code(), want.Code())
	}
}

// --- purpose / trust ceiling ---------------------------------------------

func TestPurpose_OnlyShadowIssuable(t *testing.T) {
	if !PurposeShadowEvaluation.Issuable() {
		t.Fatal("shadow_evaluation must be issuable")
	}
	if PurposeLiveExecution.Issuable() {
		t.Fatal("live_execution must NOT be issuable")
	}
	if PurposeUnset.Issuable() {
		t.Fatal("unset purpose must not be issuable")
	}
	// The live-execution firewall's positive half: only shadow permits shadow eval.
	if !PurposeShadowEvaluation.PermitsShadowEvaluation() {
		t.Fatal("shadow must permit shadow evaluation")
	}
	if PurposeLiveExecution.PermitsShadowEvaluation() {
		t.Fatal("live_execution must never satisfy the shadow prerequisite")
	}
}

func TestRequest_LiveExecutionPurposeRefused(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	in.Purpose = PurposeLiveExecution
	_, err := s.CreateRequest(in)
	mustReason(t, err, mcperr.ReasonApprovalPurposeUnsupported)
}

// --- lifecycle: request → approve ----------------------------------------

func TestApprove_HappyPath(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if req.Status != StatusPending {
		t.Fatalf("status = %s, want pending", req.Status)
	}
	clk.t = clk.t.Add(time.Minute)
	got, err := s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in))
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if got.Status != StatusActive {
		t.Fatalf("status = %s, want active", got.Status)
	}
	if !got.activeAsOf(clk.now()) {
		t.Fatal("approval should be active as of now")
	}
	if !got.MatchesTool(in.Tenant, in.ServerID, in.ToolName, in.Fingerprint, in.FingerprintFormatVersion) {
		t.Fatal("approval should match its bound tool")
	}
	if got.ApprovedBy != "admin@corp" {
		t.Fatalf("approver = %q", got.ApprovedBy)
	}
}

func TestApprove_Idempotent(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, _ := s.CreateRequest(in)
	a1, err := s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in))
	if err != nil {
		t.Fatalf("first approve: %v", err)
	}
	a2, err := s.Approve(req.ApprovalID, "someone-else", matchingTarget(in))
	if err != nil {
		t.Fatalf("idempotent approve: %v", err)
	}
	if a1.ApprovalID != a2.ApprovalID || a2.Status != StatusActive {
		t.Fatal("re-approve must be idempotent and stay active")
	}
	if a2.ApprovedBy != "admin@corp" {
		t.Fatalf("idempotent approve must not change approver: %q", a2.ApprovedBy)
	}
}

// --- stale-target / exact-fingerprint binding (Sec 4/5/14/15) ------------

func TestApprove_FingerprintMismatchRejected(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, _ := s.CreateRequest(in)
	// A DIFFERENT fingerprint was ingested (F1 → F2): reject stale, never retarget.
	target := matchingTarget(in)
	target.Fingerprint = fp(0x22)
	_, err := s.Approve(req.ApprovalID, "admin@corp", target)
	mustReason(t, err, mcperr.ReasonToolFingerprintMismatch)
	// The approval stays pending — no partial promotion.
	got, _ := s.Get(req.ApprovalID, in.Tenant)
	if got.Status != StatusPending {
		t.Fatalf("status after mismatch = %s, want pending", got.Status)
	}
}

func TestApprove_FingerprintFormatVersionMismatchRejected(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, _ := s.CreateRequest(in)
	target := matchingTarget(in)
	target.FingerprintFormatVersion = 2 // a scheme change invalidates
	_, err := s.Approve(req.ApprovalID, "admin@corp", target)
	mustReason(t, err, mcperr.ReasonToolFingerprintMismatch)
}

func TestApprove_TenantConflictRejected(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, _ := s.CreateRequest(in)
	target := matchingTarget(in)
	target.Tenant = "tenant-b" // the server now belongs to a different tenant
	_, err := s.Approve(req.ApprovalID, "admin@corp", target)
	mustReason(t, err, mcperr.ReasonApprovalTenantConflict)
}

func TestApprove_ServerNotUsableRejected(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, _ := s.CreateRequest(in)
	target := matchingTarget(in)
	target.ServerUsable = false
	_, err := s.Approve(req.ApprovalID, "admin@corp", target)
	mustReason(t, err, mcperr.ReasonServerNotUsable)
}

func TestApprove_ToolGoneRejected(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, _ := s.CreateRequest(in)
	target := matchingTarget(in)
	target.ToolExists = false
	_, err := s.Approve(req.ApprovalID, "admin@corp", target)
	mustReason(t, err, mcperr.ReasonToolNotFound)
}

func TestApprove_NotApprovableRejected(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, _ := s.CreateRequest(in)
	target := matchingTarget(in)
	target.Approvable = false // e.g. ServerDisabled by identity change
	_, err := s.Approve(req.ApprovalID, "admin@corp", target)
	mustReason(t, err, mcperr.ReasonToolNotApprovable)
}

// --- revocation (Sec 8) ---------------------------------------------------

func TestRevoke_ImmediateAndTerminal(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, _ := s.CreateRequest(in)
	if _, err := s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	rev, err := s.Revoke(req.ApprovalID, "admin@corp", in.Tenant, "compromised")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if rev.Status != StatusRevoked {
		t.Fatalf("status = %s, want revoked", rev.Status)
	}
	// A revoked approval is no longer live and never re-satisfies.
	if rev.activeAsOf(clk.now()) {
		t.Fatal("revoked approval must not be active")
	}
	// Re-approving a revoked approval fails closed — a fresh decision is required.
	_, err = s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in))
	mustReason(t, err, mcperr.ReasonApprovalRevoked)
	// Idempotent revoke.
	if _, err := s.Revoke(req.ApprovalID, "admin@corp", in.Tenant, "again"); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
}

func TestRevoke_CrossTenantUniformNotFound(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, _ := s.CreateRequest(in)
	_, err := s.Revoke(req.ApprovalID, "admin@corp", "tenant-b", "x")
	mustReason(t, err, mcperr.ReasonApprovalNotFound)
}

func TestRevoke_RevokedNeverReactivatesAcrossReload(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, _ := s.CreateRequest(in)
	_, _ = s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in))
	_, _ = s.Revoke(req.ApprovalID, "admin@corp", in.Tenant, "revoked")

	// Reload from disk: a revoked approval must never come back as active.
	s2, err := NewStore(Config{Path: s.path, Clock: clk.now})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if act := s2.ActiveApprovals(clk.now()); len(act) != 0 {
		t.Fatalf("revoked approval reappeared active after reload: %d", len(act))
	}
}

// --- expiry (Sec 9) -------------------------------------------------------

func TestExpiry_LazyAndSweep(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	exp := clk.t.Add(10 * time.Minute)
	in.ExpiresAt = &exp
	req, _ := s.CreateRequest(in)
	if _, err := s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Before expiry: active.
	if len(s.ActiveApprovals(clk.now())) != 1 {
		t.Fatal("should be active before expiry")
	}
	// After expiry: not active (derived), even before a sweep.
	clk.t = exp.Add(time.Second)
	if len(s.ActiveApprovals(clk.now())) != 0 {
		t.Fatal("expired approval must not be active")
	}
	// Sweep transitions it to Expired durably and reports it for demotion.
	expired, err := s.ExpireDue(clk.now())
	if err != nil {
		t.Fatalf("ExpireDue: %v", err)
	}
	if len(expired) != 1 || expired[0].Status != StatusExpired {
		t.Fatalf("sweep should expire 1: %+v", expired)
	}
	// Approving an expired grant fails closed.
	_, err = s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in))
	mustReason(t, err, mcperr.ReasonApprovalExpired)
}

// --- Codex P1: a request whose TTL elapsed before approval is rejected ----

func TestApprove_PendingExpiredBeforeApprovalRejected(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	exp := clk.t.Add(5 * time.Minute)
	in.ExpiresAt = &exp
	req, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	// The admin does not get to it until AFTER the TTL elapses.
	clk.t = exp.Add(time.Second)
	_, err = s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in))
	mustReason(t, err, mcperr.ReasonApprovalExpired)
	// It must stay pending→never active (no grant was conferred).
	got, _ := s.Get(req.ApprovalID, in.Tenant)
	if got.Status == StatusActive {
		t.Fatal("an expired pending request must never be activated")
	}
	if len(s.ActiveApprovals(clk.now())) != 0 {
		t.Fatal("no active grant may exist for an expired-before-approval request")
	}
}

// --- Codex P2: reviewed revision advancing (same fingerprint) is stale ----

func TestApprove_CatalogRevisionAdvancedRejected(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest() // records CatalogRevision 7
	req, _ := s.CreateRequest(in)
	target := matchingTarget(in)
	target.CatalogRevision = in.CatalogRevision + 1 // identical rediscovery bumped the revision
	_, err := s.Approve(req.ApprovalID, "admin@corp", target)
	mustReason(t, err, mcperr.ReasonToolApprovalStale)
	got, _ := s.Get(req.ApprovalID, in.Tenant)
	if got.Status != StatusPending {
		t.Fatalf("a revision-stale approve must leave the request pending, got %s", got.Status)
	}
}

func TestApprove_ServerRevisionAdvancedRejected(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest() // records ServerRevision 3
	req, _ := s.CreateRequest(in)
	target := matchingTarget(in)
	target.ServerRevision = in.ServerRevision + 1
	_, err := s.Approve(req.ApprovalID, "admin@corp", target)
	mustReason(t, err, mcperr.ReasonToolApprovalStale)
}

// --- Codex P2: a pruned terminal record is restored on persist failure ----

func TestCreate_PrunePersistFailureRestoresEvicted(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	s, err := NewStore(Config{Path: filepath.Join(dir, "approvals.json"), Clock: clk.now, MaxRecords: 2, MaxPerTenant: 8})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Fill to the total cap with two terminal (rejected) records.
	in1 := goodRequest()
	in1.ToolName = "one"
	r1, _ := s.CreateRequest(in1)
	in2 := goodRequest()
	in2.ToolName = "two"
	r2, _ := s.CreateRequest(in2)
	if err := s.Reject(r1.ApprovalID, "admin@corp", "x"); err != nil {
		t.Fatalf("reject r1: %v", err)
	}
	if err := s.Reject(r2.ApprovalID, "admin@corp", "x"); err != nil {
		t.Fatalf("reject r2: %v", err)
	}
	// Now a new create at cap must prune the oldest terminal — but persistence fails.
	s.writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	in3 := goodRequest()
	in3.ToolName = "three"
	if _, err := s.CreateRequest(in3); err == nil {
		t.Fatal("create must fail when persistence fails")
	}
	// The evicted terminal record must be RESTORED (no silent loss), and the new record
	// must be absent — the in-memory index matches the durable file (still 2 records).
	s.mu.Lock()
	_, haveR1 := s.byID[r1.ApprovalID]
	_, haveR2 := s.byID[r2.ApprovalID]
	n := len(s.byID)
	s.mu.Unlock()
	if !haveR1 || !haveR2 || n != 2 {
		t.Fatalf("prune must be restored on persist failure: r1=%v r2=%v n=%d", haveR1, haveR2, n)
	}
}

// --- reject ---------------------------------------------------------------

func TestReject_TerminalAndIdempotent(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, _ := s.CreateRequest(in)
	if err := s.Reject(req.ApprovalID, "admin@corp", "not needed"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if err := s.Reject(req.ApprovalID, "admin@corp", "again"); err != nil {
		t.Fatalf("idempotent reject: %v", err)
	}
	// A rejected request can never be approved.
	_, err := s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in))
	mustReason(t, err, mcperr.ReasonApprovalTerminalState)
}

// --- persistence / recovery (Sec 13) -------------------------------------

func TestRecover_ActiveGrantSurvivesReload(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, _ := s.CreateRequest(in)
	if _, err := s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	s2, err := NewStore(Config{Path: s.path, Clock: clk.now})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	act := s2.ActiveApprovals(clk.now())
	if len(act) != 1 {
		t.Fatalf("active after reload = %d, want 1", len(act))
	}
	if act[0].Fingerprint != in.Fingerprint {
		t.Fatal("recovered approval lost its bound fingerprint")
	}
}

func TestLoad_CorruptFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(Config{Path: path, Clock: clk.now})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Load(); err == nil {
		t.Fatal("corrupt file must fail closed, not load empty")
	}
}

func TestLoad_UnknownSchemaFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":9999,"approvals":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewStore(Config{Path: path, Clock: clk.now})
	if err := s.Load(); err == nil {
		t.Fatal("unknown schema must fail closed")
	}
}

func TestLoad_UnknownFieldFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"approvals":[],"evil":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewStore(Config{Path: path, Clock: clk.now})
	if err := s.Load(); err == nil {
		t.Fatal("unknown field must fail closed (strict decode)")
	}
}

func TestPersistFailure_LeavesStateUnchanged(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	// Inject a failing writer AFTER construction.
	s.writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	_, err := s.CreateRequest(goodRequest())
	if err == nil {
		t.Fatal("CreateRequest must fail when persistence fails")
	}
	// Durable-before-effect: the in-memory index must be byte-unchanged.
	s.mu.Lock()
	n := len(s.byID)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("failed create left %d records in memory", n)
	}
}

func TestApprovePersistFailure_KeepsPending(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, _ := s.CreateRequest(in)
	s.writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	_, err := s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in))
	if err == nil {
		t.Fatal("Approve must fail when persistence fails")
	}
	got, _ := s.Get(req.ApprovalID, in.Tenant)
	if got.Status != StatusPending {
		t.Fatalf("failed approve must leave status pending, got %s", got.Status)
	}
}

// --- tenant isolation + bounds -------------------------------------------

func TestGet_TenantIsolation(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	req, _ := s.CreateRequest(goodRequest())
	if _, err := s.Get(req.ApprovalID, "tenant-b"); err == nil {
		t.Fatal("cross-tenant Get must be uniform not-found")
	} else {
		mustReason(t, err, mcperr.ReasonApprovalNotFound)
	}
}

func TestCreate_PerTenantCap(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	for i := 0; i < 8; i++ {
		in := goodRequest()
		in.ToolName = "tool-" + string(rune('a'+i))
		if _, err := s.CreateRequest(in); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	_, err := s.CreateRequest(goodRequest())
	mustReason(t, err, mcperr.ReasonAdminRangeExceeded)
}

func TestCreate_RejectsOverBoundReason(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	in.Reason = string(make([]byte, maxReasonBytes+1))
	_, err := s.CreateRequest(in)
	mustReason(t, err, mcperr.ReasonAdminRequestInvalid)
}

func TestCreate_RejectsEmptyIdentityFields(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	in.ServerID = ""
	_, err := s.CreateRequest(in)
	mustReason(t, err, mcperr.ReasonAdminRequestInvalid)
}

// --- ActiveApprovals never leaks a drifted tool (fingerprint match is the caller's) ---

func TestActiveApprovals_DoesNotSelfMatchFingerprint(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	req, _ := s.CreateRequest(in)
	_, _ = s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in))
	act := s.ActiveApprovals(clk.now())
	if len(act) != 1 {
		t.Fatalf("want 1 active, got %d", len(act))
	}
	// The coordinator must match the CURRENT fingerprint; the approval binds F1, so a
	// tool now at F2 must NOT match.
	if act[0].MatchesTool(in.Tenant, in.ServerID, in.ToolName, fp(0x22), 1) {
		t.Fatal("active approval must not match a drifted fingerprint")
	}
	if !act[0].MatchesTool(in.Tenant, in.ServerID, in.ToolName, in.Fingerprint, 1) {
		t.Fatal("active approval must match its exact reviewed fingerprint")
	}
}
