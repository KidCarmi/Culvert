package tooltrust

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

func TestPurpose_ShadowAndLiveIssuable(t *testing.T) {
	// Both shadow_evaluation and live_execution are now issuable at the coarse purpose gate; the
	// live-execution-specific governance (mandatory ≤24h expiry, four-eyes) is layered by the
	// issue path, not by Issuable().
	if !PurposeShadowEvaluation.Issuable() {
		t.Fatal("shadow_evaluation must be issuable")
	}
	if !PurposeLiveExecution.Issuable() {
		t.Fatal("live_execution must now be issuable (under stronger governance)")
	}
	if PurposeUnset.Issuable() {
		t.Fatal("unset purpose must not be issuable")
	}
	// The live-execution firewall stays disjoint: shadow permits ONLY shadow eval, live permits
	// ONLY live execution — no purpose satisfies both.
	if !PurposeShadowEvaluation.PermitsShadowEvaluation() || PurposeShadowEvaluation.PermitsLiveExecution() {
		t.Fatal("shadow must permit shadow evaluation and never live execution")
	}
	if PurposeLiveExecution.PermitsShadowEvaluation() || !PurposeLiveExecution.PermitsLiveExecution() {
		t.Fatal("live_execution must permit live execution and never satisfy the shadow prerequisite")
	}
}

func TestRequest_LiveExecutionRequiresExplicitExpiry(t *testing.T) {
	// A live_execution request with NO expiry is refused: no expiry is ever silently defaulted in
	// for a live grant (§6). The refusal is a request-shape error, not purpose-unsupported.
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	in.Purpose = PurposeLiveExecution
	in.ExpiresAt = nil
	_, err := s.CreateRequest(in)
	mustReason(t, err, mcperr.ReasonAdminRequestInvalid)
}

func TestRequest_LiveExecutionTTLCeiling(t *testing.T) {
	// A live_execution request whose window exceeds MaxLiveExecutionApprovalTTL is refused early.
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	in.Purpose = PurposeLiveExecution
	tooLong := clk.t.Add(MaxLiveExecutionApprovalTTL + time.Hour)
	in.ExpiresAt = &tooLong
	_, err := s.CreateRequest(in)
	mustReason(t, err, mcperr.ReasonAdminRequestInvalid)
}

func TestRequest_LiveExecutionWithExpirySucceeds(t *testing.T) {
	// A live_execution request WITH a valid finite in-ceiling expiry is now accepted as a pending
	// request (issuance under governance). It is not yet a grant — four-eyes is enforced at approve.
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	in.Purpose = PurposeLiveExecution
	exp := clk.t.Add(time.Hour)
	in.ExpiresAt = &exp
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("live request with valid expiry must succeed, got %v", err)
	}
	if a.Purpose != PurposeLiveExecution || a.Status != StatusPending {
		t.Fatalf("want pending live request, got purpose=%v status=%v", a.Purpose, a.Status)
	}
	if a.ExpiresAt == nil {
		t.Fatal("live request must retain its expiry")
	}
}

// liveRequest builds a valid live_execution request with a short in-ceiling expiry from the clock.
func liveRequest(clk *fakeClock) RequestInput {
	in := goodRequest()
	in.Purpose = PurposeLiveExecution
	exp := clk.t.Add(time.Hour)
	in.ExpiresAt = &exp
	return in
}

func TestLiveApprove_FourEyesRequiresDistinctApprover(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := liveRequest(clk)
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("create live: %v", err)
	}
	// Self-approval (approver == requester) is refused fail-closed with the precise reason.
	if _, err := s.Approve(a.ApprovalID, in.RequestedBy, matchingTarget(in)); mcperr.ReasonOf(err) != mcperr.ReasonApprovalSelfApproval {
		t.Fatalf("self-approval must be refused with self_approval, got %v", mcperr.ReasonOf(err).Code())
	}
	// A DISTINCT approver succeeds — the grant becomes active with four-eyes evidence.
	g, err := s.Approve(a.ApprovalID, "approver@corp", matchingTarget(in))
	if err != nil {
		t.Fatalf("four-eyes approve must succeed: %v", err)
	}
	if g.Status != StatusActive || g.ApprovedBy != "approver@corp" || g.ApprovedBy == g.RequestedBy {
		t.Fatalf("want a distinct-approver active grant, got %+v", g)
	}
}

func TestLiveApprove_TTLCeilingFromApprovedAt(t *testing.T) {
	// Request a valid 23h window, then approve under a clock rolled BACK so the window measured from
	// ApprovedAt (= approve-now) exceeds MaxLiveExecutionApprovalTTL — the approve-time ceiling
	// (defense-in-depth vs a clock-skew / long-dormant grant) must refuse it.
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	in.Purpose = PurposeLiveExecution
	exp := clk.t.Add(23 * time.Hour)
	in.ExpiresAt = &exp
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	clk.t = clk.t.Add(-2 * time.Hour) // approvedAt = T-2h, expiry = T+23h ⇒ window 25h > 24h
	if _, err := s.Approve(a.ApprovalID, "approver@corp", matchingTarget(in)); mcperr.ReasonOf(err) != mcperr.ReasonAdminRequestInvalid {
		t.Fatalf("approve with a >24h window from ApprovedAt must be refused, got %v", mcperr.ReasonOf(err).Code())
	}
}

func TestLiveApprove_ExactStateFingerprintDrift(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := liveRequest(clk)
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	tgt := matchingTarget(in)
	tgt.Fingerprint = fp(0x22) // the tool drifted since review — exact-state revalidation must fail closed
	if _, err := s.Approve(a.ApprovalID, "approver@corp", tgt); mcperr.ReasonOf(err) != mcperr.ReasonToolFingerprintMismatch {
		t.Fatalf("a drifted target must fail with fingerprint mismatch, got %v", mcperr.ReasonOf(err).Code())
	}
}

func TestLiveApprove_StaleCatalogRevisionRefused(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := liveRequest(clk)
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	tgt := matchingTarget(in)
	tgt.CatalogRevision = in.CatalogRevision + 1 // the reviewed catalog revision advanced under the decision
	if _, err := s.Approve(a.ApprovalID, "approver@corp", tgt); mcperr.ReasonOf(err) != mcperr.ReasonToolApprovalStale {
		t.Fatalf("a stale catalog revision must be refused, got %v", mcperr.ReasonOf(err).Code())
	}
}

func TestLiveApprove_StaleServerRevisionRefused(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := liveRequest(clk)
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	tgt := matchingTarget(in)
	tgt.ServerRevision = in.ServerRevision + 1 // the reviewed server revision advanced under the decision
	if _, err := s.Approve(a.ApprovalID, "approver@corp", tgt); mcperr.ReasonOf(err) != mcperr.ReasonToolApprovalStale {
		t.Fatalf("a stale server revision must be refused, got %v", mcperr.ReasonOf(err).Code())
	}
}

func TestLiveApprove_PersistFailureRevertsState(t *testing.T) {
	// Durable-before-effect: if the authoritative durable write fails, the live approve must NOT change
	// the trust state — the record stays pending, not laundered into an active grant.
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := liveRequest(clk)
	a, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	s.writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	if _, err := s.Approve(a.ApprovalID, "approver@corp", matchingTarget(in)); err == nil {
		t.Fatal("approve must fail when the durable write fails")
	}
	// Get reads the in-memory index (no write); the revert restored it to pending.
	got, err := s.Get(a.ApprovalID, in.Tenant)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != StatusPending {
		t.Fatalf("a failed durable write must leave the live approval pending, got %v", got.Status)
	}
}

func TestLoad_LiveWithoutExpiryFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	a := &ToolApproval{
		SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
		FingerprintFormatVersion: 1, Purpose: PurposeLiveExecution, Status: StatusActive,
		RequestedBy: "op", RequestedAt: time.Unix(1000, 0),
		ApprovedBy: "adm", ApprovedAt: time.Unix(1001, 0),
		// ExpiresAt nil — a live record must ALWAYS carry an expiry; Load fails closed.
	}
	raw, _ := json.Marshal(persistedStore{SchemaVersion: SchemaVersion, Approvals: []*ToolApproval{a}})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewStore(Config{Path: path, Clock: clk.now})
	if err := s.Load(); err == nil {
		t.Fatal("a live_execution record without an expiry must fail closed")
	}
}

func TestLoad_ActiveLiveWithoutFourEyesFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	exp := time.Unix(2000, 0)
	a := &ToolApproval{
		SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
		FingerprintFormatVersion: 1, Purpose: PurposeLiveExecution, Status: StatusActive,
		RequestedBy: "same", RequestedAt: time.Unix(1000, 0),
		ApprovedBy: "same", ApprovedAt: time.Unix(1001, 0), // approver == requester — no four-eyes
		ExpiresAt: &exp,
	}
	raw, _ := json.Marshal(persistedStore{SchemaVersion: SchemaVersion, Approvals: []*ToolApproval{a}})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewStore(Config{Path: path, Clock: clk.now})
	if err := s.Load(); err == nil {
		t.Fatal("an active live_execution record without four-eyes evidence must fail closed")
	}
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

func TestLoad_TrailingDataFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	// Each of these is a valid envelope followed by trailing bytes that a naive
	// Decoder.More check misses (a trailing delimiter reads as "no more elements").
	for name, body := range map[string]string{
		"second_value":    `{"schema_version":1,"approvals":[]}{"evil":1}`,
		"closing_bracket": `{"schema_version":1,"approvals":[]}]`,
		"closing_brace":   `{"schema_version":1,"approvals":[]}}`,
		"garbage":         `{"schema_version":1,"approvals":[]} not json`,
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "approvals.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		s, _ := NewStore(Config{Path: path, Clock: clk.now})
		if err := s.Load(); err == nil {
			t.Fatalf("[%s] trailing data after the envelope must fail closed", name)
		}
	}
}

func TestLoad_ActiveWithoutApprovalEvidenceFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	// A record whose status was tampered to Active but carries NO approval evidence.
	a := &ToolApproval{
		SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
		FingerprintFormatVersion: 1, Purpose: PurposeShadowEvaluation, Status: StatusActive,
		RequestedBy: "op", RequestedAt: time.Unix(1000, 0),
		// ApprovedBy empty, ApprovedAt zero — must be rejected.
	}
	raw, _ := json.Marshal(persistedStore{SchemaVersion: SchemaVersion, Approvals: []*ToolApproval{a}})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewStore(Config{Path: path, Clock: clk.now})
	if err := s.Load(); err == nil {
		t.Fatal("an active record without recorded approval evidence must fail closed")
	}
}

func TestLoad_UnknownStatusFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	a := &ToolApproval{
		SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
		FingerprintFormatVersion: 1, Purpose: PurposeShadowEvaluation, Status: Status(99),
		RequestedBy: "op", RequestedAt: time.Unix(1000, 0),
	}
	raw, _ := json.Marshal(persistedStore{SchemaVersion: SchemaVersion, Approvals: []*ToolApproval{a}})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewStore(Config{Path: path, Clock: clk.now})
	if err := s.Load(); err == nil {
		t.Fatal("an unknown status must fail closed")
	}
}

func TestLoad_InvalidUTF8InStringFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")

	// Produce a genuinely VALID active record through the real request→approve flow, so the
	// only thing wrong with the persisted file below is the injected invalid UTF-8 byte.
	s, err := NewStore(Config{Path: path, Clock: clk.now})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	in := goodRequest()
	req, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if _, err := s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in)); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the untouched file loads cleanly (isolates the corruption as the sole cause).
	s2, _ := NewStore(Config{Path: path, Clock: clk.now})
	if err := s2.Load(); err != nil {
		t.Fatalf("the untouched persisted store must load: %v", err)
	}

	// Inject an invalid UTF-8 byte INSIDE a JSON string value (the Reason). encoding/json would
	// tolerate it by replacing it with U+FFFD, so without the raw-bytes UTF-8 guard the record
	// would decode and its per-field utf8.ValidString checks would pass — publishing the active
	// grant. The guard must reject it before decoding.
	idx := bytes.Index(raw, []byte(in.Reason))
	if idx < 0 {
		t.Fatal("could not locate the Reason string in the persisted file")
	}
	corrupt := append([]byte(nil), raw...)
	corrupt[idx] = 0xff // a lone 0xff is never valid UTF-8
	if utf8.Valid(corrupt) {
		t.Fatal("test setup error: corrupted bytes are still valid UTF-8")
	}
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}

	s3, _ := NewStore(Config{Path: path, Clock: clk.now})
	err = s3.Load()
	if err == nil {
		t.Fatal("invalid UTF-8 in the store file must fail closed, not load via U+FFFD replacement")
	}
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("expected the fail-closed reason to name invalid UTF-8, got: %v", err)
	}
}

func TestLoad_LoneSurrogateEscapeFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")

	// A genuinely valid active record, so the injected surrogate escape is the sole defect.
	s, err := NewStore(Config{Path: path, Clock: clk.now})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	in := goodRequest()
	req, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if _, err := s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in)); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the Reason string content with a lone HIGH-surrogate escape. The file stays pure
	// ASCII, so utf8.Valid remains true; encoding/json would decode \ud800 to U+FFFD, and the
	// per-field utf8.ValidString checks would then accept it — exactly the gap this guards.
	tampered := bytes.Replace(raw, []byte(in.Reason), []byte(`\ud800`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("test setup: could not locate the Reason string to tamper")
	}
	if !utf8.Valid(tampered) {
		t.Fatal("test setup: tampered bytes must still be valid UTF-8 (the escape is ASCII)")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	s2, _ := NewStore(Config{Path: path, Clock: clk.now})
	err = s2.Load()
	if err == nil {
		t.Fatal("a lone surrogate escape must fail closed, not decode via U+FFFD replacement")
	}
	if !strings.Contains(err.Error(), "surrogate") {
		t.Fatalf("expected the fail-closed reason to name the surrogate escape, got: %v", err)
	}
}

func TestHasUnpairedSurrogateEscape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"plain ascii", `{"reason":"hello"}`, false},
		{"valid pair (emoji)", `{"reason":"😀"}`, false},
		{"lone high", `{"reason":"\ud800"}`, true},
		{"lone low", `{"reason":"\udc00"}`, true},
		{"high then non-low", `{"reason":"\ud800A"}`, true},
		{"escaped backslash then literal uD800", `{"reason":"\\uD800"}`, false},
		{"bmp escape (letter A)", `{"reason":"A"}`, false},
		{"truncated escape", `{"reason":"\ud80`, false}, // malformed; left for the JSON decoder
	}
	for _, c := range cases {
		if got := hasUnpairedSurrogateEscape([]byte(c.in)); got != c.want {
			t.Errorf("%s: hasUnpairedSurrogateEscape(%q) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

func TestCreate_ExpiredPendingRequestsFreeCapacity(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	s, err := NewStore(Config{Path: filepath.Join(dir, "approvals.json"), Clock: clk.now, MaxRecords: 64, MaxPerTenant: 2})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	exp := clk.t.Add(time.Minute)
	for i := 0; i < 2; i++ {
		in := goodRequest()
		in.ToolName = "tool-" + string(rune('a'+i))
		in.ExpiresAt = &exp
		if _, err := s.CreateRequest(in); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	// At the per-tenant cap with two pending. Advance past their TTL: they must no longer
	// count against capacity, so a fresh request succeeds instead of failing forever.
	clk.t = exp.Add(time.Second)
	in := goodRequest()
	in.ToolName = "fresh"
	if _, err := s.CreateRequest(in); err != nil {
		t.Fatalf("abandoned expired pending requests must free capacity, got %v", err)
	}
}

func TestExpireDue_PersistFailureStillExcludesFromActive(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	exp := clk.t.Add(5 * time.Minute)
	in.ExpiresAt = &exp
	req, _ := s.CreateRequest(in)
	if _, err := s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Advance past expiry, then make the durable Expired transition fail.
	clk.t = exp.Add(time.Second)
	s.writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	if _, err := s.ExpireDue(clk.now()); err == nil {
		t.Fatal("ExpireDue must surface the persist failure")
	}
	// Even though the durable status could not flip to Expired, the grant is past its
	// expiry, so it is NOT active — the coordinator's re-derivation therefore demotes its
	// tool regardless of the persistence failure (the expiry invariant does not depend on
	// a successful write).
	if act := s.ActiveApprovals(clk.now()); len(act) != 0 {
		t.Fatalf("an expired grant must be excluded from ActiveApprovals even if the Expired persist failed, got %d", len(act))
	}
	// And it is still refused at approve (pastExpiry), never re-activated.
	if _, err := s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in)); mcperr.ReasonOf(err) != mcperr.ReasonApprovalExpired {
		t.Fatalf("expired grant must stay refused, got %v", mcperr.ReasonOf(err).Code())
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

// --- Codex round 5 regressions --------------------------------------------

// TestCreate_DoesNotPruneExpiredActiveGrant proves the round-5 P1: at the total cap, a
// past-expiry ACTIVE grant (which may still project catalog.Usable) is NOT chosen as the
// prune victim, because deleting its last ToolRef would strand the projection with no
// record for reconcile to demote. The create fails closed until a sweep converts the
// grant to Expired (genuinely terminal), after which it is prunable.
func TestCreate_DoesNotPruneExpiredActiveGrant(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	s, err := NewStore(Config{Path: filepath.Join(dir, "approvals.json"), Clock: clk.now, MaxRecords: 1, MaxPerTenant: 8})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	in := goodRequest()
	exp := clk.t.Add(time.Minute)
	in.ExpiresAt = &exp
	req, err := s.CreateRequest(in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Approve(req.ApprovalID, "admin@corp", matchingTarget(in)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Advance past expiry. The grant is now past-expiry ACTIVE and the store is at its
	// 1-record cap. A new request must NOT prune the expired-active grant (that would orphan
	// its Usable projection); it fails closed instead.
	clk.t = exp.Add(time.Second)
	fresh := goodRequest()
	fresh.ToolName = "fresh"
	if _, err := s.CreateRequest(fresh); err == nil {
		t.Fatal("must not prune a past-expiry ACTIVE grant to make room — expected capacity error")
	} else {
		mustReason(t, err, mcperr.ReasonAdminRangeExceeded)
	}
	// The expired-active grant is still present, so its ToolRef survives for the coordinator
	// to demote.
	if refs := s.ToolRefs(); len(refs) != 1 {
		t.Fatalf("the expired-active grant's ToolRef must survive for reconcile, got %d refs", len(refs))
	}
	// Sweep it to Expired (what the periodic reconcile does), then the slot is reclaimable.
	if _, err := s.ExpireDue(clk.now()); err != nil {
		t.Fatalf("ExpireDue: %v", err)
	}
	if _, err := s.CreateRequest(fresh); err != nil {
		t.Fatalf("after the sweep the now-Expired record must be prunable, got %v", err)
	}
}

// TestLoad_RejectedFlippedToActiveFailsClosed proves the round-5 P1: a rejection records
// its decider in its OWN fields (RejectedBy/RejectedAt), so a Rejected record whose status
// byte is flipped to Active — even one that also carries approval fields — is caught by the
// Active-lifecycle invariant that forbids terminal-decision evidence, instead of loading as
// a live grant.
func TestLoad_RejectedFlippedToActiveFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	when := time.Unix(1000, 0)
	cases := map[string]*ToolApproval{
		// Simple single-byte flip: rejection evidence present, no approval evidence.
		"flip_only": {
			SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
			FingerprintFormatVersion: 1, Purpose: PurposeShadowEvaluation, Status: StatusActive,
			RequestedBy: "op", RequestedAt: when,
			RejectedBy: "admin", RejectedAt: &when,
		},
		// Flip that also forges approval fields to satisfy the approval-evidence check: still
		// caught because the leftover rejection evidence is forbidden on an Active record.
		"flip_with_forged_approval": {
			SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
			FingerprintFormatVersion: 1, Purpose: PurposeShadowEvaluation, Status: StatusActive,
			RequestedBy: "op", RequestedAt: when,
			ApprovedBy: "admin", ApprovedAt: when,
			RejectedBy: "admin", RejectedAt: &when,
		},
	}
	for name, a := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, "approvals.json")
		raw, _ := json.Marshal(persistedStore{SchemaVersion: SchemaVersion, Approvals: []*ToolApproval{a}})
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		s, _ := NewStore(Config{Path: path, Clock: clk.now})
		if err := s.Load(); err == nil {
			t.Fatalf("[%s] a rejected record flipped to Active must fail closed", name)
		}
	}
}

// TestLoad_RejectedRequiresOwnEvidence proves a Rejected record must carry its own
// RejectedBy/RejectedAt, and that a genuine rejection round-trips through reload.
func TestLoad_RejectedRequiresOwnEvidence(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	when := time.Unix(1000, 0)
	// Missing rejection evidence → fail closed.
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	missing := &ToolApproval{
		SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
		FingerprintFormatVersion: 1, Purpose: PurposeShadowEvaluation, Status: StatusRejected,
		RequestedBy: "op", RequestedAt: when,
	}
	raw, _ := json.Marshal(persistedStore{SchemaVersion: SchemaVersion, Approvals: []*ToolApproval{missing}})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewStore(Config{Path: path, Clock: clk.now})
	if err := s.Load(); err == nil {
		t.Fatal("a rejected record without its own rejection evidence must fail closed")
	}
}

// TestReject_PersistsDistinctEvidenceAndSurvivesReload proves Reject records RejectedBy/
// RejectedAt (not ApprovedBy/ApprovedAt) and the terminal state survives a reload.
func TestReject_PersistsDistinctEvidenceAndSurvivesReload(t *testing.T) {
	clk := &fakeClock{t: time.Unix(2000, 0)}
	s := newTestStore(t, clk)
	req, err := s.CreateRequest(goodRequest())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Reject(req.ApprovalID, "admin@corp", "not this build"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	got, err := s.Get(req.ApprovalID, "tenant-a")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != StatusRejected {
		t.Fatalf("status = %v, want rejected", got.Status)
	}
	if got.RejectedBy != "admin@corp" || got.RejectedAt == nil {
		t.Fatalf("rejection must record its own decider fields, got by=%q at=%v", got.RejectedBy, got.RejectedAt)
	}
	if got.ApprovedBy != "" || !got.ApprovedAt.IsZero() {
		t.Fatalf("a rejection must NOT write approval evidence, got by=%q at=%v", got.ApprovedBy, got.ApprovedAt)
	}
	// Reload the durable file: the rejected record must survive validation.
	s2, _ := NewStore(Config{Path: s.path, Clock: clk.now, MaxRecords: 64, MaxPerTenant: 8})
	if err := s2.Load(); err != nil {
		t.Fatalf("a legitimately-rejected record must reload cleanly, got %v", err)
	}
}

// TestLoad_OverRecordCountFailsClosed proves the round-5 P2: a file with more records than
// the configured MaxRecords fails closed rather than publishing an over-capacity index.
func TestLoad_OverRecordCountFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	var recs []*ToolApproval
	for i := 0; i < 3; i++ {
		recs = append(recs, &ToolApproval{
			SchemaVersion: SchemaVersion, ApprovalID: "id-" + string(rune('a'+i)),
			Tenant: "t", ServerID: "s", ToolName: "n", FingerprintFormatVersion: 1,
			Purpose: PurposeShadowEvaluation, Status: StatusPending, RequestedBy: "op",
			RequestedAt: time.Unix(1000, 0),
		})
	}
	raw, _ := json.Marshal(persistedStore{SchemaVersion: SchemaVersion, Approvals: recs})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewStore(Config{Path: path, Clock: clk.now, MaxRecords: 2, MaxPerTenant: 8})
	if err := s.Load(); err == nil {
		t.Fatal("a store file exceeding MaxRecords must fail closed")
	}
}

// TestLoad_OverPerTenantFailsClosed proves the per-tenant non-terminal bound is enforced at
// recovery (a restore from a larger-cap store cannot exceed this store's per-tenant cap).
func TestLoad_OverPerTenantFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	var recs []*ToolApproval
	for i := 0; i < 3; i++ {
		recs = append(recs, &ToolApproval{
			SchemaVersion: SchemaVersion, ApprovalID: "id-" + string(rune('a'+i)),
			Tenant: "t", ServerID: "s", ToolName: "n", FingerprintFormatVersion: 1,
			Purpose: PurposeShadowEvaluation, Status: StatusPending, RequestedBy: "op",
			RequestedAt: time.Unix(1000, 0),
		})
	}
	raw, _ := json.Marshal(persistedStore{SchemaVersion: SchemaVersion, Approvals: recs})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewStore(Config{Path: path, Clock: clk.now, MaxRecords: 64, MaxPerTenant: 2})
	if err := s.Load(); err == nil {
		t.Fatal("a store file exceeding MaxPerTenant non-terminal records must fail closed")
	}
}

// TestLoad_OversizeFileFailsClosed proves the recovery read is byte-bounded: a file larger
// than the size a within-cap store could occupy fails closed before it is fully decoded,
// closing the startup-OOM vector.
func TestLoad_OversizeFileFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	// MaxRecords=1 → readLimit = 1*maxRecordJSONBytes + storeEnvelopeSlackBytes. Write more.
	limit := 1*maxRecordJSONBytes + storeEnvelopeSlackBytes
	big := make([]byte, limit+1024)
	for i := range big {
		big[i] = ' '
	}
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewStore(Config{Path: path, Clock: clk.now, MaxRecords: 1, MaxPerTenant: 8})
	if err := s.Load(); err == nil {
		t.Fatal("an oversized store file must fail closed before full decode")
	}
}

// TestLoad_WorstCaseEscapedRecordRoundTrips proves the round-6 P2: a lifecycle-valid record
// whose bounded string fields are packed with control characters (each expanding to a six-byte
// unicode JSON escape) serializes past the naive 8 KiB estimate the read cap replaced, and the
// worst-case-derived cap still accepts the store own persisted file (no self-rejection).
func TestLoad_WorstCaseEscapedRecordRoundTrips(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	when := time.Unix(1000, 0)
	ctrl := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = 0x01 // a control byte json.Marshal expands each into a six-byte unicode escape
		}
		return string(b)
	}
	// A lifecycle-valid Revoked record with every bounded string field at max length, filled
	// with control characters (the JSON worst case).
	rec := &ToolApproval{
		SchemaVersion: SchemaVersion, ApprovalID: "id", Tenant: "t", ServerID: "s", ToolName: "n",
		FingerprintFormatVersion: 1, Purpose: PurposeShadowEvaluation, Status: StatusRevoked,
		RequestedBy: ctrl(maxActorBytes), RequestedAt: when,
		ApprovedBy: ctrl(maxActorBytes), ApprovedAt: when,
		Reason: ctrl(maxReasonBytes), TicketRef: ctrl(maxTicketBytes),
		RevokedBy: ctrl(maxActorBytes), RevokedAt: &when, RevocationReason: ctrl(maxReasonBytes),
	}
	if one, _ := json.Marshal(rec); len(one) <= 8192 {
		t.Fatalf("a worst-case-escaped record must exceed the old 8192 estimate (got %d) for this test to be meaningful", len(one))
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	raw, _ := json.Marshal(persistedStore{SchemaVersion: SchemaVersion, Approvals: []*ToolApproval{rec}})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewStore(Config{Path: path, Clock: clk.now, MaxRecords: 1, MaxPerTenant: 8})
	if err := s.Load(); err != nil {
		t.Fatalf("the store own worst-case-escaped record must reload, got %v", err)
	}
}

// TestCreate_TenantBoundMatchesInventoryOwnerScope proves the round-7 P2: the tenant byte
// bound is >= the catalog's authoritative MaxOwnerScopeBytes (512), so a valid inventory
// tenant at that maximum is approvable instead of failing CreateRequest validation.
func TestCreate_TenantBoundMatchesInventoryOwnerScope(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	in := goodRequest()
	in.Tenant = strings.Repeat("a", 512) // the inventory owner-scope maximum
	if _, err := s.CreateRequest(in); err != nil {
		t.Fatalf("a 512-byte tenant (the inventory owner-scope max) must be accepted, got %v", err)
	}
	over := goodRequest()
	over.ToolName = "other"
	over.Tenant = strings.Repeat("a", 513)
	if _, err := s.CreateRequest(over); err == nil {
		t.Fatal("a tenant over the byte bound must still be rejected")
	}
}

// TestPersistFailure_ClassifiedAsStoreUnavailable proves the round-8 P2: a durable-write
// failure (full/read-only disk) is classified as the retryable ReasonApprovalStoreUnavailable
// (→ HTTP 503), never ReasonConfigInvalid (→ 400), so a client is not told its valid input is
// permanently invalid.
func TestPersistFailure_ClassifiedAsStoreUnavailable(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	s.writeFile = func(string, []byte, os.FileMode) error { return errors.New("no space left on device") }
	_, err := s.CreateRequest(goodRequest())
	mustReason(t, err, mcperr.ReasonApprovalStoreUnavailable)
}

// TestList_ReturnsNewestFirstWithinLimit proves the round-10 P2: List returns the NEWEST
// records first, so truncating to a limit surfaces recent (incl. brand-new pending) requests
// instead of hiding them behind the oldest ones (the endpoint has no cursor/offset).
func TestList_ReturnsNewestFirstWithinLimit(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	s := newTestStore(t, clk)
	var ids []string
	for i := 0; i < 3; i++ {
		in := goodRequest()
		in.ToolName = "tool-" + string(rune('a'+i))
		req, err := s.CreateRequest(in)
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		ids = append(ids, req.ApprovalID)
		clk.t = clk.t.Add(time.Minute) // each request is newer than the previous
	}
	// ids[2] is the newest. A limit of 2 must return the two NEWEST and exclude the oldest.
	got := s.List("tenant-a", 2)
	if len(got) != 2 {
		t.Fatalf("want 2 results, got %d", len(got))
	}
	if got[0].ApprovalID != ids[2] {
		t.Fatalf("newest-first: got[0] = %s, want newest %s", got[0].ApprovalID, ids[2])
	}
	for _, a := range got {
		if a.ApprovalID == ids[0] {
			t.Fatal("the OLDEST record must be excluded when the limit truncates, not the newest")
		}
	}
}

// TestLoad_PendingWithDecisionEvidenceFailsClosed proves the round-12 P2: a pending record
// that carries terminal (rejection/revocation) or approval evidence — e.g. a rejected record
// whose status byte was corrupted to pending — is rejected at Load. Otherwise a normal approve
// would launder it into an Active record still carrying that evidence, which the Active
// lifecycle check then rejects on the next restart (bricking tool trust).
func TestLoad_PendingWithDecisionEvidenceFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	when := time.Unix(1000, 0)
	cases := map[string]*ToolApproval{
		"rejection_evidence": {
			SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
			FingerprintFormatVersion: 1, Purpose: PurposeShadowEvaluation, Status: StatusPending,
			RequestedBy: "op", RequestedAt: when, RejectedBy: "admin", RejectedAt: &when,
		},
		"revocation_evidence": {
			SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
			FingerprintFormatVersion: 1, Purpose: PurposeShadowEvaluation, Status: StatusPending,
			RequestedBy: "op", RequestedAt: when, RevokedBy: "admin", RevokedAt: &when,
		},
		"approval_evidence": {
			SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
			FingerprintFormatVersion: 1, Purpose: PurposeShadowEvaluation, Status: StatusPending,
			RequestedBy: "op", RequestedAt: when, ApprovedBy: "admin", ApprovedAt: when,
		},
	}
	for name, a := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, "approvals.json")
		raw, _ := json.Marshal(persistedStore{SchemaVersion: SchemaVersion, Approvals: []*ToolApproval{a}})
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		s, _ := NewStore(Config{Path: path, Clock: clk.now})
		if err := s.Load(); err == nil {
			t.Fatalf("[%s] a pending record carrying decision evidence must fail closed", name)
		}
	}
	// A clean pending record (no decision fields) still loads.
	clean := &ToolApproval{
		SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
		FingerprintFormatVersion: 1, Purpose: PurposeShadowEvaluation, Status: StatusPending,
		RequestedBy: "op", RequestedAt: when,
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	raw, _ := json.Marshal(persistedStore{SchemaVersion: SchemaVersion, Approvals: []*ToolApproval{clean}})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewStore(Config{Path: path, Clock: clk.now})
	if err := s.Load(); err != nil {
		t.Fatalf("a clean pending record must load, got %v", err)
	}
}

// TestLoad_ReasonOnlyTerminalEvidenceFailsClosed proves the round-13 P2: the pending/active
// evidence checks include the terminal REASON fields (RejectedReason/RevocationReason), so a
// corrupt record carrying only a reason — with no decider actor/timestamp — is still rejected,
// on both the pending and the active path.
func TestLoad_ReasonOnlyTerminalEvidenceFailsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	when := time.Unix(1000, 0)
	cases := map[string]*ToolApproval{
		"pending_rejected_reason": {
			SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
			FingerprintFormatVersion: 1, Purpose: PurposeShadowEvaluation, Status: StatusPending,
			RequestedBy: "op", RequestedAt: when, RejectedReason: "denied",
		},
		"pending_revocation_reason": {
			SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
			FingerprintFormatVersion: 1, Purpose: PurposeShadowEvaluation, Status: StatusPending,
			RequestedBy: "op", RequestedAt: when, RevocationReason: "rotated",
		},
		"active_rejected_reason": {
			SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
			FingerprintFormatVersion: 1, Purpose: PurposeShadowEvaluation, Status: StatusActive,
			RequestedBy: "op", RequestedAt: when, ApprovedBy: "admin", ApprovedAt: when, RejectedReason: "denied",
		},
		"active_revocation_reason": {
			SchemaVersion: SchemaVersion, ApprovalID: "a", Tenant: "t", ServerID: "s", ToolName: "n",
			FingerprintFormatVersion: 1, Purpose: PurposeShadowEvaluation, Status: StatusActive,
			RequestedBy: "op", RequestedAt: when, ApprovedBy: "admin", ApprovedAt: when, RevocationReason: "rotated",
		},
	}
	for name, a := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, "approvals.json")
		raw, _ := json.Marshal(persistedStore{SchemaVersion: SchemaVersion, Approvals: []*ToolApproval{a}})
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		s, _ := NewStore(Config{Path: path, Clock: clk.now})
		if err := s.Load(); err == nil {
			t.Fatalf("[%s] a record carrying a terminal reason without a decider must fail closed", name)
		}
	}
}
