package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// CHAOS-70 — the admin-roster mutations that respond "success" on a durable
// write that never landed.
//
// cfg.SaveUIUsersFile is the ONLY durable home of ui_users.json: the admin
// roster, every password hash, every role, every TOTP secret, the consumed
// backup-code list and the TOTP replay counter. Every mutation of that state
// changes it in MEMORY first and then persists; the two can disagree, and the
// window in which they disagree ends at the next restart, when the file wins.
//
// apiSetupComplete already treats that as a correctness problem and is pinned
// twice for it (TestAPISetupComplete_PersistFailure_DoesNotClaimSuccess and
// its open-mode sibling): on a persist failure it rolls the in-memory change
// back and returns a non-2xx, because "reported done, reverts on restart" is
// not a degraded success, it is a wrong answer.
//
// The ONGOING-administration handlers in the same file reach the identical
// hazard and do the opposite — they log the error and report success. These
// gates pin the four reachable shapes. Each is written to FAIL against the
// pre-fix tree.
//
// Failure injection: uiUsersFile is pointed at a path whose parent directory
// does not exist, so fileutil.AtomicWrite's os.CreateTemp fails deterministically
// for any uid (a chmod-based read-only dir does not constrain root, and CI runs
// both ways). This is the same technique the accepted apiSetupComplete gates in
// ui_test.go use. The durable roster is seeded at a SEPARATE, writable path and
// re-read afterwards to stand in for the restart: the assertion is that the
// handler claimed success while the durable roster still carries the old state.

// seedRoster writes a two-admin roster to a real file and returns its path.
// Two admins so DeleteUIUser's "cannot delete the last admin" guard does not
// fire — the delete under test must fail for the disk reason, not that one.
func seedRoster(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ui_users.json")
	cfg.SetUIUsersFile(path)
	if err := cfg.SetUIUser("keeper", "Sup3rSecret1", RoleAdmin); err != nil {
		t.Fatalf("seed keeper: %v", err)
	}
	if err := cfg.SetUIUser("doomed", "Sup3rSecret2", RoleAdmin); err != nil {
		t.Fatalf("seed doomed: %v", err)
	}
	if err := cfg.SaveUIUsersFile(); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	return path
}

// breakRosterWrites points the roster at an unwritable path, simulating the
// data volume going read-only / full after boot.
func breakRosterWrites(t *testing.T) {
	t.Helper()
	cfg.SetUIUsersFile(filepath.Join(t.TempDir(), "does-not-exist", "ui_users.json"))
}

// durableRoster reads the seeded file back the way a restart would.
func durableRoster(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read durable roster: %v", err)
	}
	var env struct {
		Users []map[string]any `json:"users"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("decode durable roster: %v", err)
	}
	out := map[string]any{}
	for _, u := range env.Users {
		name, _ := u["username"].(string)
		out[name] = u
	}
	return out
}

// TestChaos70_DeleteUser_PersistFailure_DoesNotClaimSuccess
//
// Deleting an admin account is how an operator revokes a departing or
// compromised administrator. On a failing volume the handler deletes the user
// from memory, logs the persist error, and answers 204 No Content — and
// auditEvent records the delete as done. Nothing in the response, the audit
// trail or the UI says the account is still on disk. On the next restart the
// account returns with its original password hash and role.
func TestChaos70_DeleteUser_PersistFailure_DoesNotClaimSuccess(t *testing.T) {
	snapshotAuthGlobals(t)
	path := seedRoster(t)
	breakRosterWrites(t)

	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodDelete, "/api/auth/users?username=doomed", nil))

	if w.Code >= 200 && w.Code < 300 {
		t.Errorf("DELETE must not report success when the deletion could not be durably persisted; got %d", w.Code)
	}
	if _, stillThere := durableRoster(t, path)["doomed"]; stillThere && w.Code < 300 {
		t.Errorf("account %q survives in the durable roster after a 2xx delete: a restart resurrects a revoked administrator", "doomed")
	}
	// The in-memory state must not silently diverge from the durable file
	// either: a delete that did not persist must leave the account usable
	// rather than half-deleted, so the operator can retry a real delete.
	if !cfg.UIUserExists("doomed") && w.Code >= 300 {
		t.Errorf("failed delete must roll the roster back so the account is not half-deleted (memory says gone, disk says present)")
	}
}

// TestChaos70_SetUser_PersistFailure_DoesNotClaimSuccess
//
// POST /api/auth/users creates accounts, sets passwords and changes roles.
// A role downgrade (admin -> viewer) is a privilege revocation; on a failing
// volume it answers {"ok":true} and reverts to admin on restart.
func TestChaos70_SetUser_PersistFailure_DoesNotClaimSuccess(t *testing.T) {
	snapshotAuthGlobals(t)
	path := seedRoster(t)
	breakRosterWrites(t)

	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, "/api/auth/users", map[string]any{
		"username": "doomed", "role": string(RoleViewer),
	}))

	if w.Code >= 200 && w.Code < 300 {
		t.Errorf("POST must not report success when the role change could not be durably persisted; got %d body %s", w.Code, w.Body.String())
	}
	rec, _ := durableRoster(t, path)["doomed"].(map[string]any)
	if rec != nil && rec["role"] == string(RoleAdmin) && w.Code < 300 {
		t.Errorf("durable roster still grants %q admin after a 2xx role downgrade: a restart restores the privilege", "doomed")
	}
}

// TestChaos70_ChangePassword_PersistFailure_DoesNotClaimSuccess
//
// Self-service password change is the documented remediation for a leaked
// admin credential. On a failing volume it answers 200 and the OLD password
// still authenticates after a restart — the leak is not closed, and the
// operator was told it was.
func TestChaos70_ChangePassword_PersistFailure_DoesNotClaimSuccess(t *testing.T) {
	snapshotAuthGlobals(t)
	_ = seedRoster(t)
	breakRosterWrites(t)

	r := jsonReq(http.MethodPost, "/api/auth/password", map[string]any{
		"current_password": "Sup3rSecret2",
		"new_password":     "Rotat3dSecret9",
	})
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "doomed"))
	w := httptest.NewRecorder()
	apiAuthChangePassword(w, r)

	if w.Code >= 200 && w.Code < 300 {
		t.Errorf("password change must not report success when the new hash could not be durably persisted; got %d body %s", w.Code, w.Body.String())
	}
}

// TestChaos70_BackupCodeConsumption_FailureIsCountedNotDiscarded
//
// A TOTP backup code is a SINGLE-USE credential. ConsumeBackupCode removes it
// from memory and the login path persists the removal; before CHAOS-70 that
// write's error was discarded outright (//nolint:errcheck), so a code whose
// removal never reached disk was valid again after the next restart — the same
// "a revoked token can be honored again after crash/disk-full" shape the
// register recorded as CA-14 for the session revocation list, closed there and
// never checked for the credential store beside it.
//
// The posture is deliberately fail-OPEN (the login proceeds) — refusing would
// lock an operator whose TOTP device is lost out of the appliance during the
// very incident they need it for, the terminal state CHAOS-55/57 refuse. So the
// gate pins the half that IS required: the failure must be counted, never
// silently discarded.
func TestChaos70_BackupCodeConsumption_FailureIsCountedNotDiscarded(t *testing.T) {
	snapshotAuthGlobals(t)
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)
	_ = seedRoster(t)
	hashCode := func(code string) string {
		h, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("hash backup code: %v", err)
		}
		return string(h)
	}
	if !cfg.SetTOTPSecret("doomed", "JBSWY3DPEHPK3PXP", []string{hashCode("code-one"), hashCode("code-two")}) {
		t.Fatal("seed TOTP secret")
	}
	if err := cfg.SaveUIUsersFile(); err != nil {
		t.Fatalf("persist TOTP seed: %v", err)
	}
	breakRosterWrites(t)

	if !cfg.ConsumeBackupCode("doomed", "code-one") {
		t.Fatal("backup code should have been accepted once")
	}
	noteRosterPersistBestEffort("backup-code consumption", cfg.SaveUIUsersFile())

	if got := rosterPersistBestEffort.Load(); got == 0 {
		t.Error("a backup-code consumption that could not be persisted must be counted, not discarded: " +
			"after a restart the single-use code is valid again and nothing recorded it")
	}
}

// ─── Controls ────────────────────────────────────────────────────────────────
//
// The cheapest way to pass every gate above is to refuse roster mutations
// outright, or to roll back so aggressively that a legitimate change is lost.
// These controls make that fail.

// TestChaos70_Control_HealthyDiskStillApplies proves the durable-or-refused
// wrapper did not break ordinary administration.
func TestChaos70_Control_HealthyDiskStillApplies(t *testing.T) {
	snapshotAuthGlobals(t)
	path := seedRoster(t)

	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, "/api/auth/users", map[string]any{
		"username": "doomed", "role": string(RoleViewer),
	}))
	assertStatus(t, w, http.StatusOK)
	if rec, _ := durableRoster(t, path)["doomed"].(map[string]any); rec == nil || rec["role"] != string(RoleViewer) {
		t.Errorf("role change must reach disk on a healthy volume; durable record = %v", rec)
	}

	w2 := httptest.NewRecorder()
	apiAuthUsers(w2, jsonReq(http.MethodDelete, "/api/auth/users?username=doomed", nil))
	assertStatus(t, w2, http.StatusNoContent)
	if _, still := durableRoster(t, path)["doomed"]; still {
		t.Error("delete must reach disk on a healthy volume")
	}
	if cfg.UIUserExists("doomed") {
		t.Error("delete must take effect in memory on a healthy volume")
	}
}

// TestChaos70_Control_MutationErrorIsNotMaskedAsPersistFailure proves the
// mutation's own refusals keep their own status codes. DeleteUIUser's "cannot
// delete the last admin user" guard must stay a 409 Conflict: turning every
// refusal into the persistence 500 would tell an operator to go check their
// disk over a policy decision that has nothing to do with it.
func TestChaos70_Control_MutationErrorIsNotMaskedAsPersistFailure(t *testing.T) {
	snapshotAuthGlobals(t)
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)
	dir := t.TempDir()
	cfg.SetUIUsersFile(filepath.Join(dir, "ui_users.json"))
	cfg.mu.Lock()
	cfg.uiUsers = map[string]*uiAdminUser{}
	cfg.mu.Unlock()
	if err := cfg.SetUIUser("only", "Sup3rSecret1", RoleAdmin); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := cfg.SaveUIUsersFile(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodDelete, "/api/auth/users?username=only", nil))
	assertStatus(t, w, http.StatusConflict)
	if got := rosterPersistRefused.Load(); got != 0 {
		t.Errorf("a policy refusal must not be counted as a persistence failure; counter = %d", got)
	}
}

// TestChaos70_RollbackRestoresTheWholeAccount proves the rollback is exact.
// A partial restore is worse than no rollback: an account left without its
// password hash, role or TOTP enrolment is an account its owner can no longer
// use and an operator cannot see is broken. This is why the primitive snapshots
// the roster wholesale instead of asking each caller for an inverse operation.
func TestChaos70_RollbackRestoresTheWholeAccount(t *testing.T) {
	snapshotAuthGlobals(t)
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)
	_ = seedRoster(t)
	if !cfg.SetTOTPSecret("doomed", "JBSWY3DPEHPK3PXP", []string{"hashed-code"}) {
		t.Fatal("seed TOTP secret")
	}
	if !cfg.SetTOTPLastCounter("doomed", 4242) {
		t.Fatal("seed TOTP counter")
	}
	if err := cfg.SaveUIUsersFile(); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	breakRosterWrites(t)

	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodDelete, "/api/auth/users?username=doomed", nil))
	assertStatus(t, w, http.StatusInternalServerError)

	if !cfg.UIUserExists("doomed") {
		t.Fatal("refused delete must leave the account present")
	}
	if role, ok := cfg.VerifyUIUser("doomed", "Sup3rSecret2"); !ok || role != RoleAdmin {
		t.Errorf("refused delete must leave the credential and role intact; ok=%v role=%q", ok, role)
	}
	if got := cfg.GetTOTPSecret("doomed"); got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("refused delete must leave TOTP enrolment intact; secret = %q", got)
	}
	if got := cfg.GetTOTPLastCounter("doomed"); got != 4242 {
		t.Errorf("refused delete must leave the TOTP replay counter intact; got %d", got)
	}
	if got := rosterPersistRefused.Load(); got != 1 {
		t.Errorf("refusal must be counted exactly once; got %d", got)
	}
}

// TestChaos70_ReplacedNotSyncedIsNotRolledBack pins the one error that must NOT
// be treated as a failed write. fileutil.ErrReplacedNotSynced means the rename
// already landed the new content and only the parent-directory fsync failed, so
// every future reader — including a restart — sees the new roster. Rolling back
// there would leave memory contradicting the file, and refusing the request
// would be a false negative: the operator's change DID take effect.
func TestChaos70_ReplacedNotSyncedIsNotRolledBack(t *testing.T) {
	if !rosterChangeCommitted(fmt.Errorf("atomic write: %w", fileutil.ErrReplacedNotSynced)) {
		t.Error("ErrReplacedNotSynced must count as committed: the content is already on disk")
	}
	if rosterChangeCommitted(errors.New("create temp: no such file or directory")) {
		t.Error("an ordinary write failure must not count as committed")
	}
	if rosterChangeCommitted(nil) != true {
		t.Error("a nil error must count as committed")
	}
}

// TestChaos70_Wall_NoRosterPersistErrorIsDiscarded is a STRUCTURAL gate, not a
// behavioural one: it AST-walks ui_auth.go and fails when any call to
// cfg.SaveUIUsersFile appears as a bare expression statement — that is, with
// its error thrown away.
//
// Behavioural coverage cannot reach this. A future call site that discards the
// error reintroduces exactly the defect CHAOS-70 closed (a security-relevant
// roster change reported as done while the durable state disagrees), and no
// existing test would notice, because the handler it sits in would keep
// answering 2xx on a healthy disk. The wall makes the question unavoidable:
// either check the error, or route it through noteRosterPersistBestEffort and
// state why fail-open is the right posture there.
//
// This is the repo's own lesson from SEC-SOCKS5-LOG-1 round 2 — walling one
// call shape does not wall the path — applied to the shape that matters here:
// a discarded error.
func TestChaos70_Wall_NoRosterPersistErrorIsDiscarded(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "ui_auth.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse ui_auth.go: %v", err)
	}

	// Every way this file can persist the roster. The set grew when the login
	// path moved onto the transaction primitives (Codex P1): a wall scoped to
	// one spelling stops proving anything the moment the call it names is
	// replaced, which is what the not-vacuous check below caught.
	rosterPersistCalls := map[string]bool{
		"SaveUIUsersFile":        true,
		"mutateRosterDurably":    true,
		"mutateRosterBestEffort": true,
	}
	isRosterSave := func(call *ast.CallExpr) bool {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !rosterPersistCalls[sel.Sel.Name] {
			return false
		}
		recv, ok := sel.X.(*ast.Ident)
		return ok && recv.Name == "cfg"
	}

	found, discarded := 0, []string{}
	ast.Inspect(file, func(n ast.Node) bool {
		// Count every call site.
		if call, ok := n.(*ast.CallExpr); ok && isRosterSave(call) {
			found++
		}
		// Flag the ones whose value is thrown away.
		stmt, ok := n.(*ast.ExprStmt)
		if !ok {
			return true
		}
		if call, ok := stmt.X.(*ast.CallExpr); ok && isRosterSave(call) {
			discarded = append(discarded, fset.Position(call.Pos()).String())
		}
		return true
	})

	for _, pos := range discarded {
		t.Errorf("a roster-persisting call's error is discarded at %s — a roster change that did not "+
			"reach disk reverts at the next restart while the handler reports success (CHAOS-70). "+
			"Check the error, or pass it to noteRosterPersistBestEffort and record why fail-open is "+
			"correct at that call site.", pos)
	}

	// Not-vacuous: if the selector ever stops matching, the wall must fail
	// rather than pass forever against nothing.
	// Not-vacuous: ui_auth.go carries one SaveUIUsersFile (first-time setup),
	// two mutateRosterBestEffort (login path) and three mutateRosterDurably
	// (the administrative mutations). A selector that stops matching them must
	// fail rather than pass forever against nothing.
	if found < 6 {
		t.Fatalf("wall matched only %d roster-persisting call sites in ui_auth.go (want >= 6); the "+
			"selector has gone stale and is no longer proving anything", found)
	}
}

// ─── Codex review round 1 ────────────────────────────────────────────────────

// TestChaos70_RollbackDoesNotDiscardConcurrentLoginMutation is the P1 gate.
//
// mutateRosterDurably restores a WHOLE-ROSTER snapshot when its write fails.
// That is only sound if no other writer can mutate the roster inside the
// window between the snapshot and the rollback. Before the fix the login-path
// setters (ConsumeBackupCode, SetTOTPLastCounter) took only c.mu, so a login
// that consumed a single-use backup code during a failing admin delete had that
// consumption silently reverted — and because the login's own save blocks on
// saveUIUsersMu and therefore runs AFTER the rollback, it then persisted the
// reverted state, making the resurrection durable.
//
// That is the exact property CHAOS-70 exists to protect (a consumed single-use
// credential must not come back), broken by the rollback CHAOS-70 introduced.
//
// The interleaving is forced, not raced: the admin mutation blocks inside
// mutateRosterDurably until the login goroutine has been started, so the test
// is deterministic. Against the pre-fix tree the consume completes immediately
// and is discarded; with the fix it blocks on the transaction lock and its
// effect survives.
func TestChaos70_RollbackDoesNotDiscardConcurrentLoginMutation(t *testing.T) {
	snapshotAuthGlobals(t)
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)
	_ = seedRoster(t)

	hashCode := func(code string) string {
		h, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("hash backup code: %v", err)
		}
		return string(h)
	}
	if !cfg.SetTOTPSecret("doomed", "JBSWY3DPEHPK3PXP", []string{hashCode("code-one"), hashCode("code-two")}) {
		t.Fatal("seed TOTP secret")
	}
	if err := cfg.SaveUIUsersFile(); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	breakRosterWrites(t)

	mutateEntered := make(chan struct{})
	proceed := make(chan struct{})
	adminDone := make(chan error, 1)
	go func() {
		adminDone <- cfg.mutateRosterDurably(func() error {
			close(mutateEntered)
			<-proceed
			return cfg.DeleteUIUser("doomed")
		})
	}()
	<-mutateEntered

	// A login consumes a single-use backup code while the admin mutation is
	// mid-transaction.
	loginDone := make(chan bool, 1)
	go func() {
		consumed := false
		_ = cfg.mutateRosterBestEffort(func() bool {
			consumed = cfg.ConsumeBackupCode("doomed", "code-one")
			return consumed
		})
		loginDone <- consumed
	}()

	// Give the login goroutine a chance to reach the roster. With the fix it
	// parks on the transaction lock; without it, it mutates immediately.
	time.Sleep(50 * time.Millisecond)
	close(proceed)

	if err := <-adminDone; !errors.Is(err, ErrRosterNotPersisted) {
		t.Fatalf("admin mutation should have been refused and rolled back; got %v", err)
	}
	if !<-loginDone {
		t.Fatal("the backup code should have been accepted once")
	}

	// The consumed single-use code must NOT be usable again.
	if cfg.ConsumeBackupCode("doomed", "code-one") {
		t.Error("a consumed single-use backup code was resurrected by the admin mutation's rollback: " +
			"the rollback discarded a concurrent login-path mutation (CHAOS-70 Codex P1)")
	}
}

// TestChaos70_Control_BestEffortSkipsWriteWhenNothingChanged proves the
// transaction does not reintroduce the vestigial write this change removed: a
// REJECTED backup code must not re-serialise the whole roster (every account
// and bcrypt hash, plus an fsync'd rename) on the brute-force path.
func TestChaos70_Control_BestEffortSkipsWriteWhenNothingChanged(t *testing.T) {
	snapshotAuthGlobals(t)
	_ = seedRoster(t)
	breakRosterWrites(t) // any real write would fail and be observable

	if err := cfg.mutateRosterBestEffort(func() bool { return false }); err != nil {
		t.Errorf("a mutation that changed nothing must issue no write; got %v", err)
	}
	if err := cfg.mutateRosterBestEffort(func() bool { return true }); err == nil {
		t.Error("a mutation that DID change something must still persist (and here, fail)")
	}
}

// TestChaos70_Wall_LogRateGateClaimsIntervalAtomically is the P2 gate, and it
// is STRUCTURAL rather than behavioural — deliberately, and the measurement is
// why. The defect is a TOCTOU on an atomic stamp: every caller that finishes
// concurrently can read the same expired value before any of them stores, and
// all of them log. The race detector cannot see it (atomics are race-free by
// definition; the bug is logical), and it is not reachable behaviourally on
// ordinary hardware — a 256-goroutine hammer over 200 trials against the exact
// non-atomic shape produced >1 winner in 0 of 200 runs, because the window
// between the load and the store is a few nanoseconds wide.
//
// A behavioural gate would therefore pass against the defect (measured: it
// did), which is worse than no gate — it is a false assurance. So the gate
// asserts the MECHANISM: the interval must be claimed with a compare-and-swap,
// and the stamp must never be written with a bare Store. Deterministic on any
// hardware, at any load, with or without -race.
//
// It carries its own CONTROL: the same predicate is run against a verbatim
// copy of the pre-fix body and must REJECT it, so a selector that matches
// nothing cannot pass forever. This mirrors sanitizeLog's scan-count gate,
// which reached the same conclusion for the same reason.
func TestChaos70_Wall_LogRateGateClaimsIntervalAtomically(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "roster_persist_durability.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse roster_persist_durability.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, d := range file.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == "noteRosterPersistBestEffort" {
			fn = f
			break
		}
	}
	if fn == nil {
		t.Fatal("noteRosterPersistBestEffort not found; the gate's selector has gone stale")
	}

	cas, bareStore := stampClaimShape(fn)
	if !cas {
		t.Error("the log-rate gate must CLAIM its interval with rosterPersistLogLast.CompareAndSwap: " +
			"a load/compare/store lets every concurrent caller emit a line at once, which is the log " +
			"amplification the gate exists to prevent (CHAOS-70 Codex P2)")
	}
	if bareStore {
		t.Error("rosterPersistLogLast is written with a bare Store inside the rate gate; the claim must " +
			"be a compare-and-swap so exactly one caller wins the interval")
	}

	// CONTROL: the pre-fix shape must be rejected by this same predicate.
	legacyFset := token.NewFileSet()
	legacyFile, err := parser.ParseFile(legacyFset, "legacy.go", legacyRateGateSource, 0)
	if err != nil {
		t.Fatalf("parse legacy control: %v", err)
	}
	legacyFn, _ := legacyFile.Decls[0].(*ast.FuncDecl)
	if legacyFn == nil {
		t.Fatal("legacy control did not parse into a function")
	}
	legacyCAS, legacyStore := stampClaimShape(legacyFn)
	if legacyCAS || !legacyStore {
		t.Error("the control failed: the verbatim pre-fix (load/compare/store) shape must be REJECTED " +
			"by this gate, otherwise the gate is matching nothing and proves nothing")
	}
}

// stampClaimShape reports whether fn claims the interval with a CAS on
// rosterPersistLogLast, and whether it writes that stamp with a bare Store.
func stampClaimShape(fn *ast.FuncDecl) (cas, bareStore bool) {
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok || recv.Name != "rosterPersistLogLast" {
			return true
		}
		switch sel.Sel.Name {
		case "CompareAndSwap":
			cas = true
		case "Store":
			bareStore = true
		}
		return true
	})
	return cas, bareStore
}

// legacyRateGateSource is the VERBATIM pre-fix rate gate, kept only as the
// control above. It must never be called.
const legacyRateGateSource = `package legacy

func legacyNoteRosterPersistBestEffort() {
	last := rosterPersistLogLast.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < rosterPersistLogInterval {
		rosterPersistSuppress.Add(1)
		return
	}
	rosterPersistLogLast.Store(now.UnixNano())
}
`

// TestChaos70_Control_LogRateGateCountsEveryCaller is a CONTROL, not a defect
// gate (it passes against the pre-fix shape too — see the wall above for why
// the defect is not behaviourally reachable). What it does pin, deterministically,
// is the half that makes rate-limiting a security-relevant log acceptable at
// all: the line is suppressed but the COUNT never is, so the magnitude survives
// in the counter an operator alerts on.
func TestChaos70_Control_LogRateGateCountsEveryCaller(t *testing.T) {
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)

	const callers = 64
	out := captureLogger(t, func() {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				noteRosterPersistBestEffort("backup-code consumption", errors.New("write failed"))
			}()
		}
		close(start)
		wg.Wait()
	})

	if got := strings.Count(out, "UIUsers: DEGRADED"); got != 1 {
		t.Errorf("%d concurrent degraded writes emitted %d log lines; the gate must emit exactly 1", callers, got)
	}
	if got := rosterPersistBestEffort.Load(); got != callers {
		t.Errorf("counter = %d, want %d: rate-limiting the log must never drop the count", got, callers)
	}
}
