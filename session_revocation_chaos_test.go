package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// CHAOS-68 root gates — the Control Plane's place in the revocation plane, and
// the visibility of a revocation that is not durable.
//
// The defect gates were verified failing against their reintroduced pre-fix
// shapes.

func withChaos68Revocations(t *testing.T) {
	t.Helper()
	restore := sessionRevoked.SwapForTest()
	resetSessionRevocationHealthForTest()
	prevPath := session.RevocationsPath()
	t.Cleanup(func() {
		restore()
		session.SetRevocationsPath(prevPath)
		resetSessionRevocationHealthForTest()
	})
}

func withChaos68Aggregator(t *testing.T) {
	t.Helper()
	globalRevAggregator.mu.Lock()
	prevPerNode, prevLocal := globalRevAggregator.perNode, globalRevAggregator.cpLocal
	globalRevAggregator.perNode = map[string][]RevocationEntry{}
	globalRevAggregator.cpLocal = nil
	globalRevAggregator.mu.Unlock()
	t.Cleanup(func() {
		globalRevAggregator.mu.Lock()
		globalRevAggregator.perNode, globalRevAggregator.cpLocal = prevPerNode, prevLocal
		globalRevAggregator.mu.Unlock()
	})
}

// DEFECT. The aggregator had exactly one writer — a Data Plane push — so the
// Control Plane, which is the node the admin UI runs on, contributed nothing
// to the fleet-wide merge. An admin revoking a session on the CP revoked it on
// the CP alone.
func TestChaos68_ControlPlaneOwnRevocationsReachTheFleet(t *testing.T) {
	withChaos68Aggregator(t)

	cpLocal := []RevocationEntry{
		{Token: "cp-logout-token", Expiry: time.Now().Add(time.Hour).Unix()},
		{Token: "user:deleted-admin", User: "deleted-admin", Expiry: time.Now().Add(time.Hour).Unix()},
	}
	globalRevAggregator.UpdateLocal(cpLocal)
	globalRevAggregator.Update("dp-1", nil)

	merged := globalRevAggregator.MergedExcluding("dp-1")
	var sawToken, sawUser bool
	for _, e := range merged {
		if e.Token == "cp-logout-token" {
			sawToken = true
		}
		if e.User == "deleted-admin" {
			sawUser = true
		}
	}
	if !sawToken {
		t.Error("a logout performed on the Control Plane never reaches a Data Plane")
	}
	if !sawUser {
		t.Error("an account deleted on the Control Plane never reaches a Data Plane")
	}
}

// STRUCTURAL. The CP's slot must not be addressable as a node id, or an
// enrolled node could overwrite it — or be excluded from its own merge.
func TestChaos68_CPSlotIsNotAddressableByANodeID(t *testing.T) {
	withChaos68Aggregator(t)

	globalRevAggregator.UpdateLocal([]RevocationEntry{
		{Token: "cp-entry", Expiry: time.Now().Add(time.Hour).Unix()},
	})
	// A node may be named anything at all; none of it may displace the CP slot.
	for _, hostile := range []string{"", "cpLocal", "__culvert_control_plane_local__", "cp"} {
		globalRevAggregator.Update(hostile, []RevocationEntry{
			{Token: "hostile", Expiry: time.Now().Add(time.Hour).Unix()},
		})
		var sawCP bool
		for _, e := range globalRevAggregator.MergedExcluding(hostile) {
			if e.Token == "cp-entry" {
				sawCP = true
			}
		}
		if !sawCP {
			t.Fatalf("a node named %q displaced or excluded the Control Plane's own revocations", hostile)
		}
	}
}

// CONTROL. The requesting node must still not be sent its own entries back —
// the CP contribution must not defeat the exclusion the merge exists for.
func TestChaos68_RequesterStillExcludedFromItsOwnEntries(t *testing.T) {
	withChaos68Aggregator(t)

	globalRevAggregator.Update("dp-1", []RevocationEntry{
		{Token: "dp1-token", Expiry: time.Now().Add(time.Hour).Unix()},
	})
	globalRevAggregator.Update("dp-2", []RevocationEntry{
		{Token: "dp2-token", Expiry: time.Now().Add(time.Hour).Unix()},
	})

	for _, e := range globalRevAggregator.MergedExcluding("dp-1") {
		if e.Token == "dp1-token" {
			t.Fatal("a node was sent its own revocation entries back")
		}
	}
}

// Expired entries in the CP's own slot must not ride the merge forever.
func TestChaos68_ExpiredCPEntriesAreNotMerged(t *testing.T) {
	withChaos68Aggregator(t)

	globalRevAggregator.UpdateLocal([]RevocationEntry{
		{Token: "stale-cp", Expiry: time.Now().Add(-time.Hour).Unix()},
	})
	for _, e := range globalRevAggregator.MergedExcluding("dp-1") {
		if e.Token == "stale-cp" {
			t.Fatal("an expired Control-Plane revocation was merged into the fleet view")
		}
	}
}

// DEFECT. An account deletion must leave a DURABLE revocation. Before this,
// apiAuthUsers' DELETE branch revoked in memory only, so the next restart
// resurrected the deleted account's live sessions for the rest of their TTL.
func TestChaos68_AccountDeletionRevocationIsDurable(t *testing.T) {
	withChaos68Revocations(t)
	path := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(path)

	// The exact pair the DELETE branch performs.
	sessionRevoked.RevokeUser("departing-admin")
	if err := sessionRevoked.SaveRevocations(); err != nil {
		t.Fatalf("save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the account deletion wrote no revocations file: %v", err)
	}
	if !strings.Contains(string(data), "departing-admin") {
		t.Errorf("the deleted account is not in the persisted revocation list: %s", data)
	}
}

// DEFECT. A revocation that could not be written down must be countable and
// must turn the operator-contract row to fail — the admin action reports
// success either way, so this row is the only thing that disagrees with them.
func TestChaos68_PersistFailureIsVisibleToTheOperator(t *testing.T) {
	withChaos68Revocations(t)

	if got := checkSessionRevocation(); got.Status == diagFail {
		t.Fatalf("row already failing before the fault: %+v", got)
	}
	noteRevocationPersistFailure(os.ErrPermission)

	row := checkSessionRevocation()
	if row.Status != diagFail {
		t.Errorf("status = %q, want %q — a non-durable revocation must not read as healthy", row.Status, diagFail)
	}
	if row.OperatorAction == "" {
		t.Error("the row names no operator action")
	}
	if revocationsAreDurable() {
		t.Error("revocationsAreDurable() is true after an observed persist failure")
	}
}

// DEFECT. The DEFAULT posture — no revocations file configured — must be
// stated, not silent. It is the shipped posture, and combined with a stable
// signing key (which every clustered deployment sets) it means a cookie
// outlives the restart that discards its revocation.
func TestChaos68_UnconfiguredPersistenceIsReported(t *testing.T) {
	withChaos68Revocations(t)
	session.SetRevocationsPath("")

	row := checkSessionRevocation()
	if row.Status != diagWarn {
		t.Errorf("status = %q, want %q for an unconfigured revocations file", row.Status, diagWarn)
	}
	if !strings.Contains(row.OperatorAction, "-revocations-file") {
		t.Errorf("the row does not name the remedy: %q", row.OperatorAction)
	}
	if revocationsAreDurable() {
		t.Error("revocationsAreDurable() is true with no persistence configured")
	}
}

// A failed LOAD means revocations the operator already applied are not in
// force on this node, which must not read as healthy either.
func TestChaos68_DegradedLoadIsReported(t *testing.T) {
	withChaos68Revocations(t)
	noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
	noteRevocationLoadDegraded(session.ErrRevocationsCorrupt)

	if row := checkSessionRevocation(); row.Status != diagFail {
		t.Errorf("status = %q, want %q after a failed load", row.Status, diagFail)
	}
	if revocationsAreDurable() {
		t.Error("revocationsAreDurable() is true after a degraded load")
	}
}

// An UNREADABLE file is deliberately not quarantined, so its recovery action
// must not point at a readiness row or a .corrupt.* copy that do not exist —
// while a CORRUPT file's action still must.
func TestChaos68_LoadFailureActionMatchesTheFault(t *testing.T) {
	withChaos68Revocations(t)
	noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
	noteRevocationLoadDegraded(fmt.Errorf("read revocations: %w", os.ErrPermission))
	row := checkSessionRevocation()
	if row.Status != diagFail {
		t.Fatalf("status = %q, want %q after an unreadable load", row.Status, diagFail)
	}
	if strings.Contains(row.OperatorAction, ".corrupt.") || strings.Contains(row.OperatorAction, "state_file_session_revocations") {
		t.Errorf("unreadable-file action points at quarantine artifacts that do not exist: %q", row.OperatorAction)
	}
	if !strings.Contains(row.OperatorAction, "permission") {
		t.Errorf("unreadable-file action = %q, want it to name the permission/mount fix", row.OperatorAction)
	}

	withChaos68Revocations(t)
	noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
	noteRevocationLoadDegraded(session.ErrRevocationsCorrupt)
	if row := checkSessionRevocation(); !strings.Contains(row.OperatorAction, ".corrupt.") {
		t.Errorf("corrupt-file action = %q, want it to name the quarantined copy", row.OperatorAction)
	}
}

// CONTROL. A healthy, configured node must read OK — a row that always fails
// is worth nothing, and would train an operator to ignore it.
func TestChaos68_HealthyNodeReadsOK(t *testing.T) {
	withChaos68Revocations(t)
	noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))

	row := checkSessionRevocation()
	if row.Status != diagOK {
		t.Errorf("status = %q, want %q on a healthy configured node (%s)", row.Status, diagOK, row.Message)
	}
	if !revocationsAreDurable() {
		t.Error("revocationsAreDurable() is false on a healthy configured node")
	}
}

// The row is a viewer-reachable surface, so it must carry counts and a remedy
// but never the revoked usernames themselves.
func TestChaos68_ContractRowDoesNotLeakRevokedIdentities(t *testing.T) {
	withChaos68Revocations(t)
	sessionRevoked.RevokeUser("secret-person")
	sessionRevoked.Revoke("secret-token-payload", time.Now().Add(time.Hour))

	for _, row := range []OperatorContractCheck{checkSessionRevocation()} {
		blob := row.Message + " " + row.OperatorAction
		if strings.Contains(blob, "secret-person") || strings.Contains(blob, "secret-token-payload") {
			t.Errorf("the contract row discloses a revoked identity: %q", blob)
		}
	}
}

// The row must be registered in the operator contract, or none of the above
// reaches an operator.
func TestChaos68_ContractRowIsRegistered(t *testing.T) {
	oc := buildOperatorContract()
	for i := range oc.Checks {
		if oc.Checks[i].Code == "session_revocation" {
			return
		}
	}
	t.Fatal("session_revocation is not in the operator contract")
}

// STRUCTURAL WALL. The aggregator gates above prove the PRIMITIVE carries the
// Control Plane's revocations; this proves the handler actually calls it.
//
// Behavioural coverage cannot reach SyncRevocations without an mTLS peer
// context, an enrolled node and an unfenced HA lease, so the wiring is pinned
// by shape instead — the same instrument, and the same reason, as
// TestSOCKS5_EveryDestinationSinkIsAudited. Both directions are required: a
// Control Plane that contributes but does not consume still fails to enforce a
// logout performed on a Data Plane.
func TestChaos68_SyncRevocationsWiresBothDirections(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "controlplane_server.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var body *ast.FuncDecl
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "SyncRevocations" {
			body = fn
			break
		}
	}
	if body == nil {
		t.Fatal("SyncRevocations not found in controlplane_server.go")
	}

	want := map[string]bool{
		"UpdateLocal":       false, // contribute: the CP's own list enters the merge
		"MergeRevocations":  false, // consume: a DP's revocations are enforced on the CP
		"ExportRevocations": false, // the contribution is the LIVE list, not a stale copy
	}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if name := chaos68CalleeName(call); name != "" {
			if _, tracked := want[name]; tracked {
				want[name] = true
			}
		}
		return true
	})
	for name, found := range want {
		if !found {
			t.Errorf("SyncRevocations does not call %s — the Control Plane is isolated from the revocation plane in at least one direction", name)
		}
	}
}

// The session_revocation row is viewer-reachable through /api/diagnostics,
// which is walled against echoing secret names and raw filesystem paths
// (TestApiDiagnostics_NoSensitiveValues). That wall only fires when this row
// happens to be in its warn branch, so whether it catches a regression depends
// on test ORDER — the first draft of this row named both a /data/ path and the
// session-secret environment variable and passed the unshuffled suite.
//
// This gate drives every branch of the row deterministically and applies the
// same forbidden list, so the order dependence cannot hide a leak here again.
func TestChaos68_ContractRowNeverEchoesSensitiveTokens(t *testing.T) {
	forbidden := []string{"sessionSecret", "CULVERT_SESSION_SECRET", "-----BEGIN", "/data/"}

	// Each branch declares the status it must reach. Without that a setup that
	// silently lands in a DIFFERENT branch would still pass the leak check, and
	// the wall's claim to drive every branch would be false while green — the
	// vacuous-gate failure mode this sweep keeps pinning against.
	branches := []struct {
		name  string
		want  string
		setup func(t *testing.T)
	}{
		{"unconfigured", diagWarn, func(*testing.T) {}},
		{"healthy", diagOK, func(t *testing.T) {
			noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
		}},
		{"load-degraded-corrupt", diagFail, func(t *testing.T) {
			noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
			noteRevocationLoadDegraded(session.ErrRevocationsCorrupt)
		}},
		// AU-36. The read-failure branch is a SECOND composition of this row,
		// and a wall that drives only its sibling would not see a leak here —
		// the branch-coverage lesson this wall exists for, one branch deeper.
		{"load-degraded-unreadable", diagFail, func(t *testing.T) {
			noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
			noteRevocationLoadDegraded(fmt.Errorf("open: %w", os.ErrPermission))
		}},
		{"persist-failed", diagFail, func(t *testing.T) {
			noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
			noteRevocationPersistFailure(os.ErrPermission)
		}},
		// AU-35. The row names a mount and a deletion, which is the branch most
		// likely to reach for a raw path when someone rewords it.
		{"vanished-file", diagFail, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "revocations.json")
			session.SetRevocationsPath(path)
			noteRevocationPersistenceConfigured(path)
		}},
	}

	for _, b := range branches {
		t.Run(b.name, func(t *testing.T) {
			withChaos68Revocations(t)
			b.setup(t)
			row := checkSessionRevocation()
			if row.Status != b.want {
				t.Fatalf("setup reached status %q, want %q — this sub-case is no longer driving the %s branch", row.Status, b.want, b.name)
			}
			blob := row.Code + " " + row.Message + " " + row.OperatorAction
			for _, needle := range forbidden {
				if strings.Contains(blob, needle) {
					t.Errorf("the %s branch leaks %q on a viewer-reachable surface: %q", b.name, needle, blob)
				}
			}
			if row.Message == "" {
				t.Error("branch produced an empty message")
			}
		})
	}
}

// DEFECT (Codex P2). The diagnostics row and the durable gauge must recover
// when the volume is repaired. Keyed on the cumulative counter they never did,
// and this file's own comment claimed the opposite — the ca_health.go mistake,
// reproduced in the change that cites ca_health.go as its model.
func TestChaos68_DurabilityRecoversWhenWritesSucceedAgain(t *testing.T) {
	withChaos68Revocations(t)
	noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))

	noteRevocationPersistFailure(os.ErrPermission)
	if revocationsAreDurable() {
		t.Fatal("durable while writes are failing")
	}
	if checkSessionRevocation().Status != diagFail {
		t.Fatal("row is not failing while writes are failing")
	}

	// The operator repairs the volume and a save lands.
	noteRevocationPersistSuccess()

	if !revocationsAreDurable() {
		t.Error("revocationsAreDurable() is still false after a successful write — the row latches until process restart")
	}
	if row := checkSessionRevocation(); row.Status != diagOK {
		t.Errorf("status = %q, want %q after recovery (%s)", row.Status, diagOK, row.Message)
	}
	// The incident stays visible as magnitude, on /metrics, not as a stuck row.
	if got := sessionRevocationPersistFailures.Load(); got != 1 {
		t.Errorf("cumulative failures = %d, want 1 — recovery must not erase the incident's magnitude", got)
	}
}

// A failure AFTER a recovery must degrade again — the flag is state, not a
// one-shot latch in either direction.
func TestChaos68_DurabilityDegradesAgainAfterRecovery(t *testing.T) {
	withChaos68Revocations(t)
	noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))

	noteRevocationPersistFailure(os.ErrPermission)
	noteRevocationPersistSuccess()
	noteRevocationPersistFailure(os.ErrPermission)

	if revocationsAreDurable() {
		t.Error("a second write failure did not re-degrade the durability signal")
	}
	if got := sessionRevocationPersistFailures.Load(); got != 2 {
		t.Errorf("cumulative failures = %d, want 2", got)
	}
}

// DEFECT (Codex P1). The HA standby verifies the SAME cookies as the leader —
// the bundle replicates SessionHMAC — while SyncRevocations, the only other
// carrier of revocations, is fenced on a standby. Without revocations in the
// bundle, a session revoked on the leader authenticated against the standby and
// survived a promotion with full authority.
func TestChaos68_HABundleCarriesRevocationsToTheStandby(t *testing.T) {
	leader := session.NewRevocationList()
	leader.Revoke("leader-logout", time.Now().Add(time.Hour))
	leader.RevokeUser("fired-admin")

	bundle := HAStateBundle{Revocations: leader.ExportRevocations()}

	// Round-trip the wire form: the standby decodes JSON, not a Go value.
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got HAStateBundle
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	standby := session.NewRevocationList()
	standby.MergeRevocations(got.Revocations)

	if !standby.IsRevoked("leader-logout") {
		t.Error("a logout performed on the leader does not reach the standby")
	}
	if !standby.IsUserRevoked("fired-admin") {
		t.Error("an account deleted on the leader does not reach the standby — after promotion its sessions authenticate again")
	}
}

// The bundle must stay byte-identical when there is nothing to replicate, so a
// standby predating this field is unaffected.
func TestChaos68_HABundleOmitsEmptyRevocations(t *testing.T) {
	raw, err := json.Marshal(HAStateBundle{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "revocations") {
		t.Errorf("an empty revocation set is on the wire: %s", raw)
	}
}

// STRUCTURAL WALL. The bundle carrying the field is worth nothing unless the
// leader fills it and the standby applies it. applyHABundle and the HASync
// handler both need live HA state to drive behaviourally, so the wiring is
// pinned by shape — the same instrument as SyncRevocationsWiresBothDirections.
func TestChaos68_HAWiresRevocationsInBothDirections(t *testing.T) {
	for _, tc := range []struct{ file, fn, call string }{
		{"controlplane_server.go", "HASync", "ExportRevocations"},
		{"ha.go", "applyHABundle", "MergeRevocations"},
	} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, tc.file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", tc.file, err)
		}
		var target *ast.FuncDecl
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Name.Name == tc.fn {
				target = fn
				break
			}
		}
		if target == nil {
			t.Errorf("%s not found in %s", tc.fn, tc.file)
			continue
		}
		var found bool
		ast.Inspect(target, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if chaos68CalleeName(call) == tc.call {
					found = true
				}
			}
			return true
		})
		if !found {
			t.Errorf("%s does not call %s — the HA standby is isolated from the revocation plane in that direction", tc.fn, tc.call)
		}
	}
}

// DEFECT (CI-only, found by the determinism and -race gates on PR #1437).
// The session_revocation row is the sweep's only diagFail-capable row, and both
// states that produce it are PROCESS-GLOBALS that LATCH: the persist-failure
// flag clears only on an observed successful write, and the load-degraded flag
// never clears (it is a boot fact).
//
// In production that is correct. In the test binary it is cross-talk: any test
// whose SaveRevocations fails — an unwritable dataDir, a revocations path left
// pointing at a removed temp dir — latches the record for the rest of the run,
// and from then on the aggregate /api/diagnostics verdict is "fail". Every
// later test asserting `Verdict != diagFail` then fails, in an order-dependent
// way that only shows up under -shuffle/-count=2.
//
// resetDiagVerdictGlobals exists to enumerate exactly these globals, and
// CHAOS-45, CHAOS-47 and CHAOS-57 each had to register theirs when they added a
// diagFail-capable row. This sweep added one and did not — the same "a second
// thing was added beside an existing one and the existing machinery was never
// taught about it" shape §38.8 names.
func TestChaos68_RevocationHealthIsIsolatedFromTheAggregateVerdict(t *testing.T) {
	// Dirty the record the way a failing-volume test does, WITHOUT the
	// per-test isolation helper — this is the cross-talk, not a tidy test.
	noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
	noteRevocationPersistFailure(os.ErrPermission)
	if checkSessionRevocation().Status != diagFail {
		t.Fatal("precondition: a persist failure must make the row fail")
	}

	// A later diagnostics test declares its isolation the canonical way.
	t.Run("verdict-asserting test after the cross-talk", func(t *testing.T) {
		resetDiagVerdictGlobals(t)
		if got := checkSessionRevocation().Status; got == diagFail {
			t.Errorf("session_revocation is still %q after resetDiagVerdictGlobals — "+
				"the latched record leaks into every later aggregate-verdict assertion", got)
		}
		if c := buildOperatorContract(); c.Verdict == diagFail {
			t.Errorf("aggregate verdict = %q; an earlier test's revocation-write failure "+
				"must not fail an unrelated test's diagnostics report", c.Verdict)
		}
	})

	// And the helper must restore, not merely clear: this outer test's own
	// record is its business, and a helper that leaked the OTHER way would
	// silently disarm the production signal for the rest of the binary.
	t.Cleanup(resetSessionRevocationHealthForTest)
}

// DEFECT (Codex P2, PR #1437) — a docs defect with a behavioural root, so it is
// pinned behaviourally rather than by grepping the runbook.
//
// The runbook's first draft told operators to PAGE on
// `culvert_session_revocation_durable == 0`, describing it as "writes are
// failing RIGHT NOW". That gauge is derived from revocationsAreDurable(), which
// is deliberately false when persistence is simply UNCONFIGURED — the shipped
// default, and the posture most appliances are in. So the suggested page would
// have fired permanently on every default installation, for a node with a
// perfectly healthy disk and zero write failures, while metrics.go's own comment
// called the same expression a warn.
//
// This gate pins the fact the documentation has to reflect: the gauge is
// two-valued over three causes, so `durable == 0` alone cannot distinguish the
// default posture from an active fault. The page therefore keys on the
// current write-degraded state (culvert_session_revocation_persist_degraded),
// and that is what the runbook and metrics.go now both say.
func TestChaos68_DurableZeroDoesNotImplyAWriteFailure(t *testing.T) {
	withChaos68Revocations(t)

	// The shipped default: no revocations file configured, nothing wrong.
	if revocationsAreDurable() {
		t.Fatal("precondition: an unconfigured node must not report durable")
	}
	if got := sessionRevocationPersistFailures.Load(); got != 0 {
		t.Fatalf("precondition: a healthy default node must have 0 persist failures, got %d", got)
	}

	// So an alert keyed on the gauge ALONE fires here — on a healthy appliance.
	// That is the whole finding: the expression is true, and nothing is wrong.
	if sessionRevocationPersistDegraded.Load() {
		t.Error("an unconfigured node must not be reported as write-degraded — " +
			"conflating the two is what made the bare gauge look pageable")
	}

	// The conjunction the runbook and metrics.go now document does NOT fire
	// here, which is the property that makes it safe to page on.
	pageWouldFire := sessionRevocationPersistDegraded.Load()
	if pageWouldFire {
		t.Error("the documented page fires on a healthy default appliance")
	}

	// And it DOES fire once a write actually fails, so the conjunction has not
	// been tightened into something that never pages.
	noteRevocationPersistFailure(os.ErrPermission)
	pageFiresOnRealFailure := sessionRevocationPersistDegraded.Load()
	if !pageFiresOnRealFailure {
		t.Error("the documented page does not fire when writes are actually failing")
	}
}

// scrapeSessionRevocationPersistDegraded returns the value of
// culvert_session_revocation_persist_degraded on /metrics, or -1 if absent.
func scrapeSessionRevocationPersistDegraded(t *testing.T) int {
	t.Helper()
	prevTok := metricsToken
	metricsToken = ""
	t.Cleanup(func() { metricsToken = prevTok })
	w := httptest.NewRecorder()
	handleMetrics(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	for _, line := range strings.Split(w.Body.String(), "\n") {
		if v, ok := strings.CutPrefix(line, "culvert_session_revocation_persist_degraded "); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				t.Fatalf("unparseable persist_degraded value %q", v)
			}
			return n
		}
	}
	return -1
}

// DEFECT (Codex P2, PR #1437, second round). The runbook's page was
// `durable == 0 and increase(persist_failures_total[15m]) > 0`. After ONE
// failed save with no further logout/sync to trigger another write, the
// degradation is still in force (durable stays 0) but increase() over the
// window drops to 0 after 15 minutes — so the page cleared while durability
// had NOT recovered. The page must be driven by CURRENT write state that only
// a landed save clears; this pins that the series exists, is 0 on a healthy
// default node, latches on a failure with no further writes, and clears only
// on a successful save.
func TestChaos68_WriteDegradedPageLatchesUntilASaveLands(t *testing.T) {
	withChaos68Revocations(t)

	if got := scrapeSessionRevocationPersistDegraded(t); got != 0 {
		t.Fatalf("culvert_session_revocation_persist_degraded = %d on a healthy default node; want 0 "+
			"(-1 means the series is missing, so there is nothing current-state to page on)", got)
	}
	noteRevocationPersistFailure(os.ErrPermission)
	// No further write happens — the increase()-window shape would clear here
	// once the window passes. The state-based series must not.
	for i := 0; i < 3; i++ {
		if got := scrapeSessionRevocationPersistDegraded(t); got != 1 {
			t.Fatalf("scrape %d after an unresolved save failure: persist_degraded = %d; want 1", i, got)
		}
	}
	noteRevocationPersistSuccess()
	if got := scrapeSessionRevocationPersistDegraded(t); got != 0 {
		t.Fatalf("persist_degraded = %d after a save landed; want 0", got)
	}
}

// chaos68UnwritablePath returns a path whose PARENT is a regular file, so every
// write fails with ENOTDIR. Deliberately not a permission bit: root bypasses
// DAC, so a mode-based fault would make this gate skip on the CI runner — which
// is exactly where a durability regression must not go unnoticed.
func chaos68UnwritablePath(t *testing.T) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	return filepath.Join(blocker, "revocations.json")
}

// DEFECT GATE (Codex P1, PR #1437 — AU-34). All three cluster merge sites used
// to persist only inside `if added > 0`. MergeRevocations returns 0 once the
// entry is already in memory, so ONE transient failure was permanent: every
// later sync carried the same entry, added nothing, and never retried. The
// revocation stayed in RAM, never reached disk, and a restart resurrected the
// session it was meant to withdraw.
//
// Verified failing against the pre-fix shape (`if added > 0 { save }`): the
// repaired path was never written and the entry was lost.
func TestChaos68_FailedSaveIsRetriedOnALaterSyncThatAddsNothing(t *testing.T) {
	withChaos68Revocations(t)

	bad := chaos68UnwritablePath(t)
	session.SetRevocationsPath(bad)
	noteRevocationPersistenceConfigured(bad)

	exp := time.Now().Add(time.Hour)
	entries := []RevocationEntry{{Token: "tok-must-become-durable", Expiry: exp.Unix()}}

	// First sync: the entry merges, the save fails.
	if added := mergeAndPersistRevocations(entries, "test"); added != 1 {
		t.Fatalf("first merge added %d, want 1", added)
	}
	if revocationsAreDurable() {
		t.Fatal("reported durable while the write was failing")
	}

	// The operator repairs the volume.
	good := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(good)

	// A LATER sync carries the SAME entry, so the merge adds nothing.
	if added := mergeAndPersistRevocations(entries, "test"); added != 0 {
		t.Fatalf("second merge added %d, want 0 — the entry is already in memory", added)
	}

	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatalf("the repaired path was never written, so the revocation is still not durable: %v", err)
	}
	if !strings.Contains(string(raw), "tok-must-become-durable") {
		t.Errorf("persisted document does not carry the revocation: %s", raw)
	}
	if !revocationsAreDurable() {
		t.Error("still reported non-durable after a save that landed")
	}
}

// CONTROL. The cheapest way to pass the gate above is to save on EVERY merge
// call. The standby syncs every 5s and the DP loop every 3s, so that would
// rewrite the whole list continuously on every node in the fleet, forever —
// trading a durability defect for a write-amplification one.
func TestChaos68_HealthyNodeDoesNotRewriteOnEverySync(t *testing.T) {
	withChaos68Revocations(t)
	path := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(path)
	noteRevocationPersistenceConfigured(path)

	exp := time.Now().Add(time.Hour)
	entries := []RevocationEntry{{Token: "tok-a", Expiry: exp.Unix()}}
	if added := mergeAndPersistRevocations(entries, "test"); added != 1 {
		t.Fatalf("first merge added %d, want 1", added)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("first merge did not persist: %v", err)
	}

	// Scribble a sentinel over the file so a later write is observable, then
	// re-sync the SAME entries on a healthy node. Nothing new, nothing
	// degraded, nothing to do — the sentinel must survive.
	//
	// The instrument used to be os.Remove, and AU-35 turned that into a
	// measurement error: a missing file is now itself a reason to rewrite, so
	// the control was creating the very condition it meant to rule out and
	// could no longer tell "a healthy node wrote" from "a node repaired a file
	// this test deleted". A sentinel leaves the file PRESENT — the actual
	// healthy state — and is replaced only by a real write, which is the one
	// thing being asked about.
	sentinel := []byte(`["do-not-rewrite-me"]`)
	if err := os.WriteFile(path, sentinel, 0o600); err != nil {
		t.Fatalf("seed sentinel: %v", err)
	}
	for i := 0; i < 3; i++ {
		if added := mergeAndPersistRevocations(entries, "test"); added != 0 {
			t.Fatalf("re-merge added %d, want 0", added)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, sentinel) {
		t.Errorf("a healthy node rewrote the revocations file on a sync that changed nothing: %s", got)
	}
}

// CONTROL. While a volume is broken the retry runs on every sync, so the
// failure line must be keyed on the TRANSITION rather than the attempt — at a
// 3-5s cadence a per-attempt line is hundreds an hour, and a mitigation for a
// durability defect must not become a write-amplification one. The magnitude
// stays in the counter.
func TestChaos68_RetryLogsOncePerEpisodeNotPerAttempt(t *testing.T) {
	withChaos68Revocations(t)
	bad := chaos68UnwritablePath(t)
	session.SetRevocationsPath(bad)
	noteRevocationPersistenceConfigured(bad)

	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	exp := time.Now().Add(time.Hour)
	entries := []RevocationEntry{{Token: "tok-noisy", Expiry: exp.Unix()}}
	for i := 0; i < 8; i++ {
		mergeAndPersistRevocations(entries, "test")
	}

	if n := strings.Count(buf.String(), "failed to persist merged revocations"); n != 1 {
		t.Errorf("emitted %d failure lines across 8 syncs, want exactly 1 (onset only): %s", n, buf.String())
	}
	if got := sessionRevocationPersistFailures.Load(); got < 8 {
		t.Errorf("cumulative failures = %d, want >= 8 — the counter must carry the magnitude the log suppresses", got)
	}
}

// CONTROL. Recovery is announced once, so an operator watching the log can see
// the episode close without tailing metrics.
func TestChaos68_RetrySuccessAnnouncesRecoveryOnce(t *testing.T) {
	withChaos68Revocations(t)
	bad := chaos68UnwritablePath(t)
	session.SetRevocationsPath(bad)
	noteRevocationPersistenceConfigured(bad)

	exp := time.Now().Add(time.Hour)
	entries := []RevocationEntry{{Token: "tok-recover", Expiry: exp.Unix()}}
	mergeAndPersistRevocations(entries, "test")

	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	session.SetRevocationsPath(filepath.Join(t.TempDir(), "revocations.json"))
	for i := 0; i < 3; i++ {
		mergeAndPersistRevocations(entries, "test")
	}

	if n := strings.Count(buf.String(), "durable again"); n != 1 {
		t.Errorf("emitted %d recovery lines, want exactly 1: %s", n, buf.String())
	}
}

// STRUCTURAL WALL. The reviewer found this on the HA standby, but all three
// cluster merge sites carried the identical shape — and the CP handler is not
// behaviourally reachable from a test (it needs an mTLS peer, an enrolled node
// and an unfenced HA lease, which is why SyncRevocationsWiresBothDirections is
// a wall too). Requiring every site to route through the one primitive is what
// stops a fourth merge site reintroducing the gap silently.
func TestChaos68_EveryRevocationMergeSiteRetriesThroughThePrimitive(t *testing.T) {
	// Anchored to pkgSourceDir(), never the CWD: a concurrent os.Chdir in
	// another test would otherwise make this wall flake (static_read_wall_test.go).
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	found := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		n := strings.Count(string(src), "sessionRevoked.MergeRevocations(")
		if n == 0 {
			continue
		}
		found += n
		if name != "session_revocation_health.go" {
			t.Errorf("%s calls sessionRevoked.MergeRevocations directly (%d time(s)) — route it through mergeAndPersistRevocations, or a failed save there is never retried (AU-34)", name, n)
		}
	}
	if found != 1 {
		t.Errorf("found %d direct MergeRevocations call(s) in package main, want exactly 1 (the primitive) — the selector is stale, so this wall is not guarding anything", found)
	}
}

// chaos68CalleeName returns the called function's name whether it is spelled as
// a method (sessionRevoked.MergeRevocations) or a plain function
// (mergeAndPersistRevocations), and folds the retry primitive onto the
// requirement it satisfies.
//
// The two "wires both directions" walls below scan for a literal
// MergeRevocations call. AU-34 moved every cluster merge site behind
// mergeAndPersistRevocations, so those walls fired — correctly: as spelled, the
// function no longer did what they required. The property they guard is
// unchanged (the CP and the HA standby each participate in BOTH directions), so
// the right repair is to teach them the new spelling, never to relax them.
func chaos68CalleeName(call *ast.CallExpr) string {
	var name string
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		name = fn.Sel.Name
	case *ast.Ident:
		name = fn.Name
	default:
		return ""
	}
	if name == "mergeAndPersistRevocations" {
		return "MergeRevocations"
	}
	return name
}

// DEFECT (AU-35). A backing file that disappears AFTER the boot probe leaves
// every observer clear — no write was attempted, so no failure fired, so the
// persist-degraded flag stays false. Keying the retry on that flag alone meant
// a cluster sync carrying only already-known entries took the early return
// forever, and the revocations stayed in RAM only. The next restart loaded a
// file that had never received them and the cookies were live again.
//
// Reported by Codex on PR #1437 as a P2, against the merge primitive's early
// return.
func TestChaos68_VanishedBackingFileIsRewrittenOnTheNextSync(t *testing.T) {
	withChaos68Revocations(t)
	path := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(path)
	noteRevocationPersistenceConfigured(path)

	exp := time.Now().Add(time.Hour)
	entries := []RevocationEntry{{Token: "tok-gone", Expiry: exp.Unix()}}
	if added := mergeAndPersistRevocations(entries, "test"); added != 1 {
		t.Fatalf("first merge added %d, want 1", added)
	}

	// The mount is replaced, or an operator deletes the file. Nothing observes
	// it: no save was attempted, so the degraded flag is still clear.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if sessionRevocationPersistDegraded.Load() {
		t.Fatal("precondition: the flag must still be clear — the whole point is that nothing observed the deletion")
	}

	// The next sync carries the SAME entry, so the merge adds nothing.
	if added := mergeAndPersistRevocations(entries, "test"); added != 0 {
		t.Fatalf("re-merge added %d, want 0 — the entry is already in memory", added)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the vanished revocations file was not rewritten: %v", err)
	}
	if !strings.Contains(string(data), "tok-gone") {
		t.Errorf("the rewritten file does not carry the in-force revocation: %s", data)
	}
}

// The repair is SELF-LIMITING: once the file is back, the next sync finds it
// present and takes the early return again. Exactly one extra write per
// disappearance, not one per tick — otherwise the fix for a durability defect
// becomes the write-amplification defect this file keeps refusing to ship.
func TestChaos68_VanishedFileRepairIsOneWriteNotAPerTickRewrite(t *testing.T) {
	withChaos68Revocations(t)
	path := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(path)
	noteRevocationPersistenceConfigured(path)

	exp := time.Now().Add(time.Hour)
	entries := []RevocationEntry{{Token: "tok-once", Expiry: exp.Unix()}}
	mergeAndPersistRevocations(entries, "test")
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	// First sync after the disappearance repairs it.
	mergeAndPersistRevocations(entries, "test")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("repair did not happen: %v", err)
	}

	// Every sync after that must leave the file alone, proven with the same
	// non-perturbing sentinel the healthy-node control uses.
	sentinel := []byte(`["do-not-rewrite-me"]`)
	if err := os.WriteFile(path, sentinel, 0o600); err != nil {
		t.Fatalf("seed sentinel: %v", err)
	}
	for i := 0; i < 3; i++ {
		mergeAndPersistRevocations(entries, "test")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, sentinel) {
		t.Errorf("the repair kept firing after the file was restored: %s", got)
	}
}

// CONTROL. A node with no persistence configured must pay nothing — no stat
// storm, no save attempt, no degradation — on a sync that adds nothing. The
// cheapest way to pass the defect gate is to drop the early return entirely,
// which would put every unconfigured appliance in the fleet through a save
// attempt on every 3-5s tick.
func TestChaos68_UnconfiguredNodePaysNothingForTheVanishedFileCheck(t *testing.T) {
	withChaos68Revocations(t)
	session.SetRevocationsPath("")

	if revocationBackingFileIsGone() {
		t.Error("an unconfigured node reports its backing file missing — there is no backing file")
	}
	exp := time.Now().Add(time.Hour)
	entries := []RevocationEntry{{Token: "tok-unconf", Expiry: exp.Unix()}}
	mergeAndPersistRevocations(entries, "test")
	if added := mergeAndPersistRevocations(entries, "test"); added != 0 {
		t.Fatalf("re-merge added %d, want 0", added)
	}
	if sessionRevocationPersistDegraded.Load() {
		t.Error("an unconfigured node was marked persist-degraded")
	}
}

// Only a DEFINITIVELY absent file counts as gone. An unreadable one is not
// evidence the content is missing — it may be intact behind a transient fault
// — and this file already applies that rule to LoadRevocations. A second,
// stricter posture for the same question is the divergence class this sweep
// keeps closing.
func TestChaos68_UnreadablePathIsNotReportedAsAVanishedFile(t *testing.T) {
	withChaos68Revocations(t)
	// A path whose PARENT is a regular file: stat fails with ENOTDIR, which is
	// an error but is not "the file is not there".
	session.SetRevocationsPath(chaos68UnwritablePath(t))

	if revocationBackingFileIsGone() {
		t.Error("an unstattable path was reported as a definitively missing file; only ENOENT may count")
	}
}

// The operator-contract row must SAY the in-force revocations are no longer on
// disk. Its OK message claims they are durable, which is exactly the
// proposition a vanished file falsifies — distinct from the durable gauge,
// whose claim ("a revocation applied right now would survive") stays true
// because SaveRevocations recreates the file.
func TestChaos68_VanishedBackingFileFailsTheContractRow(t *testing.T) {
	withChaos68Revocations(t)
	path := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(path)
	noteRevocationPersistenceConfigured(path)

	sessionRevoked.RevokeUser("departed")
	if err := sessionRevoked.SaveRevocations(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if row := checkSessionRevocation(); row.Status != diagOK {
		t.Fatalf("precondition: row = %q, want %q (%s)", row.Status, diagOK, row.Message)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	row := checkSessionRevocation()
	if row.Status != diagFail {
		t.Errorf("status = %q, want %q once the backing file is gone (%s)", row.Status, diagFail, row.Message)
	}
	// Viewer-reachable surface: counts and a remedy, never the revoked identity
	// and never a raw path.
	if strings.Contains(row.Message, "departed") || strings.Contains(row.OperatorAction, "departed") {
		t.Errorf("the row leaked a revoked identity: %+v", row)
	}
	if strings.Contains(row.Message, path) || strings.Contains(row.OperatorAction, path) {
		t.Errorf("the row leaked the raw revocations path: %+v", row)
	}
}

// The repair announces the MISSING FILE, not a recovery. Reporting it as
// "durable again" would claim recovery from a degradation that was never
// reported, sending an operator to hunt for a failure line that does not
// exist — and the line must be one per disappearance, not one per 3-5s tick.
func TestChaos68_VanishedFileRepairAnnouncesItselfOncePerDisappearance(t *testing.T) {
	withChaos68Revocations(t)
	path := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(path)
	noteRevocationPersistenceConfigured(path)

	exp := time.Now().Add(time.Hour)
	entries := []RevocationEntry{{Token: "tok-log", Expiry: exp.Unix()}}
	mergeAndPersistRevocations(entries, "test")
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	for i := 0; i < 6; i++ {
		mergeAndPersistRevocations(entries, "test")
	}

	out := buf.String()
	if n := strings.Count(out, "the revocations file is missing"); n != 1 {
		t.Errorf("emitted %d missing-file lines across 6 syncs, want exactly 1: %s", n, out)
	}
	if strings.Contains(out, "durable again") {
		t.Errorf("a repaired vanished file was reported as recovery from a degradation that was never reported: %s", out)
	}
}

// ---------------------------------------------------------------------------
// AU-36: an unreadable revocations file gets the remedy that matches it.
//
// The load path already distinguished a PARSE failure (quarantined, leaves a
// .corrupt.* copy and a state_file_session_revocations readiness row) from a
// READ failure (deliberately NOT quarantined — the content may be intact
// behind a transient permission or I/O fault). It then discarded the
// distinction when recording the health, so the contract row printed the
// quarantine remedy for both and sent an operator hunting artifacts that only
// exist in the other case, mid-incident, on the one control that can withdraw
// an already-issued session.
//
// Same defect class as CHAOS-66's socks5BindRemedy: a bounded classifier is
// worth nothing if one remedy is printed for every class.
// ---------------------------------------------------------------------------

// DEFECT GATE. An unreadable file must not be described as quarantined, and
// must not point at evidence that was never produced.
func TestChaos68_AU36_UnreadableLoadDoesNotAdvertiseAQuarantine(t *testing.T) {
	withChaos68Revocations(t)
	noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
	noteRevocationLoadDegraded(fmt.Errorf("open revocations: %w", os.ErrPermission))

	row := checkSessionRevocation()
	if row.Status != diagFail {
		t.Fatalf("status = %q, want %q after an unreadable load", row.Status, diagFail)
	}
	blob := row.Message + " " + row.OperatorAction
	// Each of these exists ONLY after a parse failure. Naming any of them on
	// the read-failure branch is the defect.
	for _, absent := range []string{".corrupt", "quarantin", "state_file_session_revocations"} {
		if strings.Contains(strings.ToLower(blob), strings.ToLower(absent)) {
			t.Errorf("the unreadable-load row names %q, which only exists after a PARSE failure: %q", absent, blob)
		}
	}
	// It must still say what to do.
	low := strings.ToLower(blob)
	if !strings.Contains(low, "permission") || !strings.Contains(low, "restart") {
		t.Errorf("the unreadable-load row does not name the permission/mount repair or the restart: %q", blob)
	}
}

// DEFECT GATE. The remedy must warn that the file is still overwritable.
//
// The boot probe deliberately does not write on this branch, but all three
// production writers (revokeSessionCookie, the account-delete handler, and
// mergeAndPersistRevocations) call SaveRevocations unconditionally — so the
// first revocation after boot REPLACES the file this process could not read.
// "The contents may be intact" is only actionable if the operator is told how
// long that stays true.
func TestChaos68_AU36_UnreadableRemedyWarnsTheFileIsStillOverwritable(t *testing.T) {
	withChaos68Revocations(t)
	noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
	noteRevocationLoadDegraded(fmt.Errorf("read revocations: %w", errors.New("input/output error")))

	action := strings.ToLower(checkSessionRevocation().OperatorAction)
	if !strings.Contains(action, "replaces it") && !strings.Contains(action, "overwrit") {
		t.Errorf("the unreadable-load remedy does not warn that the next revocation replaces the file: %q", action)
	}
}

// CONTROL. The corrupt branch must KEEP pointing at the quarantine. The
// cheapest way to pass the two gates above is to delete the quarantine remedy
// entirely, which would strip the one branch that really does leave a
// restorable copy of its only recovery instruction.
func TestChaos68_AU36_CorruptLoadStillNamesTheQuarantine(t *testing.T) {
	withChaos68Revocations(t)
	noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
	noteRevocationLoadDegraded(session.ErrRevocationsCorrupt)

	row := checkSessionRevocation()
	if row.Status != diagFail {
		t.Fatalf("status = %q, want %q after a corrupt load", row.Status, diagFail)
	}
	blob := strings.ToLower(row.Message + " " + row.OperatorAction)
	// "quarantin" is here on purpose: the established vocabulary of this
	// codebase and the runbook, which the CORRUPT branch may use freely. Only
	// the READ branch is forbidden it, because there it names nothing real.
	for _, needle := range []string{".corrupt", "state_file_session_revocations", "quarantin"} {
		if !strings.Contains(blob, needle) {
			t.Errorf("the corrupt-load row no longer names %q — the operator's only restore path: %q", needle, blob)
		}
	}
}

// CONTROL. The two branches must actually DIFFER. A switch that returns one
// string satisfies every "names its own remedy" assertion above — the CHAOS-66
// distinct-remedy control, applied here.
func TestChaos68_AU36_TheTwoLoadFailuresCarryDistinctRemedies(t *testing.T) {
	read := func(err error) OperatorContractCheck {
		withChaos68Revocations(t)
		noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
		noteRevocationLoadDegraded(err)
		return checkSessionRevocation()
	}
	corrupt := read(session.ErrRevocationsCorrupt)
	unreadable := read(fmt.Errorf("open: %w", os.ErrPermission))

	if corrupt.OperatorAction == unreadable.OperatorAction {
		t.Errorf("both load failures print one remedy, so the classifier buys nothing: %q", corrupt.OperatorAction)
	}
	if corrupt.Message == unreadable.Message {
		t.Errorf("both load failures print one message: %q", corrupt.Message)
	}
}

// WALL. The quarantine decision and the remedy selection must consult ONE
// predicate. If a call site classifies the error itself, the action taken and
// the action advertised can drift apart — which is the defect AU-36 closed.
func TestChaos68_AU36_QuarantineAndRemedyShareOnePredicate(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "session_startup.go"))
	if err != nil {
		t.Fatalf("read session_startup.go: %v", err)
	}
	body := string(src)
	if !strings.Contains(body, "revocationLoadIsCorrupt(err)") {
		t.Error("session_startup.go no longer decides the quarantine with revocationLoadIsCorrupt")
	}
	if strings.Contains(body, "ErrRevocationsCorrupt") {
		t.Error("session_startup.go classifies the load error itself; it must ask revocationLoadIsCorrupt " +
			"so the quarantine and the advertised remedy cannot disagree")
	}
	// Not vacuous: the recorder must be the one place the classification is
	// stored, and it must derive it from the same predicate.
	health, err := os.ReadFile(filepath.Join(pkgSourceDir(), "session_revocation_health.go"))
	if err != nil {
		t.Fatalf("read session_revocation_health.go: %v", err)
	}
	if !strings.Contains(string(health), "corrupt := revocationLoadIsCorrupt(err)") {
		t.Error("noteRevocationLoadDegraded no longer derives LoadCorrupt from the shared predicate")
	}
}
