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

// INVERTED by AU-37. This gate used to require the remedy to WARN that the
// next revocation would overwrite the unread file — it pinned a documented
// hazard. AU-37 removed the hazard instead: SaveRevocations now refuses while
// the file is unread, so the remedy must promise the opposite, that the file
// is preserved and a restart after the repair recovers it. Inverting it is
// deliberate, not incidental: the old assertion would now pass only if the
// fence were gone.
func TestChaos68_AU37_UnreadableRemedyPromisesTheFileIsPreserved(t *testing.T) {
	withChaos68Revocations(t)
	noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
	noteRevocationLoadDegraded(fmt.Errorf("read revocations: %w", errors.New("input/output error")))

	action := strings.ToLower(checkSessionRevocation().OperatorAction)
	if strings.Contains(action, "replaces it") {
		t.Errorf("the remedy still warns the file will be overwritten, which AU-37 made false: %q", action)
	}
	if !strings.Contains(action, "not being written") {
		t.Errorf("the remedy does not state that the unread file is protected from writes: %q", action)
	}
	if !strings.Contains(action, "restart") {
		t.Errorf("the remedy does not name the restart that recovers the contents: %q", action)
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

// ---------------------------------------------------------------------------
// AU-37: a file that could not be READ is never overwritten.
//
// A read failure is deliberately not quarantined, on the reasoning that the
// content may be intact behind a transient fault and moving a healthy
// security-critical file aside is the worse error. That reasoning only holds
// if nothing LATER overwrites it — and something did. The process boots with an
// EMPTY list, and the first logout, account deletion or cluster sync that adds
// an entry calls SaveRevocations, which renames a complete temp file over the
// target. AtomicWrite needs only the parent DIRECTORY to be writable, so an
// unreadable file in a writable directory is replaced by the handful of
// revocations this process happens to know about; every revocation that was on
// disk and never read is gone, and the operator's own remedy (fix the
// permission, restart) then loads the truncated file.
//
// Fail-OPEN on the one control that can withdraw an already-issued session,
// reachable by ordinary operation rather than by a second fault. Reported by
// Codex on PR #1437 as a P1.
//
// The boot probe already refused to write on this branch for exactly this
// reason; the runtime writers did not. Same file, same fault, opposite
// postures — the "two answers to one question" class this sweep keeps closing.
// ---------------------------------------------------------------------------

// au37UnreadableFeed returns a list whose backing file exists, holds content,
// and cannot be read — the real shape, driven through the real load path.
func au37UnreadableFeed(t *testing.T) (rl *session.RevocationList, path string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "revocations.json")
	// Content a healthy boot WOULD have loaded. Its survival is the property.
	original := []byte(`[{"token":"user:victim","exp":4102444800}]`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	session.SetRevocationsPath(path)
	rl = session.NewRevocationList()
	if err := rl.LoadRevocations(); err == nil {
		t.Skip("running as root: DAC is bypassed, so the file cannot be made unreadable here")
	}
	return rl, path
}

// DEFECT GATE. A save after an unreadable load must not touch the file.
func TestChaos68_AU37_SaveRefusesAfterAnUnreadableLoad(t *testing.T) {
	withChaos68Revocations(t)
	rl, path := au37UnreadableFeed(t)

	rl.Revoke("a-token-this-process-knows", time.Now().Add(time.Hour))
	err := rl.SaveRevocations()
	if !errors.Is(err, session.ErrRevocationsUnread) {
		t.Fatalf("SaveRevocations err = %v, want ErrRevocationsUnread — an unread file must never be overwritten", err)
	}

	// The original bytes must still be there. Read as the owner can.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(got), "user:victim") {
		t.Errorf("the unread revocations file was overwritten and its contents are gone: %s", got)
	}
}

// DEFECT GATE. The refusal is not a persistence FAILURE: no write was
// attempted, so it must not set the degraded flag or move the failure counter,
// which would replace the load-degraded row's remedy (fix the permission) with
// "check free space" — the wrong investigation.
func TestChaos68_AU37_RefusalIsNotCountedAsAWriteFailure(t *testing.T) {
	withChaos68Revocations(t)
	rl, _ := au37UnreadableFeed(t)

	rl.Revoke("another-token", time.Now().Add(time.Hour))
	_ = rl.SaveRevocations()

	if sessionRevocationPersistDegraded.Load() {
		t.Error("a refusal set the persist-degraded flag; it is not a write failure and the volume may be healthy")
	}
	if got := sessionRevocationPersistFailures.Load(); got != 0 {
		t.Errorf("persist failures = %d, want 0 — a refused save attempted no write", got)
	}
}

// DEFECT GATE. The refusal is COUNTED. It is the operator's only measure of
// how many revocations are memory-only, which is also the size of the re-apply
// job the contract row asks for.
func TestChaos68_AU37_RefusalsAreCountedAndSurfaced(t *testing.T) {
	withChaos68Revocations(t)
	path := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(path)
	noteRevocationPersistenceConfigured(path)
	noteRevocationLoadDegraded(fmt.Errorf("read revocations: %w", os.ErrPermission))

	noteRevocationPersistRefused(3)
	if got := sessionRevocationPersistRefused.Load(); got != 3 {
		t.Fatalf("refused counter = %d, want 3", got)
	}
	if msg := checkSessionRevocation().Message; !strings.Contains(msg, "3") {
		t.Errorf("the row does not report how many revocations are memory-only: %q", msg)
	}
}

// CONTROL. A healthy node must still persist. The cheapest way to pass every
// gate above is to refuse every save, which would silently delete the
// durability this whole sweep exists to provide.
func TestChaos68_AU37_ReadableFileStillPersists(t *testing.T) {
	withChaos68Revocations(t)
	path := filepath.Join(t.TempDir(), "revocations.json")
	session.SetRevocationsPath(path)
	rl := session.NewRevocationList()
	if err := rl.LoadRevocations(); err != nil {
		t.Fatalf("load on a clean path: %v", err)
	}
	rl.Revoke("token", time.Now().Add(time.Hour))
	if err := rl.SaveRevocations(); err != nil {
		t.Fatalf("a healthy node must still persist: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(got), "token") {
		t.Errorf("a healthy save wrote nothing useful: %s", got)
	}
}

// CONTROL. A CORRUPT file must STILL be writable after the caller quarantines
// it. The fence is specific to an UNREAD file; extending it to the corrupt case
// would leave a quarantined node unable to persist anything until a restart,
// which is a durability outage the quarantine exists to avoid.
func TestChaos68_AU37_CorruptFileDoesNotFenceTheSave(t *testing.T) {
	withChaos68Revocations(t)
	path := filepath.Join(t.TempDir(), "revocations.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	session.SetRevocationsPath(path)
	rl := session.NewRevocationList()
	err := rl.LoadRevocations()
	if !errors.Is(err, session.ErrRevocationsCorrupt) {
		t.Fatalf("load err = %v, want ErrRevocationsCorrupt", err)
	}
	// The caller quarantines, then the node carries on. A save must work.
	rl.Revoke("post-quarantine", time.Now().Add(time.Hour))
	if err := rl.SaveRevocations(); err != nil {
		t.Fatalf("a corrupt (quarantined) file must not fence the save: %v", err)
	}
}

// UID-INDEPENDENT COUNTERPART to the two chmod gates above, which skip as root
// because DAC cannot deny root a read. A DIRECTORY at the configured path fails
// os.ReadFile with EISDIR for every uid, so the same fence is driven on every
// runner — without it, the two gates above are unguarded on exactly the lanes
// this repository runs as root.
//
// The write target is then pointed at an ordinary file holding known content,
// which is what makes this a proof of the fence rather than of the directory:
// the refusal must happen before any path work, so a save must return the
// sentinel and leave those bytes alone.
func TestChaos68_AU37_UnreadLoadFencesEverySubsequentSave(t *testing.T) {
	withChaos68Revocations(t)
	dir := t.TempDir()

	unreadable := filepath.Join(dir, "revocations-as-a-directory.json")
	if err := os.Mkdir(unreadable, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	session.SetRevocationsPath(unreadable)
	rl := session.NewRevocationList()
	err := rl.LoadRevocations()
	if err == nil {
		t.Fatal("reading a directory as the revocations file must fail")
	}
	if errors.Is(err, session.ErrRevocationsCorrupt) {
		t.Fatalf("EISDIR must classify as a READ failure, not corruption: %v", err)
	}

	target := filepath.Join(dir, "revocations.json")
	original := []byte(`[{"token":"user:victim","exp":4102444800}]`)
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	session.SetRevocationsPath(target)

	rl.Revoke("token-known-only-to-this-process", time.Now().Add(time.Hour))
	if err := rl.SaveRevocations(); !errors.Is(err, session.ErrRevocationsUnread) {
		t.Fatalf("SaveRevocations err = %v, want ErrRevocationsUnread", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("a save after an unread load wrote to disk: %s", got)
	}
	if sessionRevocationPersistDegraded.Load() {
		t.Error("the refusal set the persist-degraded flag; no write was attempted")
	}
}

// DEFECT GATE for the MERGE path's wiring, which the other AU-37 gates do not
// reach: mergeAndPersistRevocations is the one writer that runs on a LOOP
// (the CP handler, the DP sync, the HA bundle apply, every 3-5s), so it is the
// one place a refusal could become both an uncounted event and a per-tick log
// line. Removing its refusal branch left every other gate green — which is why
// this exists.
func TestChaos68_AU37_MergePathCountsTheRefusalAndStaysQuiet(t *testing.T) {
	withChaos68Revocations(t)
	dir := t.TempDir()

	unreadable := filepath.Join(dir, "as-a-directory.json")
	if err := os.Mkdir(unreadable, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	session.SetRevocationsPath(unreadable)
	if err := sessionRevoked.LoadRevocations(); err == nil {
		t.Fatal("reading a directory as the revocations file must fail")
	}
	noteRevocationPersistenceConfigured(unreadable)
	noteRevocationLoadDegraded(errors.New("read revocations: is a directory"))

	var logged bytes.Buffer
	prev := logger
	logger = log.New(&logged, "", 0)
	t.Cleanup(func() { logger = prev })

	before := sessionRevocationPersistRefused.Load()
	added := mergeAndPersistRevocations([]RevocationEntry{
		{Token: "user:alice", User: "alice", Expiry: time.Now().Add(time.Hour).Unix()},
		{Token: "user:bob", User: "bob", Expiry: time.Now().Add(time.Hour).Unix()},
	}, "test")
	if added != 2 {
		t.Fatalf("added = %d, want 2 — the merge itself must still apply", added)
	}
	if got := sessionRevocationPersistRefused.Load() - before; got != 2 {
		t.Errorf("refused counter moved by %d, want 2 — the merge path must charge what it could not persist", got)
	}
	if sessionRevocationPersistDegraded.Load() {
		t.Error("the merge path treated a refusal as a write failure")
	}
	// The sync loops run every few seconds; a per-attempt line here is the
	// write-amplification this function's own contract forbids. The condition
	// was already logged once at boot and is on the contract row.
	if strings.Contains(logged.String(), "failed to persist") {
		t.Errorf("the merge path logged a refusal as a persistence failure, once per sync tick: %q", logged.String())
	}
}

// ---------------------------------------------------------------------------
// AU-38 / AU-39: two premises that can be false.
//
// AU-37 fenced saves for a file that could not be READ, and deliberately
// exempted the CORRUPT branch because "the quarantine moves the file aside, so
// the path is free". AU-35 left the durable gauge alone because "AtomicWrite
// creates the file". Both are conditional statements that were treated as
// unconditional: the quarantine can FAIL (leaving the only copy in place), and
// AtomicWrite cannot create anything when the PARENT DIRECTORY is gone.
//
// Both reported by Codex on PR #1437 as P2s, and both reproduced before fixing.
// ---------------------------------------------------------------------------

// au38LongBase returns a basename in the band where AtomicWrite's `.tmp.<10>`
// suffix still fits inside the 255-byte filename limit but the quarantine's
// longer `.corrupt.<19-digit ns>` does not — the shape that makes a failed
// rename coexist with a successful write.
func au38LongBase() string { return strings.Repeat("r", 235) }

// DEFECT GATE. A corrupt file that could not be quarantined must never be
// overwritten: it is the only copy of whatever the node was enforcing.
//
// This drives the REAL boot path (loadSession), not the primitive. A first
// draft called quarantineCorruptStateFile and FenceWritesUnquarantined
// directly from the test, and BOTH the pre-fix shape and an over-broad
// always-fence shape passed it — it proved the fence works and nothing about
// the call site that has to arm it, which is the entire fix. The same vacuity
// AU-37's merge-path mutation exposed, one finding later.
func TestChaos68_AU38_FailedQuarantineFencesTheSave(t *testing.T) {
	withChaos68Revocations(t)
	dir := t.TempDir()
	path := filepath.Join(dir, au38LongBase())
	corrupt := []byte(`{this is not a revocations array`)
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Probe the filesystem band before asserting anything about it.
	if err := os.Rename(path, fmt.Sprintf("%s.corrupt.%d", path, time.Now().UnixNano())); err == nil {
		t.Skip("this filesystem allows the longer .corrupt.<ns> name; the band is not reproducible here")
	}

	if err := loadSession(sessionStartupConfig{RevocationsFile: path}); err == nil {
		t.Fatal("loadSession must report the corrupt revocations file")
	}

	sessionRevoked.Revoke("a-token-this-process-knows", time.Now().Add(time.Hour))
	if err := sessionRevoked.SaveRevocations(); !errors.Is(err, session.ErrRevocationsUnquarantined) {
		t.Fatalf("SaveRevocations err = %v, want ErrRevocationsUnquarantined", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, corrupt) {
		t.Errorf("the only copy of the corrupt file was overwritten: %q", got)
	}
	if row := checkSessionRevocation(); row.Status != diagFail {
		t.Errorf("contract row = %q, want %q", row.Status, diagFail)
	}
}

// DEFECT GATE. The two refusals must be DISTINGUISHABLE, because their
// remedies differ — an unread file needs a permission repair, an
// unquarantined one needs its path freed by hand.
func TestChaos68_AU38_TheTwoRefusalsAreDistinctButBothFenced(t *testing.T) {
	if errors.Is(session.ErrRevocationsUnquarantined, session.ErrRevocationsUnread) ||
		errors.Is(session.ErrRevocationsUnread, session.ErrRevocationsUnquarantined) {
		t.Error("the two refusal sentinels are not distinguishable, so a caller cannot tell the remedies apart")
	}
	for _, err := range []error{session.ErrRevocationsUnread, session.ErrRevocationsUnquarantined} {
		if !session.IsWriteFenced(err) {
			t.Errorf("IsWriteFenced(%v) = false; a call site would count this refusal as a failing volume", err)
		}
	}
	if session.IsWriteFenced(os.ErrPermission) {
		t.Error("IsWriteFenced accepted an ordinary write error, which would hide a real persistence failure")
	}
}

// DEFECT GATE. The row must not send the operator after a .corrupt.* copy that
// the failed quarantine never created.
func TestChaos68_AU38_FailedQuarantineRowDoesNotPromiseACopy(t *testing.T) {
	withChaos68Revocations(t)
	noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
	noteRevocationLoadDegraded(session.ErrRevocationsCorrupt)
	noteRevocationQuarantineFailed()

	row := checkSessionRevocation()
	if row.Status != diagFail {
		t.Fatalf("status = %q, want %q", row.Status, diagFail)
	}
	blob := strings.ToLower(row.Message + " " + row.OperatorAction)
	if strings.Contains(blob, "restore the quarantined") {
		t.Errorf("the row offers a quarantined copy that was never created: %q", blob)
	}
	if !strings.Contains(blob, "only copy") && !strings.Contains(blob, "still in place") {
		t.Errorf("the row does not say the damaged file is still at its path: %q", blob)
	}
}

// CONTROL. A SUCCESSFUL quarantine must still leave the path writable — the
// cheapest way to pass the gates above is to fence every corrupt load, which
// would leave a quarantined node unable to persist anything until a restart.
func TestChaos68_AU38_SuccessfulQuarantineStillAllowsSaves(t *testing.T) {
	withChaos68Revocations(t)
	path := filepath.Join(t.TempDir(), "revocations.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := loadSession(sessionStartupConfig{RevocationsFile: path}); err == nil {
		t.Fatal("loadSession must report the corrupt revocations file")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("precondition: an ordinary path must have been quarantined away")
	}
	sessionRevoked.Revoke("post-quarantine", time.Now().Add(time.Hour))
	if err := sessionRevoked.SaveRevocations(); err != nil {
		t.Fatalf("a successfully quarantined path must stay writable: %v", err)
	}
}

// DEFECT GATE. A vanished PARENT falsifies "a revocation applied right now
// would survive"; a vanished FILE does not. The gauge must tell them apart.
func TestChaos68_AU39_VanishedParentIsNotDurable(t *testing.T) {
	withChaos68Revocations(t)
	parent := filepath.Join(t.TempDir(), "mount")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(parent, "revocations.json")
	session.SetRevocationsPath(path)
	noteRevocationPersistenceConfigured(path)
	if err := sessionRevoked.SaveRevocations(); err != nil {
		t.Fatalf("baseline save: %v", err)
	}
	if !revocationsAreDurable() {
		t.Fatalf("precondition: a healthy node must read durable")
	}

	if err := os.RemoveAll(parent); err != nil {
		t.Fatalf("remove parent: %v", err)
	}
	if revocationsAreDurable() {
		t.Error("durable is true with the parent directory gone, but no save can recreate the target")
	}
	row := checkSessionRevocation()
	if row.Status != diagFail {
		t.Errorf("status = %q, want %q with the parent gone", row.Status, diagFail)
	}
	blob := strings.ToLower(row.Message + " " + row.OperatorAction)
	if !strings.Contains(blob, "director") && !strings.Contains(blob, "mount") {
		t.Errorf("the row does not name the missing directory/mount: %q", blob)
	}
	// It must NOT repeat the vanished-FILE remedy, which is false here.
	if strings.Contains(blob, "next logout or account deletion recreates it") {
		t.Errorf("the row promises a recreate that cannot happen with no parent: %q", blob)
	}
}

// CONTROL. A vanished FILE with an intact parent is still durable — the
// cheapest way to pass the gate above is to report every ENOENT non-durable,
// which would contradict AU-35's recorded (and correct) split and page every
// node whose file is merely waiting to be rewritten.
func TestChaos68_AU39_VanishedFileWithIntactParentStaysDurable(t *testing.T) {
	withChaos68Revocations(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "revocations.json")
	session.SetRevocationsPath(path)
	noteRevocationPersistenceConfigured(path)
	if err := sessionRevoked.SaveRevocations(); err != nil {
		t.Fatalf("baseline save: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove file: %v", err)
	}
	if !revocationsAreDurable() {
		t.Error("a deleted file with an intact parent is still recreatable by the next save; durable must stay true")
	}
	if revocationTargetParentMissing() {
		t.Error("revocationTargetParentMissing reported a missing parent for an intact directory")
	}
}

// CONTROL. An UNCONFIGURED node must pay nothing and claim nothing.
func TestChaos68_AU39_UnconfiguredNodeNeedsNoParentCheck(t *testing.T) {
	withChaos68Revocations(t)
	session.SetRevocationsPath("")
	if revocationTargetParentMissing() {
		t.Error("an unconfigured node reported a missing parent")
	}
	if revocationsAreDurable() {
		t.Error("an unconfigured node must not read durable")
	}
}
