package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
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
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if _, tracked := want[sel.Sel.Name]; tracked {
				want[sel.Sel.Name] = true
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

	branches := []struct {
		name  string
		setup func(t *testing.T)
	}{
		{"unconfigured", func(*testing.T) {}},
		{"healthy", func(t *testing.T) {
			noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
		}},
		{"load-degraded", func(t *testing.T) {
			noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
			noteRevocationLoadDegraded(session.ErrRevocationsCorrupt)
		}},
		{"persist-failed", func(t *testing.T) {
			noteRevocationPersistenceConfigured(filepath.Join(t.TempDir(), "revocations.json"))
			noteRevocationPersistFailure(os.ErrPermission)
		}},
	}

	for _, b := range branches {
		t.Run(b.name, func(t *testing.T) {
			withChaos68Revocations(t)
			b.setup(t)
			row := checkSessionRevocation()
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
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == tc.call {
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
