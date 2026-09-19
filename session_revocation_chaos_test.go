package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// CHAOS-66 root gates — the Control Plane's place in the revocation plane, and
// the visibility of a revocation that is not durable.
//
// The defect gates were verified failing against their reintroduced pre-fix
// shapes.

func withChaos66Revocations(t *testing.T) {
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

func withChaos66Aggregator(t *testing.T) {
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
func TestChaos66_ControlPlaneOwnRevocationsReachTheFleet(t *testing.T) {
	withChaos66Aggregator(t)

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
func TestChaos66_CPSlotIsNotAddressableByANodeID(t *testing.T) {
	withChaos66Aggregator(t)

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
func TestChaos66_RequesterStillExcludedFromItsOwnEntries(t *testing.T) {
	withChaos66Aggregator(t)

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
func TestChaos66_ExpiredCPEntriesAreNotMerged(t *testing.T) {
	withChaos66Aggregator(t)

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
func TestChaos66_AccountDeletionRevocationIsDurable(t *testing.T) {
	withChaos66Revocations(t)
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
func TestChaos66_PersistFailureIsVisibleToTheOperator(t *testing.T) {
	withChaos66Revocations(t)

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
func TestChaos66_UnconfiguredPersistenceIsReported(t *testing.T) {
	withChaos66Revocations(t)
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
func TestChaos66_DegradedLoadIsReported(t *testing.T) {
	withChaos66Revocations(t)
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
func TestChaos66_HealthyNodeReadsOK(t *testing.T) {
	withChaos66Revocations(t)
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
func TestChaos66_ContractRowDoesNotLeakRevokedIdentities(t *testing.T) {
	withChaos66Revocations(t)
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
func TestChaos66_ContractRowIsRegistered(t *testing.T) {
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
func TestChaos66_SyncRevocationsWiresBothDirections(t *testing.T) {
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
func TestChaos66_ContractRowNeverEchoesSensitiveTokens(t *testing.T) {
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
			withChaos66Revocations(t)
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
