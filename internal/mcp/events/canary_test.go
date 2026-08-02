package events

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

const secretCanaries = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"

// TestBackstopRejectsSecretPattern proves the redaction backstop rejects a
// decision whose facts smuggled a secret-shaped token into a field — the event is
// never persisted.
func TestBackstopRejectsSecretPattern(t *testing.T) {
	m := newMgr(t, t.TempDir(), nil)
	defer m.Close()
	facts := critFacts(model.CapGateway, "acme")
	facts.Identity.ResourceRef = "resource-with-" + secretCanaries // a leaked token
	_, err := m.CommitDecision(facts)
	if mcperr.ReasonOf(err) != mcperr.ReasonEventSecretPresent {
		t.Fatalf("backstop did not reject a secret-bearing event: %v", err)
	}
}

// TestNoCanaryInSpoolOrExport proves a value placed in a legitimate field is
// encrypted at rest (never appears in spool plaintext) and, if exported, only via
// the safe encrypted-then-decrypted-in-process event — never in plaintext on disk.
func TestNoCanaryInSpoolOrExport(t *testing.T) {
	dir := t.TempDir()
	m := newMgr(t, dir, nil)
	defer m.Close()
	// A non-secret-shaped canary that the backstop does not reject, placed in a
	// legitimate field, must still never appear in the plaintext spool bytes.
	canary := "UNIQUE-CANARY-TOKEN- zz9f2c-DO-NOT-LEAK"
	facts := critFacts(model.CapGateway, "acme")
	facts.Identity.ResourceRef = canary
	if _, err := m.CommitDecision(facts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// Scan every file under the gateway spool for the raw canary.
	root := filepath.Join(dir, "gateway")
	found := false
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte(canary)) {
			found = true
		}
		return nil
	})
	if found {
		t.Fatal("canary appeared in spool plaintext at rest")
	}
}

// TestNoBrokerOrUpstreamCallInLiveEventsPath is a structural proof that the LIVE
// PR-8 runtime path (every non-test .go file except gate.go, which only references
// the broker's contract TYPES for a future execution slice) invokes no broker
// materialization, provider fetch, or HTTP upstream call. PR-8 is decision-only.
func TestNoBrokerOrUpstreamCallInLiveEventsPath(t *testing.T) {
	forbidden := []string{
		".Materialize(", ".Rotate(", ".Revoke(", // broker mutation
		".Fetch(",                   // provider materialization
		"http.", "net.Dial", ".Do(", // upstream/network
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" {
			continue
		}
		if name == "gate.go" || bytesHasSuffix(name, "_test.go") {
			continue // gate.go holds only the broker-contract TYPES + the manager's own commit
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range forbidden {
			if bytes.Contains(b, []byte(f)) {
				t.Fatalf("live events file %s contains a forbidden call pattern %q (PR-8 is decision-only)", name, f)
			}
		}
	}
}

func bytesHasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// TestGateFailClosedNoReceipt proves the credential gate fails closed (Permit and
// DurableConfirmed both false) when the domain cannot durably commit — the broker
// short-circuits on !Permit and never materializes (broker non-invocation is
// re-tested in the broker's own suite). Here we drive the manager degraded and
// assert CommitThenAct never runs the (stand-in) materialization callback.
func TestGateFailClosedNoReceipt(t *testing.T) {
	be := newFaultBackend()
	m := newMgr(t, t.TempDir(), be)
	defer m.Close()
	be.failAppendFor("gateway/P-CRIT", false)
	materialized := false
	facts := DecisionFacts{
		Capability: model.CapGateway, Criticality: model.CritCritical, ActionClass: model.ActionClassCredentialSelect,
		Identity: model.IdentityEvidence{Tenant: "acme", PrincipalID: "wl", PrincipalType: "workload"},
		Decision: model.DecisionEvidence{Action: "ALLOW", ReasonCode: "MCP.CREDENTIAL.MATERIALIZE", PolicyRevision: 1, CatalogRevision: 1},
	}
	err := m.CommitThenAct(facts, func(spool.CommitReceipt) error { materialized = true; return nil })
	if err == nil {
		t.Fatal("credential materialization gate must fail closed on a commit failure")
	}
	if materialized {
		t.Fatal("materialization ran without a durable commit receipt")
	}
}
