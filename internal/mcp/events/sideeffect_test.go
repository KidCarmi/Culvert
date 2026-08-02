package events

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
)

// sideEffects records every downstream irreversible action a flow could take. A
// per-class absence test asserts that on a FAILED commit, NONE of them fired —
// per EVENT-MODEL §4a the assertion is per-FLOW (every action reachable downstream
// of the commit gate), not only the class's eponymous action.
type sideEffects struct {
	upstreamCall   bool
	materialize    bool
	sign           bool
	push           bool
	revisionBumped bool
	stateChanged   bool
	credMinted     bool
	credRotated    bool
	credRevoked    bool
	providerCall   bool
}

func (s *sideEffects) any() bool {
	return s.upstreamCall || s.materialize || s.sign || s.push || s.revisionBumped ||
		s.stateChanged || s.credMinted || s.credRotated || s.credRevoked || s.providerCall
}

// TestPerClassSideEffectAbsence proves that for EVERY critical action class, a
// failed durable commit means NONE of the irreversible actions reachable
// downstream of the commit gate occurred (queue saturation AND post-admission
// commit failure are both fail-closed; here we drive the post-admission fsync/
// storage fault). PR-8 uses stub actions for classes whose real mechanism arrives
// later (config publication → PR-10, Management mutation → the Future
// Management-Mutation Gate); those real paths are re-tested there.
func TestPerClassSideEffectAbsence(t *testing.T) {
	classes := []struct {
		name  string
		class model.ActionClass
		// act runs the full downstream side-effect set for this class; it must never
		// be reached on a failed commit.
		act func(se *sideEffects)
	}{
		{"write", model.ActionClassWrite, func(se *sideEffects) { se.upstreamCall = true; se.materialize = true }},
		{"destructive", model.ActionClassDestructive, func(se *sideEffects) { se.upstreamCall = true; se.materialize = true }},
		{"config_publication", model.ActionClassConfigPublication, func(se *sideEffects) { se.sign = true; se.push = true; se.revisionBumped = true }},
		{"credential_issue", model.ActionClassCredentialIssue, func(se *sideEffects) { se.credMinted = true; se.providerCall = true; se.upstreamCall = true }},
		{"credential_rotate", model.ActionClassCredentialRotate, func(se *sideEffects) { se.credRotated = true; se.providerCall = true }},
		{"credential_revoke", model.ActionClassCredentialRevoke, func(se *sideEffects) { se.credRevoked = true; se.providerCall = true }},
		{"credential_select", model.ActionClassCredentialSelect, func(se *sideEffects) { se.materialize = true; se.providerCall = true; se.upstreamCall = true }},
		{"management_mutation", model.ActionClassManagementMutation, func(se *sideEffects) {
			se.stateChanged = true
			se.sign = true
			se.push = true
			se.revisionBumped = true
		}},
	}
	for _, tc := range classes {
		t.Run(tc.name, func(t *testing.T) {
			be := newFaultBackend()
			m := newMgr(t, t.TempDir(), be)
			defer m.Close()
			be.failAppendFor("gateway/P-CRIT", false) // post-admission append fault

			facts := DecisionFacts{
				Capability: model.CapGateway, Criticality: model.CritCritical, ActionClass: tc.class,
				Identity: model.IdentityEvidence{Tenant: "acme", PrincipalID: "p", PrincipalType: "workload"},
				Decision: model.DecisionEvidence{Action: "ALLOW", ReasonCode: "MCP.POLICY.OK", PolicyRevision: 1, CatalogRevision: 1},
			}
			var se sideEffects
			err := m.CommitThenAct(facts, func(spool.CommitReceipt) error {
				tc.act(&se)
				return nil
			})
			if err == nil {
				t.Fatal("failed commit must fail closed")
			}
			if se.any() {
				t.Fatalf("%s: an irreversible action fired despite a failed commit: %+v", tc.name, se)
			}
			// The domain must be degraded on the critical track.
			if m.WriteAllowedCritical(model.CapGateway) {
				t.Fatalf("%s: domain not degraded after critical commit failure", tc.name)
			}
		})
	}
}

// TestCommitThenActRunsOnlyAfterCommit proves the ordering: on a SUCCESSFUL commit
// the callback runs exactly once, after the commit, with a valid receipt.
func TestCommitThenActRunsOnlyAfterCommit(t *testing.T) {
	m := newMgr(t, t.TempDir(), nil)
	defer m.Close()
	facts := critFacts(model.CapGateway, "acme")
	ran := 0
	var gotValid bool
	err := m.CommitThenAct(facts, func(r spool.CommitReceipt) error { ran++; gotValid = r.Valid(); return nil })
	if err != nil {
		t.Fatalf("CommitThenAct: %v", err)
	}
	if ran != 1 || !gotValid {
		t.Fatalf("callback ran=%d validReceipt=%v", ran, gotValid)
	}
}
