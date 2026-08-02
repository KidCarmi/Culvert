package events

import (
	"context"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/broker"
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// CredentialGate is the PR-8 adapter for the PR-4 broker.PreMaterializationGate
// contract. It durably commits a critical decision event for a credential
// materialization BEFORE the broker may touch a provider or cache, and returns
// DurableConfirmed=true ONLY after that commit is confirmed. A high-risk plan the
// broker will only materialize when DurableConfirmed is thus gated on a real
// durable receipt: if the commit fails (queue saturation, fsync/ENOSPC/encryption
// failure, or a degraded domain), the gate denies and the broker's own ordering
// guarantees that no credential is minted, rotated, revoked, or fetched.
//
// PR-8 does NOT invoke the broker from the live runtime path; this adapter exists
// so a future execution slice — and the PR-8 tests — can prove the commit-before-
// side-effect ordering against the real gate contract.
type CredentialGate struct {
	mgr *Manager
}

// NewCredentialGate returns a gate backed by the manager.
func (m *Manager) NewCredentialGate() *CredentialGate { return &CredentialGate{mgr: m} }

// Authorize implements broker.PreMaterializationGate. It commits a critical
// credential decision event and reports Permit/DurableConfirmed = the commit
// outcome. It never returns DurableConfirmed=true without a confirmed durable
// commit.
func (g *CredentialGate) Authorize(_ context.Context, plan broker.CredentialPlan) (broker.GateDecision, error) {
	facts := DecisionFacts{
		Capability:  model.CapGateway,
		Criticality: model.CritCritical,
		ActionClass: model.ActionClassCredentialSelect,
		Identity: model.IdentityEvidence{
			Tenant:        string(plan.Tenant()),
			PrincipalID:   plan.PlanID(),
			PrincipalType: "workload",
		},
		Decision: model.DecisionEvidence{
			Action: "ALLOW", ReasonCode: "MCP.CREDENTIAL.MATERIALIZE",
			PolicyRevision: plan.ProfileRevision(), CatalogRevision: 0,
			OperationClass: plan.Operation().String(),
			RiskClass:      plan.Risk().String(),
			ExecutionState: "not_implemented",
		},
		Credential: model.CredentialEvidence{
			ProfileID:    string(plan.ProfileID()),
			ProviderID:   string(plan.ProviderID()),
			PlannedKind:  plan.Kind().String(),
			PowerCeiling: plan.PowerCeiling().String(),
			PlanID:       plan.PlanID(),
			Version:      plan.ProfileRevision(),
		},
	}
	rec, err := g.mgr.CommitDecision(facts)
	if err != nil || !rec.Valid() {
		// Fail closed: the broker must not materialize without a durable receipt.
		return broker.GateDecision{Permit: false, DurableConfirmed: false}, err
	}
	// The receipt must be bound to exactly this credential decision.
	if !rec.Matches(rec.EventDigest(), string(plan.Tenant()), model.CapGateway, model.ActionClassCredentialSelect) {
		return broker.GateDecision{Permit: false, DurableConfirmed: false}, mgrErr(mcperr.ReasonEventReceiptInvalid, "receipt binding mismatch")
	}
	return broker.GateDecision{Permit: true, DurableConfirmed: true}, nil
}

// CommitThenAct is the generic irreversible-action harness proving the
// commit → side-effect ordering: it durably commits the decision event and runs
// the irreversible callback ONLY on a confirmed commit. The callback receives the
// bound receipt. If the commit fails (admission, encryption, append, sync,
// checkpoint, or a degraded domain), the callback is NEVER invoked and the commit
// error is returned — there is no convenience path that skips the commit.
func (m *Manager) CommitThenAct(f DecisionFacts, act func(spool.CommitReceipt) error) error {
	rec, err := m.CommitDecision(f)
	if err != nil {
		return err // commit failed → the irreversible action is never reached
	}
	if !rec.Valid() {
		return mgrErr(mcperr.ReasonEventReceiptInvalid, "no valid receipt")
	}
	return act(rec)
}

// Ensure the adapter satisfies the broker contract at compile time.
var _ broker.PreMaterializationGate = (*CredentialGate)(nil)
