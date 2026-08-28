package execution

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/broker"
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// SEC-MCP-08. The durable decision event is the ONLY authoritative record of who
// caused an irreversible upstream side effect. The executor hard-coded
// PrincipalType "workload" while the runtime authenticates token subjects as
// humans, so every execution event in the archive would have claimed a workload
// identity for a human actor — an attribution error that no downstream consumer
// (admin decisions API, export, incident review) can detect or correct.
func TestEvidence_PrincipalTypeMirrorsTheAuthenticatedSubject(t *testing.T) {
	cases := []struct {
		kind policy.SubjectKind
		want string
	}{
		{policy.SubjectHuman, "human"},
		{policy.SubjectWorkload, "workload"},
		{policy.SubjectUnset, ""},
	}
	for _, c := range cases {
		in := execInput(policy.ActionAllow, false)
		in.Input.Principal.Kind = c.kind
		if got := decisionFacts(in).Identity.PrincipalType; got != c.want {
			t.Fatalf("subject kind %v ⇒ PrincipalType %q, want %q", c.kind, got, c.want)
		}
	}
}

// The decision event must carry the identity and target evidence the incident
// reviewer actually needs. Silently dropping them is not a cosmetic gap: a
// destructive execution whose event names no server, no tool and no client cannot
// be attributed after the fact.
func TestEvidence_DecisionFactsCarryTheFullTarget(t *testing.T) {
	in := execInput(policy.ActionAllow, false)
	in.Input.Principal.Kind = policy.SubjectHuman
	f := decisionFacts(in)
	if f.Identity.ClientID != "cl1" {
		t.Fatalf("ClientID = %q, want cl1", f.Identity.ClientID)
	}
	if f.Identity.ServerID != "s1" {
		t.Fatalf("ServerID = %q, want s1", f.Identity.ServerID)
	}
	if f.Identity.ToolName != "read_file" || f.Identity.ToolFingerprint != "fp1" {
		t.Fatalf("tool evidence = %q/%q, want read_file/fp1", f.Identity.ToolName, f.Identity.ToolFingerprint)
	}
	if f.Decision.OperationClass != policy.OpRead.String() {
		t.Fatalf("OperationClass = %q, want %q", f.Decision.OperationClass, policy.OpRead.String())
	}
	if f.Decision.PolicySnapshotHash != "snap1" {
		t.Fatalf("PolicySnapshotHash = %q, want snap1", f.Decision.PolicySnapshotHash)
	}
}

// The OUTCOME event must actually COMMIT for every operation class — including the
// mutating ones, which are the only executions whose outcome anyone needs.
//
// This test previously asserted struct fields on outcomeFacts and nothing else. It
// passed while asserting an impossible combination: ordinary criticality carrying a
// write/destructive ActionClass, which model.Event.Validate rejects outright
// ("critical action class on an ordinary event"). Because the outcome commit is
// best-effort and its error was discarded, every mutating execution silently lost
// its outcome evidence — and the test that was supposed to guard the evidence was
// the thing asserting the broken shape.
//
// It now commits through a REAL events.Manager. Reading back fields can only tell
// you the fields are what you set; committing tells you the event exists.
func TestEvidence_OutcomeCommitsForEveryOperationClass(t *testing.T) {
	for _, class := range []policy.OperationClass{policy.OpRead, policy.OpWrite, policy.OpDestructive} {
		mgr := realEvents(t, nil)
		in := execInput(policy.ActionAllow, false)
		in.Input.Operation.Class = class

		f := outcomeFacts(in)
		rec, err := mgr.CommitDecision(f)
		if err != nil {
			t.Fatalf("op class %v: outcome event was REJECTED and would be silently lost: %v", class, err)
		}
		if !rec.Valid() {
			t.Fatalf("op class %v: outcome commit returned no valid receipt", class)
		}
		// The real classification must survive on the field that carries it, so no
		// consumer has to infer the operation from ActionClass.
		if got := f.Decision.OperationClass; got != class.String() {
			t.Fatalf("op class %v: outcome OperationClass = %q, want %q", class, got, class.String())
		}
		if f.Decision.ExecutionState != "executed" {
			t.Fatalf("op class %v: outcome ExecutionState = %q, want executed", class, f.Decision.ExecutionState)
		}
	}
}

// The criticality/action-class pair is a model invariant, not a local convention:
// setting one without the other is what produced an unvalidatable event. Pin the
// pairing directly so a future edit to either side has to keep them coupled.
func TestEvidence_OutcomePairIsAlwaysValid(t *testing.T) {
	for _, class := range []policy.OperationClass{policy.OpRead, policy.OpWrite, policy.OpDestructive} {
		in := execInput(policy.ActionAllow, false)
		in.Input.Operation.Class = class
		f := outcomeFacts(in)
		if f.Criticality == model.CritOrdinary && f.ActionClass.IsCritical() {
			t.Fatalf("op class %v: ordinary outcome carries critical action class %v — "+
				"model.Event.Validate rejects this pairing", class, f.ActionClass)
		}
		if f.Criticality == model.CritCritical && !f.ActionClass.IsCritical() {
			t.Fatalf("op class %v: critical outcome lacks a critical action class", class)
		}
	}
}

// SEC-MCP-09. The decision event commits durably BEFORE anything with a side
// effect, on BOTH paths. Driving the CREDENTIAL path with a broker whose planning
// fails distinguishes the orders: pre-fix the credential branch returned blocked
// from Plan with ZERO events committed, so an execution attempt with a credential
// profile left no critical decision evidence at all.
func TestEvidence_CredentialPathCommitsTheDecisionBeforeAnySideEffect(t *testing.T) {
	up := &fakeUpstream{}
	ev := realEvents(t, nil)
	e, err := New(Config{
		State: stateForMode(t, rollout.ModeCanary), Upstream: up, Events: ev,
		// A broker with no profile store: Plan fails for any profile reference, which
		// is exactly the "credential branch, no side effect yet" shape.
		Broker:          broker.New(broker.Deps{}, limits.DefaultCredential()),
		ResponseProfile: inspection.DefaultGatewayProfile(1),
		Clock:           func() time.Time { return time.Unix(0, 1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	in := execInput(policy.ActionAllow, false)
	in.Input.Principal.Kind = policy.SubjectHuman
	in.Decision.Obligations.CredentialProfile = "profile-a"

	before := ev.Health().Domains[model.CapGateway].CommitOK
	out := runExec(e, context.Background(), in)
	after := ev.Health().Domains[model.CapGateway].CommitOK

	if up.calls != 0 {
		t.Fatalf("a failed credential plan must not reach upstream, calls=%d", up.calls)
	}
	if out.Executed {
		t.Fatal("a failed credential plan must not report an execution")
	}
	if after <= before {
		t.Fatalf("the credential path committed no decision event before the side-effect region (%d → %d)", before, after)
	}
}

// The commit must GATE the side effect, not merely accompany it: a durable commit
// failure leaves zero upstream calls on either path.
func TestEvidence_CommitFailureBlocksTheUpstreamCall(t *testing.T) {
	up := &fakeUpstream{}
	fb := &failAppendBackend{Backend: spool.NewOSBackend()}
	ev := realEvents(t, fb)
	// A HIGH-RISK scope: write/destructive never enter a rollout through a plain
	// scope, so the critical (commit-gated) path is only reachable with one.
	st := rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits())
	if err := st.SetConfig(rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeProduction, ScopeRevision: 1,
		Scope: rollout.ScopeSpec{
			Capability: rollout.CapabilityGateway, Servers: []string{"s1"},
			Operations: []rollout.RiskClass{rollout.RiskWrite}, HighRisk: true,
		},
		ConnectorMode: rollout.ConnectorLocalClient,
	}, "a", 1); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	e := newExec(t, st, up, ev)

	in := execInput(policy.ActionAllow, false)
	in.Input.Operation.Class = policy.OpWrite // CRITICAL criticality

	// Sanity: this configuration really does execute, so a zero call count below is
	// caused by the commit failure and not by the rollout scope.
	if warm := runExec(e, context.Background(), in); !warm.Executed {
		t.Fatalf("fixture does not execute (eff=%q); the commit gate is not exercised", warm.EffectiveAction)
	}
	up.calls = 0

	// From here every durable append fails: the critical decision event cannot
	// commit.
	fb.fail.Store(true)

	out := runExec(e, context.Background(), in)
	if up.calls != 0 {
		t.Fatalf("a failed critical commit must prevent the upstream side effect, calls=%d", up.calls)
	}
	if out.Executed {
		t.Fatal("a failed critical commit must not report an execution")
	}
}

// failAppendBackend is a spool backend whose durable append can be switched to
// always fail, simulating ENOSPC / a failing volume under the event spool.
type failAppendBackend struct {
	spool.Backend
	fail atomic.Bool
}

func (f *failAppendBackend) AppendSync(path string, frame []byte, perm os.FileMode) error {
	if f.fail.Load() {
		return errors.New("simulated durable-append failure")
	}
	return f.Backend.AppendSync(path, frame, perm)
}
