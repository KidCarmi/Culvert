package broker

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// SEC-MCP-15. The credential plan must carry the AUTHENTICATED PRINCIPAL, because
// the durable credential event built from it has to attribute a materialization to
// the party that caused it. Before this, the event gate had nothing to attribute
// to: it put the PLAN id in PrincipalID and asserted PrincipalType "workload" — a
// type nothing had determined — so the archive named a plan as a principal and
// invented a subject type for it.
func TestPlan_CarriesTheAuthenticatedPrincipal(t *testing.T) {
	h := newHarness(t, provider.Capabilities{}, profile.PowerReadOnly)
	plan, err := h.broker.Plan(PlanInput{Identity: h.id, Profile: profID, Environment: "prod", Operation: profile.OpRead})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if got := plan.PrincipalID(); got != "u1" {
		t.Fatalf("PrincipalID = %q, want the authenticated subject %q", got, "u1")
	}
	if got := plan.PrincipalKind(); got != "human" {
		t.Fatalf("PrincipalKind = %q, want human", got)
	}
	// The plan id is NOT lost — it is carried where it belongs.
	if plan.PlanID() == "" {
		t.Fatal("plan id is empty")
	}
	if plan.PrincipalID() == plan.PlanID() {
		t.Fatal("PrincipalID still substitutes the plan id")
	}
	// A one-way correlator to the credential is carried, never the credential.
	if plan.TokenDigest() == "" {
		t.Fatal("token digest correlator missing")
	}
}

// The principal type is never INVENTED: a workload subject reports workload, and
// neither branch may report the other.
func TestPlan_PrincipalKindIsNeverInvented(t *testing.T) {
	if got := subjectKindLabel(nil); got != "" {
		t.Fatalf("nil identity must yield no principal type, got %q", got)
	}
	if got := subjectRefID(nil); got != "" {
		t.Fatalf("nil identity must yield no principal id, got %q", got)
	}
	sub := identity.Subject{Kind: identity.SubjectWorkload, Workload: &identity.Workload{Service: "svc-9", Tenant: "t"}}
	// Management carries no server/tool authority, so it resolves without a registry.
	wctx, err := identity.Resolve(identity.ResolveInput{
		Capability: protocol.Management, Tenant: identity.Tenant{ID: "t"}, Subject: sub,
		Client: identity.Client{ClientID: "c", Tenant: "t", Capability: protocol.Management},
	}, nil, nil)
	if err != nil {
		t.Fatalf("resolve workload: %v", err)
	}
	if got := subjectKindLabel(wctx); got != "workload" {
		t.Fatalf("workload subject ⇒ %q, want workload", got)
	}
	if got := subjectRefID(wctx); got != "svc-9" {
		t.Fatalf("workload subject id = %q, want svc-9", got)
	}
}
