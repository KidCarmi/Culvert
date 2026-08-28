package export

import (
	"encoding/json"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
)

// shadowEv returns a valid v2 Shadow decision event on P-ORD for the given tenant.
func shadowEv(tenant string) model.Event {
	e := model.Event{
		SchemaVersion: model.SchemaVersionV2, EventID: "evt_shx", Phase: model.PhaseDecision,
		Criticality: model.CritOrdinary, Partition: model.PartOrd, Capability: model.CapGateway,
		ActionClass: model.ActionClassRead, NodeID: "dp", DomainID: "d", TimeUnixNano: 1,
		ReplayID: "rpl_shx", CorrelationID: "cor_shx",
		Identity: model.IdentityEvidence{Tenant: tenant, PrincipalID: "u", PrincipalType: "human"},
		Decision: model.DecisionEvidence{
			Action: "ALLOW", ReasonCode: "MCP.POLICY.OK", PolicyRevision: 1, CatalogRevision: 1,
			ExecutionState: "shadow_evaluated",
		},
		Shadow: &model.ShadowEvidence{
			Outcome: "would_execute", Override: false, CredentialPlan: "credential_plan_valid",
			MaterializationReadiness: "not_evaluated", RequestInspection: "would_pass",
			ResponseInspection: "not_evaluated",
		},
	}
	_, _ = e.ComputeDigest()
	return e
}

// TestShadowV2_ExportReadRoundTripPreservesEvidence is the §10 export round-trip: a v2
// Shadow event read for export retains its full ShadowEvidence, and a
// read → marshal → re-read cycle (what an exporter and its downstream do) preserves the
// schema, the shadow facts, and a verifiable digest. Mutation: dropping omitempty or the
// Shadow field from the export encoding loses the durable evidence and fails here.
func TestShadowV2_ExportReadRoundTripPreservesEvidence(t *testing.T) {
	lim := limits.DefaultGatewayEvent()
	want := shadowEv("acme")
	r := &fakeReader{cap: model.CapGateway, events: []model.Event{want}}

	res, err := Read(r, lim, gwAuth("acme"), model.PartOrd, 0)
	if err != nil {
		t.Fatalf("export Read: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("export returned %d events, want 1", len(res.Events))
	}
	got := res.Events[0]
	if got.SchemaVersion != model.SchemaVersionV2 || got.Shadow == nil {
		t.Fatalf("export lost the v2 shadow shape: schema=%d shadow=%v", got.SchemaVersion, got.Shadow)
	}
	if *got.Shadow != *want.Shadow {
		t.Fatalf("export changed the ShadowEvidence:\n  got  %+v\n  want %+v", *got.Shadow, *want.Shadow)
	}

	// read → marshal → re-read (a downstream consumer of the exported bytes).
	enc, err := got.Marshal()
	if err != nil {
		t.Fatalf("marshal exported event: %v", err)
	}
	var back model.Event
	if err := json.Unmarshal(enc, &back); err != nil {
		t.Fatalf("re-read exported bytes: %v", err)
	}
	if back.Shadow == nil || *back.Shadow != *want.Shadow {
		t.Fatal("the durable ShadowEvidence did not survive read → marshal → re-read")
	}
	if !back.VerifyDigest() {
		t.Fatal("exported v2 event fails digest verification after round-trip")
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("exported v2 event fails validation after round-trip: %v", err)
	}
}
