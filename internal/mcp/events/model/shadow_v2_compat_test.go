package model

import (
	"strings"
	"testing"
)

// goldenV1Digests are the canonical digests of goldenV1Fixtures(), CAPTURED ON THE
// PRE-v2 TREE (before Event gained the Shadow field and v2 support). The v2 change is
// digest-compatible for every v1 event iff these are byte-identical after the change:
// adding a nil `Shadow *ShadowEvidence` with omitempty omits the field from the
// canonical encoding of a v1 event, so its digest is unchanged (SHADOW-EVIDENCE-ROUTING-1
// §13). If any of these changes, STOP — a v1 event's on-disk identity moved and existing
// durable evidence would misverify.
var goldenV1Digests = map[string]string{
	"evt_ord1":         "898a654376a34ce89f8f8fc3756d309061903ecef2031329e840a3d2d0fbddd4",
	"evt_shadowlegacy": "f95980073d59a6cdc1f5102c31e22814f66c7db20532b0d0e683fe8fa001253b",
	"evt_crit1":        "d1b0a10fe00794e79a0449729443cc716e05c47343de696c1ce520371f65125d",
	"evt_outcome1":     "628b61b3e0ea0c16fd3dcd659630549d0a302e2c899c8d90d85a008d1cca099d",
	"evt_den1":         "3f01ae847af32829fc4d3f011de4c3367d417aed5913552e8c7f5011cfca9520",
	"evt_mk1":          "33bdea81b5ab3d2a0c9303e98a921120d2cd1032a96127dcdb9881c306d979ac",
}

// TestV1DigestCompatibility_GoldenVectorsUnchanged is the mechanical §13 proof: every
// pre-v2 v1 fixture retains the EXACT same canonical digest after the v2 change, and its
// canonical encoding never contains a "shadow" key. Mutation: dropping `omitempty` from
// Event.Shadow, or reordering/renaming any v1 field, changes a digest and fails here.
func TestV1DigestCompatibility_GoldenVectorsUnchanged(t *testing.T) {
	fixtures := goldenV1Fixtures()
	if len(fixtures) != len(goldenV1Digests) {
		t.Fatalf("fixture count %d != golden count %d", len(fixtures), len(goldenV1Digests))
	}
	for _, e := range fixtures {
		if e.SchemaVersion != SchemaVersionV1 {
			t.Fatalf("%s: fixture is not v1 (schema %d)", e.EventID, e.SchemaVersion)
		}
		want, ok := goldenV1Digests[e.EventID]
		if !ok {
			t.Fatalf("%s: no golden digest", e.EventID)
		}
		got, err := e.Digest()
		if err != nil {
			t.Fatalf("%s: digest: %v", e.EventID, err)
		}
		if got != want {
			t.Fatalf("%s: v1 digest changed\n  got  %s\n  want %s\n"+
				"a v1 event's on-disk identity moved — durable v1 evidence would misverify", e.EventID, got, want)
		}
		cb, err := e.CanonicalBytes()
		if err != nil {
			t.Fatalf("%s: canonical: %v", e.EventID, err)
		}
		if strings.Contains(string(cb), `"shadow"`) {
			t.Fatalf("%s: a v1 event's canonical encoding must never contain a shadow key: %s", e.EventID, cb)
		}
	}
}

// goldenV1Fixtures is a spread of representative, structurally-valid v1 events across
// phases/criticalities/partitions with the full sub-evidence populated. It is fixed:
// changing it invalidates the golden vectors and defeats the compatibility proof.
func goldenV1Fixtures() []Event {
	base := func(id string) Event {
		return Event{
			SchemaVersion: 1, EventID: "evt_" + id, Phase: PhaseDecision,
			Criticality: CritOrdinary, Partition: PartOrd, Capability: CapGateway,
			ActionClass: ActionClassRead, NodeID: "node-1", DomainID: "dom-1",
			TimeUnixNano: 1730000000000000000, ReplayID: "rpl_" + id, CorrelationID: "cor_" + id,
			SnapshotHash: "snaphash",
			Identity: IdentityEvidence{
				Tenant: "acme", PrincipalID: "p1", PrincipalType: "human",
				AgentID: "ag1", ClientID: "cl1", ServerID: "srv1", ToolName: "t1",
				ToolFingerprint: "fp1", Assurance: "high", SenderBinding: "mtls",
				SessionCorrelation: "sess", Chain: []ChainLink{{Kind: "human", ID: "h1"}},
			},
			Decision: DecisionEvidence{
				Action: "ALLOW", ReasonCode: "MCP.POLICY.OK", PolicyRevision: 7,
				CatalogRevision: 3, RegistryRevision: 2, InspectionRevision: 1,
				RuntimeRevision: 4, ConfigEpoch: 9, PolicySnapshotHash: "psh",
				OperationClass: "read", RiskClass: "read", ExecutionState: "not_implemented",
				Obligations: []string{"logging:standard"},
			},
			Inspection: InspectionEvidence{SchemaStatus: "valid", MaxSeverity: "none"},
			Credential: CredentialEvidence{ProfileID: "prof1", ProviderID: "prov1"},
		}
	}
	shadow := base("shadowlegacy")
	shadow.Decision.ExecutionState = "shadow_evaluated" // legacy v1 shadow marker, no sub-facts

	crit := base("crit1")
	crit.Criticality = CritCritical
	crit.Partition = PartCrit
	crit.ActionClass = ActionClassWrite
	crit.Decision.Action = "ALLOW"
	crit.Decision.OperationClass = "write"
	crit.Decision.RiskClass = "write"

	outcome := base("outcome1")
	outcome.Phase = PhaseOutcome
	outcome.Outcome = &OutcomeEvidence{DecisionRef: "evt_crit1", Executed: true, StatusClass: "2xx"}

	denial := Event{
		SchemaVersion: 1, EventID: "evt_den1", Phase: PhaseDenialAggregate,
		Criticality: CritDenial, Partition: PartDen, Capability: CapGateway,
		ActionClass: ActionClassNone, NodeID: "node-1", DomainID: "dom-1",
		TimeUnixNano: 1730000000000000000, ReplayID: "rpl_den1", CorrelationID: "cor_den1",
		Denial: &DenialEvidence{
			DenialReason: "auth_failed", SourceBucket: "b1", Count: 5,
			FirstSeenUnixNano: 1730000000000000000, LastSeenUnixNano: 1730000000000000001,
		},
	}
	marker := Event{
		SchemaVersion: 1, EventID: "evt_mk1", Phase: PhaseRecoveryMarker,
		Criticality: CritOrdinary, Partition: PartOrd, Capability: CapManagement,
		ActionClass: ActionClassNone, NodeID: "node-1", DomainID: "dom-1",
		TimeUnixNano: 1730000000000000000, ReplayID: "rpl_mk1", CorrelationID: "cor_mk1",
		Marker: &MarkerEvidence{State: "degraded", Scope: "P-CRIT", Reason: "disk"},
	}
	return []Event{base("ord1"), shadow, crit, outcome, denial, marker}
}
