package spool

import (
	"os"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

// shadowV2Event returns a valid SchemaVersionV2 Shadow decision event (a write-class
// tools/call, the realistic shape) with its digest computed.
func shadowV2Event(id string) *model.Event {
	e := &model.Event{
		SchemaVersion: model.SchemaVersionV2, EventID: "evt_" + id, Phase: model.PhaseDecision,
		Criticality: model.CritCritical, Partition: model.PartCrit, Capability: model.CapGateway,
		ActionClass: model.ActionClassWrite, NodeID: "dp-test", DomainID: "d",
		TimeUnixNano: 1000, ReplayID: "rpl_" + id, CorrelationID: "cor_" + id,
		Identity: model.IdentityEvidence{Tenant: "acme", PrincipalID: "p1", PrincipalType: "human"},
		Decision: model.DecisionEvidence{
			Action: "ALLOW", ReasonCode: "MCP.POLICY.OK", PolicyRevision: 7, CatalogRevision: 3,
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

// TestShadowV2_RecoverRoundTripPreservesEvidence is the §8/§10 durable round-trip: a v2
// Shadow event committed, then read back after a fresh open+Recover, carries the complete
// ShadowEvidence and re-verifies its digest — the durable record survives restart with the
// same facts the client saw at request time.
func TestShadowV2_RecoverRoundTripPreservesEvidence(t *testing.T) {
	root := t.TempDir()
	s := newTestSpool(t, root)
	want := shadowV2Event("sh01")
	if _, err := s.Commit(want); err != nil {
		t.Fatalf("commit v2 shadow event: %v", err)
	}

	// Fresh open + recover (simulates a restart).
	s2 := newTestSpool(t, root)
	if _, err := s2.Recover(); err != nil {
		t.Fatalf("recover: %v", err)
	}
	evs, _, _, err := s2.CommittedForExport(model.PartCrit, 0, 100)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var got *model.Event
	for i := range evs {
		if evs[i].EventID == want.EventID {
			got = &evs[i]
		}
	}
	if got == nil {
		t.Fatal("the committed v2 shadow event did not survive recovery")
	}
	if got.SchemaVersion != model.SchemaVersionV2 {
		t.Fatalf("recovered schema = %d, want v2", got.SchemaVersion)
	}
	if got.Shadow == nil {
		t.Fatal("recovered v2 event lost its ShadowEvidence")
	}
	if *got.Shadow != *want.Shadow {
		t.Fatalf("ShadowEvidence changed across recovery\n  got  %+v\n  want %+v", *got.Shadow, *want.Shadow)
	}
	if !got.VerifyDigest() {
		t.Fatal("recovered v2 event fails digest verification")
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("recovered v2 event fails validation: %v", err)
	}
}

// TestShadowV2_MixedV1V2HistoryRecovers proves a segment holding BOTH v1 and v2 events
// recovers cleanly and preserves each event's schema and shadow presence/absence.
func TestShadowV2_MixedV1V2HistoryRecovers(t *testing.T) {
	root := t.TempDir()
	s := newTestSpool(t, root)
	v1 := criticalEvent("v1a", "x")  // v1, no shadow
	v2 := shadowV2Event("v2a")       // v2, shadow
	v1b := criticalEvent("v1b", "y") // v1 again, after a v2
	for _, e := range []*model.Event{v1, v2, v1b} {
		if _, err := s.Commit(e); err != nil {
			t.Fatalf("commit %s: %v", e.EventID, err)
		}
	}
	s2 := newTestSpool(t, root)
	if _, err := s2.Recover(); err != nil {
		t.Fatalf("recover mixed history: %v", err)
	}
	evs, _, _, err := s2.CommittedForExport(model.PartCrit, 0, 100)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	byID := map[string]model.Event{}
	for _, e := range evs {
		byID[e.EventID] = e
	}
	if e, ok := byID["evt_v1a"]; !ok || e.SchemaVersion != model.SchemaVersionV1 || e.Shadow != nil {
		t.Fatalf("v1 event recovered wrong: %+v (present=%v)", byID["evt_v1a"], ok)
	}
	if e, ok := byID["evt_v2a"]; !ok || e.SchemaVersion != model.SchemaVersionV2 || e.Shadow == nil {
		t.Fatalf("v2 event recovered wrong: present=%v", ok)
	}
	if e, ok := byID["evt_v1b"]; !ok || e.SchemaVersion != model.SchemaVersionV1 || e.Shadow != nil {
		t.Fatalf("second v1 event recovered wrong: present=%v", ok)
	}
}

// TestShadowV2_InteriorCorruptionOfShadowRecordFailsClosed proves a byte flipped inside a
// committed v2 shadow record is detected on recovery as corruption (fail closed) — the
// AEAD + digest chain protects the durable ShadowEvidence, never silently recovering it.
func TestShadowV2_InteriorCorruptionOfShadowRecordFailsClosed(t *testing.T) {
	root := t.TempDir()
	s := newTestSpool(t, root)
	if _, err := s.Commit(shadowV2Event("corrupt1")); err != nil {
		t.Fatalf("commit: %v", err)
	}
	seg := critSegPath(root)
	b, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	pos := segHeaderLen + recFixedPrefixLen + 3
	if pos >= len(b) {
		t.Fatalf("segment too small: %d", len(b))
	}
	b[pos] ^= 0xFF
	if err := os.WriteFile(seg, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := newTestSpool(t, root)
	rep, err := s2.Recover()
	if err != nil {
		t.Fatalf("recover returned error (want Corrupt flag): %v", err)
	}
	if !rep.Corrupt || rep.CorruptPartition != model.PartCrit {
		t.Fatalf("corruption of a v2 shadow record not detected: %+v", rep)
	}
}

// TestShadowV2_CommitRejectsMalformedShadowEvidence proves the write-time enforcement
// point: a v2 event that is missing or malformed shadow evidence is REJECTED at Commit and
// never reaches the durable spool (so a valid-digest-but-malformed record cannot exist on
// disk without the KEK). This is the primary fail-closed guarantee; the recovery-time
// ValidateShadowEvidence is defense-in-depth over the same model contract.
func TestShadowV2_CommitRejectsMalformedShadowEvidence(t *testing.T) {
	root := t.TempDir()
	s := newTestSpool(t, root)
	cases := map[string]func(*model.Event){
		"missing shadow evidence":  func(e *model.Event) { e.Shadow = nil },
		"unknown outcome":          func(e *model.Event) { e.Shadow.Outcome = "would_maybe" },
		"materialization ready":    func(e *model.Event) { e.Shadow.MaterializationReadiness = "ready" },
		"response inspection pass": func(e *model.Event) { e.Shadow.ResponseInspection = "would_pass" },
	}
	for name, mut := range cases {
		e := shadowV2Event("m")
		mut(e)
		_, _ = e.ComputeDigest() // a valid digest over malformed content
		if _, err := s.Commit(e); err == nil {
			t.Fatalf("%s: Commit must reject a malformed v2 shadow event, never persist it", name)
		}
	}
}
