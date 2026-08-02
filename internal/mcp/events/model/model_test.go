package model

import (
	"errors"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// baseDecision returns a minimal valid critical decision event.
func baseDecision() Event {
	return Event{
		SchemaVersion: SchemaVersion,
		EventID:       "evt_0001",
		Phase:         PhaseDecision,
		Criticality:   CritCritical,
		Partition:     PartCrit,
		Capability:    CapGateway,
		ActionClass:   ActionClassWrite,
		NodeID:        "dp-1",
		DomainID:      "dp-1|gateway|P-CRIT",
		TimeUnixNano:  1,
		ReplayID:      "rpl_0001",
		CorrelationID: "cor_0001",
		Identity:      IdentityEvidence{Tenant: "acme", PrincipalID: "user-1", PrincipalType: "human"},
		Decision:      DecisionEvidence{Action: "ALLOW", ReasonCode: "MCP.POLICY.OK", PolicyRevision: 1, CatalogRevision: 1},
	}
}

func mustReason(t *testing.T, err error, want mcperr.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error %v, got nil", want)
	}
	if got := mcperr.ReasonOf(err); got != want {
		t.Fatalf("reason = %v, want %v", got, want)
	}
}

func TestValidDecisionEvent(t *testing.T) {
	e := baseDecision()
	if err := e.Validate(); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
}

func TestUnknownSchemaVersionRejected(t *testing.T) {
	e := baseDecision()
	e.SchemaVersion = 999
	mustReason(t, e.Validate(), mcperr.ReasonEventSchemaVersion)
}

func TestCapabilityAbsentRejected(t *testing.T) {
	e := baseDecision()
	e.Capability = CapNone
	mustReason(t, e.Validate(), mcperr.ReasonEventInvalid)
}

func TestCriticalRoutedOutsidePCRIT(t *testing.T) {
	e := baseDecision()
	e.Partition = PartOrd // critical must be P-CRIT
	mustReason(t, e.Validate(), mcperr.ReasonEventPartitionMismatch)
}

func TestDenialRoutedIntoPCRIT(t *testing.T) {
	e := Event{
		SchemaVersion: SchemaVersion, EventID: "evt_9", Phase: PhaseDenialAggregate,
		Criticality: CritDenial, Partition: PartCrit, Capability: CapGateway,
		NodeID: "dp-1", DomainID: "d", TimeUnixNano: 1, ReplayID: "rpl_9", CorrelationID: "cor_9",
		Denial: &DenialEvidence{DenialReason: "auth", SourceBucket: "ip:1", Count: 1, FirstSeenUnixNano: 1, LastSeenUnixNano: 2},
	}
	mustReason(t, e.Validate(), mcperr.ReasonEventPartitionMismatch)
}

func TestCriticalWithoutActionClassBinding(t *testing.T) {
	e := baseDecision()
	e.ActionClass = ActionClassNone
	mustReason(t, e.Validate(), mcperr.ReasonEventEvidenceMissing)
}

func TestOrdinaryWithCriticalActionClass(t *testing.T) {
	e := baseDecision()
	e.Criticality = CritOrdinary
	e.Partition = PartOrd
	// still ActionClassWrite → mismatch
	mustReason(t, e.Validate(), mcperr.ReasonEventPartitionMismatch)
}

func TestOutcomeRequiresCommittedDecisionRef(t *testing.T) {
	e := baseDecision()
	e.Phase = PhaseOutcome
	e.Criticality = CritOrdinary
	e.Partition = PartOrd
	e.ActionClass = ActionClassRead
	e.Outcome = &OutcomeEvidence{Executed: true} // no DecisionRef
	mustReason(t, e.Validate(), mcperr.ReasonEventEvidenceMissing)
	e.Outcome.DecisionRef = "evt_0001"
	if err := e.Validate(); err != nil {
		t.Fatalf("outcome with decision ref rejected: %v", err)
	}
}

func TestAuthenticatedEventRequiresTenant(t *testing.T) {
	e := baseDecision()
	e.Identity.Tenant = ""
	mustReason(t, e.Validate(), mcperr.ReasonEventTenantConflict)
}

func TestDecisionEvidenceRequired(t *testing.T) {
	e := baseDecision()
	e.Decision.Action = ""
	mustReason(t, e.Validate(), mcperr.ReasonEventEvidenceMissing)
}

func TestMalformedIDsRejected(t *testing.T) {
	for _, tc := range []struct{ mut func(*Event) }{
		{func(e *Event) { e.EventID = "0001" }},          // missing prefix
		{func(e *Event) { e.EventID = "evt_" }},          // empty body
		{func(e *Event) { e.EventID = "evt_bad space" }}, // bad charset
		{func(e *Event) { e.ReplayID = "x_0001" }},       // wrong prefix
		{func(e *Event) { e.CorrelationID = "bad" }},     // wrong prefix
	} {
		e := baseDecision()
		tc.mut(&e)
		mustReason(t, e.Validate(), mcperr.ReasonEventCorrelationMalformed)
	}
}

func TestDenialAggregateValidation(t *testing.T) {
	base := Event{
		SchemaVersion: SchemaVersion, EventID: "evt_d", Phase: PhaseDenialAggregate,
		Criticality: CritDenial, Partition: PartDen, Capability: CapGateway,
		NodeID: "dp-1", DomainID: "d", TimeUnixNano: 1, ReplayID: "rpl_d", CorrelationID: "cor_d",
		Denial: &DenialEvidence{DenialReason: "auth_failed", SourceBucket: "ip:203.0.113.0", Count: 5, FirstSeenUnixNano: 10, LastSeenUnixNano: 20},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid denial aggregate rejected: %v", err)
	}
	// zero count
	e := base
	d := *base.Denial
	d.Count = 0
	e.Denial = &d
	mustReason(t, e.Validate(), mcperr.ReasonEventEvidenceMissing)
	// last < first
	e = base
	d = *base.Denial
	d.LastSeenUnixNano = 5
	e.Denial = &d
	mustReason(t, e.Validate(), mcperr.ReasonEventInvalid)
}

func TestDigestDeterministicAndVerifies(t *testing.T) {
	e := baseDecision()
	d1, err := e.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	// A canonically identical event yields the identical digest.
	e2 := baseDecision()
	d2, err := e2.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("digest not deterministic: %q vs %q", d1, d2)
	}
	if !e.VerifyDigest() {
		t.Fatal("VerifyDigest failed for freshly computed digest")
	}
	// Mutating any content field changes the digest (tamper evidence).
	e.Decision.Action = "DENY"
	if e.VerifyDigest() {
		t.Fatal("VerifyDigest passed after content mutation")
	}
}

func TestDigestExcludesDigestField(t *testing.T) {
	e := baseDecision()
	if _, err := e.ComputeDigest(); err != nil {
		t.Fatal(err)
	}
	// Recomputing over the event that already carries the digest must reproduce
	// the same value (the digest field is excluded from its own input).
	again, err := e.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if again != e.EventDigest {
		t.Fatalf("digest not stable when field is populated: %q vs %q", again, e.EventDigest)
	}
}

func TestErrorsAreMCPErr(t *testing.T) {
	e := baseDecision()
	e.SchemaVersion = 2
	err := e.Validate()
	var me *mcperr.Error
	if !errors.As(err, &me) {
		t.Fatalf("want *mcperr.Error, got %T", err)
	}
}
