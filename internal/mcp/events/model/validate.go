package model

import (
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

const (
	// maxIDBytes bounds an event/replay/correlation id (safe charset, prefixed).
	maxIDBytes = 96
	// maxFieldBytes bounds any single safe string field, a cheap structural guard
	// independent of the per-event byte bound enforced with the limits.
	maxFieldBytes = 8192
)

func evtErr(r mcperr.Reason, detail string) error {
	return mcperr.New(r, "events.model.validate", detail)
}

// Validate reports whether the event is structurally valid and safe to persist.
// It enforces the EVENT-MODEL rejection rules: capability present, the
// (criticality → partition) binding, no critical routed outside P-CRIT, no denial
// routed into P-CRIT, no Gateway/Management mixing, required decision evidence,
// the critical action-class binding, an outcome event referencing a committed
// decision, well-formed ids, and a known schema version. Secret exclusion is
// STRUCTURAL (no field is a raw token); the events package adds a redaction
// backstop scan over the encoded event as defence in depth.
//
// No malformed event may partially publish: Validate is called before the event
// reaches the queue, and a non-nil error blocks persistence entirely.
func (e Event) Validate() error { //nolint:gocyclo,cyclop // a flat set of independent structural rejections
	if e.SchemaVersion != SchemaVersion {
		return evtErr(mcperr.ReasonEventSchemaVersion, "unknown schema version")
	}
	if !e.Phase.Valid() {
		return evtErr(mcperr.ReasonEventInvalid, "invalid phase")
	}
	if !e.Capability.Valid() {
		return evtErr(mcperr.ReasonEventInvalid, "capability absent or invalid")
	}
	if !e.Criticality.Valid() {
		return evtErr(mcperr.ReasonEventInvalid, "invalid criticality")
	}
	if !e.Partition.Valid() {
		return evtErr(mcperr.ReasonEventInvalid, "invalid partition")
	}
	// The (criticality → partition) binding is mechanical: a critical event can
	// never route outside P-CRIT, and a denial can never route into P-CRIT.
	if e.Criticality.ExpectedPartition() != e.Partition {
		return evtErr(mcperr.ReasonEventPartitionMismatch, "criticality/partition mismatch")
	}
	if err := checkID("event_id", "evt_", e.EventID); err != nil {
		return err
	}
	if err := checkID("replay_id", "rpl_", e.ReplayID); err != nil {
		return err
	}
	if err := checkID("correlation_id", "cor_", e.CorrelationID); err != nil {
		return err
	}
	if e.NodeID == "" || len(e.NodeID) > maxFieldBytes {
		return evtErr(mcperr.ReasonEventInvalid, "node id missing or over-bound")
	}
	if e.DomainID == "" || len(e.DomainID) > maxFieldBytes {
		return evtErr(mcperr.ReasonEventInvalid, "domain id missing or over-bound")
	}
	if e.TimeUnixNano <= 0 {
		return evtErr(mcperr.ReasonEventInvalid, "timestamp missing")
	}
	if err := e.validateFieldBounds(); err != nil {
		return err
	}
	if err := e.validatePhase(); err != nil {
		return err
	}
	return nil
}

// validatePhase enforces per-phase evidence requirements and the
// criticality/action-class coupling by delegating to a per-phase helper.
func (e Event) validatePhase() error {
	switch e.Phase {
	case PhaseDecision, PhaseOutcome:
		return e.validateDecisionPhase()
	case PhaseDenialAggregate:
		return e.validateDenialPhase()
	case PhaseRecoveryMarker, PhaseHealth:
		if e.Marker == nil || e.Marker.State == "" {
			return evtErr(mcperr.ReasonEventEvidenceMissing, "marker event without marker state")
		}
	}
	return nil
}

// validateDecisionPhase validates a decision or outcome event: authenticated
// identity, decision evidence, the criticality/action-class coupling, and (for an
// outcome) a committed decision reference.
func (e Event) validateDecisionPhase() error {
	if e.Identity.Tenant == "" {
		return evtErr(mcperr.ReasonEventTenantConflict, "authenticated event without tenant")
	}
	if e.Identity.PrincipalID == "" {
		return evtErr(mcperr.ReasonEventEvidenceMissing, "authenticated event without principal")
	}
	if e.Denial != nil {
		return evtErr(mcperr.ReasonEventInvalid, "denial evidence on a non-denial event")
	}
	if e.Decision.Action == "" || e.Decision.ReasonCode == "" {
		return evtErr(mcperr.ReasonEventEvidenceMissing, "decision evidence missing action/reason")
	}
	if e.Criticality == CritCritical && !e.ActionClass.IsCritical() {
		return evtErr(mcperr.ReasonEventEvidenceMissing, "critical decision lacks an action-class binding")
	}
	if e.Criticality == CritOrdinary && e.ActionClass.IsCritical() {
		return evtErr(mcperr.ReasonEventPartitionMismatch, "critical action class on an ordinary event")
	}
	if e.Phase == PhaseOutcome {
		if e.Outcome == nil {
			return evtErr(mcperr.ReasonEventEvidenceMissing, "outcome event without outcome evidence")
		}
		// An outcome event MUST reference a committed decision; it never replaces
		// the pre-execution decision commit.
		if err := checkID("decision_ref", "evt_", e.Outcome.DecisionRef); err != nil {
			return evtErr(mcperr.ReasonEventEvidenceMissing, "outcome event without a committed decision ref")
		}
	} else if e.Outcome != nil {
		return evtErr(mcperr.ReasonEventInvalid, "outcome evidence on a non-outcome event")
	}
	return nil
}

// validateDenialPhase validates a coalesced denial aggregate. Tenant attribution
// is NOT structurally required or forbidden here: the aggregator sets it only when
// verified identity existed and never invents it pre-identity (that rule is owned
// and tested by the aggregator).
func (e Event) validateDenialPhase() error {
	if e.Criticality != CritDenial {
		return evtErr(mcperr.ReasonEventPartitionMismatch, "denial aggregate must be criticality denial")
	}
	if e.Denial == nil {
		return evtErr(mcperr.ReasonEventEvidenceMissing, "denial aggregate without denial evidence")
	}
	if e.Denial.DenialReason == "" || e.Denial.SourceBucket == "" {
		return evtErr(mcperr.ReasonEventEvidenceMissing, "denial aggregate missing reason/source")
	}
	if e.Denial.Count == 0 {
		return evtErr(mcperr.ReasonEventEvidenceMissing, "denial aggregate with zero count")
	}
	if e.Denial.FirstSeenUnixNano <= 0 || e.Denial.LastSeenUnixNano < e.Denial.FirstSeenUnixNano {
		return evtErr(mcperr.ReasonEventInvalid, "denial aggregate with invalid first/last seen")
	}
	if e.Outcome != nil {
		return evtErr(mcperr.ReasonEventInvalid, "outcome evidence on a denial aggregate")
	}
	return nil
}

// validateFieldBounds bounds every safe string field so a single over-large
// field cannot slip past the per-event byte bound before it is encoded.
func (e Event) validateFieldBounds() error {
	for _, s := range []string{
		e.SnapshotHash, e.Identity.Tenant, e.Identity.PrincipalID, e.Identity.PrincipalType,
		e.Identity.AgentID, e.Identity.ClientID, e.Identity.ServerID, e.Identity.ToolName,
		e.Identity.ToolFingerprint, e.Identity.ResourceRef, e.Identity.ResourceHash,
		e.Identity.Assurance, e.Identity.SenderBinding, e.Identity.SessionCorrelation,
		e.Decision.Action, e.Decision.ReasonCode, e.Decision.MatchedRuleID,
		e.Decision.DecisiveConditionID, e.Decision.Remediation, e.Decision.PolicySnapshotHash,
		e.Decision.OperationClass, e.Decision.RiskClass, e.Decision.ExecutionState,
		e.Inspection.SchemaStatus, e.Inspection.OutputSchemaStatus, e.Inspection.MaxSeverity,
		e.Inspection.DLPDisposition, e.Inspection.DestinationClass, e.Inspection.PinEvidenceHash,
		e.Inspection.RedirectStatus, e.Inspection.OriginalHash, e.Inspection.TransformedHash,
		e.Inspection.RedactionProfile, e.Credential.ProfileID, e.Credential.ProviderID,
		e.Credential.PlannedKind, e.Credential.PowerCeiling, e.Credential.PlanID, e.Credential.CacheState,
	} {
		if len(s) > maxFieldBytes {
			return evtErr(mcperr.ReasonEventTooLarge, "a safe field exceeds its structural bound")
		}
	}
	for _, l := range e.Identity.Chain {
		if len(l.Kind) > maxFieldBytes || len(l.ID) > maxFieldBytes {
			return evtErr(mcperr.ReasonEventTooLarge, "a chain link exceeds its structural bound")
		}
	}
	return nil
}

// checkID validates a prefixed, bounded, safe-charset identifier. IDs are safe
// correlation handles, never security tokens, and must be non-empty, carry the
// expected prefix, and contain only [0-9A-Za-z_-].
func checkID(field, prefix, s string) error {
	if s == "" {
		return evtErr(mcperr.ReasonEventCorrelationMalformed, field+" missing")
	}
	if len(s) > maxIDBytes {
		return evtErr(mcperr.ReasonEventCorrelationMalformed, field+" over-bound")
	}
	if !strings.HasPrefix(s, prefix) {
		return evtErr(mcperr.ReasonEventCorrelationMalformed, field+" bad prefix")
	}
	body := s[len(prefix):]
	if body == "" {
		return evtErr(mcperr.ReasonEventCorrelationMalformed, field+" empty body")
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		ok := (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == '-'
		if !ok {
			return evtErr(mcperr.ReasonEventCorrelationMalformed, field+" bad charset")
		}
	}
	return nil
}
