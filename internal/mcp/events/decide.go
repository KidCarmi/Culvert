package events

import (
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/redaction"
)

// DecisionFacts are the sanitized, already-safe fields the runtime maps from a
// live policy.Decision / inspection.Summary / identity.ResolvedContext (the
// mapping helpers live in adapt.go). The manager never receives a policy, token,
// argument or output object — only these typed facts — so a secret cannot reach
// the event through this API by construction. The redaction scrubber runs as a
// BACKSTOP over the encoded event before commit.
type DecisionFacts struct {
	Capability  model.Capability
	Criticality model.Criticality
	ActionClass model.ActionClass

	Identity   model.IdentityEvidence
	Decision   model.DecisionEvidence
	Inspection model.InspectionEvidence
	Credential model.CredentialEvidence
	// Shadow, when non-nil, carries the durable Shadow enforcement prediction. Its
	// presence makes the built event a SchemaVersionV2 Shadow decision event; every
	// other event stays v1 (buildEvent). It is set ONLY by the Shadow evaluator's
	// shadowDecisionFacts, from the SAME ShadowDecision returned to the client.
	Shadow *model.ShadowEvidence

	// Outcome, when non-nil, carries the post-execution / send-intent evidence
	// (attempt identity, reservation binding, activation generation, physical send
	// state). It is set for PhaseSendIntent and PhaseOutcome events.
	Outcome *model.OutcomeEvidence
	// Reconciliation, when non-nil, carries append-only witness-reconciliation
	// evidence. Set only for PhaseReconciliation events.
	Reconciliation *model.ReconciliationEvidence
	// Phase selects the event phase. The zero value is PhaseDecision, so every
	// existing caller is byte-identical; PhaseSendIntent and PhaseOutcome are set
	// explicitly by the execution path.
	Phase model.Phase

	SnapshotHash  string
	CorrelationID string // optional; generated when empty
}

// CommitDecision constructs a sanitized decision event from facts, runs the
// redaction backstop, and DURABLY COMMITS it to the correct partition. On success
// it returns an unforgeable receipt (evidence a future execution stage may
// proceed) — the runtime still returns execution_state "not_implemented". On a
// critical commit failure it drives the domain into critical-durability-degraded
// (fail closed) and returns a classified error; a critical operation whose event
// cannot commit MUST NOT proceed. An ordinary commit failure applies the low-risk
// loss policy (recorded, never silent).
func (m *Manager) CommitDecision(f DecisionFacts) (spool.CommitReceipt, error) {
	d, err := m.domainFor(f.Capability)
	if err != nil {
		return spool.CommitReceipt{}, err
	}
	// A degraded critical domain fails a new critical operation closed BEFORE any
	// event construction — no durable receipt is minted in a degraded domain.
	if f.Criticality == model.CritCritical && !d.state.WriteAllowedCritical() {
		return spool.CommitReceipt{}, mgrErr(mcperr.ReasonEventDurabilityDegraded, "critical domain degraded")
	}

	e := m.buildEvent(d, f)
	if err := e.Validate(); err != nil {
		return spool.CommitReceipt{}, err
	}
	if err := backstopScan(e); err != nil {
		return spool.CommitReceipt{}, err
	}
	if _, err := e.ComputeDigest(); err != nil {
		return spool.CommitReceipt{}, mgrErr(mcperr.ReasonEventInvalid, "digest")
	}

	d.pendingCrit.Add(pendingWeight(f.Criticality))
	rec, cerr := d.spool.Commit(e)
	d.pendingCrit.Add(-pendingWeight(f.Criticality))
	if cerr != nil {
		return spool.CommitReceipt{}, m.onCommitFailure(d, f.Criticality, cerr)
	}
	d.commitOK.Add(1)
	return rec, nil
}

// buildEvent assembles the immutable event envelope from facts, stamping ids,
// timestamp, node and domain.
func (m *Manager) buildEvent(d *domain, f DecisionFacts) *model.Event {
	part := f.Criticality.ExpectedPartition()
	corr := f.CorrelationID
	if corr == "" {
		corr = randID("cor_")
	}
	// A Shadow decision event (carrying ShadowEvidence) is stamped SchemaVersionV2 — the
	// only events that are v2 — and an attempt-evidence event SchemaVersionV3 (below,
	// derived from the assembled event). Every other event stays the default v1, so its
	// canonical digest is unchanged (SHADOW-EVIDENCE-ROUTING-1 §5, smallest
	// compatibility-safe model).
	schema := model.SchemaVersion
	if f.Shadow != nil {
		schema = model.SchemaVersionV2
	}
	// The zero Phase means PhaseDecision, preserving every pre-existing caller.
	phase := f.Phase
	if phase == model.PhaseNone {
		phase = model.PhaseDecision
	}
	ev := &model.Event{
		SchemaVersion:  schema,
		EventID:        randID("evt_"),
		Phase:          phase,
		Criticality:    f.Criticality,
		Partition:      part,
		Capability:     f.Capability,
		ActionClass:    f.ActionClass,
		NodeID:         m.nodeID,
		DomainID:       d.spool.DomainID(part),
		TimeUnixNano:   m.clock().UnixNano(),
		ReplayID:       randID("rpl_"),
		CorrelationID:  corr,
		SnapshotHash:   f.SnapshotHash,
		Identity:       f.Identity,
		Decision:       f.Decision,
		Inspection:     f.Inspection,
		Credential:     f.Credential,
		Outcome:        f.Outcome,
		Reconciliation: f.Reconciliation,
		Shadow:         f.Shadow,
	}
	// The attempt-evidence stamp is derived from the EVENT, not from the facts, so
	// the version can never disagree with the shape that is actually about to be
	// canonicalized and digested. A record carrying v3 fields under a v1 stamp reads
	// back on an older build as spool corruption rather than as an unsupported
	// schema — see model.CarriesAttemptEvidence.
	if ev.CarriesAttemptEvidence() {
		ev.SchemaVersion = model.SchemaVersionV3
	}
	return ev
}

// onCommitFailure classifies a commit failure by criticality and drives the state
// machine. A critical failure enters critical-durability-degraded (distinct
// counter); an ordinary failure applies the low-risk loss policy (recorded).
func (m *Manager) onCommitFailure(d *domain, crit model.Criticality, cause error) error {
	d.commitFail.Add(1)
	if crit == model.CritCritical {
		_ = d.state.OnCriticalCommitFailure(d.spool.DomainID(model.PartCrit), mcperr.ReasonOf(cause).Code())
		return mcperr.Wrap(mcperr.ReasonEventDurabilityDegraded, "events.manager", "critical event not durable", cause)
	}
	// Ordinary: low-risk loss policy — recorded and counted, never silent.
	d.ordinaryLoss.Add(1)
	return cause
}

// pendingWeight is the criterion-4 backlog weight of an in-flight commit.
func pendingWeight(c model.Criticality) int64 {
	if c == model.CritCritical {
		return 1
	}
	return 0
}

// backstopScan is the defence-in-depth redaction check. Structural exclusion is
// the primary guarantee (the event is a typed, secret-free envelope), but the
// scrubber runs over the encoded event as a backstop: if it detects any secret
// pattern in a field, the event is rejected rather than persisted.
func backstopScan(e *model.Event) error {
	b, err := e.Marshal()
	if err != nil {
		return mgrErr(mcperr.ReasonEventInvalid, "marshal for backstop")
	}
	if _, _, n := redaction.ScrubDetailDefault(string(b)); n > 0 {
		return mgrErr(mcperr.ReasonEventSecretPresent, "redaction backstop detected secret material")
	}
	return nil
}
