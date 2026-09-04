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
	if !SupportedSchemaVersion(e.SchemaVersion) {
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
	if err := e.validateShadow(); err != nil {
		return err
	}
	if err := e.validateShadowWriteOnly(); err != nil {
		return err
	}
	if err := e.validateAttemptSchema(); err != nil {
		return err
	}
	return nil
}

// validateAttemptSchema enforces the v3 attempt-evidence pairing in BOTH directions:
// an event carrying attempt evidence must be stamped v3, and a v3 event must carry
// it. The forward direction is the load-bearing one — a record whose canonical bytes
// include fields its stamped version does not describe reads back on an older build
// as SPOOL CORRUPTION rather than as an unsupported schema, so a version rollback
// would raise the tampering alarm and abort recovery. The reverse direction keeps the
// version honest: a v3 stamp on an event with nothing v3 in it would silently make an
// ordinary record unreadable to a build that could otherwise have read it.
//
// Shadow (v2) and attempt evidence (v3) are mutually exclusive by construction: a
// Shadow evaluation never sends anything, so it has no attempt to identify. That is
// asserted rather than assumed — the two stamps are single-valued, so an event
// carrying both shapes could only be recorded under one of them.
func (e Event) validateAttemptSchema() error {
	carries := e.CarriesAttemptEvidence()
	if carries && e.Shadow != nil {
		return evtErr(mcperr.ReasonEventInvalid, "shadow evidence on an attempt-evidence event")
	}
	switch {
	case carries && e.SchemaVersion != SchemaVersionV3:
		return evtErr(mcperr.ReasonEventInvalid, "attempt evidence requires schema v3")
	case !carries && e.SchemaVersion == SchemaVersionV3:
		return evtErr(mcperr.ReasonEventInvalid, "schema v3 requires attempt evidence")
	}
	return nil
}

// ValidateEvidenceSchema is the NARROW, recovery-scoped version pairing check, the
// attempt-evidence sibling of ValidateShadowEvidence. The spool applies it to a
// digest-verified record so a stamp/shape disagreement is reported as the schema
// fault it is, instead of being silently accepted into recovery.
func (e Event) ValidateEvidenceSchema() error { return e.validateAttemptSchema() }

// validateShadowWriteOnly rejects shapes that must never be PRODUCED, even though a legacy
// instance of them may still be READ. Validate runs only on the write/commit path
// (CommitDecision, spool.Commit); recovery uses ValidateShadowEvidence, which does NOT run
// this. So this is the write-time-only guard: a NEW shadow event must be a complete
// SchemaVersionV2 record (Shadow present), never a bare v1 "shadow_evaluated" marker with no
// durable verdict. A legacy v1 marker written by a pre-v2 binary stays readable on recovery;
// this only stops an adapter regression or another producer from persisting incomplete Shadow
// evidence going forward (SHADOW-EVIDENCE-ROUTING-1, Codex P2 PR #1235).
func (e Event) validateShadowWriteOnly() error {
	if e.SchemaVersion == SchemaVersionV1 && e.Decision.ExecutionState == shadowExecutionState {
		return evtErr(mcperr.ReasonEventInvalid, "a new shadow event must be schema v2 with complete evidence, not a bare v1 marker")
	}
	return nil
}

// Bounded ShadowEvidence enum vocabularies (SHADOW-EVIDENCE-ROUTING-1). These mirror
// the execution-package ShadowDecision producer exactly; an unknown value fails closed.
const (
	shadowExecutionState = "shadow_evaluated"

	shadowOutMaterializeNotEval = "not_evaluated"
	shadowRespInspectionNotEval = "not_evaluated"

	shadowReqInspWouldPass = "would_pass"
	shadowReqInspWouldFail = "would_fail"
	shadowReqInspNotEval   = "not_evaluated"

	shadowOutWouldExecute         = "would_execute"
	shadowOutWouldBlock           = "would_block"
	shadowOutWouldFailInspection  = "would_fail_inspection"
	shadowOutWouldFailHardControl = "would_fail_hard_control"
	shadowOutWouldFailStale       = "would_fail_stale_decision"
	shadowOutRequireApproval      = "would_require_approval"
	shadowOutRequireConfirm       = "would_require_confirmation"
	// gosec G101 matches a credential-like identifier; these are enum TOKENS, so the
	// names deliberately avoid the "credential" pattern (repo gosec convention).
	shadowOutWouldFailCredReady = "would_fail_credential_readiness"
	shadowPlanInvalid           = "credential_plan_invalid"
	shadowPlanNoPlanner         = "no_planner_composed"
	shadowPlanNone              = "no_credential_profile"
)

// shadowCredReadyFailPlans are the credential-plan statuses that a would_fail_credential_readiness
// outcome may carry: an invalid plan (planned and rejected), or no planner composed while a credential
// was required (the live executor fails closed rather than reach the upstream with no Authorization —
// Codex P2 round-6). Both are failure statuses in a biconditional with the fail outcome.
var shadowCredReadyFailPlans = map[string]struct{}{
	shadowPlanInvalid:   {},
	shadowPlanNoPlanner: {},
}

// shadowPrePlanningOutcomes are the outcomes decide() returns BEFORE the credential-readiness
// step (step 5): the pre-executor inspection hard-fail and hard control (step 1), the
// policy-class gates block/approval/confirmation (step 2), allowance denial (step 3), and the
// server-usability hard-fail (step 4). None of these reach credentialReadiness, so the plan
// stays at its unplanned default (no_credential_profile). A valid/invalid/no_planner status on
// one of these would falsely claim credential readiness was evaluated (Codex P2, PR #1235).
var shadowPrePlanningOutcomes = map[string]struct{}{
	shadowOutWouldBlock:           {},
	shadowOutRequireApproval:      {},
	shadowOutRequireConfirm:       {},
	shadowOutWouldFailInspection:  {},
	shadowOutWouldFailHardControl: {},
}

// Override is the durable, LEAF-SAFE projection of the policy action class: the producer
// sets ShadowOverride = !action.IsAllowClass() (shadow_evaluator.decide). It is the ONLY
// action-class fact the event pipeline carries — the leaf model/events packages deliberately
// do NOT import the policy action taxonomy (the same discipline rollout follows), so the
// Action STRING↔class binding stays owned by the producer that maps policy.Action → class.
// These two sets pin the Outcome→Override consistency that IS expressible in the leaf: an
// outcome reachable ONLY through the producer's allow-class path can never carry a restrictive
// Override, and an outcome emitted ONLY by a restrictive policy class can never carry a
// permissive one (SHADOW-EVIDENCE-ROUTING-1, Codex P2 PR #1235).
var shadowAllowClassOnlyOutcomes = map[string]struct{}{
	shadowOutWouldExecute:       {}, // decide() step 7: everything before the side effect passed
	shadowOutWouldFailCredReady: {}, // step 5: reached only after the policy class passed
	shadowOutWouldFailStale:     {}, // step 6: reached only after the policy class passed
}

var shadowRestrictiveClassOutcomes = map[string]struct{}{
	shadowOutRequireApproval: {}, // policyClassOutcome(Approval): non-allow class ⇒ Override true
	shadowOutRequireConfirm:  {}, // policyClassOutcome(Confirm): non-allow class ⇒ Override true
}

var shadowOutcomes = map[string]struct{}{
	"would_execute": {}, "would_block": {}, "would_require_approval": {},
	"would_require_confirmation": {}, "would_fail_credential_readiness": {},
	"would_fail_inspection": {}, "would_fail_stale_decision": {}, "would_fail_hard_control": {},
}

var shadowCredentialPlans = map[string]struct{}{
	"no_credential_profile": {}, "credential_plan_valid": {},
	"credential_plan_invalid": {}, "no_planner_composed": {},
}

var shadowRequestInspections = map[string]struct{}{
	shadowReqInspWouldPass: {}, shadowReqInspWouldFail: {}, shadowReqInspNotEval: {},
}

// ValidateShadowEvidence is the NARROW, evidence-scoped Shadow check the spool applies
// to a digest-verified record on recovery. It fails closed only on the ShadowEvidence
// contract this schema owns (schema/shadow consistency, enum membership, impossible
// combinations) and deliberately does NOT re-run the full structural Validate: recovery
// must never "repair" malformed evidence into valid evidence, and must never newly reject
// a pre-existing NON-shadow event (the v1 branch passes for a nil Shadow). The spool
// checks SupportedSchemaVersion separately for a clean unknown-schema signal.
func (e Event) ValidateShadowEvidence() error { return e.validateShadow() }

// validateShadow enforces the v1/v2 ShadowEvidence contract:
//   - a v1 event MUST NOT carry ShadowEvidence (a Shadow event is v2 by construction);
//   - a v2 event is a Shadow decision event: it MUST be a decision phase, carry
//     ExecutionState "shadow_evaluated", and carry a complete, valid ShadowEvidence;
//   - conversely ExecutionState "shadow_evaluated" MUST be a v2 event with ShadowEvidence
//     (a v1 "shadow_evaluated" marker is a legacy record and is only ever READ, never
//     produced by this build — see the v2 reader contract; it is not writable here).
//
// Every ShadowEvidence field is a bounded enum, and the architecturally-impossible
// combinations fail closed (§7): a Shadow evaluation never materializes and never has an
// upstream response, and would_execute is unreachable through a failing request inspection.
func (e Event) validateShadow() error {
	switch e.SchemaVersion {
	case SchemaVersionV1:
		// v1 never carries the new sub-facts. A legacy v1 "shadow_evaluated" marker is
		// tolerated on READ (no ShadowEvidence), but a v1 event with ShadowEvidence is
		// structurally impossible and must fail closed.
		if e.Shadow != nil {
			return evtErr(mcperr.ReasonEventInvalid, "shadow evidence on a v1 event")
		}
		return nil
	case SchemaVersionV2:
		return e.validateShadowV2()
	case SchemaVersionV3:
		// v3 is the attempt-evidence envelope. It never carries Shadow — the two are
		// mutually exclusive (validateAttemptSchema) — so the v1 rule applies verbatim.
		if e.Shadow != nil {
			return evtErr(mcperr.ReasonEventInvalid, "shadow evidence on a v3 event")
		}
		return nil
	default:
		// Unreachable: SupportedSchemaVersion already gated the version.
		return evtErr(mcperr.ReasonEventSchemaVersion, "unknown schema version")
	}
}

func (e Event) validateShadowV2() error {
	// A v2 event is a Shadow decision event by construction.
	if e.Phase != PhaseDecision {
		return evtErr(mcperr.ReasonEventInvalid, "v2 shadow event must be a decision phase")
	}
	if err := validateShadowRouting(e.Capability, e.Criticality); err != nil {
		return err
	}
	if e.Decision.ExecutionState != shadowExecutionState {
		return evtErr(mcperr.ReasonEventInvalid, "v2 shadow event must carry execution_state shadow_evaluated")
	}
	// shadow_evaluated + Shadow == nil -> invalid (§7): a Shadow event must carry the
	// complete durable evidence, never claim to be a shadow evaluation without it.
	sh := e.Shadow
	if sh == nil {
		return evtErr(mcperr.ReasonEventEvidenceMissing, "v2 shadow event without shadow evidence")
	}
	// The durable Override boolean is the producer's action-class projection: decide()
	// sets ShadowOverride = !action.IsAllowClass() over the SAME policy action that becomes
	// Decision.Action. Bind the two here so a v2 shadow event whose action and override
	// disagree is rejected at the write boundary — a restrictive action mislabelled as an
	// override-free (executable-class) decision, or the inverse. An action outside the known
	// nine-code taxonomy fails closed: the leaf model cannot classify it, so it cannot prove
	// the durable evidence is consistent (SHADOW-EVIDENCE-ROUTING-1, Codex round PR #1235).
	if err := validateShadowActionOverride(e.Decision.Action, sh.Override); err != nil {
		return err
	}
	if err := validateShadowGatedOutcomeAction(e.Decision.Action, sh.Outcome); err != nil {
		return err
	}
	if err := validateShadowRedactionOutcome(e.Decision.Action, sh.Outcome); err != nil {
		return err
	}
	if err := validateShadowBlockOutcome(e.Decision.Action, sh.Outcome); err != nil {
		return err
	}
	return validateShadowEvidenceFields(sh)
}

// validateShadowBlockOutcome binds would_block to the actions that can actually reach it. In the
// producer, would_block comes only from decide() step 2 (policyClassOutcome gates DENY/QUARANTINE
// via ActionKindDenied and ALLOW_WITH_REDACTION via ActionKindRedaction to it) or step 3 (an
// unsatisfied ALLOW_ONCE/ALLOW_FOR_SESSION allowance; needsAllowance is true only for those two).
// An unconditional ALLOW/MONITOR carries no allowance and continues past step 3, and
// REQUIRE_APPROVAL/REQUIRE_CONFIRMATION resolve to their own gate outcomes, so would_block on any
// of those four misstates an executable-or-gated decision as blocked. would_block stays Override-
// ambiguous (DENY/QUARANTINE are restrictive, the three allow-class sources are not), so this binds
// the ACTION, not the override (SHADOW-EVIDENCE-ROUTING-1, Codex round PR #1235). Runs on recovery
// too; a real v2 record always satisfies it.
func validateShadowBlockOutcome(action, outcome string) error {
	if outcome != shadowOutWouldBlock {
		return nil
	}
	if _, ok := shadowBlockReachableActions[action]; !ok {
		return evtErr(mcperr.ReasonEventInvalid, "would_block is unreachable for this action; the producer resolves it only for DENY/QUARANTINE, ALLOW_WITH_REDACTION, or an unsatisfied ALLOW_ONCE/ALLOW_FOR_SESSION allowance")
	}
	return nil
}

// validateShadowRedactionOutcome constrains ALLOW_WITH_REDACTION — the one ALLOW-CLASS action the
// live execution layer fails closed. In the producer mapAction(ALLOW_WITH_REDACTION) is
// ActionKindRedaction, which policyClassOutcome gates to would_block at step 2 (the guarded path
// performs no request-argument redaction), so it NEVER reaches the allow-path steps (5–7). Because
// it is allow-class the Action↔Override binding correctly pins Override=false — but that alone
// leaves the allow-path-only outcomes acceptable, letting an adapter regression present an action
// a fully-enforcing mode would BLOCK as executable. Its only reachable outcomes are would_block
// (step 2) and the step-1 hard-fails (would_fail_inspection / would_fail_hard_control), so reject
// any allow-path-only outcome (SHADOW-EVIDENCE-ROUTING-1, Codex round PR #1235). Runs on recovery
// too; a real v2 record always satisfies it.
func validateShadowRedactionOutcome(action, outcome string) error {
	if action != actionCodeAllowWithRedaction {
		return nil
	}
	if _, ok := shadowAllowClassOnlyOutcomes[outcome]; ok {
		return evtErr(mcperr.ReasonEventInvalid, "ALLOW_WITH_REDACTION cannot carry an allow-path outcome; a redaction action is gated to would_block")
	}
	return nil
}

// validateShadowGatedOutcomeAction binds the two policy-gating outcomes that have a 1:1
// correspondence with a single policy action to that EXACT action. In the producer,
// policyClassOutcome emits would_require_approval ONLY for REQUIRE_APPROVAL and
// would_require_confirmation ONLY for REQUIRE_CONFIRMATION, so a would_require_approval record
// carrying any other action (e.g. DENY) misstates a denial as an approval gate — and the
// class-only Action↔Override binding cannot catch it, because DENY and REQUIRE_APPROVAL are
// BOTH restrictive. would_block is deliberately NOT bound here: the producer emits it for
// DENY, QUARANTINE, ALLOW_WITH_REDACTION AND an allow-class allowance miss, so it maps to no
// single action (SHADOW-EVIDENCE-ROUTING-1, Codex round PR #1235). Runs on recovery too; a real
// v2 record always satisfies it.
func validateShadowGatedOutcomeAction(action, outcome string) error {
	switch outcome {
	case shadowOutRequireApproval:
		if action != actionCodeRequireApproval {
			return evtErr(mcperr.ReasonEventInvalid, "shadow would_require_approval must carry the REQUIRE_APPROVAL action")
		}
	case shadowOutRequireConfirm:
		if action != actionCodeRequireConfirmation {
			return evtErr(mcperr.ReasonEventInvalid, "shadow would_require_confirmation must carry the REQUIRE_CONFIRMATION action")
		}
	}
	return nil
}

// validateShadowRouting enforces that a v2 Shadow event is a GATEWAY ordinary/critical decision
// — never a Management event, never a denial aggregate. The producer only ever emits Shadow
// evidence for Gateway tool calls, routed by criticalityFor to P-ORD (read) or P-CRIT (write /
// destructive); a denial is the SEPARATE attacker-mintable lane (P-DEN, PhaseDenialAggregate) and
// Management is read-only with no Shadow decisions. The binary-downgrade runbook preserves the
// Management subtree and the Gateway P-DEN partition on EXACTLY this premise (they can never hold a
// v2 record), so a malformed producer landing a v2 Shadow event in either would silently defeat the
// documented cleanup and keep a pre-v2 restart failing. Reject it at the write/recovery boundary so
// the premise is a validated invariant, not an assumption (SHADOW-EVIDENCE-ROUTING-1, Codex round
// PR #1235). Runs on recovery too (ValidateShadowEvidence): a real v2 record always satisfies it, so
// only a malformed one is newly rejected.
func validateShadowRouting(capability Capability, crit Criticality) error {
	if capability != CapGateway {
		return evtErr(mcperr.ReasonEventInvalid, "v2 shadow event must be a Gateway capability event")
	}
	if crit != CritOrdinary && crit != CritCritical {
		return evtErr(mcperr.ReasonEventInvalid, "v2 shadow event must be an ordinary or critical Gateway decision, never a denial")
	}
	return nil
}

// validateShadowActionOverride binds the durable Override to the event's own policy action
// code via the model-local action-class classifier (which the cross-package parity wall pins
// to policy.Action.IsAllowClass()). An unknown action fails closed; a known action must
// carry Override == !isAllowClass(action). It deliberately does NOT infer that every
// allow-class action produces would_execute: ALLOW_WITH_REDACTION is allow-class at policy
// level but currently fails closed in the live execution layer, so the Outcome↔Override and
// Outcome↔sub-fact checks (validateShadowEvidenceFields) remain the authority on the outcome.
func validateShadowActionOverride(action string, override bool) error {
	isAllowClass, known := shadowActionClass(action)
	if !known {
		return evtErr(mcperr.ReasonEventInvalid, "v2 shadow event carries an unknown decision action")
	}
	if override != !isAllowClass {
		return evtErr(mcperr.ReasonEventInvalid, "shadow override must equal !isAllowClass(decision action)")
	}
	return nil
}

// validateShadowEvidenceFields fails closed on the ShadowEvidence value contract. It is
// split into enum/constant membership and cross-field combination checks only to keep each
// function under the cyclop threshold; the rules and their order are unchanged.
func validateShadowEvidenceFields(sh *ShadowEvidence) error {
	if err := validateShadowEvidenceEnums(sh); err != nil {
		return err
	}
	return validateShadowEvidenceCombinations(sh)
}

// validateShadowEvidenceEnums checks enum membership and the architectural not_evaluated
// constants (Shadow never materializes and never has an upstream response).
func validateShadowEvidenceEnums(sh *ShadowEvidence) error {
	if _, ok := shadowOutcomes[sh.Outcome]; !ok {
		return evtErr(mcperr.ReasonEventInvalid, "unknown shadow outcome")
	}
	if _, ok := shadowCredentialPlans[sh.CredentialPlan]; !ok {
		return evtErr(mcperr.ReasonEventInvalid, "unknown shadow credential plan")
	}
	if _, ok := shadowRequestInspections[sh.RequestInspection]; !ok {
		return evtErr(mcperr.ReasonEventInvalid, "unknown shadow request inspection")
	}
	if sh.MaterializationReadiness != shadowOutMaterializeNotEval {
		return evtErr(mcperr.ReasonEventInvalid, "shadow materialization_readiness must be not_evaluated")
	}
	if sh.ResponseInspection != shadowRespInspectionNotEval {
		return evtErr(mcperr.ReasonEventInvalid, "shadow response_inspection must be not_evaluated")
	}
	return nil
}

// validateShadowEvidenceCombinations fails closed on the impossible outcome↔sub-fact
// combinations and the outcome↔override consistency. Split into the sub-fact and override
// halves only to keep each function under the cyclop threshold; the rules are unchanged.
func validateShadowEvidenceCombinations(sh *ShadowEvidence) error {
	if err := validateShadowOutcomeSubfacts(sh); err != nil {
		return err
	}
	return validateShadowOutcomeOverride(sh)
}

// validateShadowOutcomeSubfacts pins the impossible outcome↔(inspection, credential-plan)
// combinations that mirror the producer (decide()):
//   - would_execute is unreachable when the request inspection would fail;
//   - would_fail_inspection ⇔ a failing request inspection (both halves of the bicondition);
//   - would_fail_credential_readiness ⇔ an invalid credential plan (both halves); and
//   - an outcome decide() returns before the credential step carries no_credential_profile.
func validateShadowOutcomeSubfacts(sh *ShadowEvidence) error {
	if sh.Outcome == shadowOutWouldExecute && sh.RequestInspection == shadowReqInspWouldFail {
		return evtErr(mcperr.ReasonEventInvalid, "would_execute with a failing request inspection")
	}
	if sh.Outcome == shadowOutWouldFailInspection && sh.RequestInspection != shadowReqInspWouldFail {
		return evtErr(mcperr.ReasonEventInvalid, "would_fail_inspection without a failing request inspection")
	}
	// The inspection biconditional's other half: a failing request inspection is handled
	// FIRST in decide() (step 1, before policy class / credential / staleness) and always
	// yields would_fail_inspection (requestInspectionStatus returns would_fail iff
	// Inspection.HardFail, and hardFailure is true whenever Inspection.HardFail).
	if sh.RequestInspection == shadowReqInspWouldFail && sh.Outcome != shadowOutWouldFailInspection {
		return evtErr(mcperr.ReasonEventInvalid, "a failing request inspection must yield would_fail_inspection")
	}
	if _, credFail := shadowCredReadyFailPlans[sh.CredentialPlan]; sh.Outcome == shadowOutWouldFailCredReady && !credFail {
		return evtErr(mcperr.ReasonEventInvalid, "would_fail_credential_readiness without a failing credential plan (invalid or no_planner_composed)")
	}
	// decide() sets a failing plan status (invalid, or no_planner_composed while a credential is
	// required) only on the fail branch that also sets this outcome, and no ready-branch outcome ever
	// carries a failing plan, so it is a biconditional.
	if _, credFail := shadowCredReadyFailPlans[sh.CredentialPlan]; credFail && sh.Outcome != shadowOutWouldFailCredReady {
		return evtErr(mcperr.ReasonEventInvalid, "a failing credential plan must yield would_fail_credential_readiness")
	}
	// An outcome decide() returns before the credential step never evaluated the plan, so it
	// must carry the unplanned default — a valid/invalid/no_planner status would falsely claim
	// credential readiness was evaluated when it was not.
	if _, ok := shadowPrePlanningOutcomes[sh.Outcome]; ok && sh.CredentialPlan != shadowPlanNone {
		return evtErr(mcperr.ReasonEventInvalid, "a pre-credential-step outcome must carry no_credential_profile")
	}
	return nil
}

// validateShadowOutcomeOverride pins the verdict↔Override (action-class projection)
// consistency: an allow-path-only outcome carrying a restrictive Override is a restrictive
// policy decision falsely presented as executable; a policy-gating outcome carrying a
// permissive Override is its inverse. Both are impossible in the producer.
func validateShadowOutcomeOverride(sh *ShadowEvidence) error {
	if _, ok := shadowAllowClassOnlyOutcomes[sh.Outcome]; ok && sh.Override {
		return evtErr(mcperr.ReasonEventInvalid, "an allow-class-only shadow outcome cannot carry a restrictive override")
	}
	if _, ok := shadowRestrictiveClassOutcomes[sh.Outcome]; ok && !sh.Override {
		return evtErr(mcperr.ReasonEventInvalid, "a policy-gating shadow outcome must carry a restrictive override")
	}
	return nil
}

// validatePhase enforces per-phase evidence requirements and the
// criticality/action-class coupling by delegating to a per-phase helper.
func (e Event) validatePhase() error {
	// Witness evidence belongs to exactly one phase. Allowing it to ride on any
	// other event would let a reconciliation claim reach the ledger attached to a
	// record the reconciliation state machine never inspects.
	if e.Reconciliation != nil && e.Phase != PhaseReconciliation {
		return evtErr(mcperr.ReasonEventInvalid, "reconciliation evidence on a non-reconciliation event")
	}
	switch e.Phase {
	case PhaseDecision, PhaseOutcome:
		return e.validateDecisionPhase()
	case PhaseDenialAggregate:
		return e.validateDenialPhase()
	case PhaseRecoveryMarker, PhaseHealth:
		return e.validateMarkerPhase()
	case PhaseReconciliation:
		return e.validateReconciliationPhase()
	case PhaseSendIntent:
		return e.validateSendIntentPhase()
	}
	return nil
}

// validateMarkerPhase validates a recovery-marker or health event.
func (e Event) validateMarkerPhase() error {
	if e.Marker == nil || e.Marker.State == "" {
		return evtErr(mcperr.ReasonEventEvidenceMissing, "marker event without marker state")
	}
	return nil
}

// validateReconciliationPhase validates append-only witness evidence.
//
// Evidence that cannot name its attempt or its result is not evidence; committing
// it would put an unusable record in the ledger. And a reconciliation event may not
// carry a terminal outcome: the ABSENCE of one is precisely what defines the orphan
// this event exists to resolve.
func (e Event) validateReconciliationPhase() error {
	if e.Reconciliation == nil || e.Reconciliation.AttemptID == "" {
		return evtErr(mcperr.ReasonEventEvidenceMissing, "reconciliation without attempt identity")
	}
	if !e.Reconciliation.Result.Valid() {
		return evtErr(mcperr.ReasonEventInvalid, "reconciliation with unknown result")
	}
	if e.Outcome != nil {
		return evtErr(mcperr.ReasonEventInvalid, "outcome evidence on a reconciliation event")
	}
	return nil
}

// validateSendIntentPhase validates a durable pre-send intent.
//
// An intent that cannot name its attempt is useless for reconciliation: an orphan
// with no AttemptID can never be matched against an independent witness, so it fails
// closed rather than committing unusable evidence.
func (e Event) validateSendIntentPhase() error {
	if e.Outcome == nil || e.Outcome.AttemptID == "" {
		return evtErr(mcperr.ReasonEventEvidenceMissing, "send intent without attempt identity")
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
	if o := e.Outcome; o != nil {
		// Attempt/reservation identity and the send state are structural, but they
		// are still strings on a durable record and must not be able to blow the
		// per-event bound.
		for _, s := range []string{o.AttemptID, o.ReservationID, string(o.PhysicalSendState)} {
			if len(s) > maxFieldBytes {
				return evtErr(mcperr.ReasonEventTooLarge, "an outcome field exceeds its structural bound")
			}
		}
	}
	if rc := e.Reconciliation; rc != nil {
		// These come from an INDEPENDENT WITNESS — i.e. outside this process. An
		// unbounded witness string is the one way external input could grow a durable
		// ledger record without limit, so it is bounded here, structurally.
		for _, s := range []string{
			rc.AttemptID, rc.ReservationID, string(rc.Result), rc.WitnessSource,
			rc.CompletenessWatermark, rc.EvidenceDigest,
		} {
			if len(s) > maxFieldBytes {
				return evtErr(mcperr.ReasonEventTooLarge, "a reconciliation field exceeds its structural bound")
			}
		}
	}
	if sh := e.Shadow; sh != nil {
		for _, s := range []string{sh.Outcome, sh.CredentialPlan, sh.MaterializationReadiness, sh.RequestInspection, sh.ResponseInspection} {
			if len(s) > maxFieldBytes {
				return evtErr(mcperr.ReasonEventTooLarge, "a shadow field exceeds its structural bound")
			}
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
