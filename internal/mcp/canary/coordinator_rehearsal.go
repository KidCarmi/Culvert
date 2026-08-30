package canary

// Authoritative rollback rehearsal evidence (CANARY-ROLLBACK-COORDINATOR-REHEARSAL). This is the
// STRONGER sibling of RollbackRehearsalRecord. That record proves rollback MECHANICS — a real
// persist/restore round-trip — and drives the readiness fact RollbackPathHealthy. This record proves
// something the mechanics drill cannot: that the Canary→Shadow→Observe demotion ladder was driven
// through the REAL authoritative rollout coordinator (commitRolloutTransitionCore, the same body every
// production transition runs), so the rehearsal fails for every security reason a real rollback would
// fail (Shadow preflight, emergency kill, config/revision validity, durability). It drives the SEPARATE
// readiness fact RollbackCoordinatorRehearsed (reason rollback_coordinator_rehearsal_pending).
//
// It is a DISTINCT record — its own schema, its own durable file — so the two concepts never merge: a
// mechanics record can never satisfy the coordinator prerequisite, and vice versa. Binding to the
// runtime identity (build version) is load-bearing exactly as for the mechanics record: an ancient
// coordinator drill against a materially changed runtime — whose coordinator semantics may have
// regressed — must NOT satisfy the current build's readiness.

// CoordinatorRollbackRehearsalSchemaVersion is the on-disk schema version. A record at any other
// version is treated as corruption (fail closed) rather than silently reinterpreted.
const CoordinatorRollbackRehearsalSchemaVersion = 1

// coordinatorRecoveredMode is the mode a correct coordinator drill must RESTORE from its scratch file
// after committing the full demotion ladder — proving the durable persist+recover landed at the bottom
// of the ladder (Observe), not merely that the in-memory transitions succeeded.
const coordinatorRecoveredMode = "observe"

// CoordinatorRollbackRehearsalRecord is the durable, schema-versioned evidence that a real rollback
// drill was driven through the authoritative coordinator for a capability against the current build.
// It carries NO tenant/subject/secret — only the capability token, the build identity it ran under, the
// coordinator-routed flag, the exact demotion steps the coordinator committed, the mode recovered from
// the scratch persistence, and the instant.
type CoordinatorRollbackRehearsalRecord struct {
	SchemaVersion int             `json:"schema_version"`
	Capability    string          `json:"capability"`         // rollout capability token ("gateway"/"management")
	Identity      RuntimeIdentity `json:"identity"`           // the build the drill actually ran under
	Routed        bool            `json:"coordinator_routed"` // the demotion ran through commitRolloutTransitionCore (never a bypass)
	Steps         []string        `json:"steps"`              // the demotion ladder the coordinator committed, in order
	RecoveredMode string          `json:"recovered_mode"`     // the mode restored from the scratch file after the drill (must be coordinatorRecoveredMode)

	RehearsedAtUnixNano int64 `json:"rehearsed_at_unix_nano"`
}

// CoordinatorRehearsalReason is a bounded classification for why a coordinator-rehearsal record does
// NOT satisfy readiness. Fixed vocabulary; never interpolated with runtime data.
type CoordinatorRehearsalReason string

// Coordinator-rehearsal rejection sub-reasons (CoordinatorRehearsalOK is the empty admissible value).
const (
	CoordinatorRehearsalOK               CoordinatorRehearsalReason = ""
	CoordinatorRehearsalMissing          CoordinatorRehearsalReason = "coordinator_rehearsal_missing"
	CoordinatorRehearsalSchemaUnknown    CoordinatorRehearsalReason = "coordinator_rehearsal_schema_unknown"
	CoordinatorRehearsalNoCapability     CoordinatorRehearsalReason = "coordinator_rehearsal_no_capability"
	CoordinatorRehearsalCapabilityWrong  CoordinatorRehearsalReason = "coordinator_rehearsal_capability_mismatch"
	CoordinatorRehearsalNotRouted        CoordinatorRehearsalReason = "coordinator_rehearsal_not_routed"
	CoordinatorRehearsalIncompletePath   CoordinatorRehearsalReason = "coordinator_rehearsal_incomplete_path"
	CoordinatorRehearsalRecoveryMismatch CoordinatorRehearsalReason = "coordinator_rehearsal_recovery_mismatch"
	CoordinatorRehearsalIdentityMismatch CoordinatorRehearsalReason = "coordinator_rehearsal_identity_mismatch"
)

// ValidateCoordinatorRehearsal reports whether rec is a coordinator-routed rollback-rehearsal record
// that satisfies readiness for capability capToken against the current runtime identity. Pure,
// fail-closed: a nil, wrong-schema, wrong-capability, NOT-coordinator-routed, incomplete-path,
// wrong-recovered-mode, or identity-mismatched record is rejected with its named reason. Crucially,
// the Routed flag being false is its own rejection, so a record that did not go through the coordinator
// (a mechanics record shape, or a fabricated one lacking the flag) can NEVER satisfy this prerequisite.
func ValidateCoordinatorRehearsal(rec *CoordinatorRollbackRehearsalRecord, capToken string, current RuntimeIdentity) CoordinatorRehearsalReason {
	if rec == nil {
		return CoordinatorRehearsalMissing
	}
	if rec.SchemaVersion != CoordinatorRollbackRehearsalSchemaVersion {
		return CoordinatorRehearsalSchemaUnknown
	}
	if rec.Capability == "" {
		return CoordinatorRehearsalNoCapability
	}
	if rec.Capability != capToken {
		return CoordinatorRehearsalCapabilityWrong
	}
	if !rec.Routed {
		return CoordinatorRehearsalNotRouted
	}
	if !sameSteps(rec.Steps, requiredRollbackPath) {
		return CoordinatorRehearsalIncompletePath
	}
	if rec.RecoveredMode != coordinatorRecoveredMode {
		return CoordinatorRehearsalRecoveryMismatch
	}
	// Identity binding: the drill must have run under the CURRENT build. An empty current identity (a
	// build with no stamp) fails closed — nothing can be attested for it.
	if !current.Valid() || rec.Identity.BuildVersion != current.BuildVersion {
		return CoordinatorRehearsalIdentityMismatch
	}
	return CoordinatorRehearsalOK
}

// CoordinatorRehearsalValid is the boolean form of ValidateCoordinatorRehearsal.
func CoordinatorRehearsalValid(rec *CoordinatorRollbackRehearsalRecord, capToken string, current RuntimeIdentity) bool {
	return ValidateCoordinatorRehearsal(rec, capToken, current) == CoordinatorRehearsalOK
}

// CoordinatorRecoveredMode returns the mode a correct coordinator drill must recover from its scratch
// persistence, so the composition-layer drill and its tests share the SINGLE source of truth.
func CoordinatorRecoveredMode() string { return coordinatorRecoveredMode }
