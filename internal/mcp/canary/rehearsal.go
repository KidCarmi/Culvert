package canary

// Rollback-rehearsal executable evidence (§5, Canary Activation Gate). The first Canary is the
// first time Culvert causes a real, irreversible MCP upstream side effect, so its rollback path
// must be PROVEN reversible BEFORE it may be reported ready — not merely asserted by a boolean an
// operator can toggle. RollbackRehearsalRecord is the PURE, schema-versioned, build-bound record
// that a real demotion drill (Canary → Shadow → Observe, driven through the actual rollout
// persist/restore path in the composition layer) produces. This file owns only the record and its
// fail-closed validator; the drill and its durable I/O live in the root (mcp_canary_rollback_rehearsal.go).
//
// The record proves a SPECIFIC thing: that THIS build/state successfully exercised the exact
// demotion ladder a first-Canary rollback requires. Binding it to the runtime identity (build
// version) is load-bearing — an ancient drill against a materially different runtime must NOT
// satisfy the current build's readiness (a rollback path can regress between builds), exactly as
// the Shadow Exit attestation binds to the same identity.

// RollbackRehearsalSchemaVersion is the on-disk schema version. A record at any other version is
// treated as corruption (fail closed) rather than silently reinterpreted.
const RollbackRehearsalSchemaVersion = 1

// requiredRollbackPath is the exact demotion ladder a first-Canary rollback rehearsal must
// exercise, in order: a Canary-configured state must be provably reversible down to Shadow and
// then to Observe through the durable persist/restore path. A record whose Steps do not match
// this sequence proves an INCOMPLETE drill and does not satisfy readiness.
var requiredRollbackPath = []string{"canary", "shadow", "observe"}

// RollbackRehearsalRecord is the durable, schema-versioned evidence that a real rollback drill
// executed for a capability against the current build. It carries NO tenant/subject/secret — only
// the capability token, the build identity it was produced under, the executed flag, the exact
// demotion steps exercised, and the instant.
type RollbackRehearsalRecord struct {
	SchemaVersion       int             `json:"schema_version"`
	Capability          string          `json:"capability"` // rollout capability token ("gateway"/"management")
	Identity            RuntimeIdentity `json:"identity"`   // the build the drill actually ran under
	Executed            bool            `json:"executed"`   // the drill completed every required step
	Steps               []string        `json:"steps"`      // the demotion ladder actually exercised, in order
	RehearsedAtUnixNano int64           `json:"rehearsed_at_unix_nano"`
}

// RehearsalReason is a bounded classification for why a rehearsal record does NOT satisfy
// readiness. Fixed vocabulary; never interpolated with runtime data.
type RehearsalReason string

// Rehearsal rejection sub-reasons (RehearsalOK is the empty admissible value).
const (
	RehearsalOK               RehearsalReason = ""
	RehearsalMissing          RehearsalReason = "rehearsal_missing"
	RehearsalSchemaUnknown    RehearsalReason = "rehearsal_schema_unknown"
	RehearsalNoCapability     RehearsalReason = "rehearsal_no_capability"
	RehearsalCapabilityWrong  RehearsalReason = "rehearsal_capability_mismatch"
	RehearsalNotExecuted      RehearsalReason = "rehearsal_not_executed"
	RehearsalIncompletePath   RehearsalReason = "rehearsal_incomplete_path"
	RehearsalIdentityMismatch RehearsalReason = "rehearsal_identity_mismatch"
)

// ValidateRehearsal reports whether rec is a rollback-rehearsal record that satisfies readiness
// for capability cap against the current runtime identity. Pure, fail-closed: a nil, wrong-schema,
// wrong-capability, not-executed, incomplete-path, or identity-mismatched record is rejected with
// its named reason. It NEVER returns OK for a record that did not exercise the full required
// demotion ladder under the current build.
func ValidateRehearsal(rec *RollbackRehearsalRecord, capToken string, current RuntimeIdentity) RehearsalReason {
	if rec == nil {
		return RehearsalMissing
	}
	if rec.SchemaVersion != RollbackRehearsalSchemaVersion {
		return RehearsalSchemaUnknown
	}
	if rec.Capability == "" {
		return RehearsalNoCapability
	}
	if rec.Capability != capToken {
		return RehearsalCapabilityWrong
	}
	if !rec.Executed {
		return RehearsalNotExecuted
	}
	if !sameSteps(rec.Steps, requiredRollbackPath) {
		return RehearsalIncompletePath
	}
	// Identity binding: the drill must have run under the CURRENT build. An empty current
	// identity (a build with no stamp) fails closed — nothing can be attested for it.
	if !current.Valid() || rec.Identity.BuildVersion != current.BuildVersion {
		return RehearsalIdentityMismatch
	}
	return RehearsalOK
}

// RehearsalValid is the boolean form of ValidateRehearsal.
func RehearsalValid(rec *RollbackRehearsalRecord, capToken string, current RuntimeIdentity) bool {
	return ValidateRehearsal(rec, capToken, current) == RehearsalOK
}

// RequiredRollbackPath returns a copy of the exact demotion ladder a rehearsal must exercise, so
// the composition-layer drill and its tests share the SINGLE source of truth (no drift between
// what the drill executes and what the validator requires).
func RequiredRollbackPath() []string {
	out := make([]string, len(requiredRollbackPath))
	copy(out, requiredRollbackPath)
	return out
}

// sameSteps reports whether a equals b element-for-element in order.
func sameSteps(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
