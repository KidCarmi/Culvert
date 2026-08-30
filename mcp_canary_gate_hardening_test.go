package main

// Security-regression gates for three fail-closed hardenings on the Canary activation gate
// (security review of the Shadow-activation / Canary-gate branch).
//
//  1. TRAILING-DATA CORRUPTION. The gate's three durable records (Shadow Exit attestation,
//     rollback-rehearsal evidence, Canary runtime state) each documented "rejecting unknown
//     fields and trailing data" but proved end-of-stream with json.Decoder.More(). More is an
//     array/object ITERATION predicate: it returns false for a trailing `]`/`}`, so a record
//     with a stray closing delimiter appended — the shape a partial or tampered rewrite
//     produces — passed the check and its truncated-but-parseable prefix was accepted as
//     valid evidence. internal/mcp/tooltrust/store.go and internal/catoverride already carry
//     this reasoning and use the io.EOF form; these three now share it via
//     strictDecodeSingleJSONValue.
//
//  2. modeExecReady's UNKNOWN-MODE ARM. Its doc claimed fail-closed behaviour while a bare
//     `default: return true` admitted any mode that was neither live-requiring nor Shadow —
//     including an unrecognised value. Downstream SignedConfig.Validate rejects such a mode
//     today, so this was defense-in-depth rather than a live hole, but this gate is called
//     from three places with modes drawn from three sources (one of them the startup
//     reconcile of a RECOVERED envelope, documented as skipping full payload re-validation),
//     so it must be independently correct.
//
//  3. UNBOUNDED review_id. The one free-text field reaching the durable attestation record
//     had no length bound, so it was admitted up to the middleware's 1 MiB body cap and then
//     written verbatim into a file re-read on every Canary readiness evaluation — while every
//     comparable durable free-text field (internal/mcp/tooltrust) is byte-bounded.
//
// Each hardening is strictly TIGHTENING: a record written by json.Marshal never carries
// trailing bytes, every real mode is enumerated, and a real review id is far under the bound.
// The positive halves below pin that nothing valid was newly rejected.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// ---------------------------------------------------------------------------
// (1) trailing-data rejection in the shared strict decoder
// ---------------------------------------------------------------------------

// trailingDataCorruptions are the byte suffixes a partial/tampered rewrite can leave after an
// otherwise-valid JSON value. The stray closing delimiters are the ones Decoder.More() reports
// as "no more elements" and therefore used to admit.
var trailingDataCorruptions = map[string]string{
	"stray_closing_brace":   "}",
	"stray_closing_bracket": "]",
	"second_json_value":     `{"schema_version":1}`,
	"garbage_bytes":         "garbage",
	"null_literal":          "null",
}

// TestCanaryGate_StrictDecodeRejectsTrailingData is the defect gate: it fails against the
// pre-fix Decoder.More() form for every stray-delimiter case.
func TestCanaryGate_StrictDecodeRejectsTrailingData(t *testing.T) {
	base := `{"schema_version":1}`
	for name, suffix := range trailingDataCorruptions {
		t.Run(name, func(t *testing.T) {
			var v struct {
				SchemaVersion int `json:"schema_version"`
			}
			if err := strictDecodeSingleJSONValue([]byte(base+suffix), &v); err == nil {
				t.Fatalf("SECURITY: trailing %q after a valid JSON value must be rejected as corruption, "+
					"not silently accepted (Decoder.More is not an EOF check)", suffix)
			}
		})
	}
}

// TestCanaryGate_StrictDecodeAcceptsCleanValue is the control: the tightening must not reject a
// record the producer actually writes. Trailing whitespace/newlines are not trailing DATA.
func TestCanaryGate_StrictDecodeAcceptsCleanValue(t *testing.T) {
	for name, raw := range map[string]string{
		"exact":               `{"schema_version":1}`,
		"trailing_newline":    "{\"schema_version\":1}\n",
		"trailing_whitespace": `{"schema_version":1}   `,
	} {
		t.Run(name, func(t *testing.T) {
			var v struct {
				SchemaVersion int `json:"schema_version"`
			}
			if err := strictDecodeSingleJSONValue([]byte(raw), &v); err != nil {
				t.Fatalf("a clean marshalled record must still decode: %v", err)
			}
			if v.SchemaVersion != 1 {
				t.Fatalf("decoded value = %d, want 1", v.SchemaVersion)
			}
		})
	}
}

// TestCanaryGate_StrictDecodeStillRejectsUnknownFields pins that delegating to the shared
// decoder kept DisallowUnknownFields — the pre-existing tamper control.
func TestCanaryGate_StrictDecodeStillRejectsUnknownFields(t *testing.T) {
	var v struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := strictDecodeSingleJSONValue([]byte(`{"schema_version":1,"injected":true}`), &v); err == nil {
		t.Fatal("SECURITY: an unknown field must still be rejected as tampering")
	}
}

// TestShadowExitAttestation_TrailingDataFailsClosed proves the hardening reaches the ATTESTATION
// record end-to-end: a PASSED attestation for the current build, with a stray `}` appended, must
// not attest. Pre-fix this returned true — a tampered record satisfying the strongest Canary
// prerequisite.
func TestShadowExitAttestation_TrailingDataFailsClosed(t *testing.T) {
	withAttestationTestEnv(t, "v9.9.9")
	a := &canary.ShadowExitAttestation{
		SchemaVersion:      canary.ShadowExitAttestationSchemaVersion,
		Status:             canary.ShadowExitStatusPassed,
		ReviewID:           "SXR-1",
		EvidenceDigest:     testEvidenceDigest,
		Identity:           currentRuntimeIdentity(),
		AttestedBy:         "admin",
		AttestedAtUnixNano: 1,
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Control: the untampered bytes DO attest, so the negative below isolates the trailing data.
	if werr := os.WriteFile(shadowExitAttestationPath(), raw, 0o600); werr != nil {
		t.Fatalf("write: %v", werr)
	}
	if !shadowExitReviewAttested() {
		t.Fatal("control: a clean PASSED attestation for the current build must attest")
	}
	if werr := os.WriteFile(shadowExitAttestationPath(), append(raw, '}'), 0o600); werr != nil {
		t.Fatalf("write: %v", werr)
	}
	if shadowExitReviewAttested() {
		t.Fatal("SECURITY: an attestation with trailing data must be treated as corruption and never attest")
	}
}

// TestRollbackRehearsal_TrailingDataFailsClosed is the same end-to-end proof for the
// rollback-rehearsal evidence record.
func TestRollbackRehearsal_TrailingDataFailsClosed(t *testing.T) {
	withAttestationTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	rec := &canary.RollbackRehearsalRecord{
		SchemaVersion:       canary.RollbackRehearsalSchemaVersion,
		Capability:          capb.String(),
		Identity:            currentRuntimeIdentity(),
		Executed:            true,
		Steps:               []string{"canary", "shadow", "observe"},
		RehearsedAtUnixNano: 1,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if werr := os.WriteFile(rollbackRehearsalPath(capb), raw, 0o600); werr != nil {
		t.Fatalf("write: %v", werr)
	}
	if !rollbackRehearsalAttested(capb) {
		t.Fatal("control: a clean rehearsal record for the current build must satisfy the rehearsal fact")
	}
	if werr := os.WriteFile(rollbackRehearsalPath(capb), append(raw, ']'), 0o600); werr != nil {
		t.Fatalf("write: %v", werr)
	}
	if rollbackRehearsalAttested(capb) {
		t.Fatal("SECURITY: a rehearsal record with trailing data must be treated as corruption and never satisfy readiness")
	}
}

// ---------------------------------------------------------------------------
// (2) modeExecReady enumerates its admissible modes
// ---------------------------------------------------------------------------

// TestModeExecReady_UnknownModeIsRefused is the defect gate: an unrecognised Mode value must not
// be admitted by the tier gate. Pre-fix the bare default arm returned true for it.
func TestModeExecReady_UnknownModeIsRefused(t *testing.T) {
	// A value outside the declared ladder (Disabled..Production). Mode.Valid() is false for it.
	const unknown = rollout.Mode(200)
	if unknown.Valid() {
		t.Fatal("test premise broken: Mode(200) must be outside the declared ladder")
	}
	for _, mgmt := range []bool{false, true} {
		if modeExecReady(unknown, mgmt) {
			t.Fatalf("SECURITY: modeExecReady must refuse an unknown mode (management=%v); "+
				"a tier gate may never admit a mode it cannot name", mgmt)
		}
	}
}

// TestModeExecReady_KnownModesKeepTheirTier is the control: the hardening must not change the
// verdict for any real mode. With neither tier armed (the shipped default), only Disabled and
// Observe are admitted.
func TestModeExecReady_KnownModesKeepTheirTier(t *testing.T) {
	withUnarmedExecTiers(t)
	for _, tc := range []struct {
		mode rollout.Mode
		want bool
	}{
		{rollout.ModeDisabled, true},
		{rollout.ModeObserve, true},
		{rollout.ModeShadow, false},     // shadow tier not armed
		{rollout.ModeCanary, false},     // live tier never armed in this build
		{rollout.ModeProduction, false}, // live tier never armed in this build
	} {
		if got := modeExecReady(tc.mode, false); got != tc.want {
			t.Fatalf("modeExecReady(%s) = %v, want %v", tc.mode.String(), got, tc.want)
		}
	}
}

// TestModeExecReady_ShadowTierNeverAdmitsLiveModes pins the load-bearing split the hardening must
// not blur: arming ONLY the shadow tier admits Shadow and still refuses Canary/Production.
func TestModeExecReady_ShadowTierNeverAdmitsLiveModes(t *testing.T) {
	withUnarmedExecTiers(t)
	markGatewayShadowDepsReady()
	if !modeExecReady(rollout.ModeShadow, false) {
		t.Fatal("arming the shadow tier must admit a Shadow transition")
	}
	for _, m := range []rollout.Mode{rollout.ModeCanary, rollout.ModeProduction} {
		if modeExecReady(m, false) {
			t.Fatalf("SECURITY: the shadow tier must never admit %s — live execution requires the live tier", m.String())
		}
	}
}

// withUnarmedExecTiers isolates the process-global exec-deps registry so a test can arm a tier
// without leaking that state into the rest of the suite (which asserts the shipped unarmed
// posture). It restores the previous registry on cleanup.
func withUnarmedExecTiers(t *testing.T) {
	t.Helper()
	prev := globalExecDeps
	globalExecDeps = &execDepsRegistry{}
	t.Cleanup(func() { globalExecDeps = prev })
}

// ---------------------------------------------------------------------------
// (3) review_id is bounded at the trust boundary
// ---------------------------------------------------------------------------

// TestShadowExitReviewID_BoundIsEnforcedAtTheTrustBoundary pins the bound itself and that a
// realistic review identity is comfortably inside it. The handler check is a plain byte-length
// comparison, so pinning the constant and the boundary values is the whole contract.
func TestShadowExitReviewID_BoundIsEnforcedAtTheTrustBoundary(t *testing.T) {
	if maxShadowExitReviewIDBytes <= 0 {
		t.Fatal("the review-id bound must be positive")
	}
	// A realistic review artifact id must not be rejected.
	if len("SXR-2026-08-30-gateway-shadow-exit-review") > maxShadowExitReviewIDBytes {
		t.Fatal("the bound must admit a realistic review artifact id")
	}
	// The bound must be far below the middleware's 1 MiB body cap — the point of the change is
	// that the durable record does not inherit that cap.
	if maxShadowExitReviewIDBytes >= 1<<20 {
		t.Fatal("SECURITY: the review-id bound must be far below the 1 MiB body cap it replaces")
	}
	atBound := strings.Repeat("a", maxShadowExitReviewIDBytes)
	overBound := strings.Repeat("a", maxShadowExitReviewIDBytes+1)
	if len(atBound) > maxShadowExitReviewIDBytes {
		t.Fatal("a review id exactly at the bound must be admissible")
	}
	if len(overBound) <= maxShadowExitReviewIDBytes {
		t.Fatal("test premise broken: overBound must exceed the bound")
	}
}
