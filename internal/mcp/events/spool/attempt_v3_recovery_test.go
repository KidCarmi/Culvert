package spool

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// attemptV3Event returns a valid SchemaVersionV3 attempt-outcome event — the
// First-Canary shape: one physical tool invocation, identified, bound to the
// reservation and generation that authorized it, with its conservative send state.
func attemptV3Event(id string) *model.Event {
	e := &model.Event{
		SchemaVersion: model.SchemaVersionV3, EventID: "evt_" + id, Phase: model.PhaseOutcome,
		Criticality: model.CritOrdinary, Partition: model.PartOrd, Capability: model.CapGateway,
		ActionClass: model.ActionClassRead, NodeID: "dp-test", DomainID: "d",
		TimeUnixNano: 1000, ReplayID: "rpl_" + id, CorrelationID: "cor_" + id,
		Identity: model.IdentityEvidence{Tenant: "acme", PrincipalID: "p1", PrincipalType: "human"},
		Decision: model.DecisionEvidence{
			Action: "ALLOW", ReasonCode: "MCP.POLICY.OK", PolicyRevision: 7, CatalogRevision: 3,
			ExecutionState: "executed",
		},
		Outcome: &model.OutcomeEvidence{
			DecisionRef: "evt_dec_" + id, Executed: true,
			AttemptID: "att_" + id, ReservationID: "res_" + id, ActivationGeneration: 4,
			PhysicalSendState: model.SendPeerResponseReceived,
		},
	}
	_, _ = e.ComputeDigest()
	return e
}

// TestAttemptV3_RecoverRoundTripPreservesEvidence is the POSITIVE CONTROL for the
// version work below: this build must be able to commit a v3 attempt event, restart,
// and read it back intact. Without it, every negative gate here could pass on a
// build that had simply stopped being able to persist attempt evidence at all.
func TestAttemptV3_RecoverRoundTripPreservesEvidence(t *testing.T) {
	root := t.TempDir()
	s := newTestSpool(t, root)
	want := attemptV3Event("a01")
	if _, err := s.Commit(want); err != nil {
		t.Fatalf("commit v3 attempt event: %v", err)
	}

	s2 := newTestSpool(t, root)
	if _, err := s2.Recover(); err != nil {
		t.Fatalf("recover: %v", err)
	}
	evs, _, _, err := s2.CommittedForExport(model.PartOrd, 0, 100)
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
		t.Fatal("the committed v3 attempt event did not survive recovery")
	}
	if got.SchemaVersion != model.SchemaVersionV3 {
		t.Fatalf("recovered schema = %d, want v3", got.SchemaVersion)
	}
	if got.Outcome == nil || *got.Outcome != *want.Outcome {
		t.Fatalf("attempt evidence changed across recovery\n  got  %+v\n  want %+v", got.Outcome, want.Outcome)
	}
	if !got.VerifyDigest() {
		t.Fatal("recovered v3 event fails digest verification")
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("recovered v3 event fails validation: %v", err)
	}
}

// TestAttemptV3_VersionIsReadableWhenTheStrictDecodeIsNot is the causal gate behind
// the recovery ordering fix.
//
// A record written by a NEWER build carries fields this build does not know. Both
// checks recovery used to reach first — the strict decode (DisallowUnknownFields) and
// the intrinsic digest, which is computed over exactly those unknown fields —
// structurally CANNOT pass on such a record. So recovery reported SPOOL CORRUPTION,
// the alarm reserved for tampering and disk damage, and aborted, when the true
// condition was an ordinary version rollback. The version has to be read BEFORE
// either check or it cannot be read at all.
//
// This pins both halves of that claim on the same bytes: the strict decode fails,
// and the lenient peek still recovers the version.
func TestAttemptV3_VersionIsReadableWhenTheStrictDecodeIsNot(t *testing.T) {
	plaintext, err := attemptV3Event("a02").Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Forge the shape a FUTURE build would write: an unsupported version plus a field
	// this build has never heard of.
	var raw map[string]json.RawMessage
	if uerr := json.Unmarshal(plaintext, &raw); uerr != nil {
		t.Fatalf("unmarshal to map: %v", uerr)
	}
	raw["schema_version"] = json.RawMessage("99")
	raw["future_evidence"] = json.RawMessage(`{"unknown":"to this build"}`)
	forged, merr := json.Marshal(raw)
	if merr != nil {
		t.Fatalf("marshal forged: %v", merr)
	}

	// Half 1 — the strict decode cannot see the version. This is the pre-fix path,
	// and it is why the old ordering could only ever report corruption.
	var e model.Event
	if derr := unmarshalEvent(forged, &e); derr == nil {
		t.Fatal("the strict decode accepted a record carrying an unknown field")
	}

	// Half 2 — the lenient peek recovers the version from the same bytes, so recovery
	// can name the condition: newer than this build, not corrupt.
	v, ok := peekSchemaVersion(forged)
	if !ok {
		t.Fatal("the peek failed on well-formed JSON")
	}
	if v != 99 {
		t.Fatalf("peeked schema version = %d, want 99", v)
	}
	if model.SupportedSchemaVersion(v) {
		t.Fatal("a future schema version must not be supported (fail closed)")
	}
}

// TestSchemaPeek_NonJSONIsLeftToTheStrictDecode pins that the peek claims nothing
// about bytes that are not an event at all. Genuine corruption must keep reporting as
// corruption — the whole point of separating the two conditions is that each keeps
// its own meaning.
func TestSchemaPeek_NonJSONIsLeftToTheStrictDecode(t *testing.T) {
	for _, b := range [][]byte{nil, {}, []byte("not json"), []byte(`{"schema_version":`)} {
		if _, ok := peekSchemaVersion(b); ok {
			t.Fatalf("peek claimed a version from non-JSON bytes %q", string(b))
		}
	}
	// A supported version in well-formed JSON is still read — the control that stops
	// the gate above from passing on a peek that always fails.
	v, ok := peekSchemaVersion([]byte(`{"schema_version":3}`))
	if !ok || v != model.SchemaVersionV3 {
		t.Fatalf("peek(v3) = (%d, %v), want (3, true)", v, ok)
	}
}

// TestAttemptV3_StampAndShapeMustAgreeAtRecovery pins the narrow recovery-scoped
// pairing check. A record whose stamped version disagrees with the evidence it
// carries is a schema fault; recovery must not accept it just because its digest
// happens to verify.
func TestAttemptV3_StampAndShapeMustAgreeAtRecovery(t *testing.T) {
	e := attemptV3Event("a03")
	e.SchemaVersion = model.SchemaVersionV1
	if err := e.ValidateEvidenceSchema(); err == nil {
		t.Fatal("attempt evidence under a v1 stamp must be refused")
	} else if !strings.Contains(err.Error(), "schema v3") {
		t.Fatalf("unexpected refusal reason: %v", err)
	}
	// Control: the same record, correctly stamped, passes.
	e.SchemaVersion = model.SchemaVersionV3
	if err := e.ValidateEvidenceSchema(); err != nil {
		t.Fatalf("a correctly stamped v3 record must pass: %v", err)
	}
}

// forgeSchemaVersionOnDisk rewrites the single committed record of a partition so
// its envelope claims schema version `version`, re-sealing under the spool's own key
// and repairing the hash chain and checkpoint so nothing else about the ledger is
// disturbed.
//
// It builds the ONE artifact that cannot otherwise be produced in-process: a record
// that is cryptographically intact and chain-consistent, and that this build does not
// know how to read. That is exactly what a version rollback leaves behind, and it is
// the only way to observe which of the two conditions — "newer than me" or "corrupt"
// — recovery actually reports.
func forgeSchemaVersionOnDisk(t *testing.T, root string, version int) {
	t.Helper()
	be := osBackend{}
	cr, err := openCryptor(be, filepath.Join(root, dekFileName), testKEK())
	if err != nil {
		t.Fatalf("open cryptor: %v", err)
	}
	dir := filepath.Join(root, "P-ORD")
	ckPath := filepath.Join(dir, "checkpoint.json")
	ckBytes, err := be.ReadFile(ckPath)
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	ck, err := decodeCheckpoint(ckBytes)
	if err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	if len(ck.Segments) != 1 || ck.Segments[0].Records != 1 {
		t.Fatalf("forge expects exactly one segment holding one record, got %+v", ck.Segments)
	}
	sm := ck.Segments[0]
	segPath := filepath.Join(dir, "seg-"+pad8(sm.ID)+".dat")
	raw, err := be.ReadFile(segPath)
	if err != nil {
		t.Fatalf("read segment: %v", err)
	}
	anchor, ok := parseHexChain(sm.FirstChainHex)
	if !ok {
		t.Fatal("segment anchor unparsable")
	}
	f, err := decodeRecordAt(raw[segHeaderLen:])
	if err != nil {
		t.Fatalf("decode record: %v", err)
	}
	pt, _, err := verifyRecord(cr, f)
	if err != nil {
		t.Fatalf("verify record: %v", err)
	}

	// Bump ONLY the version. The rest of the record is left byte-for-byte, so what
	// recovery meets is a well-formed event of an unknown vintage.
	var obj map[string]json.RawMessage
	if uerr := json.Unmarshal(pt, &obj); uerr != nil {
		t.Fatalf("unmarshal plaintext: %v", uerr)
	}
	obj["schema_version"] = json.RawMessage(strconv.Itoa(version))
	forgedPT, merr := json.Marshal(obj)
	if merr != nil {
		t.Fatalf("marshal forged plaintext: %v", merr)
	}

	frame, next, err := encodeRecord(cr, model.PartOrd, f.seq, anchor, forgedPT)
	if err != nil {
		t.Fatalf("encode forged record: %v", err)
	}
	out := append(append([]byte{}, raw[:segHeaderLen]...), frame...)
	if werr := be.AtomicReplace(segPath, out, filePerm); werr != nil {
		t.Fatalf("rewrite segment: %v", werr)
	}
	ck.Segments[0].CommittedLen = int64(len(out))
	ck.LastChainHex = hexChain(next)
	ck.TotalBytes = int64(len(out))
	ckOut, cerr := ck.encode()
	if cerr != nil {
		t.Fatalf("encode checkpoint: %v", cerr)
	}
	if werr := be.AtomicReplace(ckPath, ckOut, filePerm); werr != nil {
		t.Fatalf("rewrite checkpoint: %v", werr)
	}
}

// TestAttemptV3_ARollbackReportsASchemaFaultNotCorruption is the end-to-end proof of
// the recovery-ordering fix.
//
// A record written by a newer build is intact and chain-consistent; it just carries
// fields this build has never heard of. Both checks recovery used to reach first —
// the strict decode and the intrinsic digest, which is computed over exactly those
// unknown fields — structurally cannot pass on it, so an ordinary version rollback
// was reported as "record event invalid": SPOOL CORRUPTION, the condition that means
// tampering or disk damage.
//
// What changes is the DIAGNOSIS, not the posture. The partition is held degraded
// either way (both reasons are hard failures), and that is deliberate — a node must
// not serve from a ledger it cannot read. But CorruptReason is what an operator acts
// on, and "unsupported schema version" says roll the binary forward, where "record
// event invalid" says suspect the disk.
func TestAttemptV3_ARollbackReportsASchemaFaultNotCorruption(t *testing.T) {
	root := t.TempDir()
	s := newTestSpool(t, root)
	if _, err := s.Commit(attemptV3Event("a04")); err != nil {
		t.Fatalf("commit v3 attempt event: %v", err)
	}
	forgeSchemaVersionOnDisk(t, root, 99)

	s2, err := New(Config{
		Root: root, Capability: model.CapGateway, NodeID: "dp-test",
		Limits: testLimits(t), KEK: testKEK(),
		Clock: func() time.Time { return time.Unix(0, 1000) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rep, rerr := s2.Recover()
	if rerr != nil {
		t.Fatalf("Recover returned an error rather than a report: %v", rerr)
	}
	// Fail-closed half: a record this build cannot read must never be waved through.
	if !rep.Corrupt {
		t.Fatal("a record of an unsupported schema version must hold the partition degraded")
	}
	if rep.CorruptPartition != model.PartOrd {
		t.Fatalf("the fault must be attributed to P-ORD, got %v", rep.CorruptPartition)
	}
	// Diagnosis half: the reason must name the schema, not corruption.
	if !strings.Contains(rep.CorruptReason, mcperr.ReasonEventSchemaVersion.Code()) {
		t.Fatalf("a version rollback was reported as %q, want the unsupported-schema reason %q",
			rep.CorruptReason, mcperr.ReasonEventSchemaVersion.Code())
	}
}

// TestAttemptV3_TheForgeItselfIsSoundWhenTheVersionIsSupported is the CONTROL for
// the gate above, and it is not optional: the forge rewrites the record, the hash
// chain and the checkpoint, so a mistake in ANY of those would make recovery fail for
// a reason that has nothing to do with schema versions. Re-stamping the record with a
// version this build DOES support must leave a ledger that recovers cleanly.
func TestAttemptV3_TheForgeItselfIsSoundWhenTheVersionIsSupported(t *testing.T) {
	root := t.TempDir()
	s := newTestSpool(t, root)
	if _, err := s.Commit(attemptV3Event("a05")); err != nil {
		t.Fatalf("commit v3 attempt event: %v", err)
	}
	// Re-stamp with the SAME supported version: the record is re-sealed, the chain
	// recomputed and the checkpoint rewritten, exactly as in the gate above.
	forgeSchemaVersionOnDisk(t, root, model.SchemaVersionV3)

	s2 := newTestSpool(t, root)
	evs, _, _, err := s2.CommittedForExport(model.PartOrd, 0, 100)
	if err != nil {
		t.Fatalf("read back after a sound forge: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("the sound forge lost the record: got %d events", len(evs))
	}
	if evs[0].SchemaVersion != model.SchemaVersionV3 {
		t.Fatalf("recovered schema = %d, want v3", evs[0].SchemaVersion)
	}
}
