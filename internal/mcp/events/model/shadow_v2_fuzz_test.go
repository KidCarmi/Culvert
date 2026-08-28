package model

import (
	"encoding/json"
	"testing"
)

// FuzzShadowV2ValidateDigestRoundTrip fuzzes the v2/shadow surface: decode arbitrary bytes
// into an Event, run the schema/shadow validation and canonical digest, and — for a valid
// v2 shadow event — assert the digest is stable and a marshal→unmarshal round-trip
// preserves the ShadowEvidence exactly. The invariant is total: no input may panic, and a
// valid v2 event's durable shadow facts survive a JSON round-trip unchanged.
func FuzzShadowV2ValidateDigestRoundTrip(f *testing.F) {
	valid := validV2ShadowEvent()
	if b, err := valid.Marshal(); err == nil {
		f.Add(b)
	}
	// Malformed / edge seeds spanning the dispatch and the enum/impossible-combination rules.
	f.Add([]byte(`{"schema_version":2,"phase":1,"decision":{"execution_state":"shadow_evaluated"}}`)) // v2 without shadow
	f.Add([]byte(`{"schema_version":1,"shadow":{"outcome":"would_execute"}}`))                        // v1 with shadow
	f.Add([]byte(`{"schema_version":2,"shadow":{"outcome":"would_maybe"}}`))                          // unknown outcome
	f.Add([]byte(`{"schema_version":3,"shadow":{}}`))                                                 // unsupported schema
	f.Add([]byte(`{"schema_version":2,"shadow":{"materialization_readiness":"ready"}}`))              // impossible materialization

	f.Fuzz(func(t *testing.T, data []byte) {
		var e Event
		if err := json.Unmarshal(data, &e); err != nil {
			return // not an event
		}
		// Validation (incl. schema/shadow dispatch) must never panic and be deterministic.
		err1 := e.Validate()
		if (err1 == nil) != (e.Validate() == nil) {
			t.Fatal("Validate non-deterministic on the shadow surface")
		}
		// The narrow recovery guard must also never panic (defense-in-depth path).
		_ = e.ValidateShadowEvidence()
		if err1 != nil {
			return
		}
		// Valid event: digest stable, and a durable round-trip preserves the schema and
		// the full ShadowEvidence (the durable-record contract).
		if _, derr := e.ComputeDigest(); derr != nil {
			return
		}
		enc, merr := e.Marshal()
		if merr != nil {
			t.Fatalf("marshal of a valid event failed: %v", merr)
		}
		var back Event
		if uerr := json.Unmarshal(enc, &back); uerr != nil {
			t.Fatalf("re-decode of a valid event failed: %v", uerr)
		}
		if back.SchemaVersion != e.SchemaVersion {
			t.Fatalf("schema changed across round-trip: %d -> %d", e.SchemaVersion, back.SchemaVersion)
		}
		if (e.Shadow == nil) != (back.Shadow == nil) {
			t.Fatal("shadow presence changed across round-trip")
		}
		if e.Shadow != nil && *e.Shadow != *back.Shadow {
			t.Fatalf("ShadowEvidence changed across round-trip:\n  %+v\n  %+v", *e.Shadow, *back.Shadow)
		}
		if !back.VerifyDigest() {
			t.Fatal("digest failed to verify after a durable round-trip")
		}
	})
}
