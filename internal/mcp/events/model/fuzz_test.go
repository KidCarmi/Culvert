package model

import (
	"encoding/json"
	"testing"
)

// FuzzEventValidate feeds arbitrary bytes into the event decoder + validator. The
// invariant is total: no input may panic, and a decoded event either validates or
// is rejected with a typed error — never a partial publish.
func FuzzEventValidate(f *testing.F) {
	seed, _ := json.Marshal(baseDecision())
	f.Add(seed)
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var e Event
		if err := json.Unmarshal(data, &e); err != nil {
			return // not an event; nothing to validate
		}
		// Validate must never panic and must be deterministic.
		err1 := e.Validate()
		err2 := e.Validate()
		if (err1 == nil) != (err2 == nil) {
			t.Fatal("Validate is non-deterministic")
		}
		if err1 == nil {
			// A valid event must produce a stable digest.
			d1, e1 := e.Digest()
			d2, e2 := e.Digest()
			if e1 != nil || e2 != nil || d1 != d2 {
				t.Fatal("digest not deterministic for a valid event")
			}
		}
	})
}

// FuzzCanonicalDigest fuzzes field values and asserts the digest is a stable pure
// function of the content and excludes the digest field itself.
func FuzzCanonicalDigest(f *testing.F) {
	f.Add("acme", "user-1", "ALLOW", uint64(1))
	f.Fuzz(func(t *testing.T, tenant, principal, action string, rev uint64) {
		e := baseDecision()
		e.Identity.Tenant = tenant
		e.Identity.PrincipalID = principal
		e.Decision.Action = action
		e.Decision.PolicyRevision = rev
		d1, err := e.ComputeDigest()
		if err != nil {
			return
		}
		// Recompute over the event now carrying the digest — must be identical.
		d2, err := e.Digest()
		if err != nil || d1 != d2 {
			t.Fatalf("digest unstable: %q vs %q", d1, d2)
		}
		if !e.VerifyDigest() {
			t.Fatal("VerifyDigest failed on a freshly computed digest")
		}
	})
}
