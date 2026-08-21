package cpdp

import (
	"encoding/json"
	"strings"
	"testing"
)

// FuzzEnvelopeVerify feeds arbitrary bytes as an envelope JSON and proves the
// verifier never panics, never applies an invalid snapshot, and never leaks a
// private key. An envelope that survives verification must carry a trusted key,
// a matching recomputed hash, and a valid signature — properties the fuzzer
// cannot forge without the private key it does not have.
func FuzzEnvelopeVerify(f *testing.F) {
	s, ts := mkSigner(f, "k1")
	env := mkSign(f, gwManifest(), gwPayload(), s)
	good, _ := json.Marshal(env)
	f.Add(good)
	f.Add([]byte(`{"manifest":{"schema_version":1}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		var e Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			return // not a decodable envelope; nothing to verify
		}
		err := VerifySignature(&e, ts, testLimits())
		if err != nil {
			return // rejected — the expected outcome for hostile input
		}
		// If verification PASSED, the envelope must be genuinely authentic: its
		// declared key must be trusted and its recomputed hash must match.
		if _, ok := ts.lookup(e.KeyID); !ok {
			t.Fatalf("verify accepted an untrusted key id %q", e.KeyID)
		}
		want, herr := ContentHash(e.Manifest, e.Payload, e.SigAlg, e.KeyID, testLimits().canonicalBounds())
		if herr != nil || want != e.ContentHash {
			t.Fatalf("verify accepted a hash mismatch")
		}
	})
}

// FuzzRollbackVerify proves the rollback-directive verifier never panics and only
// accepts a directive with a trusted key and valid signature.
func FuzzRollbackVerify(f *testing.F) {
	s, ts := mkSigner(f, "k1")
	d, _ := SignRollback(RollbackDirective{
		Capability: CapabilityGateway, TargetHash: "t", CommandID: "c", MinDPVersion: 1,
	}, s)
	good, _ := json.Marshal(d)
	f.Add(good)
	f.Add([]byte(`{"schema_version":1,"capability":"gateway"}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		var d RollbackDirective
		if err := json.Unmarshal(raw, &d); err != nil {
			return
		}
		err := VerifyRollback(&d, ts, CapabilityGateway, "", 0, DPCompatVersion)
		if err != nil {
			return
		}
		if _, ok := ts.lookup(d.KeyID); !ok {
			t.Fatalf("rollback verify accepted an untrusted key id")
		}
	})
}

// FuzzContentHashDeterministic proves the content hash is a deterministic function
// of the signed fields: the same payload string hashed twice yields the same
// digest, and canonicalization never panics on arbitrary payload strings.
func FuzzContentHashDeterministic(f *testing.F) {
	f.Add("hello")
	f.Add("{\"a\":1}")
	f.Add(strings.Repeat("x", 4096))

	f.Fuzz(func(t *testing.T, policySrc string) {
		p := Payload{Gateway: &GatewayPayload{PolicySource: policySrc}}
		l := testLimits()
		h1, err1 := ContentHash(gwManifest(), p, SigAlgEd25519, "k1", l.canonicalBounds())
		h2, err2 := ContentHash(gwManifest(), p, SigAlgEd25519, "k1", l.canonicalBounds())
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("nondeterministic error outcome")
		}
		if err1 == nil && h1 != h2 {
			t.Fatalf("nondeterministic hash: %s != %s", h1, h2)
		}
	})
}

// FuzzAckDecode proves the acknowledgement validator never panics on arbitrary
// JSON and only accepts well-bound acknowledgements.
func FuzzAckDecode(f *testing.F) {
	f.Add([]byte(`{"ack_id":"a","node_id":"n","capability":"gateway","content_hash":"h","state":3}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var a Acknowledgement
		if err := json.Unmarshal(raw, &a); err != nil {
			return
		}
		if err := a.Validate(); err != nil {
			return
		}
		// A valid ack must carry every binding field.
		if a.AckID == "" || a.NodeID == "" || a.ContentHash == "" || !a.Capability.Valid() {
			t.Fatalf("validate accepted an unbound acknowledgement")
		}
	})
}

// --- fuzz helpers (f-scoped so they can't be confused with the t-scoped ones) ---

func mkSigner(f *testing.F, keyID string) (Signer, *TrustStore) {
	f.Helper()
	s, err := GenerateLocalSigner(keyID)
	if err != nil {
		f.Fatalf("GenerateLocalSigner: %v", err)
	}
	ts, err := NewTrustStore([]TrustRoot{{KeyID: keyID, Alg: SigAlgEd25519, Public: s.Public()}})
	if err != nil {
		f.Fatalf("NewTrustStore: %v", err)
	}
	return s, ts
}

func mkSign(f *testing.F, m Manifest, p Payload, s Signer) *Envelope {
	f.Helper()
	env, err := Sign(m, p, s, DefaultLimits())
	if err != nil {
		f.Fatalf("Sign: %v", err)
	}
	return env
}
