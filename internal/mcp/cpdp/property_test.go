package cpdp

import "testing"

// TestProperty_AnySignedFieldMutationInvalidates proves that mutating ANY signed
// field of a verified envelope invalidates verification (hash mismatch), across
// every dimension of the manifest and payload.
func TestProperty_AnySignedFieldMutationInvalidates(t *testing.T) {
	s, ts := newSigner(t, "k1")
	mutators := []struct {
		name string
		mut  func(*Envelope)
	}{
		{"epoch", func(e *Envelope) { e.Manifest.Epoch++ }},
		{"config_rev", func(e *Envelope) { e.Manifest.Revisions.Config++ }},
		{"policy_rev", func(e *Envelope) { e.Manifest.Revisions.Policy++ }},
		{"catalog_rev", func(e *Envelope) { e.Manifest.Revisions.Catalog++ }},
		{"credential_rev", func(e *Envelope) { e.Manifest.Revisions.Credential++ }},
		{"min_version", func(e *Envelope) { e.Manifest.MinDPVersion++ }},
		{"payload_type", func(e *Envelope) { e.Manifest.PayloadType += "x" }},
		{"created", func(e *Envelope) { e.Manifest.CreatedUnixNano++ }},
		{"server_enabled", func(e *Envelope) { e.Payload.Gateway.Servers[0].Enabled = false }},
		{"tool_name", func(e *Envelope) { e.Payload.Gateway.Tools[0].Name += "x" }},
		{"cred_scope", func(e *Envelope) { e.Payload.Gateway.CredentialProfiles[0].Scope += "x" }},
		{"listener_port", func(e *Envelope) { e.Payload.Gateway.Listener.Port++ }},
		{"policy_source", func(e *Envelope) { e.Payload.Gateway.PolicySource += " " }},
	}
	for _, m := range mutators {
		t.Run(m.name, func(t *testing.T) {
			env := mustSign(t, gwManifest(), gwPayload(), s)
			if err := VerifySignature(env, ts, testLimits()); err != nil {
				t.Fatalf("baseline verify: %v", err)
			}
			m.mut(env)
			if err := VerifySignature(env, ts, testLimits()); err == nil {
				t.Fatalf("mutation of %s did not invalidate verification", m.name)
			}
		})
	}
}

// TestProperty_DuplicatePublishIdempotentDifferentContentRejected proves the store
// invariants: a duplicate exact publication is idempotent, a same revision with
// different content is rejected.
func TestProperty_DuplicatePublishIdempotentDifferentContentRejected(t *testing.T) {
	s, _ := newSigner(t, "k1")
	store := NewActiveStore(CapabilityGateway)
	e1 := mustSign(t, gwManifest(), gwPayload(), s)
	if sw, _ := store.Activate(e1); !sw {
		t.Fatal("first activate should swap")
	}
	if sw, _ := store.Activate(e1); sw {
		t.Fatal("duplicate exact publication must be idempotent")
	}
	p2 := gwPayload()
	p2.Gateway.Tools[0].Name = "write"
	e2 := mustSign(t, gwManifest(), p2, s) // same manifest rev+epoch, different content
	if _, err := store.Activate(e2); err == nil {
		t.Fatal("same revision with different content must be rejected")
	}
}

// ---- benchmarks ----------------------------------------------------------------

func BenchmarkSign(b *testing.B) {
	s, _ := GenerateLocalSigner("k1")
	m, p, l := gwManifest(), gwPayload(), DefaultLimits()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Sign(m, p, s, l); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	s, _ := GenerateLocalSigner("k1")
	ts, _ := NewTrustStore([]TrustRoot{{KeyID: "k1", Alg: SigAlgEd25519, Public: s.Public()}})
	env, _ := Sign(gwManifest(), gwPayload(), s, DefaultLimits())
	l := DefaultLimits()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := VerifySignature(env, ts, l); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkContentHash(b *testing.B) {
	m, p, l := gwManifest(), gwPayload(), DefaultLimits()
	bounds := l.CanonicalBounds()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ContentHash(m, p, SigAlgEd25519, "k1", bounds); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkActiveRead(b *testing.B) {
	s, _ := GenerateLocalSigner("k1")
	store := NewActiveStore(CapabilityGateway)
	env, _ := Sign(gwManifest(), gwPayload(), s, DefaultLimits())
	store.Activate(env)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.Active()
	}
}
