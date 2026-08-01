package canonical

import (
	"bytes"
	"testing"
)

// FuzzCanonicalize proves the decoder never panics and that canonicalization is
// idempotent and deterministic: re-canonicalizing the canonical bytes yields the
// same bytes, and equal canonical form ⇒ equal hash.
func FuzzCanonicalize(f *testing.F) {
	seeds := []string{
		`{}`, `[]`, `null`, `1`, `"s"`, `true`,
		`{"b":1,"a":2}`, `[1,2,3]`, `{"a":{"b":[1,{"c":true}]}}`,
		`{"enum":["b","a"]}`, `{"required":["z","a"]}`,
		`{"type":"object","properties":{"x":{"type":"string"}}}`,
		`{"a":9007199254740993}`, `{"s":"😀"}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	b := tb()
	f.Fuzz(func(t *testing.T, raw []byte) {
		n, err := Decode(raw, b)
		if err != nil {
			return // rejected input: fine, must not panic (guaranteed by reaching here)
		}
		enc := Encode(n)
		// Idempotence: the canonical bytes re-decode and re-encode identically.
		n2, err2 := Decode(enc, b)
		if err2 != nil {
			t.Fatalf("canonical bytes failed to re-decode: %v (enc=%q)", err2, enc)
		}
		enc2 := Encode(n2)
		if !bytes.Equal(enc, enc2) {
			t.Fatalf("canonicalization not idempotent:\n first=%q\nsecond=%q", enc, enc2)
		}
		// Equal canonical form ⇒ equal hash.
		if HashNode(n) != HashNode(n2) {
			t.Fatal("equal canonical form produced different hashes")
		}
	})
}

// FuzzCanonicalizeSchema proves the schema path never panics and stays idempotent
// (schema-canonicalizing an already-schema-canonical value is a fixed point).
func FuzzCanonicalizeSchema(f *testing.F) {
	seeds := []string{
		`{"enum":["c","a","b"]}`,
		`{"anyOf":[{"type":"string"},{"type":"number"}]}`,
		`{"properties":{"enum":{"enum":["x","a"]}}}`,
		`{"items":[{"type":"string"},{"type":"number"}]}`,
		`{"oneOf":[{"type":"a"},{"type":"b"}],"required":["y","x"]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	b := tb()
	f.Fuzz(func(t *testing.T, raw []byte) {
		n, err := DecodeSchema(raw, b)
		if err != nil {
			return
		}
		enc := Encode(n)
		n2, err2 := DecodeSchema(enc, b)
		if err2 != nil {
			t.Fatalf("schema-canonical bytes failed to re-decode: %v", err2)
		}
		if !bytes.Equal(enc, Encode(n2)) {
			t.Fatal("schema canonicalization is not idempotent")
		}
	})
}

// FuzzNormalizeDescription proves the normalizer never panics and is idempotent.
func FuzzNormalizeDescription(f *testing.F) {
	for _, s := range []string{"", " ", "a b", "  a\t\nb  ", "DELETE ALL", "😀 x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		norm, err := NormalizeDescription(s, 1<<20)
		if err != nil {
			return
		}
		norm2, err2 := NormalizeDescription(norm, 1<<20)
		if err2 != nil {
			t.Fatalf("normalized text failed to re-normalize: %v", err2)
		}
		if norm != norm2 {
			t.Fatalf("normalization not idempotent: %q -> %q", norm, norm2)
		}
	})
}
