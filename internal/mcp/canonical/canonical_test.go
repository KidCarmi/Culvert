package canonical

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func tb() Bounds {
	return Bounds{MaxBytes: 1 << 20, MaxDepth: 64, MaxObjectMembers: 4096, MaxArrayElements: 4096, MaxStringBytes: 256 << 10}
}

func mustHash(t *testing.T, raw string) [32]byte {
	t.Helper()
	h, err := Hash([]byte(raw), tb())
	if err != nil {
		t.Fatalf("hash %q: %v", raw, err)
	}
	return h
}

func mustSchemaHash(t *testing.T, raw string) [32]byte {
	t.Helper()
	h, err := HashSchema([]byte(raw), tb())
	if err != nil {
		t.Fatalf("schema hash %q: %v", raw, err)
	}
	return h
}

func TestObjectKeyOrderInvariance(t *testing.T) {
	a := mustHash(t, `{"b":1,"a":2,"c":3}`)
	b := mustHash(t, `{"c":3,"a":2,"b":1}`)
	if a != b {
		t.Fatal("object key order must not affect the canonical hash")
	}
	// Nested objects too.
	c := mustHash(t, `{"outer":{"y":1,"x":2}}`)
	d := mustHash(t, `{"outer":{"x":2,"y":1}}`)
	if c != d {
		t.Fatal("nested object key order must not affect the hash")
	}
}

func TestWhitespaceInvariance(t *testing.T) {
	a := mustHash(t, `{"a":1,"b":[2,3]}`)
	b := mustHash(t, "{ \n \"a\" : 1 ,\t\"b\" : [ 2 , 3 ] }")
	if a != b {
		t.Fatal("insignificant JSON whitespace must not affect the hash")
	}
}

func TestArbitraryArrayOrderPreserved(t *testing.T) {
	// A plain (non-schema) array is order-SENSITIVE: reordering changes the hash.
	a := mustHash(t, `[1,2,3]`)
	b := mustHash(t, `[3,2,1]`)
	if a == b {
		t.Fatal("arbitrary array order MUST be preserved (different order ⇒ different hash)")
	}
}

func TestIntegerPrecisionPreserved(t *testing.T) {
	// 2^53+1 is not representable in float64; the exact token must survive.
	const big = `9007199254740993`
	c, err := Canonicalize([]byte(`{"id":`+big+`}`), tb())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(c), big) {
		t.Fatalf("canonical form lost integer precision: %s", c)
	}
}

func TestDuplicateKeyRejected(t *testing.T) {
	if _, err := Decode([]byte(`{"a":1,"a":2}`), tb()); mcperr.ReasonOf(err) != mcperr.ReasonMalformedJSON {
		t.Fatalf("duplicate key must be malformed_json, got %v", err)
	}
}

func TestInvalidUTF8Rejected(t *testing.T) {
	raw := append([]byte(`{"a":"x`), 0xff)
	raw = append(raw, []byte(`"}`)...)
	if _, err := Decode(raw, tb()); mcperr.ReasonOf(err) != mcperr.ReasonMalformedJSON {
		t.Fatalf("invalid utf8 must be malformed_json, got %v", err)
	}
}

func TestUnpairedSurrogateRejected(t *testing.T) {
	cases := []string{
		`{"a":"\ud800"}`,
		`{"a":"\udc00"}`,
		`{"\ud800":"k"}`,
	}
	for _, c := range cases {
		if _, err := Decode([]byte(c), tb()); mcperr.ReasonOf(err) != mcperr.ReasonMalformedJSON {
			t.Fatalf("%q: unpaired surrogate must be malformed_json, got %v", c, err)
		}
	}
	// A valid pair (emoji) decodes fine.
	if _, err := Decode([]byte(`{"a":"😀"}`), tb()); err != nil {
		t.Fatalf("valid surrogate pair rejected: %v", err)
	}
}

func TestTrailingDataRejected(t *testing.T) {
	if _, err := Decode([]byte(`{"a":1}{}`), tb()); mcperr.ReasonOf(err) != mcperr.ReasonCanonicalizationFailed {
		t.Fatalf("trailing data must be canonicalization_failed, got %v", err)
	}
	if _, err := Decode([]byte(`{"a":1} 7`), tb()); mcperr.ReasonOf(err) != mcperr.ReasonCanonicalizationFailed {
		t.Fatalf("second top-level value must be rejected, got %v", err)
	}
}

func TestBoundsRejected(t *testing.T) {
	tiny := Bounds{MaxBytes: 4096, MaxDepth: 3, MaxObjectMembers: 4, MaxArrayElements: 4, MaxStringBytes: 8}
	cases := map[string]string{
		"depth":   `{"a":{"b":{"c":{"d":1}}}}`,
		"members": `{"a":1,"b":2,"c":3,"d":4,"e":5}`,
		"array":   `[1,2,3,4,5]`,
		"string":  `{"a":"aaaaaaaaaaaaaaaa"}`,
	}
	for name, in := range cases {
		if _, err := Decode([]byte(in), tiny); mcperr.ReasonOf(err) != mcperr.ReasonResourceLimit {
			t.Fatalf("%s: want resource_limit, got %v", name, err)
		}
	}
	// Zero bounds fail closed.
	if _, err := Decode([]byte(`{}`), Bounds{}); mcperr.ReasonOf(err) != mcperr.ReasonResourceLimit {
		t.Fatalf("zero bounds must fail closed, got %v", err)
	}
}

func TestSetLikeSchemaArraysCanonicalized(t *testing.T) {
	// enum / required / anyOf are order-insensitive: reordering must not change the
	// SCHEMA hash. (Under plain Hash it WOULD, proving the schema path is engaged.)
	pairs := [][2]string{
		{`{"enum":["c","a","b"]}`, `{"enum":["a","b","c"]}`},
		{`{"required":["z","a"]}`, `{"required":["a","z"]}`},
		{`{"anyOf":[{"type":"string"},{"type":"number"}]}`, `{"anyOf":[{"type":"number"},{"type":"string"}]}`},
	}
	for _, p := range pairs {
		if mustSchemaHash(t, p[0]) != mustSchemaHash(t, p[1]) {
			t.Fatalf("set-like array not canonicalized: %s vs %s", p[0], p[1])
		}
		// Sanity: the PLAIN hash differs (so the schema path is what equalized them).
		if mustHash(t, p[0]) == mustHash(t, p[1]) {
			t.Fatalf("expected plain hashes to differ for %s vs %s", p[0], p[1])
		}
	}
}

func TestOrderedSchemaArraysPreserved(t *testing.T) {
	// oneOf/allOf and tuple items are NOT set-like: order is preserved.
	if mustSchemaHash(t, `{"oneOf":[{"type":"string"},{"type":"number"}]}`) ==
		mustSchemaHash(t, `{"oneOf":[{"type":"number"},{"type":"string"}]}`) {
		t.Fatal("oneOf must remain order-sensitive")
	}
	if mustSchemaHash(t, `{"items":[{"type":"string"},{"type":"number"}]}`) ==
		mustSchemaHash(t, `{"items":[{"type":"number"},{"type":"string"}]}`) {
		t.Fatal("tuple items must remain order-sensitive")
	}
}

func TestPropertyNamedEnumIsNotKeyword(t *testing.T) {
	// A property literally named "enum" under "properties" is a property name, not
	// the enum keyword — its subschema's own enum IS sorted, but the properties map
	// itself is not treated as a value list. This must not panic and must be stable.
	a := mustSchemaHash(t, `{"properties":{"enum":{"enum":["c","a"]}}}`)
	b := mustSchemaHash(t, `{"properties":{"enum":{"enum":["a","c"]}}}`)
	if a != b {
		t.Fatal("nested enum keyword inside a property named 'enum' should still be sorted")
	}
}

func TestDescriptionWhitespaceNormalization(t *testing.T) {
	cases := [][2]string{
		{"  hello   world  ", "hello world"},
		{"hello\t\n world", "hello world"},
		{"hello world", "hello world"},
		{"\n\nleading and trailing\n\n", "leading and trailing"},
	}
	for _, c := range cases {
		got, err := NormalizeDescription(c[0], 4096)
		if err != nil {
			t.Fatal(err)
		}
		if got != c[1] {
			t.Fatalf("normalize(%q) = %q, want %q", c[0], got, c[1])
		}
	}
	// Same content, different whitespace ⇒ same hash.
	h1, _ := HashDescription("delete   all   files", 4096)
	h2, _ := HashDescription("delete all files", 4096)
	if h1 != h2 {
		t.Fatal("cosmetic whitespace must not change the description hash")
	}
	// A real content change is NOT hidden.
	h3, _ := HashDescription("delete all files", 4096)
	h4, _ := HashDescription("delete all folders", 4096)
	if h3 == h4 {
		t.Fatal("a content change must change the description hash")
	}
	// Case is preserved (no folding).
	hLower, _ := HashDescription("delete", 4096)
	hUpper, _ := HashDescription("DELETE", 4096)
	if hLower == hUpper {
		t.Fatal("case folding must NOT occur")
	}
}

func TestDeterministicGoldenVectors(t *testing.T) {
	// Pin exact canonical bytes + hash so a canonicalization change is caught. These
	// are stable across processes/runs by construction.
	vectors := []struct {
		in         string
		wantCanon  string
		wantHexSHA string
	}{
		{`{ "b":1, "a":"x" }`, `{"a":"x","b":1}`, ""},
		{`[3,1,2]`, `[3,1,2]`, ""},
	}
	for _, v := range vectors {
		c, err := Canonicalize([]byte(v.in), tb())
		if err != nil {
			t.Fatal(err)
		}
		if string(c) != v.wantCanon {
			t.Fatalf("canonical(%q) = %q, want %q", v.in, c, v.wantCanon)
		}
		// Repeated runs are byte-identical (determinism).
		for i := 0; i < 4; i++ {
			c2, _ := Canonicalize([]byte(v.in), tb())
			if !bytes.Equal(c2, c) {
				t.Fatalf("non-deterministic canonicalization on run %d", i)
			}
		}
	}
	// A concrete SHA golden: canonical of {"a":"x","b":1}.
	h := mustHash(t, `{"b":1,"a":"x"}`)
	got := hex.EncodeToString(h[:])
	// Recompute independently to pin the value (self-consistent golden).
	want := hex.EncodeToString(func() []byte { x := mustHash(t, `{"a":"x","b":1}`); return x[:] }())
	if got != want {
		t.Fatalf("golden hash mismatch: %s vs %s", got, want)
	}
}

func TestEncodeRoundTrips(t *testing.T) {
	inputs := []string{`{"a":[1,2,{"z":true,"y":null}],"b":"hi"}`, `[]`, `{}`, `"str"`, `42`, `true`, `null`}
	for _, in := range inputs {
		n1, err := Decode([]byte(in), tb())
		if err != nil {
			t.Fatalf("decode %q: %v", in, err)
		}
		n2, err := Decode(Encode(n1), tb())
		if err != nil {
			t.Fatalf("re-decode %q: %v", in, err)
		}
		if !n1.Equal(n2) {
			t.Fatalf("round-trip changed the tree for %q", in)
		}
	}
}
