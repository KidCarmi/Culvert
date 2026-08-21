package schema

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func bounds() canonical.Bounds {
	return canonical.Bounds{MaxBytes: 1 << 20, MaxDepth: 64, MaxObjectMembers: 4096, MaxArrayElements: 4096, MaxStringBytes: 1 << 16}
}

func mustNode(t *testing.T, s string) *canonical.Node {
	t.Helper()
	n, err := canonical.Decode([]byte(s), bounds())
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return n
}

func compile(t *testing.T, s string) *Compiled {
	t.Helper()
	c, err := Compile(mustNode(t, s), limits.DefaultGatewayInspection())
	if err != nil {
		t.Fatalf("compile %q: %v", s, err)
	}
	return c
}

func TestValidate_Valid(t *testing.T) {
	c := compile(t, `{"type":"object","properties":{"n":{"type":"integer","minimum":1,"maximum":10},"s":{"type":"string","minLength":2}},"required":["n"],"additionalProperties":false}`)
	r := c.Validate(mustNode(t, `{"n":5,"s":"hi"}`))
	if !r.Valid() {
		t.Fatalf("expected valid, got %v path=%s detail=%s", r.Status, r.Path, r.Detail)
	}
}

func TestValidate_MissingRequired(t *testing.T) {
	c := compile(t, `{"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}`)
	r := c.Validate(mustNode(t, `{}`))
	if r.Status != StatusInvalid || r.Path != "/n" {
		t.Fatalf("expected invalid /n, got %v %s", r.Status, r.Path)
	}
}

func TestValidate_WrongType(t *testing.T) {
	c := compile(t, `{"type":"object","properties":{"n":{"type":"integer"}}}`)
	r := c.Validate(mustNode(t, `{"n":"notnum"}`))
	if r.Status != StatusInvalid || r.Path != "/n" {
		t.Fatalf("expected invalid /n, got %v %s", r.Status, r.Path)
	}
}

func TestValidate_AdditionalPropertyRejected(t *testing.T) {
	c := compile(t, `{"type":"object","properties":{"a":{"type":"string"}},"additionalProperties":false}`)
	r := c.Validate(mustNode(t, `{"a":"x","evil":1}`))
	if r.Status != StatusInvalid || r.Path != "/evil" {
		t.Fatalf("expected invalid /evil, got %v %s", r.Status, r.Path)
	}
}

func TestValidate_EnumMismatch(t *testing.T) {
	c := compile(t, `{"enum":["red","green","blue"]}`)
	if r := c.Validate(mustNode(t, `"red"`)); !r.Valid() {
		t.Fatalf("red should be valid: %v", r)
	}
	if r := c.Validate(mustNode(t, `"purple"`)); r.Status != StatusInvalid {
		t.Fatalf("purple should be invalid: %v", r)
	}
}

func TestValidate_NumericBounds_NoFloat64Loss(t *testing.T) {
	// A 64-bit-exceeding integer that float64 cannot represent exactly must still
	// compare correctly via exact rationals.
	c := compile(t, `{"type":"integer","maximum":9007199254740993}`)
	if r := c.Validate(mustNode(t, `9007199254740993`)); !r.Valid() {
		t.Fatalf("boundary equal should be valid: %v", r)
	}
	if r := c.Validate(mustNode(t, `9007199254740994`)); r.Status != StatusInvalid {
		t.Fatalf("above max should be invalid: %v", r)
	}
}

func TestValidate_ExclusiveBounds(t *testing.T) {
	c := compile(t, `{"type":"number","exclusiveMinimum":0,"exclusiveMaximum":1}`)
	if r := c.Validate(mustNode(t, `0`)); r.Status != StatusInvalid {
		t.Fatalf("0 must fail exclusiveMinimum: %v", r)
	}
	if r := c.Validate(mustNode(t, `0.5`)); !r.Valid() {
		t.Fatalf("0.5 must be valid: %v", r)
	}
}

func TestValidate_StringBounds(t *testing.T) {
	c := compile(t, `{"type":"string","minLength":3,"maxLength":5}`)
	if r := c.Validate(mustNode(t, `"ab"`)); r.Status != StatusInvalid {
		t.Fatalf("too short must be invalid: %v", r)
	}
	if r := c.Validate(mustNode(t, `"abcdef"`)); r.Status != StatusInvalid {
		t.Fatalf("too long must be invalid: %v", r)
	}
	if r := c.Validate(mustNode(t, `"abcd"`)); !r.Valid() {
		t.Fatalf("in-range must be valid: %v", r)
	}
}

func TestValidate_StringLength_RuneCount(t *testing.T) {
	// "é" is 2 bytes but 1 rune; maxLength counts runes.
	c := compile(t, `{"type":"string","maxLength":1}`)
	if r := c.Validate(mustNode(t, `"é"`)); !r.Valid() {
		t.Fatalf("single rune must satisfy maxLength=1: %v", r)
	}
}

func TestValidate_SupportedFormats(t *testing.T) {
	cases := []struct {
		format, good, bad string
	}{
		{"email", `"a@b.com"`, `"nope"`},
		{"uuid", `"12345678-1234-1234-1234-123456789012"`, `"not-a-uuid"`},
		{"ipv4", `"192.0.2.1"`, `"999.0.0.1"`},
		{"ipv6", `"2001:db8::1"`, `"1.2.3.4"`},
		{"date-time", `"2023-01-02T15:04:05Z"`, `"2023-13-40"`},
		{"uri", `"https://example.com/x"`, `"no scheme"`},
	}
	for _, tc := range cases {
		c := compile(t, `{"type":"string","format":"`+tc.format+`"}`)
		if r := c.Validate(mustNode(t, tc.good)); !r.Valid() {
			t.Errorf("format %s: %s should be valid: %v", tc.format, tc.good, r)
		}
		if r := c.Validate(mustNode(t, tc.bad)); r.Status != StatusInvalid {
			t.Errorf("format %s: %s should be invalid: %v", tc.format, tc.bad, r)
		}
	}
}

func TestCompile_UnsupportedKeyword(t *testing.T) {
	// pattern (arbitrary regex), $ref, oneOf, allOf, not, if — every one is
	// unsupported and must NOT silently compile to an accept-all schema.
	for _, s := range []string{
		`{"pattern":"^x$"}`,
		`{"$ref":"#/definitions/x"}`,
		`{"oneOf":[{"type":"string"}]}`,
		`{"allOf":[{"type":"string"}]}`,
		`{"not":{"type":"string"}}`,
		`{"if":{"type":"string"},"then":{}}`,
		`{"patternProperties":{"^x":{}}}`,
		`{"multipleOf":2}`,
		`{"contains":{"type":"string"}}`,
		`{"propertyNames":{"minLength":1}}`,
	} {
		_, err := Compile(mustNode(t, s), limits.DefaultGatewayInspection())
		if mcperr.ReasonOf(err) != mcperr.ReasonSchemaUnsupported {
			t.Errorf("schema %s: expected ReasonSchemaUnsupported, got %v", s, err)
		}
	}
}

func TestCompile_UnknownFormatUnsupported(t *testing.T) {
	_, err := Compile(mustNode(t, `{"type":"string","format":"hostname"}`), limits.DefaultGatewayInspection())
	if mcperr.ReasonOf(err) != mcperr.ReasonSchemaUnsupported {
		t.Fatalf("unknown format must be unsupported, got %v", err)
	}
}

func TestCompile_MalformedSchema(t *testing.T) {
	for _, s := range []string{
		`{"type":123}`,
		`{"type":"bogus"}`,
		`{"required":"notarray"}`,
		`{"enum":[]}`,
		`{"enum":["a","a"]}`,
		`{"minLength":-1}`,
		`{"properties":"notobj"}`,
	} {
		_, err := Compile(mustNode(t, s), limits.DefaultGatewayInspection())
		if mcperr.ReasonOf(err) != mcperr.ReasonSchemaInvalid {
			t.Errorf("schema %s: expected ReasonSchemaInvalid, got %v", s, err)
		}
	}
}

func TestCompile_AnnotationsIgnored(t *testing.T) {
	c := compile(t, `{"type":"string","title":"T","description":"d","examples":["x"],"default":"y","$comment":"c"}`)
	if r := c.Validate(mustNode(t, `"ok"`)); !r.Valid() {
		t.Fatalf("annotations must be ignored, value should validate: %v", r)
	}
}

func TestValidate_Const(t *testing.T) {
	c := compile(t, `{"const":42}`)
	if r := c.Validate(mustNode(t, `42`)); !r.Valid() {
		t.Fatalf("const match must be valid: %v", r)
	}
	if r := c.Validate(mustNode(t, `43`)); r.Status != StatusInvalid {
		t.Fatalf("const mismatch must be invalid: %v", r)
	}
}

func TestValidate_AnyOf(t *testing.T) {
	c := compile(t, `{"anyOf":[{"type":"string"},{"type":"integer"}]}`)
	if r := c.Validate(mustNode(t, `"s"`)); !r.Valid() {
		t.Fatalf("string matches anyOf: %v", r)
	}
	if r := c.Validate(mustNode(t, `5`)); !r.Valid() {
		t.Fatalf("int matches anyOf: %v", r)
	}
	if r := c.Validate(mustNode(t, `true`)); r.Status != StatusInvalid {
		t.Fatalf("bool matches no branch: %v", r)
	}
}

func TestValidate_NestedArrayItems(t *testing.T) {
	c := compile(t, `{"type":"array","items":{"type":"integer","minimum":0},"minItems":1,"maxItems":3}`)
	if r := c.Validate(mustNode(t, `[1,2]`)); !r.Valid() {
		t.Fatalf("valid array: %v", r)
	}
	if r := c.Validate(mustNode(t, `[1,-1]`)); r.Status != StatusInvalid || r.Path != "/1" {
		t.Fatalf("negative element at /1: %v", r)
	}
	if r := c.Validate(mustNode(t, `[]`)); r.Status != StatusInvalid {
		t.Fatalf("empty violates minItems: %v", r)
	}
}

func TestValidate_UniqueItems(t *testing.T) {
	c := compile(t, `{"type":"array","uniqueItems":true}`)
	if r := c.Validate(mustNode(t, `[1,2,1]`)); r.Status != StatusInvalid {
		t.Fatalf("duplicate must be invalid: %v", r)
	}
}

func TestValidate_DeeplyNestedBounded(t *testing.T) {
	// A schema and value nested to the depth bound must not panic; work is bounded.
	c := compile(t, `{"type":"object","properties":{"a":{"type":"object","properties":{"b":{"type":"object","properties":{"c":{"type":"integer"}}}}}}}`)
	if r := c.Validate(mustNode(t, `{"a":{"b":{"c":1}}}`)); !r.Valid() {
		t.Fatalf("nested valid: %v", r)
	}
}

func TestValidate_LimitExceeded(t *testing.T) {
	cfg := gwConfigForTest()
	cfg.MaxValidationOps = 3 // tiny budget
	lim, err := limits.NewInspection(cfg)
	if err != nil {
		t.Fatalf("limits: %v", err)
	}
	c, err := Compile(mustNode(t, `{"type":"array","items":{"type":"integer"}}`), lim)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	r := c.Validate(mustNode(t, `[1,2,3,4,5,6,7,8,9,10]`))
	if r.Status != StatusLimitExceeded {
		t.Fatalf("expected limit exceeded, got %v", r)
	}
}

// TestValidate_CallerAliasMutation proves the compiled schema does not alias the
// caller's input node: mutating the ORIGINAL schema node after Compile cannot
// change validation outcomes.
func TestValidate_CallerAliasMutation(t *testing.T) {
	src := mustNode(t, `{"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}`)
	c, err := Compile(src, limits.DefaultGatewayInspection())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Mutate the source node's "required" out from under the compiled schema.
	if reqVal, ok := src.Get("required"); ok {
		reqVal.Arr = nil
	}
	// Compiled schema must STILL enforce required.
	if r := c.Validate(mustNode(t, `{}`)); r.Status != StatusInvalid {
		t.Fatalf("compiled schema must be immune to caller mutation: %v", r)
	}
}

// gwConfigForTest returns the gateway inspection config as a plain struct so tests
// can tweak individual bounds. It mirrors the package default.
func gwConfigForTest() limits.InspectionConfig {
	// Re-derive from the exported default by validating a known-good config.
	return limits.InspectionConfig{
		MaxSchemaBytes: 256 << 10, MaxSchemaNodes: 8192, MaxSchemaAlternatives: 512,
		MaxValidationOps: 1 << 18, MaxArgNodes: 8192, MaxOutputBytes: 4 << 20,
		MaxOutputNodes: 8192, MaxStringsScanned: 8192, MaxBytesPerString: 256 << 10,
		MaxTotalScanBytes: 8 << 20, MaxFindings: 1024, MaxRedactions: 1024,
		MaxExtractionPaths: 256, MaxExtractedDests: 64, MaxURLBytes: 4096,
		MaxHostBytes: 512, MaxQueryBytes: 2048, MaxDNSConcurrency: 16,
		MaxDNSAddresses: 32, MaxDNSWork: 16, MaxRedirectHops: 8, MaxRedirectEvidence: 8,
		MaxInjectionOps: 1 << 18, MaxTransformedBytes: 4 << 20, MaxSafeResultBytes: 64 << 10,
		MaxTruncatedTextBytes: 32 << 10,
	}
}
