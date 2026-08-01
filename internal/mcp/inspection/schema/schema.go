// Package schema is the PR-7 SEMANTIC tool-argument schema validator
// (MCP-INSP-001). It compiles the exact registered catalog input/output schema
// ONCE into an immutable, bounded representation and validates an
// already-decoded canonical value against it — business-schema conformance and
// value constraints, NOT the PR-1 structural parse bounds (those are owned by the
// protocol kernel and are not re-litigated here).
//
// Load-bearing properties, all asserted by tests:
//
//   - Single semantic representation. Compilation and validation operate on the
//     canonical.Node tree produced by the ONE strict decode (internal/mcp/canonical).
//     There is no second, differently-behaving parser, and numbers are compared
//     via exact rationals (canonical.NumCmp) — never routed through float64.
//   - Closed supported V1 subset. Only the keywords in supportedKeywords are
//     enforced; a small set of pure annotation keywords is ignored; EVERY other
//     keyword — including $ref, pattern, patternProperties, oneOf, allOf, not,
//     if/then/else, contains, propertyNames, dependentSchemas, multipleOf — makes
//     the schema UNSUPPORTED at compile time (fail conservative). An unsupported
//     security-relevant keyword on a decision-point tool is NEVER silently ignored.
//   - No remote/filesystem/network/executable/regex escape. There is no $ref
//     resolution, no filesystem or network access, no user-supplied regex, and no
//     executable custom format. `format` asserts only a fixed, closed set of
//     deterministic validators; an unknown format value is unsupported.
//   - Bounded work. Compilation and validation are bounded by the injected
//     immutable limits (schema nodes, alternatives, validation operations); a
//     hostile schema or value can force neither unbounded recursion nor work.
package schema

import (
	"strconv"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Status is the stable outcome class of a validation.
type Status uint8

const (
	// StatusUnset — zero value; never returned by Validate (fails closed if seen).
	StatusUnset Status = iota
	// StatusValid — the value conforms to the compiled schema.
	StatusValid
	// StatusInvalid — the value violates a supported constraint (type, required,
	// enum, bounds, additionalProperties, format).
	StatusInvalid
	// StatusUnsupported — the schema uses a security-relevant keyword outside the
	// supported V1 subset; the value is treated as un-inspectable (fail conservative).
	StatusUnsupported
	// StatusLimitExceeded — a compile/validation bound was exceeded.
	StatusLimitExceeded
)

// String returns the stable status label.
func (s Status) String() string {
	switch s {
	case StatusValid:
		return "valid"
	case StatusInvalid:
		return "invalid"
	case StatusUnsupported:
		return "unsupported"
	case StatusLimitExceeded:
		return "limit_exceeded"
	default:
		return "unset"
	}
}

// Result is the immutable, sanitized validation outcome. Path is a bounded,
// JSON-pointer-like location of the FIRST failure (e.g. "/foo/0") — never a raw
// argument value. Detail is fixed developer text.
type Result struct {
	Status Status
	Path   string
	Detail string
}

// Valid reports whether the result is StatusValid.
func (r Result) Valid() bool { return r.Status == StatusValid }

// supportedKeywords is the CLOSED set of JSON Schema keywords enforced in V1.
var supportedKeywords = map[string]struct{}{
	"type": {}, "properties": {}, "required": {}, "additionalProperties": {},
	"enum": {}, "const": {}, "items": {}, "anyOf": {},
	"minimum": {}, "maximum": {}, "exclusiveMinimum": {}, "exclusiveMaximum": {},
	"minLength": {}, "maxLength": {}, "format": {},
	"minItems": {}, "maxItems": {}, "uniqueItems": {},
}

// ignoredKeywords are pure annotation/metadata keywords that do not affect
// validation and are safely skipped (they can never widen what is accepted).
var ignoredKeywords = map[string]struct{}{
	"title": {}, "description": {}, "$comment": {}, "$schema": {}, "$id": {},
	"examples": {}, "default": {}, "deprecated": {}, "readOnly": {}, "writeOnly": {},
}

// supportedFormats is the CLOSED set of deterministic `format` assertions. An
// unknown format value makes the schema unsupported (never silently ignored).
var supportedFormats = map[string]struct{}{
	"email": {}, "uuid": {}, "date-time": {}, "uri": {}, "ipv4": {}, "ipv6": {},
}

// Compiled is an immutable compiled schema, safe for concurrent reads. It is a
// bounded tree mirroring the supported keyword subset; it holds only canonical
// nodes (for enum/const) and pre-parsed bounds, never a live schema reference.
type Compiled struct {
	node *compiledNode
	lim  limits.InspectionLimits
}

type compiledNode struct {
	// A boolean schema (`true`/`false`) short-circuits: acceptAll/rejectAll.
	boolSchema bool
	boolAccept bool

	types  []string // allowed JSON types (empty ⇒ any)
	enum   []*canonical.Node
	konst  *canonical.Node // "const" (nil ⇒ absent)
	anyOf  []*compiledNode
	format string

	// object
	properties map[string]*compiledNode
	required   []string
	addlNode   *compiledNode // additionalProperties as schema (nil unless addlIsSchema)
	addlBool   bool          // additionalProperties as bool value
	addlIsBool bool
	addlIsNode bool

	// array
	items     *compiledNode   // single-schema items (nil unless present)
	tuple     []*compiledNode // tuple items (nil unless present)
	hasItems  bool
	minItems  *int64
	maxItems  *int64
	uniqueArr bool

	// number/string bounds (exact tokens for numbers; ints for lengths)
	minimum          string
	maximum          string
	exclusiveMinimum string
	exclusiveMaximum string
	minLength        *int64
	maxLength        *int64
}

// compileState bounds the compile pass.
type compileState struct {
	lim      limits.InspectionLimits
	nodes    int
	alts     int
	unsupErr error // set when an unsupported keyword is seen (fail conservative)
}

// errLimit / errUnsupported are the compile-time sentinels.
func compileLimit(detail string) error {
	return mcperr.New(mcperr.ReasonSchemaLimitExceeded, "schema.compile", detail)
}

func compileUnsupported(detail string) error {
	return mcperr.New(mcperr.ReasonSchemaUnsupported, "schema.compile", detail)
}

func compileInvalid(detail string) error {
	return mcperr.New(mcperr.ReasonSchemaInvalid, "schema.compile", detail)
}

// Compile turns a canonical schema node into an immutable Compiled representation
// under the injected limits. A nil schema compiles to an accept-all schema (a
// tool that declares no input schema constrains nothing at the schema layer;
// higher layers still bound and DLP-scan the value). It returns a typed mcperr on
// an unsupported keyword (ReasonSchemaUnsupported), a malformed schema
// (ReasonSchemaInvalid), or an over-bound schema (ReasonSchemaLimitExceeded).
func Compile(schema *canonical.Node, lim limits.InspectionLimits) (*Compiled, error) {
	st := &compileState{lim: lim}
	if schema == nil {
		return &Compiled{node: &compiledNode{boolSchema: true, boolAccept: true}, lim: lim}, nil
	}
	n, err := st.compile(schema, 1)
	if err != nil {
		return nil, err
	}
	return &Compiled{node: n, lim: lim}, nil
}

// SupportedKeywords returns the sorted, closed V1 keyword subset (declared for
// documentation/tests). Callers must treat any keyword absent from this set as
// unsupported.
func SupportedKeywords() []string {
	out := make([]string, 0, len(supportedKeywords))
	for k := range supportedKeywords {
		out = append(out, k)
	}
	// deterministic order
	sortStrings(out)
	return out
}

func (st *compileState) compile(s *canonical.Node, depth int) (*compiledNode, error) {
	if depth > st.lim.MaxSchemaNodes() { // depth is bounded by node budget too
		return nil, compileLimit("schema depth")
	}
	st.nodes++
	if st.nodes > st.lim.MaxSchemaNodes() {
		return nil, compileLimit("schema nodes")
	}
	// A boolean schema.
	if s.Kind == canonical.KindBool {
		return &compiledNode{boolSchema: true, boolAccept: s.Bool}, nil
	}
	if s.Kind != canonical.KindObject {
		return nil, compileInvalid("schema is not an object or boolean")
	}
	cn := &compiledNode{}
	for i, key := range s.Keys {
		if _, ok := ignoredKeywords[key]; ok {
			continue
		}
		if _, ok := supportedKeywords[key]; !ok {
			// EVERY other keyword is unsupported (fail conservative): $ref, pattern,
			// patternProperties, oneOf, allOf, not, if/then/else, contains,
			// propertyNames, dependentSchemas, multipleOf, x-*, unknown, ...
			return nil, compileUnsupported("unsupported schema keyword")
		}
		if err := st.compileKeyword(cn, key, s.Vals[i], depth); err != nil {
			return nil, err
		}
	}
	return cn, nil
}

// compileKeyword dispatches one supported keyword; kept small to bound complexity.
func (st *compileState) compileKeyword(cn *compiledNode, key string, v *canonical.Node, depth int) error {
	switch key {
	case "type":
		return compileType(cn, v)
	case "enum":
		return st.compileEnum(cn, v)
	case "const":
		cn.konst = v
		return nil
	case "anyOf":
		return st.compileAnyOf(cn, v, depth)
	case "properties":
		return st.compileProperties(cn, v, depth)
	case "required":
		return compileRequired(cn, v)
	case "additionalProperties":
		return st.compileAdditional(cn, v, depth)
	case "items":
		return st.compileItems(cn, v, depth)
	case "minItems", "maxItems":
		return compileIntBound(cn, key, v)
	case "uniqueItems":
		return compileBoolKeyword(&cn.uniqueArr, v)
	case "minLength", "maxLength":
		return compileIntBound(cn, key, v)
	case "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum":
		return compileNumBound(cn, key, v)
	case "format":
		return compileFormat(cn, v)
	default:
		return compileUnsupported("unsupported schema keyword")
	}
}

func compileType(cn *compiledNode, v *canonical.Node) error {
	switch v.Kind {
	case canonical.KindString:
		if !validTypeName(v.Str) {
			return compileInvalid("unknown type name")
		}
		cn.types = []string{v.Str}
	case canonical.KindArray:
		for _, e := range v.Arr {
			if e.Kind != canonical.KindString || !validTypeName(e.Str) {
				return compileInvalid("invalid type array member")
			}
			cn.types = append(cn.types, e.Str)
		}
		if len(cn.types) == 0 {
			return compileInvalid("empty type array")
		}
	default:
		return compileInvalid("type must be a string or array of strings")
	}
	return nil
}

func validTypeName(s string) bool {
	switch s {
	case "object", "array", "string", "number", "integer", "boolean", "null":
		return true
	}
	return false
}

func (st *compileState) compileEnum(cn *compiledNode, v *canonical.Node) error {
	if v.Kind != canonical.KindArray {
		return compileInvalid("enum must be an array")
	}
	if len(v.Arr) == 0 {
		return compileInvalid("enum must be non-empty")
	}
	st.alts += len(v.Arr)
	if st.alts > st.lim.MaxSchemaAlternatives() {
		return compileLimit("enum/anyOf alternatives")
	}
	// Reject duplicate canonical members (contradictory/ambiguous form).
	seen := make(map[string]struct{}, len(v.Arr))
	for _, e := range v.Arr {
		k := string(canonical.Encode(e))
		if _, dup := seen[k]; dup {
			return compileInvalid("duplicate enum member")
		}
		seen[k] = struct{}{}
		cn.enum = append(cn.enum, e)
	}
	return nil
}

func (st *compileState) compileAnyOf(cn *compiledNode, v *canonical.Node, depth int) error {
	if v.Kind != canonical.KindArray || len(v.Arr) == 0 {
		return compileInvalid("anyOf must be a non-empty array")
	}
	st.alts += len(v.Arr)
	if st.alts > st.lim.MaxSchemaAlternatives() {
		return compileLimit("anyOf alternatives")
	}
	for _, e := range v.Arr {
		sub, err := st.compile(e, depth+1)
		if err != nil {
			return err
		}
		cn.anyOf = append(cn.anyOf, sub)
	}
	return nil
}

func (st *compileState) compileProperties(cn *compiledNode, v *canonical.Node, depth int) error {
	if v.Kind != canonical.KindObject {
		return compileInvalid("properties must be an object")
	}
	cn.properties = make(map[string]*compiledNode, len(v.Keys))
	for i, k := range v.Keys {
		sub, err := st.compile(v.Vals[i], depth+1)
		if err != nil {
			return err
		}
		cn.properties[k] = sub
	}
	return nil
}

func compileRequired(cn *compiledNode, v *canonical.Node) error {
	if v.Kind != canonical.KindArray {
		return compileInvalid("required must be an array")
	}
	seen := make(map[string]struct{}, len(v.Arr))
	for _, e := range v.Arr {
		if e.Kind != canonical.KindString {
			return compileInvalid("required member is not a string")
		}
		if _, dup := seen[e.Str]; dup {
			return compileInvalid("duplicate required member")
		}
		seen[e.Str] = struct{}{}
		cn.required = append(cn.required, e.Str)
	}
	return nil
}

func (st *compileState) compileAdditional(cn *compiledNode, v *canonical.Node, depth int) error {
	switch v.Kind {
	case canonical.KindBool:
		cn.addlIsBool = true
		cn.addlBool = v.Bool
		return nil
	case canonical.KindObject:
		sub, err := st.compile(v, depth+1)
		if err != nil {
			return err
		}
		cn.addlIsNode = true
		cn.addlNode = sub
		return nil
	default:
		return compileInvalid("additionalProperties must be a boolean or schema")
	}
}

func (st *compileState) compileItems(cn *compiledNode, v *canonical.Node, depth int) error {
	cn.hasItems = true
	switch v.Kind {
	case canonical.KindObject, canonical.KindBool:
		sub, err := st.compile(v, depth+1)
		if err != nil {
			return err
		}
		cn.items = sub
		return nil
	case canonical.KindArray: // tuple items — order preserved
		for _, e := range v.Arr {
			sub, err := st.compile(e, depth+1)
			if err != nil {
				return err
			}
			cn.tuple = append(cn.tuple, sub)
		}
		return nil
	default:
		return compileInvalid("items must be a schema or array of schemas")
	}
}

func compileIntBound(cn *compiledNode, key string, v *canonical.Node) error {
	if v.Kind != canonical.KindNumber {
		return compileInvalid(key + " must be a number")
	}
	n, err := strconv.ParseInt(v.Num, 10, 64)
	if err != nil || n < 0 {
		return compileInvalid(key + " must be a non-negative integer")
	}
	switch key {
	case "minLength":
		cn.minLength = &n
	case "maxLength":
		cn.maxLength = &n
	case "minItems":
		cn.minItems = &n
	case "maxItems":
		cn.maxItems = &n
	}
	return nil
}

func compileNumBound(cn *compiledNode, key string, v *canonical.Node) error {
	if v.Kind != canonical.KindNumber {
		return compileInvalid(key + " must be a number")
	}
	// Validate it is a real numeric token (exact-rational parseable).
	if _, ok := canonical.NumCmp(v.Num, v.Num); !ok {
		return compileInvalid(key + " is not a valid number")
	}
	switch key {
	case "minimum":
		cn.minimum = v.Num
	case "maximum":
		cn.maximum = v.Num
	case "exclusiveMinimum":
		cn.exclusiveMinimum = v.Num
	case "exclusiveMaximum":
		cn.exclusiveMaximum = v.Num
	}
	return nil
}

func compileBoolKeyword(dst *bool, v *canonical.Node) error {
	if v.Kind != canonical.KindBool {
		return compileInvalid("expected a boolean keyword value")
	}
	*dst = v.Bool
	return nil
}

func compileFormat(cn *compiledNode, v *canonical.Node) error {
	if v.Kind != canonical.KindString {
		return compileInvalid("format must be a string")
	}
	if _, ok := supportedFormats[v.Str]; !ok {
		return compileUnsupported("unsupported format")
	}
	cn.format = v.Str
	return nil
}

func sortStrings(s []string) {
	// insertion sort — bounded, no import; the set is tiny.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
