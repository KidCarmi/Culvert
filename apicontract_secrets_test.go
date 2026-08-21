package main

// Gate 10 (partial) — no secret-like values in the contract or its rendered
// artifacts. Examples must use placeholders only; a real key, token, or private
// address must never be committed into the API documentation.

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"PEM private key", regexp.MustCompile(`-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}`)},
	{"AWS access key id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"GitHub token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`)},
	{"private IPv4 (10/8)", regexp.MustCompile(`\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)},
	{"private IPv4 (192.168/16)", regexp.MustCompile(`\b192\.168\.\d{1,3}\.\d{1,3}\b`)},
	{"private IPv4 (172.16/12)", regexp.MustCompile(`\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b`)},
}

func TestOpenAPI_Gate10_NoSecretsInContract(t *testing.T) {
	files := []string{
		"api/openapi/openapi.yaml",
		"api/openapi/openapi.json",
		"api/openapi/index.html",
		"api/openapi/index.public.html",
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, p := range secretPatterns {
			if loc := p.re.FindIndex(b); loc != nil {
				t.Errorf("%s contains a %s at byte %d — contract/docs must use placeholders only", f, p.name, loc[0])
			}
		}
	}
}

// secretBearingPropNames walks every schema in the contract and returns the
// property names the contract ITSELF declares to be secret-bearing —
// `format: password` and/or `writeOnly: true`. Deriving the list from the
// spec (rather than hardcoding names) means a NEW secret field added
// tomorrow is covered automatically.
func secretBearingPropNames(doc *openapi3.T) []string {
	w := &secretPropWalker{found: map[string]bool{}, seen: map[*openapi3.SchemaRef]bool{}}
	if doc.Components != nil {
		for _, s := range doc.Components.Schemas {
			w.visit(s)
		}
	}
	forEachSpecSchema(doc, w.visit)
	out := make([]string, 0, len(w.found))
	for n := range w.found {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// secretPropWalker collects secret-bearing property names across a schema
// graph, guarding against $ref cycles.
type secretPropWalker struct {
	found map[string]bool
	seen  map[*openapi3.SchemaRef]bool
}

func (w *secretPropWalker) visit(s *openapi3.SchemaRef) {
	if s == nil || s.Value == nil || w.seen[s] {
		return
	}
	w.seen[s] = true
	for name, prop := range s.Value.Properties {
		if prop != nil && prop.Value != nil && (prop.Value.Format == "password" || prop.Value.WriteOnly) {
			w.found[name] = true
		}
		w.visit(prop)
	}
	w.visit(s.Value.Items)
	if ap := s.Value.AdditionalProperties.Schema; ap != nil {
		w.visit(ap)
	}
	for _, sub := range [][]*openapi3.SchemaRef{s.Value.AllOf, s.Value.AnyOf, s.Value.OneOf} {
		for _, x := range sub {
			w.visit(x)
		}
	}
}

// forEachSpecSchema calls fn for every request/response body schema in the
// document.
func forEachSpecSchema(doc *openapi3.T, fn func(*openapi3.SchemaRef)) {
	if doc.Paths == nil {
		return
	}
	for _, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			if op.RequestBody != nil && op.RequestBody.Value != nil {
				for _, mt := range op.RequestBody.Value.Content {
					fn(mt.Schema)
				}
			}
			for _, resp := range op.Responses.Map() {
				if resp.Value == nil {
					continue
				}
				for _, mt := range resp.Value.Content {
					fn(mt.Schema)
				}
			}
		}
	}
}

// exampleMentionsKey reports whether an example value (decoded JSON-ish
// structure) contains key anywhere in its object keys.
func exampleMentionsKey(v any, key string) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			if k == key || exampleMentionsKey(sub, key) {
				return true
			}
		}
	case []any:
		for _, sub := range t {
			if exampleMentionsKey(sub, key) {
				return true
			}
		}
	}
	return false
}

// TestOpenAPI_Gate10_NoSecretFieldsInExamples is the governance wall the M7
// Slice 2 review asked for: a field the contract itself marks secret-bearing
// (`format: password` or `writeOnly: true`) must never appear in ANY example
// — request-body examples, named examples, or schema-level examples. An
// example is copied verbatim into the generated HTML docs and into most
// client generators' fixtures, so a "sample" credential there becomes a real
// credential-shaped string in published artifacts.
//
// The check is derived from the contract, so it automatically covers any
// future secret-bearing field without needing to be updated.
func TestOpenAPI_Gate10_NoSecretFieldsInExamples(t *testing.T) {
	spec := loadContract(t)
	secretProps := secretBearingPropNames(spec.Doc)
	if len(secretProps) == 0 {
		t.Skip("contract declares no secret-bearing (password/writeOnly) properties yet")
	}
	t.Logf("secret-bearing properties under governance: %v", secretProps)

	c := &secretExampleChecker{t: t, props: secretProps}
	forEachSpecOperation(spec.Doc, func(where string, op *openapi3.Operation) {
		if op.RequestBody != nil && op.RequestBody.Value != nil {
			c.checkContent(where+" requestBody", op.RequestBody.Value.Content)
		}
		for code, resp := range op.Responses.Map() {
			if resp.Value != nil {
				c.checkContent(where+" response "+code, resp.Value.Content)
			}
		}
	})
	if spec.Doc.Components != nil {
		for name, s := range spec.Doc.Components.Schemas {
			if s != nil && s.Value != nil {
				c.check("components.schemas."+name+" example", s.Value.Example)
			}
		}
	}
}

// secretExampleChecker reports any example that carries a secret-bearing
// property name.
type secretExampleChecker struct {
	t     *testing.T
	props []string
}

func (c *secretExampleChecker) check(where string, example any) {
	if example == nil {
		return
	}
	for _, prop := range c.props {
		if exampleMentionsKey(example, prop) {
			c.t.Errorf("%s includes secret-bearing field %q in an example — examples must never carry credential-shaped values", where, prop)
		}
	}
}

func (c *secretExampleChecker) checkContent(where string, content openapi3.Content) {
	for ct, mt := range content {
		c.check(where+"("+ct+")", mt.Example)
		for name, ex := range mt.Examples {
			if ex != nil && ex.Value != nil {
				c.check(where+"("+ct+") example "+name, ex.Value.Value)
			}
		}
		if mt.Schema != nil && mt.Schema.Value != nil {
			c.check(where+"("+ct+") schema example", mt.Schema.Value.Example)
		}
	}
}

// forEachSpecOperation calls fn for every operation with a "METHOD /path"
// label for error messages.
func forEachSpecOperation(doc *openapi3.T, fn func(where string, op *openapi3.Operation)) {
	if doc.Paths == nil {
		return
	}
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			fn(strings.ToUpper(method)+" "+path, op)
		}
	}
}
