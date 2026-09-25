package main

// The conformance helpers share ONE loaded contract across a top-level test's
// subtests instead of re-loading it per subtest (apicontract.LoadSpec parses
// and validates the whole document, ≈0.2 s each). Sharing is only sound if
// validation never writes to the spec, and if a shared spec still rejects what
// a fresh one rejects. These tests pin both, so a kin-openapi upgrade that
// starts caching into the schema, or a helper that stops failing on a bad
// response, is caught here rather than silently weakening the suite.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
)

// Validating every documented JSON response and request against a spread of
// good and bad bodies leaves the loaded document byte-identical.
func TestConformance_SharedSpecFixture_ValidationDoesNotMutateSpec(t *testing.T) {
	spec := loadContract(t)
	before, err := json.Marshal(spec.Doc)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	ops := len(spec.Ops)
	bodies := [][]byte{[]byte(`{}`), []byte(`[]`), []byte(`null`), []byte(`"x"`), []byte(`1`), []byte(`{"unexpected":true}`), []byte(`not json`)}
	validated := 0
	for _, o := range spec.Ops {
		if o.Op.Responses != nil {
			for code := range o.Op.Responses.Map() {
				status, err := strconv.Atoi(code)
				if err != nil {
					continue // "default" and ranges carry no single status
				}
				for _, b := range bodies {
					_ = spec.ValidateJSONResponse(o.Method, o.Path, status, b)
					validated++
				}
			}
		}
		if o.Op.RequestBody != nil {
			for _, b := range bodies {
				_ = spec.ValidateJSONRequest(o.Method, o.Path, b)
				validated++
			}
		}
	}
	if validated < 500 {
		t.Fatalf("only %d validations ran — the walk no longer reaches the contract's operations", validated)
	}
	after, err := json.Marshal(spec.Doc)
	if err != nil {
		t.Fatalf("marshal spec after validation: %v", err)
	}
	if !bytes.Equal(before, after) || len(spec.Ops) != ops {
		t.Fatalf("validation mutated the loaded contract (%d validations); a spec shared across subtests would carry state between them", validated)
	}
}

// On one shared spec, malformed responses are still rejected, and a rejection
// does not make a later conforming response fail (or a pass make a later
// malformed one succeed): cases interleave in both directions.
func TestConformance_SharedSpecFixture_StillRejectsMalformedResponses(t *testing.T) {
	spec := loadContract(t)
	const path = "/api/setup/status"
	respond := func(status int, contentType, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", contentType)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}
	}
	const good = `{"needsSetup":true,"ui_tls_fallback":false}`
	cases := []struct {
		name string
		h    http.HandlerFunc
		ok   bool
	}{
		{"real handler", apiSetupStatus, true},
		{"wrong status", respond(http.StatusInternalServerError, "application/json", good), false},
		{"conforming body", respond(http.StatusOK, "application/json", good), true},
		{"wrong content type", respond(http.StatusOK, "text/plain", good), false},
		{"wrong field type", respond(http.StatusOK, "application/json", `{"needsSetup":"yes","ui_tls_fallback":false}`), false},
		{"real handler again", apiSetupStatus, true},
		{"missing required field", respond(http.StatusOK, "application/json", `{"needsSetup":true}`), false},
		{"undocumented field", respond(http.StatusOK, "application/json", `{"needsSetup":true,"ui_tls_fallback":false,"extra":1}`), false},
		{"not JSON", respond(http.StatusOK, "application/json", `needsSetup`), false},
		{"conforming body again", respond(http.StatusOK, "application/json", good), true},
	}
	for _, role := range []UIRole{RoleViewer, RoleAdmin} {
		for _, c := range cases {
			err := checkResponseConforms(spec, http.MethodGet, path, role, c.h)
			if c.ok && err != nil {
				t.Errorf("role %s, %s: a conforming response was rejected: %v", role, c.name, err)
			}
			if !c.ok && err == nil {
				t.Errorf("role %s, %s: a malformed response was accepted", role, c.name)
			}
		}
	}
}
