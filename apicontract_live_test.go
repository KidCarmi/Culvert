package main

// Live route-coverage gate (Gate 3). This test BINDS the real, in-memory
// uiRoutes registration table to the OpenAPI contract and the route
// classification manifest via internal/apicontract. It is the durable guarantee
// the OpenAPI program exists to provide:
//
//   - a NEW registered route with no classification row  → UNCLASSIFIED ROUTE
//   - a documented route removed from the router          → STALE CLASSIFICATION
//   - a contract operation with no backing route          → PHANTOM OPERATION
//   - a route marked documented but absent from the spec  → DOCUMENTED-BUT-MISSING
//   - an exemption past its expiry                         → EXPIRED EXEMPTION
//
// Because uiRoutes is already the CI-enforced single source of truth for the
// router (C1 forward/reverse parity), this test cannot be fooled by a hand-typed
// route list: it reads the exact table the middleware and mux consume.

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/apicontract"
)

const (
	openapiSpecPath    = "api/openapi/openapi.yaml"
	classificationPath = "api/route-classification.yaml"
)

// liveRoutes flattens the live uiRoutes table into the apicontract.Route shape.
func liveRoutes() []apicontract.Route {
	var out []apicontract.Route
	for _, rt := range uiRoutes {
		for _, m := range rt.Methods {
			out = append(out, apicontract.Route{
				Path:    rt.Path,
				Method:  m.Method,
				Handler: rt.Handler,
				Domain:  rt.Domain,
				Public:  rt.Public,
				MinRole: string(m.MinRole),
				Muta:    m.Mutating,
				Audit:   m.AuditExpected,
			})
		}
	}
	return out
}

func TestOpenAPI_Gate1_SpecValidates(t *testing.T) {
	if _, err := apicontract.LoadSpec(openapiSpecPath); err != nil {
		t.Fatalf("OpenAPI contract failed validation: %v", err)
	}
}

func TestOpenAPI_Gate2_StyleLint(t *testing.T) {
	spec, err := apicontract.LoadSpec(openapiSpecPath)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	if v := apicontract.StyleLint(spec); len(v) != 0 {
		t.Fatalf("style-lint violations (%d):\n  %s", len(v), joinLines(v))
	}
}

func TestOpenAPI_Gate3_RouteCoverage(t *testing.T) {
	spec, err := apicontract.LoadSpec(openapiSpecPath)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	c, err := apicontract.LoadClassification(classificationPath)
	if err != nil {
		t.Fatalf("load classification: %v", err)
	}
	routes := liveRoutes()
	if len(routes) == 0 {
		t.Fatal("no live routes enumerated from uiRoutes")
	}
	if v := apicontract.CheckCoverage(routes, spec, c); len(v) != 0 {
		t.Fatalf("route-coverage violations (%d) — every registered route must be documented OR carry an unexpired exemption in api/route-classification.yaml:\n  %s", len(v), joinLines(v))
	}
}

func TestOpenAPI_Gate3_NoExpiredExemptions(t *testing.T) {
	c, err := apicontract.LoadClassification(classificationPath)
	if err != nil {
		t.Fatalf("load classification: %v", err)
	}
	if v := apicontract.CheckExemptions(c, time.Now()); len(v) != 0 {
		t.Fatalf("expired route exemptions (%d) — document the route or renew with justification:\n  %s", len(v), joinLines(v))
	}
}

// TestOpenAPI_Gate3_DetectsNewUndocumentedRoute proves, at the integration
// level, that adding a route the developer forgot to classify breaks the gate.
// It appends a synthetic route to a COPY of the live set (never mutating
// uiRoutes) and asserts the coverage check fires.
func TestOpenAPI_Gate3_DetectsNewUndocumentedRoute(t *testing.T) {
	spec, err := apicontract.LoadSpec(openapiSpecPath)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	c, err := apicontract.LoadClassification(classificationPath)
	if err != nil {
		t.Fatalf("load classification: %v", err)
	}
	routes := append(liveRoutes(), apicontract.Route{
		Path: "/api/newly-added-and-forgotten", Method: "POST", Handler: "apiForgot", Domain: "x",
	})
	v := apicontract.CheckCoverage(routes, spec, c)
	found := false
	for _, s := range v {
		if len(s) >= 18 && s[:18] == "UNCLASSIFIED ROUTE" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the gate to reject an unclassified new route; got %d violations: %v", len(v), v)
	}
}

func joinLines(v []string) string {
	out := ""
	for i, s := range v {
		if i > 0 {
			out += "\n  "
		}
		out += s
	}
	return out
}
