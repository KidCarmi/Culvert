package main

// ui_metadata_wildcard_route_test.go — SEC-C2WILDCARD-1.
//
// The C2 metadata index must resolve a request path to the route that OWNS it,
// for wildcard patterns as well as literal ones. Before the fix, a Go 1.22
// "{name}" pattern was stored in the index's EXACT map under its literal
// pattern text, so a real request path never matched it, fell through the
// prefix list and resolved to the "/" catch-all — whose entry is Public: true,
// RolePublic. That silently disabled C2 role enforcement, the C4
// role-divergence observation and the C2c audit-gap check for every one of
// those routes, while Lookup still answered true so c2ShadowMissingMetaTotal
// never incremented and nothing showed up in metrics either.
//
// The pre-existing TestC2_MetadataIndex_ResolvesEveryRoute passes vacuously
// here: it iterates the PATTERN LITERALS, which do hit the exact map. These
// tests substitute a concrete value for each "{…}" segment — what a request
// actually carries — which is the only shape that exercises the defect.

import (
	"strings"
	"testing"
)

// concreteWildcardPath substitutes a distinguishable literal for each "{…}"
// segment of a ServeMux pattern, producing a path a real request could carry.
//
// Deliberately uses its OWN splitting rather than the production helpers, so
// the gate still compiles — and so fails for the right reason — against a tree
// that does not have them.
func concreteWildcardPath(pattern string) string {
	segs := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	for i, s := range segs {
		if len(s) >= 2 && s[0] == '{' && s[len(s)-1] == '}' {
			segs[i] = "concrete" + strings.Trim(s, "{}.")
		}
	}
	return "/" + strings.Join(segs, "/")
}

// TestC2WildcardRoute_ConcretePathResolvesToItsOwnRoute is the defect gate: a
// request path for every wildcard route must resolve to that route, never to
// the public "/" catch-all.
func TestC2WildcardRoute_ConcretePathResolvesToItsOwnRoute(t *testing.T) {
	idx := buildMetadataIndex()

	var wildcards int
	for i := range uiRoutes {
		pattern := uiRoutes[i].Path
		if !strings.Contains(pattern, "{") {
			continue
		}
		wildcards++
		path := concreteWildcardPath(pattern)
		got, ok := idx.Lookup(path)
		if !ok {
			t.Errorf("Lookup(%q) found nothing; want the %q route", path, pattern)
			continue
		}
		if got.Path != pattern {
			t.Errorf("DEFECT: Lookup(%q) resolved to %q (public=%v); want its own route %q",
				path, got.Path, got.Public, pattern)
		}
	}
	if wildcards == 0 {
		t.Fatal("no wildcard routes in uiRoutes — this gate would pass vacuously; " +
			"delete it or re-point it if the wildcard routes were removed")
	}
	t.Logf("checked %d wildcard routes", wildcards)
}

// TestC2WildcardRoute_NeverResolvesToThePublicCatchAll states the security
// consequence directly, so a future regression reads as what it is.
func TestC2WildcardRoute_NeverResolvesToThePublicCatchAll(t *testing.T) {
	idx := buildMetadataIndex()
	for i := range uiRoutes {
		if !strings.Contains(uiRoutes[i].Path, "{") {
			continue
		}
		path := concreteWildcardPath(uiRoutes[i].Path)
		got, ok := idx.Lookup(path)
		if ok && got.Path == "/" {
			t.Errorf("DEFECT: %q resolves to the %q catch-all (Public=%v, role=%v) — "+
				"C2 role enforcement, C4 divergence and the C2c audit-gap check are all disabled for it",
				path, got.Path, got.Public, got.Methods[0].MinRole)
		}
		if ok && got.Public {
			t.Errorf("DEFECT: %q resolves to a Public route (%q)", path, got.Path)
		}
	}
}

// TestC2WildcardRoute_LongerPatternWinsOverShorter pins specificity: the
// sub-resource pattern must win over the bare "{id}" one, as the mux resolves
// it. Both exist on the support-bundle surface with different roles.
func TestC2WildcardRoute_LongerPatternWinsOverShorter(t *testing.T) {
	idx := buildMetadataIndex()
	cases := []struct {
		path string
		want string
	}{
		{"/api/support/bundles/csb_abc", "/api/support/bundles/{id}"},
		{"/api/support/bundles/csb_abc/approve", "/api/support/bundles/{id}/approve"},
		{"/api/support/bundles/csb_abc/download-sealed", "/api/support/bundles/{id}/download-sealed"},
		{"/api/support/recipients/ops-team", "/api/support/recipients/{name}"},
	}
	for _, tc := range cases {
		got, ok := idx.Lookup(tc.path)
		if !ok || got.Path != tc.want {
			t.Errorf("Lookup(%q) = (%q, %v); want %q", tc.path, got.Path, ok, tc.want)
		}
	}
}

// TestC2WildcardRoute_NegativeControls pins that the wildcard matcher did not
// become a sloppy prefix match. Each of these must NOT be claimed by a
// wildcard route.
func TestC2WildcardRoute_NegativeControls(t *testing.T) {
	idx := buildMetadataIndex()
	cases := []struct {
		name string
		path string
	}{
		// An empty id is not a segment value: "{id}" matches one NON-EMPTY
		// segment, as ServeMux does.
		{"empty id segment", "/api/support/bundles/"},
		// One segment too many must not be swallowed by "{id}".
		{"extra segment", "/api/support/bundles/csb_abc/approve/extra"},
		// A different literal prefix must not match.
		{"wrong literal", "/api/support/widgets/csb_abc"},
	}
	for _, tc := range cases {
		got, ok := idx.Lookup(tc.path)
		if ok && strings.Contains(got.Path, "{") {
			t.Errorf("%s: Lookup(%q) wrongly matched wildcard route %q", tc.name, tc.path, got.Path)
		}
	}
}

// TestC2WildcardRoute_LiteralPatternStillResolves keeps the pre-existing
// contract that TestC2_MetadataIndex_ResolvesEveryRoute relies on: looking the
// pattern text up by itself still returns that route and not the catch-all.
func TestC2WildcardRoute_LiteralPatternStillResolves(t *testing.T) {
	idx := buildMetadataIndex()
	for i := range uiRoutes {
		pattern := uiRoutes[i].Path
		got, ok := idx.Lookup(pattern)
		if !ok {
			t.Errorf("Lookup(%q) found nothing", pattern)
			continue
		}
		if got.Path != pattern {
			t.Errorf("Lookup(%q) = %q; want itself", pattern, got.Path)
		}
	}
}

// TestC2WildcardRoute_UnknownPathStillFallsToTheCatchAll is the positive
// control for the fallback the fix must not break: an unrelated path still
// resolves to "/", exactly as before.
func TestC2WildcardRoute_UnknownPathStillFallsToTheCatchAll(t *testing.T) {
	idx := buildMetadataIndex()
	for _, path := range []string{"/favicon.ico", "/index.html", "/not-a-route"} {
		got, ok := idx.Lookup(path)
		if !ok || got.Path != "/" {
			t.Errorf("Lookup(%q) = (%q, %v); want the %q catch-all", path, got.Path, ok, "/")
		}
	}
}
