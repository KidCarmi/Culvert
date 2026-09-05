package apicontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const realSpec = "../../api/openapi/openapi.yaml"
const realManifest = "../../api/route-classification.yaml"

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A minimal but VALID (per style rules) spec fixture used as the base for
// negative-mutation tests.
const goodOpTemplate = `openapi: 3.0.4
info: { title: t, version: 1.0.0 }
paths:
  /api/thing:
    get:
      operationId: getThing
      summary: Get the thing
      description: Returns the thing.
      tags: [thing]
      security: []
      x-culvert-visibility: admin-supported
      x-culvert-permission: viewer
      x-culvert-stability: stable
      x-culvert-introduced-version: 1.0.0
      responses:
        '200': { description: ok, content: { application/json: { schema: { type: object } } } }
        '403': { description: forbidden, content: { text/plain: { schema: { type: string } } } }
`

// ── Positive: the REAL artifacts load, validate, and lint clean ──────────────

func TestRealSpec_ValidatesAndLintsClean(t *testing.T) {
	spec, err := LoadSpec(realSpec)
	if err != nil {
		t.Fatalf("Gate 1 (validation) failed on the real contract: %v", err)
	}
	if len(spec.Ops) == 0 {
		t.Fatal("real spec has no operations")
	}
	if viol := StyleLint(spec); len(viol) != 0 {
		t.Fatalf("Gate 2 (style lint) found %d violations in the real contract:\n%s", len(viol), strings.Join(viol, "\n"))
	}
}

func TestRealManifest_Parses(t *testing.T) {
	c, err := LoadClassification(realManifest)
	if err != nil {
		t.Fatalf("manifest parse failed: %v", err)
	}
	if len(c.Rows) == 0 {
		t.Fatal("manifest has no rows")
	}
	// Anchor/alias resolution: every exemption must carry a concrete expiry.
	for _, r := range c.Rows {
		if r.Exemption != nil && r.Exemption.Expires == "" {
			t.Fatalf("%s %s exemption expiry did not resolve (YAML anchor?)", r.Method, r.Route)
		}
	}
}

// ── Gate 2 negative: style lint fires on a missing vendor extension ──────────

func TestStyleLint_CatchesMissingVisibility(t *testing.T) {
	bad := strings.Replace(goodOpTemplate, "      x-culvert-visibility: admin-supported\n", "", 1)
	spec, err := LoadSpec(writeTemp(t, "bad.yaml", bad))
	if err != nil {
		t.Fatalf("fixture should still be a valid OpenAPI doc: %v", err)
	}
	viol := StyleLint(spec)
	if !containsSub(viol, "x-culvert-visibility") {
		t.Fatalf("expected a visibility violation, got: %v", viol)
	}
}

func TestStyleLint_CatchesMutatingWithoutAudit(t *testing.T) {
	mutating := `openapi: 3.0.4
info: { title: t, version: 1.0.0 }
paths:
  /api/do:
    post:
      operationId: doIt
      summary: Do it
      description: Does it.
      tags: [x]
      security: []
      x-culvert-visibility: admin-supported
      x-culvert-permission: admin
      x-culvert-stability: stable
      x-culvert-introduced-version: 1.0.0
      responses:
        '200': { description: ok, content: { application/json: { schema: { type: object } } } }
        '403': { description: forbidden, content: { text/plain: { schema: { type: string } } } }
`
	spec, err := LoadSpec(writeTemp(t, "mut.yaml", mutating))
	if err != nil {
		t.Fatal(err)
	}
	viol := StyleLint(spec)
	if !containsSub(viol, "x-culvert-danger-level") || !containsSub(viol, "x-culvert-audit-event") {
		t.Fatalf("expected danger-level+audit-event violations for a mutating op, got: %v", viol)
	}
}

// ── Gate 3 negatives: coverage bijection ─────────────────────────────────────

func loadGood(t *testing.T) *Spec {
	t.Helper()
	s, err := LoadSpec(writeTemp(t, "good.yaml", goodOpTemplate))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func docRow() ClassRow {
	// MinRole left empty so it matches the bare fixture routes; role-binding is
	// exercised explicitly by TestCoverage_RoleDrift.
	return ClassRow{Route: "/api/thing", Method: "GET", Handler: "getThing", Domain: "x", Visibility: "admin-supported", Documented: true}
}

func TestCoverage_RoleDrift(t *testing.T) {
	spec := loadGood(t)
	routes := []Route{{Path: "/api/thing", Method: "GET", MinRole: "admin"}}
	c := &Classification{Rows: []ClassRow{
		{Route: "/api/thing", Method: "GET", Visibility: "admin-supported", MinRole: "viewer", Documented: true},
	}}
	if !containsSub(CheckCoverage(routes, spec, c), "ROLE DRIFT") {
		t.Fatal("expected ROLE DRIFT when manifest min_role diverges from the live router role")
	}
}

// HIGH-1 regression: the sensitive-schema lint MUST fire even when the extension
// is authored as a YAML boolean (the real-world form).
func TestStyleLint_SensitiveOpenSchema_BooleanExtension(t *testing.T) {
	spec := `openapi: 3.0.4
info: { title: t, version: 1.0.0 }
paths:
  /api/thing:
    get:
      operationId: getThing
      summary: s
      description: d
      tags: [x]
      security: []
      x-culvert-visibility: admin-supported
      x-culvert-permission: viewer
      x-culvert-stability: stable
      x-culvert-introduced-version: 1.0.0
      responses:
        '200': { description: ok, content: { application/json: { schema: { type: object } } } }
        '403': { description: forbidden, content: { text/plain: { schema: { type: string } } } }
components:
  schemas:
    Leaky:
      type: object
      additionalProperties: true
      x-culvert-sensitive: true
`
	s, err := LoadSpec(writeTemp(t, "leaky.yaml", spec))
	if err != nil {
		t.Fatal(err)
	}
	if !containsSub(StyleLint(s), "x-culvert-sensitive with additionalProperties:true") {
		t.Fatal("sensitive-schema lint did not fire for a boolean x-culvert-sensitive (HIGH-1 regression)")
	}
}

func TestCoverage_Clean(t *testing.T) {
	spec := loadGood(t)
	routes := []Route{{Path: "/api/thing", Method: "GET", Handler: "getThing"}}
	c := &Classification{Rows: []ClassRow{docRow()}}
	if v := CheckCoverage(routes, spec, c); len(v) != 0 {
		t.Fatalf("expected clean coverage, got: %v", v)
	}
}

func TestCoverage_UnclassifiedRoute(t *testing.T) {
	spec := loadGood(t)
	routes := []Route{
		{Path: "/api/thing", Method: "GET", Handler: "getThing"},
		{Path: "/api/new", Method: "POST", Handler: "apiNew"}, // not in manifest
	}
	c := &Classification{Rows: []ClassRow{docRow()}}
	if !containsSub(CheckCoverage(routes, spec, c), "UNCLASSIFIED ROUTE") {
		t.Fatal("expected UNCLASSIFIED ROUTE violation for a route missing from the manifest")
	}
}

func TestCoverage_StaleRow(t *testing.T) {
	spec := loadGood(t)
	routes := []Route{{Path: "/api/thing", Method: "GET", Handler: "getThing"}}
	c := &Classification{Rows: []ClassRow{
		docRow(),
		{Route: "/api/gone", Method: "GET", Visibility: "admin-supported", Documented: false,
			Exemption: &Exemption{Owner: "o", Reason: "r", SecurityClass: "s", Expires: "2099-01-01"}},
	}}
	if !containsSub(CheckCoverage(routes, spec, c), "STALE CLASSIFICATION") {
		t.Fatal("expected STALE CLASSIFICATION for a row with no live route")
	}
}

func TestCoverage_PhantomOperation(t *testing.T) {
	spec := loadGood(t) // documents GET /api/thing
	routes := []Route{{Path: "/api/other", Method: "GET", Handler: "apiOther"}}
	c := &Classification{Rows: []ClassRow{
		{Route: "/api/other", Method: "GET", Visibility: "admin-supported", Documented: false,
			Exemption: &Exemption{Owner: "o", Reason: "r", SecurityClass: "s", Expires: "2099-01-01"}},
	}}
	if !containsSub(CheckCoverage(routes, spec, c), "PHANTOM OPERATION") {
		t.Fatal("expected PHANTOM OPERATION for a spec op mapping to no documented route")
	}
}

func TestCoverage_DocumentedButMissingFromSpec(t *testing.T) {
	spec := loadGood(t)
	routes := []Route{
		{Path: "/api/thing", Method: "GET"},
		{Path: "/api/undocced", Method: "GET"},
	}
	c := &Classification{Rows: []ClassRow{
		docRow(),
		{Route: "/api/undocced", Method: "GET", Visibility: "admin-supported", Documented: true}, // claims documented, not in spec
	}}
	if !containsSub(CheckCoverage(routes, spec, c), "DOCUMENTED-BUT-MISSING") {
		t.Fatal("expected DOCUMENTED-BUT-MISSING for a documented row absent from the spec")
	}
}

func TestCoverage_NeitherDocumentedNorExempt(t *testing.T) {
	spec := loadGood(t)
	routes := []Route{{Path: "/api/thing", Method: "GET"}, {Path: "/api/loose", Method: "GET"}}
	c := &Classification{Rows: []ClassRow{
		docRow(),
		{Route: "/api/loose", Method: "GET", Visibility: "admin-supported", Documented: false}, // no exemption
	}}
	if !containsSub(CheckCoverage(routes, spec, c), "neither documented nor exempt") {
		t.Fatal("expected a neither-documented-nor-exempt violation")
	}
}

// ── Gate 3 time axis: exemption expiry ───────────────────────────────────────

func TestExemptions_Expired(t *testing.T) {
	c := &Classification{Rows: []ClassRow{
		{Route: "/api/x", Method: "GET", Documented: false,
			Exemption: &Exemption{Owner: "o", Reason: "r", SecurityClass: "s", Expires: "2020-01-01"}},
	}}
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	if !containsSub(CheckExemptions(c, now), "EXPIRED EXEMPTION") {
		t.Fatal("expected EXPIRED EXEMPTION for a past expiry date")
	}
}

func TestExemptions_FutureOK(t *testing.T) {
	c := &Classification{Rows: []ClassRow{
		{Route: "/api/x", Method: "GET", Documented: false,
			Exemption: &Exemption{Owner: "o", Reason: "r", SecurityClass: "s", Expires: "2026-10-01"}},
	}}
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	if v := CheckExemptions(c, now); len(v) != 0 {
		t.Fatalf("near-future exemption should pass, got: %v", v)
	}
}

func TestExemptions_TooFarFuture(t *testing.T) {
	c := &Classification{Rows: []ClassRow{
		{Route: "/api/x", Method: "GET", Documented: false,
			Exemption: &Exemption{Owner: "o", Reason: "r", SecurityClass: "s", Expires: "2099-01-01"}},
	}}
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	if !containsSub(CheckExemptions(c, now), "EXEMPTION TOO FAR") {
		t.Fatal("expected EXEMPTION TOO FAR for a far-future expiry beyond the horizon")
	}
}

func containsSub(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// 2F-E correction — openapi_extra_paths: a prefix route whose handler
// dispatches on a path suffix may serve several contract paths under ONE
// registered route + method. Each extra path counts as documented by the row
// (no PHANTOM OPERATION) and must exist in the contract (else
// DOCUMENTED-BUT-MISSING).
func TestCoverage_ExtraOpenAPIPathsCoverAndMustExist(t *testing.T) {
	spec := loadGood(t) // documents GET /api/thing
	routes := []Route{{Path: "/api/other", Method: "GET", Handler: "apiOther"}}
	covered := &Classification{Rows: []ClassRow{
		{Route: "/api/other", Method: "GET", Visibility: "admin-supported", Documented: true,
			OpenAPIPath: "/api/thing", ExtraOpenAPIPaths: []string{"/api/thing"}},
	}}
	if v := CheckCoverage(routes, spec, covered); containsSub(v, "PHANTOM OPERATION") {
		t.Fatalf("an operation named by openapi_extra_paths must count as documented: %v", v)
	}
	missing := &Classification{Rows: []ClassRow{
		{Route: "/api/other", Method: "GET", Visibility: "admin-supported", Documented: true,
			OpenAPIPath: "/api/thing", ExtraOpenAPIPaths: []string{"/api/thing/absent"}},
	}}
	if v := CheckCoverage(routes, spec, missing); !containsSub(v, "DOCUMENTED-BUT-MISSING") {
		t.Fatalf("an openapi_extra_paths entry absent from the contract must be reported: %v", v)
	}
}
