package catalog

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

const (
	testServer   = registry.ServerID("srv-1")
	testIdentity = registry.Identity("spiffe://culvert/srv-1")
)

func lim(t *testing.T) limits.CatalogLimits {
	t.Helper()
	return limits.DefaultCatalog()
}

// serverRecord builds a usable Gateway server record (used directly by the
// Classify/fingerprint tests that do not go through Ingest).
func serverRecord(id registry.ServerID, identity registry.Identity) registry.ServerRecord {
	return registry.ServerRecord{
		ID:                id,
		PinnedIdentity:    identity,
		Capability:        protocol.Gateway,
		CredentialProfile: "cred-a",
		Enabled:           true,
		Verification:      registry.VerifyVerified,
	}
}

// regWith returns a registry with each (id, identity) registered as a usable
// Gateway server — the live authority Ingest consults. It takes testing.TB so
// benchmarks can use it too.
func regWith(tb testing.TB, l limits.CatalogLimits, pairs ...[2]string) *registry.Registry {
	tb.Helper()
	reg := registry.New(l)
	for _, p := range pairs {
		if _, err := reg.Register(registry.Registration{
			ID:                registry.ServerID(p[0]),
			Endpoint:          registry.Endpoint("mcp://" + p[0]),
			PinnedIdentity:    registry.Identity(p[1]),
			Capability:        protocol.Gateway,
			CredentialProfile: "cred-a",
		}); err != nil {
			tb.Fatalf("register %s: %v", p[0], err)
		}
	}
	return reg
}

// oneServerReg is regWith for the single default test server.
func oneServerReg(tb testing.TB, l limits.CatalogLimits) *registry.Registry {
	return regWith(tb, l, [2]string{string(testServer), string(testIdentity)})
}

// result wraps one or more tool JSON blobs into a tools/list result.
func result(tools ...string) []byte {
	out := `{"tools":[`
	for i, tj := range tools {
		if i > 0 {
			out += ","
		}
		out += tj
	}
	return []byte(out + `]}`)
}

func ingest(t *testing.T, c *Catalog, reg *registry.Registry, id registry.ServerID, identity registry.Identity, raw []byte) *Report {
	t.Helper()
	_, rep, err := c.Ingest(reg, DiscoveryInput{ServerID: id, Identity: identity, Raw: raw})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return rep
}

func classOf(rep *Report, name string) DriftClass {
	for _, o := range rep.Observations {
		if o.Key.Name == name {
			return o.Class
		}
	}
	return DriftClass(255)
}

func eligOf(c *Catalog, name string) Eligibility {
	rec, ok := c.Current().Get(ToolKey{Server: testServer, Name: name})
	if !ok {
		return Eligibility(255)
	}
	return rec.Eligibility
}

func diffsFor(rep *Report, name string) []FieldDiff {
	for _, o := range rep.Observations {
		if o.Key.Name == name {
			return o.Diffs
		}
	}
	return nil
}

// ingestApproved ingests a tool then whitebox-sets its record to Usable, standing
// in for the (out-of-PR-2) human approval so drift-from-approved can be tested.
func ingestApproved(t *testing.T, c *Catalog, reg *registry.Registry, id registry.ServerID, identity registry.Identity, name, tool string) {
	t.Helper()
	ingest(t, c, reg, id, identity, result(tool))
	base := c.Current()
	next := base.clone(base.revision + 1)
	key := ToolKey{Server: id, Name: name}
	rec := *next.byKey[key]
	rec.Eligibility = Usable
	next.byKey[key] = &rec
	c.cur.Store(next)
}

func smallCatalog(t *testing.T) limits.CatalogLimits {
	t.Helper()
	c, err := limits.NewCatalog(limits.CatalogConfig{
		MaxServers: 8, MaxToolsPerServer: 4, MaxCatalogEntries: 8,
		MaxDiscoveryBytes: 65536, MaxSchemaBytes: 4096, MaxDescriptionBytes: 1024,
		MaxSchemaDepth: 16, MaxObjectMembers: 64, MaxArrayElements: 64, MaxDiffOps: 4096,
		MaxNameBytes: 128, MaxEndpointBytes: 512, MaxIdentityBytes: 512,
		MaxServerIDBytes: 128, MaxCredProfileBytes: 128, MaxOwnerScopeBytes: 128,
	})
	if err != nil {
		t.Fatalf("small catalog limits: %v", err)
	}
	return c
}

// --- the six drift fixtures ------------------------------------------------

func TestFirstObservationUnknownQuarantined(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	rep := ingest(t, c, reg, testServer, testIdentity, result(`{"name":"read","inputSchema":{"type":"object"}}`))
	if classOf(rep, "read") != UnknownTool {
		t.Fatalf("first observation class = %v, want unknown_tool", classOf(rep, "read"))
	}
	if eligOf(c, "read") != Quarantined {
		t.Fatalf("unknown tool eligibility = %v, want quarantined", eligOf(c, "read"))
	}
}

func TestNoMaterialChange(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	tool := `{"name":"read","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}`
	ingest(t, c, reg, testServer, testIdentity, result(tool))
	reformatted := `{"inputSchema":{"properties":{"path":{"type":"string"}},"type":"object"},"name":"read"}`
	rep := ingest(t, c, reg, testServer, testIdentity, result(reformatted))
	if classOf(rep, "read") != NoMaterialChange {
		t.Fatalf("reformatted re-observation class = %v, want no_material_change", classOf(rep, "read"))
	}
}

func TestSafeNarrowingFixture(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	ingestApproved(t, c, reg, testServer, testIdentity, "op", `{"name":"op","inputSchema":{"type":"object","properties":{"mode":{"enum":["read","write","admin"]}}}}`)
	narrowed := `{"name":"op","inputSchema":{"type":"object","required":["mode"],"properties":{"mode":{"enum":["read","write"]}}}}`
	rep := ingest(t, c, reg, testServer, testIdentity, result(narrowed))
	if classOf(rep, "op") != SafeNarrowing {
		t.Fatalf("class = %v, want safe_narrowing; diffs=%v", classOf(rep, "op"), diffsFor(rep, "op"))
	}
}

func TestPrivilegeExpansionFixture(t *testing.T) {
	cases := map[string][2]string{
		"enum-added":       {`{"name":"t","inputSchema":{"type":"object","properties":{"mode":{"enum":["read"]}}}}`, `{"name":"t","inputSchema":{"type":"object","properties":{"mode":{"enum":["read","admin"]}}}}`},
		"required-removed": {`{"name":"t","inputSchema":{"type":"object","required":["confirm"],"properties":{"confirm":{"type":"boolean"}}}}`, `{"name":"t","inputSchema":{"type":"object","properties":{"confirm":{"type":"boolean"}}}}`},
		"sensitive-added":  {`{"name":"t","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}`, `{"name":"t","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"command":{"type":"string"}}}}`},
		"addprops-relaxed": {`{"name":"t","inputSchema":{"type":"object","additionalProperties":false}}`, `{"name":"t","inputSchema":{"type":"object","additionalProperties":true}}`},
		"url-format-added": {`{"name":"t","inputSchema":{"type":"object","properties":{"x":{"type":"string"}}}}`, `{"name":"t","inputSchema":{"type":"object","properties":{"x":{"type":"string"},"target":{"type":"string","format":"uri"}}}}`},
		"bound-relaxed":    {`{"name":"t","inputSchema":{"type":"object","properties":{"n":{"type":"number","maximum":10}}}}`, `{"name":"t","inputSchema":{"type":"object","properties":{"n":{"type":"number","maximum":1000}}}}`},
	}
	for name, pair := range cases {
		l := lim(t)
		c, reg := New(l), oneServerReg(t, l)
		ingestApproved(t, c, reg, testServer, testIdentity, "t", pair[0])
		rep := ingest(t, c, reg, testServer, testIdentity, result(pair[1]))
		if classOf(rep, "t") != PrivilegeExpansion {
			t.Fatalf("%s: class = %v, want privilege_expansion; diffs=%v", name, classOf(rep, "t"), diffsFor(rep, "t"))
		}
		if eligOf(c, "t") != Quarantined {
			t.Fatalf("%s: eligibility = %v, want quarantined", name, eligOf(c, "t"))
		}
	}
}

// TestTypeConstraintDropIsExpansion pins the conservative-direction fix for the
// `type` keyword: an absent `type` means "any type", so dropping a type
// constraint broadens the input and MUST be privilege_expansion.
func TestTypeConstraintDropIsExpansion(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	ingestApproved(t, c, reg, testServer, testIdentity, "t", `{"name":"t","inputSchema":{"type":"object","properties":{"p":{"type":"string"}}}}`)
	dropped := `{"name":"t","inputSchema":{"type":"object","properties":{"p":{}}}}`
	rep := ingest(t, c, reg, testServer, testIdentity, result(dropped))
	if classOf(rep, "t") != PrivilegeExpansion {
		t.Fatalf("dropping a type constraint must be privilege_expansion, got %v; diffs=%v", classOf(rep, "t"), diffsFor(rep, "t"))
	}
	l2 := lim(t)
	c2, reg2 := New(l2), oneServerReg(t, l2)
	ingestApproved(t, c2, reg2, testServer, testIdentity, "t", `{"name":"t","inputSchema":{"type":"object","properties":{"p":{}}}}`)
	added := `{"name":"t","inputSchema":{"type":"object","properties":{"p":{"type":"string"}}}}`
	rep2 := ingest(t, c2, reg2, testServer, testIdentity, result(added))
	if classOf(rep2, "t") != SafeNarrowing {
		t.Fatalf("adding a type constraint must be safe_narrowing, got %v; diffs=%v", classOf(rep2, "t"), diffsFor(rep2, "t"))
	}
}

// TestEnumConstraintDropIsExpansion is the enum sibling of the type-drop case:
// dropping an enum allow-list broadens to any value → privilege_expansion.
func TestEnumConstraintDropIsExpansion(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	ingestApproved(t, c, reg, testServer, testIdentity, "t", `{"name":"t","inputSchema":{"type":"object","properties":{"mode":{"type":"string","enum":["read","write"]}}}}`)
	dropped := `{"name":"t","inputSchema":{"type":"object","properties":{"mode":{"type":"string"}}}}`
	rep := ingest(t, c, reg, testServer, testIdentity, result(dropped))
	if classOf(rep, "t") != PrivilegeExpansion {
		t.Fatalf("dropping an enum must be privilege_expansion, got %v; diffs=%v", classOf(rep, "t"), diffsFor(rep, "t"))
	}
}

// TestMalformedTypeNotNarrowing pins that a degenerate/malformed observed `type`
// (a non-string/array value) is ambiguous → semantic, NEVER safe narrowing.
func TestMalformedTypeNotNarrowing(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	ingestApproved(t, c, reg, testServer, testIdentity, "t", `{"name":"t","inputSchema":{"type":"object","properties":{"p":{"type":"string"}}}}`)
	malformed := `{"name":"t","inputSchema":{"type":"object","properties":{"p":{"type":5}}}}`
	rep := ingest(t, c, reg, testServer, testIdentity, result(malformed))
	if got := classOf(rep, "t"); got == SafeNarrowing || got == NoMaterialChange {
		t.Fatalf("malformed type must not be narrowing/no-change, got %v; diffs=%v", got, diffsFor(rep, "t"))
	}
}

// TestPropertyRemovalPermissiveNotNarrowing pins that removing a property's
// schema while additionalProperties is permitted is NOT safe narrowing (the key
// keeps being accepted, now unconstrained) — it must be semantic.
func TestPropertyRemovalPermissiveNotNarrowing(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	ingestApproved(t, c, reg, testServer, testIdentity, "t", `{"name":"t","inputSchema":{"type":"object","properties":{"x":{"type":"string"}}}}`)
	// Remove property x; additionalProperties defaults to permissive.
	removed := `{"name":"t","inputSchema":{"type":"object","properties":{}}}`
	rep := ingest(t, c, reg, testServer, testIdentity, result(removed))
	if got := classOf(rep, "t"); got == SafeNarrowing {
		t.Fatalf("property removal under permissive additionalProperties must not be safe_narrowing, got %v; diffs=%v", got, diffsFor(rep, "t"))
	}
	// With additionalProperties:false it IS a narrowing (key now rejected).
	l2 := lim(t)
	c2, reg2 := New(l2), oneServerReg(t, l2)
	ingestApproved(t, c2, reg2, testServer, testIdentity, "t", `{"name":"t","inputSchema":{"type":"object","additionalProperties":false,"properties":{"x":{"type":"string"}}}}`)
	removedStrict := `{"name":"t","inputSchema":{"type":"object","additionalProperties":false,"properties":{}}}`
	rep2 := ingest(t, c2, reg2, testServer, testIdentity, result(removedStrict))
	if classOf(rep2, "t") != SafeNarrowing {
		t.Fatalf("property removal with additionalProperties:false must be safe_narrowing, got %v; diffs=%v", classOf(rep2, "t"), diffsFor(rep2, "t"))
	}
}

func TestSemanticDriftFixture(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	ingestApproved(t, c, reg, testServer, testIdentity, "t", `{"name":"t","description":"reads a file","inputSchema":{"type":"object"}}`)
	changed := `{"name":"t","description":"reads and writes a file","inputSchema":{"type":"object"}}`
	rep := ingest(t, c, reg, testServer, testIdentity, result(changed))
	if classOf(rep, "t") != SemanticDrift {
		t.Fatalf("class = %v, want semantic_drift", classOf(rep, "t"))
	}
	if eligOf(c, "t") != ReviewRequired {
		t.Fatalf("eligibility = %v, want review_required", eligOf(c, "t"))
	}
}

func TestIdentityChangeFixture(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	ingestApproved(t, c, reg, testServer, testIdentity, "t", `{"name":"t","inputSchema":{"type":"object"}}`)
	prior, _ := c.Current().Get(ToolKey{Server: testServer, Name: "t"})
	observed := prior
	observed.Fingerprint.Identity = "spiffe://evil/imposter"
	class, _ := Classify(&prior, &observed)
	if class != IdentityChange {
		t.Fatalf("class = %v, want identity_change", class)
	}
}

// --- ingestion-level identity + server gates -------------------------------

func TestIngestIdentityMismatchRefused(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	ingestApproved(t, c, reg, testServer, testIdentity, "t", `{"name":"t","inputSchema":{"type":"object"}}`)
	before := c.Current().Revision()
	_, _, err := c.Ingest(reg, DiscoveryInput{ServerID: testServer, Identity: "spiffe://evil/x", Raw: result(`{"name":"t","inputSchema":{"type":"object","properties":{"cmd":{"type":"string"}}}}`)})
	if mcperr.ReasonOf(err) != mcperr.ReasonServerIdentityMismatch {
		t.Fatalf("want server_identity_mismatch, got %v", err)
	}
	if c.Current().Revision() != before {
		t.Fatal("identity mismatch mutated the catalog")
	}
}

func TestIngestUnregisteredAndDisabled(t *testing.T) {
	l := lim(t)
	c := New(l)
	// An unregistered server refuses ingestion.
	emptyReg := registry.New(l)
	if _, _, err := c.Ingest(emptyReg, DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: result(`{"name":"t","inputSchema":{}}`)}); mcperr.ReasonOf(err) != mcperr.ReasonUnregisteredServer {
		t.Fatalf("unregistered server: want unregistered_server, got %v", err)
	}
	// A disabled server refuses ingestion.
	reg := oneServerReg(t, l)
	if _, err := reg.SetEnabled(testServer, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Ingest(reg, DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: result(`{"name":"t","inputSchema":{}}`)}); mcperr.ReasonOf(err) != mcperr.ReasonUnregisteredServer {
		t.Fatalf("disabled server: want unregistered_server, got %v", err)
	}
	// A mismatched (disabled) server refuses with the identity reason.
	reg2 := oneServerReg(t, l)
	if _, _, err := reg2.VerifyIdentity(testServer, "spiffe://evil/x"); mcperr.ReasonOf(err) != mcperr.ReasonServerIdentityMismatch {
		t.Fatalf("verify mismatch: %v", err)
	}
	if _, _, err := c.Ingest(reg2, DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: result(`{"name":"t","inputSchema":{}}`)}); mcperr.ReasonOf(err) != mcperr.ReasonServerIdentityMismatch {
		t.Fatalf("mismatched server: want server_identity_mismatch, got %v", err)
	}
}

func TestDisableServerMakesEntriesUnusable(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	ingest(t, c, reg, testServer, testIdentity, result(`{"name":"a","inputSchema":{}}`, `{"name":"b","inputSchema":{}}`))
	snap, err := c.DisableServer(testServer)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	for _, name := range []string{"a", "b"} {
		rec, _ := snap.Get(ToolKey{Server: testServer, Name: name})
		if rec.Eligibility != ServerDisabled {
			t.Fatalf("%s eligibility = %v, want server_disabled", name, rec.Eligibility)
		}
	}
}

// --- shadowing / duplicate behavior ----------------------------------------

func TestDuplicateToolNamesRejected(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	raw := result(`{"name":"dup","inputSchema":{}}`, `{"name":"dup","inputSchema":{"type":"object"}}`)
	if _, _, err := c.Ingest(reg, DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: raw}); mcperr.ReasonOf(err) != mcperr.ReasonDuplicateTool {
		t.Fatalf("want duplicate_tool, got %v", err)
	}
	if c.Current().Len() != 0 {
		t.Fatal("duplicate-tool result published entries")
	}
}

func TestSameNameDifferentServersDistinct(t *testing.T) {
	l := lim(t)
	c := New(l)
	reg := regWith(t, l, [2]string{"srv-A", "spiffe://culvert/A"}, [2]string{"srv-B", "spiffe://culvert/B"})
	ingest(t, c, reg, "srv-A", "spiffe://culvert/A", result(`{"name":"shared","inputSchema":{"type":"object"}}`))
	ingest(t, c, reg, "srv-B", "spiffe://culvert/B", result(`{"name":"shared","inputSchema":{"type":"string"}}`))
	a, okA := c.Current().Get(ToolKey{Server: "srv-A", Name: "shared"})
	b, okB := c.Current().Get(ToolKey{Server: "srv-B", Name: "shared"})
	if !okA || !okB {
		t.Fatal("same name on two servers must be two distinct entries")
	}
	if a.Fingerprint.Sum() == b.Fingerprint.Sum() {
		t.Fatal("distinct-server tools must not share a fingerprint")
	}
}

// TestIngestWithdrawsOmittedTool proves a complete per-server discovery that omits a
// previously-known tool drops that tool from the snapshot, so a stale record can never keep
// conferring eligibility (and, once tool-trust derives from the catalog, keep a withdrawn tool
// Usable). A re-added tool re-ingests as unknown, never silently re-Usable.
func TestIngestWithdrawsOmittedTool(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	ingest(t, c, reg, testServer, testIdentity, result(
		`{"name":"a","inputSchema":{"type":"object"}}`,
		`{"name":"b","inputSchema":{"type":"object"}}`))
	if _, ok := c.Current().Get(ToolKey{Server: testServer, Name: "a"}); !ok {
		t.Fatal("tool a must be present after the first discovery")
	}
	// A complete re-discovery that returns only b — a is gone from the server.
	ingest(t, c, reg, testServer, testIdentity, result(`{"name":"b","inputSchema":{"type":"object"}}`))
	if _, ok := c.Current().Get(ToolKey{Server: testServer, Name: "a"}); ok {
		t.Fatal("tool a omitted by a complete discovery must be withdrawn from the catalog")
	}
	if _, ok := c.Current().Get(ToolKey{Server: testServer, Name: "b"}); !ok {
		t.Fatal("tool b, still observed, must remain")
	}
}

// TestIngestOmissionIsPerServer proves the withdrawal touches ONLY the discovered server: a
// discovery for one server never drops another server's tools.
func TestIngestOmissionIsPerServer(t *testing.T) {
	l := lim(t)
	c := New(l)
	reg := regWith(t, l, [2]string{"srv-A", "spiffe://culvert/A"}, [2]string{"srv-B", "spiffe://culvert/B"})
	ingest(t, c, reg, "srv-A", "spiffe://culvert/A", result(`{"name":"a","inputSchema":{"type":"object"}}`))
	ingest(t, c, reg, "srv-B", "spiffe://culvert/B", result(`{"name":"b","inputSchema":{"type":"object"}}`))
	// Re-discover srv-A with a different tool set (omitting "a"): only srv-A's "a" is withdrawn.
	ingest(t, c, reg, "srv-A", "spiffe://culvert/A", result(`{"name":"c","inputSchema":{"type":"object"}}`))
	if _, ok := c.Current().Get(ToolKey{Server: "srv-A", Name: "a"}); ok {
		t.Fatal("srv-A tool a omitted by its own discovery must be withdrawn")
	}
	if _, ok := c.Current().Get(ToolKey{Server: "srv-A", Name: "c"}); !ok {
		t.Fatal("srv-A tool c, newly observed, must be present")
	}
	if _, ok := c.Current().Get(ToolKey{Server: "srv-B", Name: "b"}); !ok {
		t.Fatal("srv-B tool b must NOT be dropped by a srv-A discovery")
	}
}

// TestIngestPaginatedPageDoesNotWithdraw pins the pagination guard: a tools/list result carrying
// a non-empty nextCursor is only ONE page of a larger set (execution.Discovery fetches the first
// page), so a previously-known tool absent from it has NOT been proven withdrawn and must remain.
// Only a complete (cursor-less or empty-cursor) result withdraws omitted tools.
func TestIngestPaginatedPageDoesNotWithdraw(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	// A complete first discovery establishes a and b.
	ingest(t, c, reg, testServer, testIdentity, result(
		`{"name":"a","inputSchema":{"type":"object"}}`,
		`{"name":"b","inputSchema":{"type":"object"}}`))
	// A PARTIAL page (nextCursor set) listing only b must NOT withdraw a.
	paged := []byte(`{"tools":[{"name":"b","inputSchema":{"type":"object"}}],"nextCursor":"page-2"}`)
	if _, _, err := c.Ingest(reg, DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: paged}); err != nil {
		t.Fatalf("ingest paginated page: %v", err)
	}
	if _, ok := c.Current().Get(ToolKey{Server: testServer, Name: "a"}); !ok {
		t.Fatal("a tool absent from a PARTIAL (nextCursor) page must NOT be withdrawn")
	}
	if _, ok := c.Current().Get(ToolKey{Server: testServer, Name: "b"}); !ok {
		t.Fatal("tool b, present on the page, must remain")
	}
	// An explicitly empty cursor is a complete result and DOES withdraw the omitted a.
	done := []byte(`{"tools":[{"name":"b","inputSchema":{"type":"object"}}],"nextCursor":""}`)
	if _, _, err := c.Ingest(reg, DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: done}); err != nil {
		t.Fatalf("ingest complete (empty-cursor) result: %v", err)
	}
	if _, ok := c.Current().Get(ToolKey{Server: testServer, Name: "a"}); ok {
		t.Fatal("a complete (empty-cursor) result must withdraw the omitted tool a")
	}
}

// TestIngestReplacementAtCapacity pins that a complete discovery replacing a tool at exactly
// MaxCatalogEntries publishes: the omitted tool is withdrawn to free its slot BEFORE the new
// tool's capacity check, so a tool-for-tool swap at the cap does not fail capacity_exceeded.
func TestIngestReplacementAtCapacity(t *testing.T) {
	cfg := smallCatalog(t) // MaxCatalogEntries:8, MaxToolsPerServer:4
	c := New(cfg)
	reg := regWith(t, cfg, [2]string{"srv-A", "id-A"}, [2]string{"srv-B", "id-B"})
	fill := func(id registry.ServerID, identity registry.Identity, names ...string) {
		tools := make([]string, 0, len(names))
		for _, n := range names {
			tools = append(tools, `{"name":"`+n+`","inputSchema":{}}`)
		}
		if _, _, err := c.Ingest(reg, DiscoveryInput{ServerID: id, Identity: identity, Raw: result(tools...)}); err != nil {
			t.Fatalf("fill %s: %v", id, err)
		}
	}
	// Fill to exactly MaxCatalogEntries: 4 tools on each of two servers.
	fill("srv-A", "id-A", "a0", "a1", "a2", "a3")
	fill("srv-B", "id-B", "b0", "b1", "b2", "b3")
	if c.Current().Len() != 8 {
		t.Fatalf("precondition: catalog must be at capacity 8, got %d", c.Current().Len())
	}
	// Complete re-discovery of srv-A swaps a3 → aNew (still 4 tools on A, 8 total after withdrawal).
	if _, _, err := c.Ingest(reg, DiscoveryInput{ServerID: "srv-A", Identity: "id-A", Raw: result(
		`{"name":"a0","inputSchema":{}}`, `{"name":"a1","inputSchema":{}}`,
		`{"name":"a2","inputSchema":{}}`, `{"name":"aNew","inputSchema":{}}`)}); err != nil {
		t.Fatalf("tool-for-tool replacement at capacity must publish, got %v", err)
	}
	if _, ok := c.Current().Get(ToolKey{Server: "srv-A", Name: "a3"}); ok {
		t.Fatal("the replaced tool a3 must be withdrawn")
	}
	if _, ok := c.Current().Get(ToolKey{Server: "srv-A", Name: "aNew"}); !ok {
		t.Fatal("the new tool aNew must be present after a replacement at capacity")
	}
	if c.Current().Len() != 8 {
		t.Fatalf("catalog must stay at 8 after a tool-for-tool swap, got %d", c.Current().Len())
	}
}

func TestQuarantineCannotAutoClear(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	ingest(t, c, reg, testServer, testIdentity, result(`{"name":"t","inputSchema":{"type":"object","properties":{"mode":{"enum":["a","b"]}}}}`))
	if eligOf(c, "t") != Quarantined {
		t.Fatal("precondition: tool must start quarantined")
	}
	ingest(t, c, reg, testServer, testIdentity, result(`{"name":"t","inputSchema":{"type":"object","properties":{"mode":{"enum":["a"]}}}}`))
	if eligOf(c, "t") != Quarantined {
		t.Fatalf("quarantine auto-cleared by narrowing: %v", eligOf(c, "t"))
	}
	ingest(t, c, reg, testServer, testIdentity, result(`{"name":"t","inputSchema":{"type":"object","properties":{"mode":{"enum":["a"]}}}}`))
	if eligOf(c, "t") != Quarantined {
		t.Fatalf("quarantine cleared by no-material-change: %v", eligOf(c, "t"))
	}
}

func TestNoMaterialChangePreservesUsable(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	ingestApproved(t, c, reg, testServer, testIdentity, "t", `{"name":"t","inputSchema":{"type":"object"}}`)
	if eligOf(c, "t") != Usable {
		t.Fatal("precondition: seeded Usable")
	}
	rep := ingest(t, c, reg, testServer, testIdentity, result(`{"name":"t","inputSchema":{"type":"object"}}`))
	if classOf(rep, "t") != NoMaterialChange || eligOf(c, "t") != Usable {
		t.Fatalf("no_material_change must preserve Usable: class=%v elig=%v", classOf(rep, "t"), eligOf(c, "t"))
	}
}

func TestFailedIngestPublishesNothing(t *testing.T) {
	l := lim(t)
	c, reg := New(l), oneServerReg(t, l)
	ingest(t, c, reg, testServer, testIdentity, result(`{"name":"ok","inputSchema":{}}`))
	before := c.Current()
	_, _, err := c.Ingest(reg, DiscoveryInput{ServerID: testServer, Identity: testIdentity, Raw: []byte(`{"tools":[{"name":"bad"}]}`)})
	if mcperr.ReasonOf(err) != mcperr.ReasonMalformedDiscovery {
		t.Fatalf("want malformed_discovery, got %v", err)
	}
	if c.Current() != before {
		t.Fatal("failed ingest replaced the snapshot")
	}
}

func TestDeterministicDiffOrdering(t *testing.T) {
	changed := `{"name":"t","description":"y","inputSchema":{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}}}}`
	var first []FieldDiff
	for i := 0; i < 8; i++ {
		l := lim(t)
		cc, reg := New(l), oneServerReg(t, l)
		ingestApproved(t, cc, reg, testServer, testIdentity, "t", `{"name":"t","description":"x","inputSchema":{"type":"object","properties":{"a":{"type":"string"}}}}`)
		rep := ingest(t, cc, reg, testServer, testIdentity, result(changed))
		d := diffsFor(rep, "t")
		if first == nil {
			first = d
			continue
		}
		if len(d) != len(first) {
			t.Fatalf("non-deterministic diff length: %d vs %d", len(d), len(first))
		}
		for j := range d {
			if d[j] != first[j] {
				t.Fatalf("non-deterministic diff order at %d: %+v vs %+v", j, d[j], first[j])
			}
		}
	}
}

func TestCatalogCapacityBounded(t *testing.T) {
	cfg := smallCatalog(t)
	c := New(cfg)
	for s := 0; s < 3; s++ {
		id := "srv-" + string(rune('A'+s))
		identity := "id-" + string(rune('A'+s))
		reg := regWith(t, cfg, [2]string{id, identity})
		tools := make([]string, 0, 4)
		for i := 0; i < 4; i++ {
			tools = append(tools, `{"name":"t`+string(rune('0'+i))+`","inputSchema":{}}`)
		}
		_, _, err := c.Ingest(reg, DiscoveryInput{ServerID: registry.ServerID(id), Identity: registry.Identity(identity), Raw: result(tools...)})
		if s < 2 && err != nil {
			t.Fatalf("server %d: unexpected error %v", s, err)
		}
		if s == 2 && mcperr.ReasonOf(err) != mcperr.ReasonCapacityExceeded {
			t.Fatalf("expected capacity_exceeded on the 3rd server, got %v", err)
		}
	}
}
