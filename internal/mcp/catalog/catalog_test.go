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

// serverRecord builds a usable Gateway server record for ingestion tests.
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

func ingest(t *testing.T, c *Catalog, srv registry.ServerRecord, identity registry.Identity, raw []byte) *Report {
	t.Helper()
	_, rep, err := c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: identity, Raw: raw})
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

// --- the six drift fixtures ------------------------------------------------

func TestFirstObservationUnknownQuarantined(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	rep := ingest(t, c, srv, testIdentity, result(`{"name":"read","inputSchema":{"type":"object"}}`))
	if classOf(rep, "read") != UnknownTool {
		t.Fatalf("first observation class = %v, want unknown_tool", classOf(rep, "read"))
	}
	if eligOf(c, "read") != Quarantined {
		t.Fatalf("unknown tool eligibility = %v, want quarantined", eligOf(c, "read"))
	}
}

func TestNoMaterialChange(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	tool := `{"name":"read","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}`
	ingest(t, c, srv, testIdentity, result(tool))
	// Re-ingest the SAME tool with cosmetic re-formatting (whitespace, key order).
	reformatted := `{"inputSchema":{"properties":{"path":{"type":"string"}},"type":"object"},"name":"read"}`
	rep := ingest(t, c, srv, testIdentity, result(reformatted))
	if classOf(rep, "read") != NoMaterialChange {
		t.Fatalf("reformatted re-observation class = %v, want no_material_change", classOf(rep, "read"))
	}
}

func TestSafeNarrowingFixture(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	ingestApproved(t, c, srv, "op", `{"name":"op","inputSchema":{"type":"object","properties":{"mode":{"enum":["read","write","admin"]}}}}`)
	// Remove an enum value (none added), add a required property: proven narrowing.
	narrowed := `{"name":"op","inputSchema":{"type":"object","required":["mode"],"properties":{"mode":{"enum":["read","write"]}}}}`
	rep := ingest(t, c, srv, testIdentity, result(narrowed))
	if classOf(rep, "op") != SafeNarrowing {
		t.Fatalf("class = %v, want safe_narrowing; diffs=%v", classOf(rep, "op"), diffsFor(rep, "op"))
	}
}

func TestPrivilegeExpansionFixture(t *testing.T) {
	srv := serverRecord(testServer, testIdentity)
	cases := map[string][2]string{
		"enum-added":       {`{"name":"t","inputSchema":{"type":"object","properties":{"mode":{"enum":["read"]}}}}`, `{"name":"t","inputSchema":{"type":"object","properties":{"mode":{"enum":["read","admin"]}}}}`},
		"required-removed": {`{"name":"t","inputSchema":{"type":"object","required":["confirm"],"properties":{"confirm":{"type":"boolean"}}}}`, `{"name":"t","inputSchema":{"type":"object","properties":{"confirm":{"type":"boolean"}}}}`},
		"sensitive-added":  {`{"name":"t","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}`, `{"name":"t","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"command":{"type":"string"}}}}`},
		"addprops-relaxed": {`{"name":"t","inputSchema":{"type":"object","additionalProperties":false}}`, `{"name":"t","inputSchema":{"type":"object","additionalProperties":true}}`},
		"url-format-added": {`{"name":"t","inputSchema":{"type":"object","properties":{"x":{"type":"string"}}}}`, `{"name":"t","inputSchema":{"type":"object","properties":{"x":{"type":"string"},"target":{"type":"string","format":"uri"}}}}`},
		"bound-relaxed":    {`{"name":"t","inputSchema":{"type":"object","properties":{"n":{"type":"number","maximum":10}}}}`, `{"name":"t","inputSchema":{"type":"object","properties":{"n":{"type":"number","maximum":1000}}}}`},
	}
	for name, pair := range cases {
		c := New(lim(t))
		ingestApproved(t, c, srv, "t", pair[0])
		rep := ingest(t, c, srv, testIdentity, result(pair[1]))
		if classOf(rep, "t") != PrivilegeExpansion {
			t.Fatalf("%s: class = %v, want privilege_expansion; diffs=%v", name, classOf(rep, "t"), diffsFor(rep, "t"))
		}
		if eligOf(c, "t") != Quarantined {
			t.Fatalf("%s: eligibility = %v, want quarantined", name, eligOf(c, "t"))
		}
	}
}

func TestSemanticDriftFixture(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	base := `{"name":"t","description":"reads a file","inputSchema":{"type":"object"}}`
	ingestApproved(t, c, srv, "t", base)
	// Description content changes, schema identical → semantic drift.
	changed := `{"name":"t","description":"reads and writes a file","inputSchema":{"type":"object"}}`
	rep := ingest(t, c, srv, testIdentity, result(changed))
	if classOf(rep, "t") != SemanticDrift {
		t.Fatalf("class = %v, want semantic_drift", classOf(rep, "t"))
	}
	if eligOf(c, "t") != ReviewRequired {
		t.Fatalf("eligibility = %v, want review_required", eligOf(c, "t"))
	}
}

func TestIdentityChangeFixture(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	ingestApproved(t, c, srv, "t", `{"name":"t","inputSchema":{"type":"object"}}`)
	// A tool-level classification with a different recorded identity is identity_change.
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
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	ingestApproved(t, c, srv, "t", `{"name":"t","inputSchema":{"type":"object"}}`)
	before := c.Current().Revision()
	// Ingest with a mismatched verified identity: refused, no mutation, and NEVER
	// downgraded to tool drift.
	_, _, err := c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: "spiffe://evil/x", Raw: result(`{"name":"t","inputSchema":{"type":"object","properties":{"cmd":{"type":"string"}}}}`)})
	if mcperr.ReasonOf(err) != mcperr.ReasonServerIdentityMismatch {
		t.Fatalf("want server_identity_mismatch, got %v", err)
	}
	if c.Current().Revision() != before {
		t.Fatal("identity mismatch mutated the catalog")
	}
}

func TestIngestUnregisteredAndDisabled(t *testing.T) {
	c := New(lim(t))
	// A disabled server refuses ingestion.
	disabled := serverRecord(testServer, testIdentity)
	disabled.Enabled = false
	if _, _, err := c.Ingest(disabled, DiscoveryInput{ServerID: disabled.ID, Identity: testIdentity, Raw: result(`{"name":"t","inputSchema":{}}`)}); mcperr.ReasonOf(err) != mcperr.ReasonUnregisteredServer {
		t.Fatalf("disabled server: want unregistered_server, got %v", err)
	}
	// A mismatched server refuses ingestion with the identity reason.
	mism := serverRecord(testServer, testIdentity)
	mism.Enabled = false
	mism.Verification = registry.VerifyIdentityMismatch
	if _, _, err := c.Ingest(mism, DiscoveryInput{ServerID: mism.ID, Identity: testIdentity, Raw: result(`{"name":"t","inputSchema":{}}`)}); mcperr.ReasonOf(err) != mcperr.ReasonServerIdentityMismatch {
		t.Fatalf("mismatched server: want server_identity_mismatch, got %v", err)
	}
}

func TestDisableServerMakesEntriesUnusable(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	ingest(t, c, srv, testIdentity, result(`{"name":"a","inputSchema":{}}`, `{"name":"b","inputSchema":{}}`))
	snap := c.DisableServer(testServer)
	for _, name := range []string{"a", "b"} {
		rec, _ := snap.Get(ToolKey{Server: testServer, Name: name})
		if rec.Eligibility != ServerDisabled {
			t.Fatalf("%s eligibility = %v, want server_disabled", name, rec.Eligibility)
		}
	}
}

// --- shadowing / duplicate behavior ----------------------------------------

func TestDuplicateToolNamesRejected(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	raw := result(`{"name":"dup","inputSchema":{}}`, `{"name":"dup","inputSchema":{"type":"object"}}`)
	if _, _, err := c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: raw}); mcperr.ReasonOf(err) != mcperr.ReasonDuplicateTool {
		t.Fatalf("want duplicate_tool, got %v", err)
	}
	if c.Current().Len() != 0 {
		t.Fatal("duplicate-tool result published entries")
	}
}

func TestSameNameDifferentServersDistinct(t *testing.T) {
	c := New(lim(t))
	srvA := serverRecord("srv-A", "spiffe://culvert/A")
	srvB := serverRecord("srv-B", "spiffe://culvert/B")
	_, _, _ = c.Ingest(srvA, DiscoveryInput{ServerID: "srv-A", Identity: "spiffe://culvert/A", Raw: result(`{"name":"shared","inputSchema":{"type":"object"}}`)})
	_, _, _ = c.Ingest(srvB, DiscoveryInput{ServerID: "srv-B", Identity: "spiffe://culvert/B", Raw: result(`{"name":"shared","inputSchema":{"type":"string"}}`)})
	a, okA := c.Current().Get(ToolKey{Server: "srv-A", Name: "shared"})
	b, okB := c.Current().Get(ToolKey{Server: "srv-B", Name: "shared"})
	if !okA || !okB {
		t.Fatal("same name on two servers must be two distinct entries")
	}
	if a.Fingerprint.Sum() == b.Fingerprint.Sum() {
		t.Fatal("distinct-server tools must not share a fingerprint")
	}
}

func TestQuarantineCannotAutoClear(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	// First observation → quarantined.
	ingest(t, c, srv, testIdentity, result(`{"name":"t","inputSchema":{"type":"object","properties":{"mode":{"enum":["a","b"]}}}}`))
	if eligOf(c, "t") != Quarantined {
		t.Fatal("precondition: tool must start quarantined")
	}
	// A subsequent SAFE NARROWING must NOT lift the quarantine.
	ingest(t, c, srv, testIdentity, result(`{"name":"t","inputSchema":{"type":"object","properties":{"mode":{"enum":["a"]}}}}`))
	if eligOf(c, "t") != Quarantined {
		t.Fatalf("quarantine auto-cleared by narrowing: %v", eligOf(c, "t"))
	}
	// And a no-material-change re-observation keeps it quarantined too.
	ingest(t, c, srv, testIdentity, result(`{"name":"t","inputSchema":{"type":"object","properties":{"mode":{"enum":["a"]}}}}`))
	if eligOf(c, "t") != Quarantined {
		t.Fatalf("quarantine cleared by no-material-change: %v", eligOf(c, "t"))
	}
}

func TestNoMaterialChangePreservesUsable(t *testing.T) {
	// Whitebox: seed an APPROVED (Usable) prior — approval is a later slice, so we
	// construct it directly — and prove no_material_change preserves it.
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	ingestApproved(t, c, srv, "t", `{"name":"t","inputSchema":{"type":"object"}}`)
	if eligOf(c, "t") != Usable {
		t.Fatal("precondition: seeded Usable")
	}
	rep := ingest(t, c, srv, testIdentity, result(`{"name":"t","inputSchema":{"type":"object"}}`))
	if classOf(rep, "t") != NoMaterialChange || eligOf(c, "t") != Usable {
		t.Fatalf("no_material_change must preserve Usable: class=%v elig=%v", classOf(rep, "t"), eligOf(c, "t"))
	}
}

func TestFailedIngestPublishesNothing(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	ingest(t, c, srv, testIdentity, result(`{"name":"ok","inputSchema":{}}`))
	before := c.Current()
	// A malformed second ingest must leave the snapshot byte-for-byte unchanged.
	_, _, err := c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: []byte(`{"tools":[{"name":"bad"}]}`)})
	if mcperr.ReasonOf(err) != mcperr.ReasonMalformedDiscovery {
		t.Fatalf("want malformed_discovery, got %v", err)
	}
	if c.Current() != before {
		t.Fatal("failed ingest replaced the snapshot")
	}
}

func TestDeterministicDiffOrdering(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	ingestApproved(t, c, srv, "t", `{"name":"t","description":"x","inputSchema":{"type":"object","properties":{"a":{"type":"string"}}}}`)
	changed := `{"name":"t","description":"y","inputSchema":{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}}}}`
	var first []FieldDiff
	for i := 0; i < 8; i++ {
		cc := New(lim(t))
		ingestApproved(t, cc, srv, "t", `{"name":"t","description":"x","inputSchema":{"type":"object","properties":{"a":{"type":"string"}}}}`)
		rep := ingest(t, cc, srv, testIdentity, result(changed))
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
	// MaxCatalogEntries is 8; MaxToolsPerServer is 4 — fill across servers.
	for s := 0; s < 3; s++ {
		id := registry.ServerID("srv-" + string(rune('A'+s)))
		sr := serverRecord(id, registry.Identity("id-"+string(rune('A'+s))))
		tools := make([]string, 0, 4)
		for i := 0; i < 4; i++ {
			tools = append(tools, `{"name":"t`+string(rune('0'+i))+`","inputSchema":{}}`)
		}
		_, _, err := c.Ingest(sr, DiscoveryInput{ServerID: id, Identity: registry.Identity("id-" + string(rune('A'+s))), Raw: result(tools...)})
		if s < 2 && err != nil {
			t.Fatalf("server %d: unexpected error %v", s, err)
		}
		if s == 2 && mcperr.ReasonOf(err) != mcperr.ReasonCapacityExceeded {
			t.Fatalf("expected capacity_exceeded on the 3rd server, got %v", err)
		}
	}
}

// --- helpers ---------------------------------------------------------------

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

// ingestApproved ingests a tool then whitebox-sets its record to Usable, standing
// in for the (out-of-PR-2) human approval so drift-from-approved can be tested.
func ingestApproved(t *testing.T, c *Catalog, srv registry.ServerRecord, name, tool string) {
	t.Helper()
	ingest(t, c, srv, srv.PinnedIdentity, result(tool))
	base := c.Current()
	next := base.clone(base.revision + 1)
	key := ToolKey{Server: srv.ID, Name: name}
	rec := *next.byKey[key]
	rec.Eligibility = Usable
	next.byKey[key] = &rec
	c.cur.Store(next)
}

func diffsFor(rep *Report, name string) []FieldDiff {
	for _, o := range rep.Observations {
		if o.Key.Name == name {
			return o.Diffs
		}
	}
	return nil
}
