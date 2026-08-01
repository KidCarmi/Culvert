package catalog

import (
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// Each test here pins a load-bearing control by demonstrating that a deliberately
// WEAKENED alternate implementation (built inline, test-local — never shipped)
// would produce the wrong answer, while the real implementation does not.

// weakNameOnlyKey models the "name-only tool identity" bug: keying by name alone
// collapses two different servers' same-named tools.
func TestAntiWeakening_NameOnlyIdentity(t *testing.T) {
	a := Fingerprint{Server: "srv-A", Identity: "idA", Name: "run", FormatVersion: 1}
	b := Fingerprint{Server: "srv-B", Identity: "idB", Name: "run", FormatVersion: 1}
	// Real identity: the composite keys differ.
	if a.Sum() == b.Sum() {
		t.Fatal("real fingerprints for same name / different server must differ")
	}
	// Weakened (name-only) identity would treat them as equal — prove the mutant is wrong.
	weakKey := func(f Fingerprint) string { return f.Name }
	if weakKey(a) != weakKey(b) {
		t.Fatal("test scaffolding: weak key should collide (that is the bug we reject)")
	}
	if ToolKey(struct {
		Server registry.ServerID
		Name   string
	}{a.Server, a.Name}) == (ToolKey{Server: b.Server, Name: b.Name}) {
		t.Fatal("real ToolKey must not collide across servers")
	}
}

// weak raw-byte hashing (no canonicalization) would flag cosmetic re-formatting
// as drift; the real canonical hash does not.
func TestAntiWeakening_RawByteHashingWithoutCanonicalization(t *testing.T) {
	a := `{"type":"object","properties":{"b":{"type":"string"},"a":{"type":"number"}}}`
	b := `{"properties":{"a":{"type":"number"},"b":{"type":"string"}},"type":"object"}`
	ha, _ := canonical.HashSchema([]byte(a), tbSchema())
	hb, _ := canonical.HashSchema([]byte(b), tbSchema())
	if ha != hb {
		t.Fatal("canonical schema hash must be equal for reordered-but-equal schemas")
	}
	// Weakened raw-byte hashing WOULD differ — proving canonicalization is doing work.
	if a == b {
		t.Fatal("scaffolding: the two raw byte strings must differ")
	}
}

// A weakened classifier that sorted arbitrary arrays would hide a tuple reorder.
// The real schema hash keeps tuple `items` order-sensitive.
func TestAntiWeakening_ArbitraryArraySorting(t *testing.T) {
	a := `{"items":[{"type":"string"},{"type":"number"}]}`
	b := `{"items":[{"type":"number"},{"type":"string"}]}`
	ha, _ := canonical.HashSchema([]byte(a), tbSchema())
	hb, _ := canonical.HashSchema([]byte(b), tbSchema())
	if ha == hb {
		t.Fatal("tuple items reorder MUST change the schema hash (arbitrary arrays are not set-like)")
	}
}

// An unknown tool must never be inserted as usable.
func TestAntiWeakening_UnknownToolNeverUsable(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	ingest(t, c, srv, testIdentity, result(`{"name":"x","inputSchema":{"type":"object"}}`))
	rec, _ := c.Current().Get(ToolKey{Server: testServer, Name: "x"})
	if rec.Eligibility == Usable {
		t.Fatal("unknown tool must never be Usable")
	}
	// The disposition map must have NO path from UnknownTool/PrivilegeExpansion to Usable.
	for _, class := range []DriftClass{UnknownTool, PrivilegeExpansion} {
		if dispositionFor(class, nil) == Usable {
			t.Fatalf("%v must never map to Usable", class)
		}
		if dispositionFor(class, &ToolRecord{Eligibility: Usable}) == Usable {
			t.Fatalf("%v with a prior-usable record must NOT stay Usable", class)
		}
	}
}

// Privilege expansion must never be labelled safe narrowing — even when the same
// observation ALSO carries a genuine narrowing signal (mixed change).
func TestAntiWeakening_ExpansionNotLabelledNarrowing(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	// Prior removes an enum value (narrowing) BUT also adds a sensitive property
	// (expansion). Precedence must pick expansion.
	ingestApproved(t, c, srv, "t", `{"name":"t","inputSchema":{"type":"object","properties":{"mode":{"enum":["a","b","c"]}}}}`)
	mixed := `{"name":"t","inputSchema":{"type":"object","properties":{"mode":{"enum":["a"]},"command":{"type":"string"}}}}`
	rep := ingest(t, c, srv, testIdentity, result(mixed))
	if classOf(rep, "t") != PrivilegeExpansion {
		t.Fatalf("mixed narrowing+expansion must classify as privilege_expansion, got %v", classOf(rep, "t"))
	}
}

// An identity mismatch must never be processed as tool drift.
func TestAntiWeakening_IdentityMismatchNotToolDrift(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	ingestApproved(t, c, srv, "t", `{"name":"t","inputSchema":{"type":"object"}}`)
	// Even a benign re-observation under a WRONG identity must be refused server-side.
	_, _, err := c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: "spiffe://evil/x", Raw: result(`{"name":"t","inputSchema":{"type":"object"}}`)})
	if mcperr.ReasonOf(err) != mcperr.ReasonServerIdentityMismatch {
		t.Fatalf("identity mismatch must be a server fault, not tool drift: %v", err)
	}
}

// Duplicate tools must never collapse last-write-wins.
func TestAntiWeakening_DuplicatesNotLastWriteWins(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	raw := result(`{"name":"d","inputSchema":{"type":"object"}}`, `{"name":"d","inputSchema":{"type":"string"}}`)
	_, _, err := c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: raw})
	if mcperr.ReasonOf(err) != mcperr.ReasonDuplicateTool {
		t.Fatalf("duplicate names must be rejected, not collapsed: %v", err)
	}
}

// A failed publish must leave the previous snapshot byte-for-byte unchanged
// (no partial publication).
func TestAntiWeakening_NoPartialPublication(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	ingest(t, c, srv, testIdentity, result(`{"name":"a","inputSchema":{}}`))
	before := c.Current()
	// A batch whose SECOND tool is malformed must not publish the first.
	raw := result(`{"name":"b","inputSchema":{}}`, `{"name":"c"}`)
	if _, _, err := c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: raw}); err == nil {
		t.Fatal("expected an error for the malformed second tool")
	}
	if c.Current() != before {
		t.Fatal("partial publication: snapshot changed after a failed multi-tool ingest")
	}
	if _, ok := c.Current().Get(ToolKey{Server: testServer, Name: "b"}); ok {
		t.Fatal("the first tool of a failed batch was partially published")
	}
}

// Catalog growth is bounded — a hostile server cannot grow it without limit.
func TestAntiWeakening_BoundedCatalogGrowth(t *testing.T) {
	cfg := smallCatalog(t) // per-server tool cap is four
	c := New(cfg)
	srv := serverRecord(testServer, testIdentity)
	// Just over the per-server tool cap: decodes structurally, then hits the
	// entity-count capacity gate (capacity_exceeded).
	tools := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		tools = append(tools, `{"name":"t`+itoaLocal(i)+`","inputSchema":{}}`)
	}
	if _, _, err := c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: result(tools...)}); mcperr.ReasonOf(err) != mcperr.ReasonCapacityExceeded {
		t.Fatalf("over-cap discovery must hit capacity, got %v", err)
	}
	// A structurally huge array is ALSO bounded (a different, earlier gate).
	huge := make([]string, 0, 500)
	for i := 0; i < 500; i++ {
		huge = append(huge, `{"name":"h`+itoaLocal(i)+`","inputSchema":{}}`)
	}
	if _, _, err := c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: result(huge...)}); mcperr.ReasonOf(err) != mcperr.ReasonResourceLimit {
		t.Fatalf("huge array must be structurally bounded, got %v", err)
	}
}

// --- concurrency ------------------------------------------------------------

func TestConcurrentIngestSameServer(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tool := `{"name":"t","inputSchema":{"type":"object","properties":{"p` + itoaLocal(i) + `":{"type":"string"}}}}`
			_, _, _ = c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: result(tool)})
		}(i)
	}
	// Readers during publication never see a torn snapshot.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = c.Current().Records()
			}
		}()
	}
	wg.Wait()
	if _, ok := c.Current().Get(ToolKey{Server: testServer, Name: "t"}); !ok {
		t.Fatal("tool missing after concurrent ingest")
	}
}

func TestConcurrentIngestAndDisable(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _, _ = c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: result(`{"name":"t","inputSchema":{"type":"object"}}`)})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			c.DisableServer(testServer)
		}
	}()
	wg.Wait()
}

// TryPublish stale semantics: a captured base that is no longer current is rejected.
func TestStaleBaseSnapshotRejected(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	ingest(t, c, srv, testIdentity, result(`{"name":"a","inputSchema":{}}`))
	stale := c.Current()
	// Advance the catalog so `stale` is no longer current.
	ingest(t, c, srv, testIdentity, result(`{"name":"b","inputSchema":{}}`))
	// A single-shot publish against the stale base must be rejected, current unchanged.
	next := stale.clone(stale.revision + 1)
	cur := c.Current()
	if err := c.tryPublish(stale, next); mcperr.ReasonOf(err) != mcperr.ReasonStaleSnapshot {
		t.Fatalf("stale publish: want stale_snapshot, got %v", err)
	}
	if c.Current() != cur {
		t.Fatal("a rejected stale publish changed the snapshot")
	}
}

// --- malicious / non-compliant corpus --------------------------------------

func TestMaliciousCorpusRejected(t *testing.T) {
	c := New(lim(t))
	srv := serverRecord(testServer, testIdentity)
	corpus := map[string][]byte{
		"duplicate-json-key":    []byte(`{"tools":[{"name":"a","name":"b","inputSchema":{}}]}`),
		"invalid-utf8":          append([]byte(`{"tools":[{"name":"`), append([]byte{0xff}, []byte(`","inputSchema":{}}]}`)...)...),
		"escaped-surrogate":     []byte(`{"tools":[{"name":"\ud800","inputSchema":{}}]}`),
		"missing-tools":         []byte(`{"nextCursor":"x"}`),
		"tools-not-array":       []byte(`{"tools":{}}`),
		"tool-missing-name":     []byte(`{"tools":[{"inputSchema":{}}]}`),
		"tool-missing-schema":   []byte(`{"tools":[{"name":"a"}]}`),
		"unknown-result-member": []byte(`{"tools":[],"evil":1}`),
		"unknown-tool-member":   []byte(`{"tools":[{"name":"a","inputSchema":{},"evil":1}]}`),
		"non-object-schema":     []byte(`{"tools":[{"name":"a","inputSchema":"nope"}]}`),
		"non-ascii-name":        []byte(`{"tools":[{"name":"tóol","inputSchema":{}}]}`),
		"control-in-name":       controlNameFixture(),
		"empty-name":            []byte(`{"tools":[{"name":"","inputSchema":{}}]}`),
		"trailing-data":         []byte(`{"tools":[]}{}`),
		"top-level-array":       []byte(`[{"name":"a"}]`),
	}
	for name, raw := range corpus {
		if _, _, err := c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: raw}); err == nil {
			t.Fatalf("%s: malicious input was accepted", name)
		}
		if c.Current().Len() != 0 {
			t.Fatalf("%s: malicious input mutated the catalog", name)
		}
	}
}

func TestMaliciousDeepNestingBounded(t *testing.T) {
	cfg := smallCatalog(t) // schema depth cap is sixteen
	c := New(cfg)
	srv := serverRecord(testServer, testIdentity)
	deep := `{"name":"a","inputSchema":` + strings.Repeat(`{"properties":{"x":`, 40) + `{}` + strings.Repeat(`}}`, 40) + `}`
	if _, _, err := c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: result(deep)}); mcperr.ReasonOf(err) != mcperr.ReasonResourceLimit {
		t.Fatalf("deep nesting must hit resource_limit, got %v", err)
	}
}

func TestMaliciousOversizedSchema(t *testing.T) {
	cfg := smallCatalog(t) // schema byte cap is 4 KiB
	c := New(cfg)
	srv := serverRecord(testServer, testIdentity)
	big := `{"name":"a","inputSchema":{"type":"object","description":"` + strings.Repeat("A", 5000) + `"}}`
	if _, _, err := c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: result(big)}); mcperr.ReasonOf(err) != mcperr.ReasonResourceLimit {
		t.Fatalf("oversized schema must hit resource_limit, got %v", err)
	}
}

// controlNameFixture builds a discovery result whose tool name contains a raw
// U+0001 control byte (assembled from bytes so no control char sits in a source
// string literal). Such a name is invalid JSON / a control character and must be
// rejected.
func controlNameFixture() []byte {
	out := []byte(`{"tools":[{"name":"a`)
	out = append(out, 0x01)
	return append(out, []byte(`b","inputSchema":{}}]}`)...)
}

func tbSchema() canonical.Bounds {
	return canonical.Bounds{MaxBytes: 1 << 20, MaxDepth: 64, MaxObjectMembers: 4096, MaxArrayElements: 4096, MaxStringBytes: 256 << 10}
}

func itoaLocal(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
