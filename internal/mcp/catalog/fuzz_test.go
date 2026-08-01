package catalog

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

func limitsForFuzz() limits.CatalogLimits { return limits.DefaultCatalog() }

// FuzzIngest proves ingestion never panics on arbitrary discovery bytes, never
// mutates the catalog on a rejected input, and never yields a Usable entry.
func FuzzIngest(f *testing.F) {
	seeds := []string{
		`{"tools":[]}`,
		`{"tools":[{"name":"a","inputSchema":{"type":"object"}}]}`,
		`{"tools":[{"name":"a","inputSchema":{},"description":"d","outputSchema":{"type":"object"}}]}`,
		`{"tools":[{"name":"a","inputSchema":{"properties":{"cmd":{"type":"string"}}}}]}`,
		`{"tools":[{"name":"a","name":"b","inputSchema":{}}]}`,
		`{"nextCursor":"x","tools":[]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	l := limitsForFuzz()
	f.Fuzz(func(t *testing.T, raw []byte) {
		c := New(l)
		srv := serverRecord(testServer, testIdentity)
		before := c.Current()
		snap, rep, err := c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: raw})
		if err != nil {
			if c.Current() != before {
				t.Fatal("rejected ingest mutated the catalog")
			}
			return
		}
		// Success: never a Usable disposition, and every observation is bounded.
		for _, o := range rep.Observations {
			if o.Eligibility == Usable {
				t.Fatal("ingestion produced a Usable disposition")
			}
		}
		if snap.Len() > l.MaxCatalogEntries() {
			t.Fatal("catalog exceeded its entry bound")
		}
	})
}

// FuzzClassify proves the classifier never panics and always returns a class in
// range, for arbitrary schema-shaped inputs, and that an identity difference
// always dominates (never a tool-level "safe" result).
func FuzzClassify(f *testing.F) {
	seeds := [][2]string{
		{`{"type":"object"}`, `{"type":"object"}`},
		{`{"enum":["a"]}`, `{"enum":["a","b"]}`},
		{`{"required":["x"]}`, `{"properties":{"x":{}}}`},
		{`{"additionalProperties":false}`, `{"additionalProperties":true}`},
	}
	for _, s := range seeds {
		f.Add([]byte(s[0]), []byte(s[1]), false)
	}
	l := limitsForFuzz()
	f.Fuzz(func(t *testing.T, a, b []byte, diffIdentity bool) {
		pr := buildRecord(t, l, "id-A", a)
		if pr == nil {
			return
		}
		obsID := registry.Identity("id-A")
		if diffIdentity {
			obsID = "id-B"
		}
		ob := buildRecordID(t, l, obsID, b)
		if ob == nil {
			return
		}
		class, _ := Classify(pr, ob)
		if class > UnknownTool {
			t.Fatalf("class out of range: %d", class)
		}
		// An identity difference must ALWAYS classify as identity_change — never a
		// tool-level safe/narrowing/no-change result.
		if diffIdentity && class != IdentityChange {
			t.Fatalf("identity difference misclassified as %v", class)
		}
	})
}

func buildRecord(t *testing.T, l limits.CatalogLimits, id registry.Identity, schema []byte) *ToolRecord {
	return buildRecordID(t, l, id, schema)
}

func buildRecordID(t *testing.T, l limits.CatalogLimits, id registry.Identity, schema []byte) *ToolRecord {
	t.Helper()
	srv := serverRecord(testServer, id)
	recs, err := parseDiscovery(srv, DiscoveryInput{ServerID: srv.ID, Identity: id, Raw: wrapTool(schema)}, l)
	if err != nil || len(recs) != 1 {
		return nil
	}
	return recs[0]
}

// wrapTool wraps an arbitrary schema blob into a one-tool discovery result.
func wrapTool(schema []byte) []byte {
	out := []byte(`{"tools":[{"name":"t","inputSchema":`)
	out = append(out, schema...)
	return append(out, []byte(`}]}`)...)
}
