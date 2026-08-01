package catalog

import (
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
)

// typicalSchema is a representative tool input schema.
const typicalSchema = `{"type":"object","required":["path"],"properties":{"path":{"type":"string","maxLength":4096},"mode":{"enum":["read","write"]},"count":{"type":"number","minimum":0,"maximum":100}},"additionalProperties":false}`

func BenchmarkCanonicalizeSchema(b *testing.B) {
	raw := []byte(typicalSchema)
	bd := tbSchema()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := canonical.HashSchema(raw, bd); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCanonicalizeMaxSchema(b *testing.B) {
	// A large but in-bound schema: many properties.
	var sb strings.Builder
	sb.WriteString(`{"type":"object","properties":{`)
	for i := 0; i < 500; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`"p`)
		sb.WriteString(itoaLocal(i))
		sb.WriteString(`":{"type":"string"}`)
	}
	sb.WriteString(`}}`)
	raw := []byte(sb.String())
	bd := tbSchema()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := canonical.HashSchema(raw, bd); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkClassifyTypicalCycle(b *testing.B) {
	l := limitsForFuzz()
	srv := serverRecord(testServer, testIdentity)
	prior, _ := parseDiscovery(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: wrapTool([]byte(typicalSchema))}, l)
	changed := `{"type":"object","required":["path"],"properties":{"path":{"type":"string","maxLength":4096},"mode":{"enum":["read","write","admin"]},"count":{"type":"number","minimum":0,"maximum":100}},"additionalProperties":false}`
	obs, _ := parseDiscovery(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: wrapTool([]byte(changed))}, l)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if class, _ := Classify(prior[0], obs[0]); class != PrivilegeExpansion {
			b.Fatalf("unexpected class %v", class)
		}
	}
}

func BenchmarkIngestPublish(b *testing.B) {
	l := limitsForFuzz()
	srv := serverRecord(testServer, testIdentity)
	raw := result(`{"name":"a","inputSchema":` + typicalSchema + `}`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c := New(l)
		if _, _, err := c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: raw}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParallelSnapshotReads(b *testing.B) {
	l := limitsForFuzz()
	c := New(l)
	srv := serverRecord(testServer, testIdentity)
	_, _, _ = c.Ingest(srv, DiscoveryInput{ServerID: srv.ID, Identity: testIdentity, Raw: result(`{"name":"a","inputSchema":` + typicalSchema + `}`)})
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = c.Current().Get(ToolKey{Server: testServer, Name: "a"})
		}
	})
}
