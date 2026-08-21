package inspection

import (
	"context"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/dlp"
)

// TestProperty_DeterministicSummary: identical input + profile ⇒ identical summary.
func TestProperty_DeterministicSummary(t *testing.T) {
	p := gwProfile(t)
	in := RequestInput{Tool: ToolRef{Name: "echo", ServerID: "s1"}, Compiled: compileSchema(t, `{}`),
		Args: nd(t, `{"a":"`+jwtCanary+`","e":"x@y.com","url":"https://public.example/x"}`)}
	r1 := InspectRequest(context.Background(), p, in, time.Unix(1, 0))
	r2 := InspectRequest(context.Background(), p, in, time.Unix(1, 0))
	if r1.HardFail != r2.HardFail || r1.Summary.SecretFound != r2.Summary.SecretFound ||
		len(r1.Findings) != len(r2.Findings) {
		t.Fatal("inspection is not deterministic")
	}
}

// TestProperty_RedactionChangesHash_PassThroughDoesNot: a redaction that removes a
// value changes the transformed hash; a value with nothing to redact leaves it
// equal to the original canonical hash.
func TestProperty_RedactionChangesHash_PassThroughDoesNot(t *testing.T) {
	p := redactProfile(t, dlp.ClassBearerToken)
	// pass-through: nothing to redact.
	clean := nd(t, `{"keep":"data"}`)
	tp, ev, err := ApplyRedaction(p, "r1", 0, clean, nil)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.HashNode(tp) != canonical.HashNode(clean) {
		t.Fatal("pass-through redaction must not change the canonical hash")
	}
	if ev.OriginalHash != ev.TransformedHash {
		t.Fatal("pass-through hashes must be equal")
	}
	// removal: hash changes.
	dirty := nd(t, `{"token":"`+jwtCanary+`","keep":"data"}`)
	td, ev2, err := ApplyRedaction(p, "r1", 0, dirty, nil)
	if err != nil {
		t.Fatal(err)
	}
	if canonical.HashNode(td) == canonical.HashNode(dirty) {
		t.Fatal("redaction must change the canonical hash")
	}
	if ev2.OriginalHash == ev2.TransformedHash {
		t.Fatal("redaction hashes must differ")
	}
}

// TestProperty_AddingSafeFieldCannotEraseSecretFinding: adding an unrelated benign
// field to a value never removes an existing secret finding.
func TestProperty_AddingSafeFieldCannotEraseSecretFinding(t *testing.T) {
	base := scanReport(t, `{"token":"`+jwtCanary+`"}`)
	withExtra := scanReport(t, `{"token":"`+jwtCanary+`","note":"hello world"}`)
	if !base.SecretFound() || !withExtra.SecretFound() {
		t.Fatal("adding a safe field erased the secret finding")
	}
}

// TestProperty_BlockedNeverAllowed: a value whose worst disposition is block always
// produces a HardFail (a block can never become a pass).
func TestProperty_BlockedNeverAllowed(t *testing.T) {
	p := gwProfile(t)
	in := RequestInput{Tool: ToolRef{Name: "t", ServerID: "s1"}, Compiled: compileSchema(t, `{}`),
		Args: nd(t, `{"secret":"`+jwtCanary+`"}`)}
	res := InspectRequest(context.Background(), p, in, time.Unix(1, 0))
	if !res.HardFail {
		t.Fatal("a block-disposition secret must never be allowed")
	}
}

func scanReport(t *testing.T, s string) *dlp.Report {
	t.Helper()
	r, err := dlp.Scan(nd(t, s), dlp.RequestMode(), defaultGwLimits())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// --- benchmarks ------------------------------------------------------------

func BenchmarkInspectRequest_Clean(b *testing.B) {
	p := DefaultGatewayProfile(1)
	args, _ := canonical.Decode([]byte(`{"msg":"hello world","count":42}`), defaultGwLimits2())
	compiled, _ := p.CompileSchema(mustDecodeSchema(`{"type":"object","properties":{"msg":{"type":"string"},"count":{"type":"integer"}}}`))
	in := RequestInput{Tool: ToolRef{Name: "t", ServerID: "s"}, Compiled: compiled, Args: args}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = InspectRequest(context.Background(), p, in, time.Unix(1, 0))
	}
}

func BenchmarkInspectRequest_Secret(b *testing.B) {
	p := DefaultGatewayProfile(1)
	args, _ := canonical.Decode([]byte(`{"token":"`+jwtCanary+`"}`), defaultGwLimits2())
	in := RequestInput{Tool: ToolRef{Name: "t", ServerID: "s"}, Args: args}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = InspectRequest(context.Background(), p, in, time.Unix(1, 0))
	}
}

func BenchmarkInspectResponse(b *testing.B) {
	p := DefaultGatewayProfile(1)
	body := []byte(`{"result":{"items":["a","b","c"],"count":3}}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = InspectResponse(context.Background(), p, ResponseInput{Body: body}, time.Unix(1, 0))
	}
}

func defaultGwLimits2() canonical.Bounds {
	return canonical.Bounds{MaxBytes: 1 << 20, MaxDepth: 64, MaxObjectMembers: 4096, MaxArrayElements: 4096, MaxStringBytes: 1 << 16}
}

func mustDecodeSchema(s string) *canonical.Node {
	n, err := canonical.Decode([]byte(s), defaultGwLimits2())
	if err != nil {
		panic(err)
	}
	return n
}
