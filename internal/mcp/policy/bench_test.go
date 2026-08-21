package policy

import "testing"

const benchDoc = `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[
	{"id":"R1","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"request_access","conditions":[{"field":"tool.name","op":"exact","value":"delete_repo"}]},
	{"id":"R2","priority":2,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"tool.name","op":"prefix","value":"read_"},{"field":"principal.groups","op":"contains_any","values":["developers","ops"]}],"obligations":{"logging":"standard"}},
	{"id":"R3","priority":3,"action":"MONITOR","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"tool.name","op":"glob","value":"list_*"}],"obligations":{"logging":"full"}},
	{"id":"R4","priority":4,"action":"REQUIRE_APPROVAL","reason":"MCP.POLICY.APPROVAL_REQUIRED","remediation":"request_approval","conditions":[{"field":"operation.class","op":"exact","value":"write"}],"obligations":{"approval":true}}
]}`

func benchSnap(b *testing.B) *Snapshot {
	b.Helper()
	snap, err := Compile([]byte(benchDoc), CreatedMeta{}, DefaultLimits())
	if err != nil {
		b.Fatalf("compile: %v", err)
	}
	return snap
}

func BenchmarkCompile(b *testing.B) {
	doc := []byte(benchDoc)
	lim := DefaultLimits()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Compile(doc, CreatedMeta{}, lim); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEvaluate_Match benchmarks a rule hit (the R2 read_ allow path).
func BenchmarkEvaluate_Match(b *testing.B) {
	snap := benchSnap(b)
	e := NewEngine(DefaultLimits())
	in := gwInput()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := e.Evaluate(snap, &in); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEvaluate_NoMatch benchmarks the full scan to default-deny.
func BenchmarkEvaluate_NoMatch(b *testing.B) {
	snap := benchSnap(b)
	e := NewEngine(DefaultLimits())
	in := gwInput()
	in.Tool.Name = "unmatched_tool"
	in.Operation.Operand = "unmatched_tool"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Evaluate(snap, &in)
	}
}

// BenchmarkEvaluate_HardOverride benchmarks the unknown-tool hard override (should
// short-circuit before any rule scan).
func BenchmarkEvaluate_HardOverride(b *testing.B) {
	snap := benchSnap(b)
	e := NewEngine(DefaultLimits())
	in := gwInput()
	in.Tool.Drift = DriftUnknownTool
	in.Tool.Disposition = DispQuarantined
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Evaluate(snap, &in)
	}
}

// BenchmarkEvaluate_Parallel proves the evaluator scales lock-free across goroutines
// (no shared mutable state on the hot path).
func BenchmarkEvaluate_Parallel(b *testing.B) {
	snap := benchSnap(b)
	e := NewEngine(DefaultLimits())
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		in := gwInput()
		for pb.Next() {
			e.Evaluate(snap, &in)
		}
	})
}

func BenchmarkStore_CurrentRead(b *testing.B) {
	st := NewStore(CapGateway)
	snap, _ := Compile([]byte(benchDoc), CreatedMeta{}, DefaultLimits())
	_ = st.Publish(0, snap)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = st.Current()
		}
	})
}
