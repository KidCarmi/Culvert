package simulate

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

func benchCorpus(n int) []Case {
	cases := make([]Case, n)
	for i := range cases {
		name := "read_file"
		if i%2 == 0 {
			name = "write_file"
		}
		cases[i] = Case{ID: itoa(i), Input: gwInput(name)}
	}
	return cases
}

func BenchmarkSimulate_Corpus(b *testing.B) {
	snap := gwSnap(b, allowRead)
	sim := New(policy.DefaultLimits())
	cases := benchCorpus(64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sim.Corpus(snap, cases); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSimulate_Compare(b *testing.B) {
	t := &testing.T{}
	oldSnap := gwSnap(t, allowRead)
	newSnap := gwSnap(t, allowRead+`,{"id":"AW","priority":2,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"tool.name","op":"exact","value":"write_file"}],"obligations":{"logging":"standard"}}`)
	sim := New(policy.DefaultLimits())
	cases := benchCorpus(64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sim.Compare(oldSnap, newSnap, cases); err != nil {
			b.Fatal(err)
		}
	}
}
