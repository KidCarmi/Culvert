package main

// F3 Performance Qualification — Evaluate microbenchmarks across realistic
// policy sizes and match positions. Untracked qualification artifact: contains
// only Benchmark functions + helpers (no Test*), so `go test ./...` is
// unaffected. Compiled identically against parent a4f9ee1 and HEAD; the
// Evaluate signature is unchanged across both, so the same file builds in each.
//
//   go test -run '^$' -bench 'BenchmarkPerfQual_Evaluate' -benchmem -count=N .

import (
	"fmt"
	"testing"
)

// buildMatchPositionStore returns a store of `size` access rules where exactly
// one rule matches the query host "target.example.com", placed at 1-based scan
// position `matchPos` (priority-ordered). Rules before it do not match, so the
// scan traverses matchPos-1 misses before the hit. matchPos<=0 builds an
// all-miss store (no-match / default-deny full scan).
func buildMatchPositionStore(size, matchPos int) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, size)
	for i := 0; i < size; i++ {
		rules[i] = PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("rule-%d", i),
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Action:   ActionAllow,
		}
	}
	if matchPos >= 1 && matchPos <= size {
		rules[matchPos-1].Name = "match"
		rules[matchPos-1].DestFQDN = "target.example.com"
	}
	ps.ReplaceAll(rules)
	return ps
}

func BenchmarkPerfQual_Evaluate(b *testing.B) {
	sizes := []int{10, 50, 100, 500}
	positions := []struct {
		name string
		pos  func(size int) int
	}{
		{"first", func(int) int { return 1 }},
		{"middle", func(s int) int { return (s + 1) / 2 }},
		{"last", func(s int) int { return s }},
		{"nomatch", func(int) int { return 0 }},
	}
	for _, size := range sizes {
		for _, p := range positions {
			mp := p.pos(size)
			ps := buildMatchPositionStore(size, mp)
			wantMatch := mp >= 1
			b.Run(fmt.Sprintf("rules=%d/%s", size, p.name), func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil)
					if wantMatch != (m != nil) {
						b.Fatalf("size=%d pos=%d: match=%v want %v", size, mp, m != nil, wantMatch)
					}
				}
			})
		}
	}
}
