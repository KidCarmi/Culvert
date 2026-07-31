package urlcatfeed

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestSourceDatasetReadiness proves the embedded SaaS dataset is
// PUBLICATION-READY after the source reconciliation
// (roadmap/FEEDS-SOURCE-RECONCILIATION.md): zero invalid hosts, zero
// multi-category assignments, zero suffix conflicts, and every host in exactly
// one category. This is the F5 publish precondition — if it regresses, an edit
// re-introduced a conflict and the feed must not publish.
func TestSourceDatasetReadiness(t *testing.T) {
	b, err := os.ReadFile("../urlcat/default_categories.json")
	if err != nil {
		t.Fatalf("read embedded dataset: %v", err)
	}
	var cats []SourceCategory
	if err := json.Unmarshal(b, &cats); err != nil {
		t.Fatalf("unmarshal dataset: %v", err)
	}
	r := EvaluateReadiness(SourceDataset{Categories: cats})
	if !r.Ready {
		t.Fatalf("embedded dataset must be publication-ready: invalid=%d multi=%d suffix=%d catname=%d structural=%d — reconcile roadmap/FEEDS-SOURCE-RECONCILIATION.md",
			len(r.InvalidHosts), len(r.MultiCategory), len(r.SuffixConflict), len(r.CategoryName), len(r.StructuralIssues))
	}
	if len(r.InvalidHosts) != 0 || len(r.MultiCategory) != 0 || len(r.SuffixConflict) != 0 || len(r.CategoryName) != 0 || len(r.StructuralIssues) != 0 {
		t.Errorf("dataset must have zero conflicts: invalid=%d multi=%d suffix=%d catname=%d structural=%d",
			len(r.InvalidHosts), len(r.MultiCategory), len(r.SuffixConflict), len(r.CategoryName), len(r.StructuralIssues))
	}
	// Every host is in exactly one category (raw == unique) and already canonical.
	if r.TotalRawHosts != r.UniqueHosts {
		t.Errorf("every host must be in exactly one category: raw=%d unique=%d", r.TotalRawHosts, r.UniqueHosts)
	}
	for i := range cats {
		for _, h := range cats[i].Hosts {
			if n, err := NormalizeHost(h); err != nil || n != h {
				t.Errorf("non-canonical host %q in %q: %v", h, cats[i].Name, err)
			}
		}
	}
}

// TestSourceDataset_GeneratesEndToEnd proves the reconciled dataset actually
// produces a valid signed-feed artifact + manifest through the real generator
// (not just that readiness is true), with deterministic bytes.
func TestSourceDataset_GeneratesEndToEnd(t *testing.T) {
	b, err := os.ReadFile("../urlcat/default_categories.json")
	if err != nil {
		t.Fatalf("read embedded dataset: %v", err)
	}
	var cats []SourceCategory
	if err := json.Unmarshal(b, &cats); err != nil {
		t.Fatalf("unmarshal dataset: %v", err)
	}
	gen := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	in := GenerateInput{Source: SourceDataset{Categories: cats}, FeedVersion: 1, GeneratedAt: gen, ExpiresAt: gen.Add(14 * 24 * time.Hour)}
	r1, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate on reconciled dataset failed: %v", err)
	}
	if r1.CategoryCount != len(cats) {
		t.Errorf("category_count = %d; want %d", r1.CategoryCount, len(cats))
	}
	// Deterministic: a second generation is byte-identical.
	r2, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(r1.ArtifactBytes) != string(r2.ArtifactBytes) || string(r1.ManifestBytes) != string(r2.ManifestBytes) {
		t.Error("generation on the embedded dataset is not deterministic")
	}
}

// EvaluateReadiness must reject every dataset Generate rejects — including the
// non-conflict structural invariants (Codex P2): Ready is the F5 publish gate.
func TestEvaluateReadiness_GeneratorParityStructural(t *testing.T) {
	// Empty dataset (Generate → ErrNoCats).
	if r := EvaluateReadiness(SourceDataset{}); r.Ready || len(r.StructuralIssues) == 0 {
		t.Errorf("empty dataset should be not-ready with a structural issue: %+v", r.StructuralIssues)
	}
	// Zero-host category (Generate → ErrEmptyCategoryHost).
	zero := EvaluateReadiness(SourceDataset{Categories: []SourceCategory{
		{Name: "AI", Hosts: []string{"anthropic.com"}},
		{Name: "Empty", Hosts: []string{}},
	}})
	if zero.Ready || len(zero.StructuralIssues) == 0 {
		t.Errorf("zero-host category should be not-ready with a structural issue: %+v", zero.StructuralIssues)
	}
	// Case-insensitive category collision (Generate → ErrCategoryCase).
	caseColl := EvaluateReadiness(SourceDataset{Categories: []SourceCategory{
		{Name: "AI", Hosts: []string{"a.example.com"}},
		{Name: "ai", Hosts: []string{"b.example.com"}},
	}})
	if caseColl.Ready || len(caseColl.StructuralIssues) == 0 {
		t.Errorf("case collision should be not-ready with a structural issue: %+v", caseColl.StructuralIssues)
	}
	// Cross-check: each of the above is also rejected by Generate.
	gen := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	for _, ds := range []SourceDataset{
		{},
		{Categories: []SourceCategory{{Name: "AI", Hosts: []string{"anthropic.com"}}, {Name: "Empty", Hosts: []string{}}}},
		{Categories: []SourceCategory{{Name: "AI", Hosts: []string{"a.example.com"}}, {Name: "ai", Hosts: []string{"b.example.com"}}}},
	} {
		if _, err := Generate(GenerateInput{Source: ds, FeedVersion: 1, GeneratedAt: gen, ExpiresAt: gen.Add(time.Hour)}); err == nil {
			t.Errorf("Generate should reject a dataset the readiness gate rejects: %+v", ds)
		}
	}
}

func TestEvaluateReadiness_CleanDatasetIsReady(t *testing.T) {
	r := EvaluateReadiness(SourceDataset{Categories: []SourceCategory{
		{Name: "AI", Hosts: []string{"anthropic.com", "openai.com"}},
		{Name: "Messaging", Hosts: []string{"slack.com"}},
	}})
	if !r.Ready {
		t.Fatalf("clean dataset should be ready; got %+v", r)
	}
	if r.UniqueHosts != 3 {
		t.Errorf("UniqueHosts = %d; want 3", r.UniqueHosts)
	}
}

func TestEvaluateReadiness_DetectsEachConflict(t *testing.T) {
	multi := EvaluateReadiness(SourceDataset{Categories: []SourceCategory{
		{Name: "AI", Hosts: []string{"x.example.com"}},
		{Name: "Dev", Hosts: []string{"x.example.com"}},
	}})
	if multi.Ready || len(multi.MultiCategory) != 1 {
		t.Errorf("multi-category not detected: %+v", multi)
	}
	suffix := EvaluateReadiness(SourceDataset{Categories: []SourceCategory{
		{Name: "A", Hosts: []string{"example.com"}},
		{Name: "B", Hosts: []string{"sub.example.com"}},
	}})
	if suffix.Ready || len(suffix.SuffixConflict) == 0 {
		t.Errorf("suffix conflict not detected: %+v", suffix)
	}
	invalid := EvaluateReadiness(SourceDataset{Categories: []SourceCategory{
		{Name: "A", Hosts: []string{"example.com/path"}},
	}})
	if invalid.Ready || len(invalid.InvalidHosts) != 1 {
		t.Errorf("invalid host not detected: %+v", invalid)
	}
	badName := EvaluateReadiness(SourceDataset{Categories: []SourceCategory{
		{Name: "A\tB", Hosts: []string{"example.com"}},
	}})
	if badName.Ready || len(badName.CategoryName) != 1 {
		t.Errorf("category-name violation not detected: %+v", badName)
	}
}

// EvaluateReadiness must be deterministic across runs (sorted output).
func TestEvaluateReadiness_Deterministic(t *testing.T) {
	ds := SourceDataset{Categories: []SourceCategory{
		{Name: "AI", Hosts: []string{"x.example.com", "y.example.com"}},
		{Name: "Dev", Hosts: []string{"x.example.com", "y.example.com"}},
	}}
	first := EvaluateReadiness(ds)
	for i := 0; i < 5; i++ {
		r := EvaluateReadiness(ds)
		if len(r.MultiCategory) != len(first.MultiCategory) {
			t.Fatal("non-deterministic conflict count")
		}
		for j := range r.MultiCategory {
			if r.MultiCategory[j] != first.MultiCategory[j] {
				t.Fatalf("non-deterministic ordering at %d", j)
			}
		}
	}
}
