package urlcatfeed

import (
	"encoding/json"
	"os"
	"testing"
)

// TestSourceDatasetReadiness evaluates the REAL embedded SaaS dataset against the
// F1 rules. It currently pins a CONTROLLED not-ready result (see
// roadmap/FEEDS-SOURCE-RECONCILIATION.md). F5's publisher MUST call
// EvaluateReadiness and refuse to publish unless Ready == true; flipping this test
// to assert Ready is the reconciliation milestone.
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
	if r.Ready {
		t.Fatal("dataset now reports READY — update this test to assert readiness and wire the F5 publish gate")
	}
	// Pin the known conflict shape so accidental dataset edits are flagged.
	if len(r.InvalidHosts) != 4 || len(r.MultiCategory) != 32 || len(r.SuffixConflict) != 6 || len(r.CategoryName) != 0 {
		t.Errorf("conflict inventory drift: invalid=%d multi=%d suffix=%d catname=%d (want 4/32/6/0) — reconcile roadmap/FEEDS-SOURCE-RECONCILIATION.md",
			len(r.InvalidHosts), len(r.MultiCategory), len(r.SuffixConflict), len(r.CategoryName))
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
