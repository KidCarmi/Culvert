package main

import (
	"context"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/support"
)

// registeredCollectorIDs is the live set of registered collector IDs.
func registeredCollectorIDs() map[string]bool {
	ids := map[string]bool{}
	for _, c := range support.Collectors() {
		ids[c.Meta().ID] = true
	}
	return ids
}

// TestSupportScopes_ReferenceRealCollectors pins that every collector ID named by
// a scope (and the baseline) exists in the registry — a typo can't ship a scope
// that silently collects nothing for that domain.
func TestSupportScopes_ReferenceRealCollectors(t *testing.T) {
	reg := registeredCollectorIDs()
	for _, id := range supportScopeBaseline {
		if !reg[id] {
			t.Errorf("baseline references unknown collector %q", id)
		}
	}
	for scope, ids := range supportIncidentScopes {
		for _, id := range ids {
			if !reg[id] {
				t.Errorf("scope %q references unknown collector %q", scope, id)
			}
		}
	}
}

func TestResolveSupportScope(t *testing.T) {
	if inc, ok := resolveSupportScope("standard"); !ok || inc != nil {
		t.Fatalf("standard: inc=%v ok=%v want nil,true", inc, ok)
	}
	if inc, ok := resolveSupportScope(""); !ok || inc != nil {
		t.Fatalf("empty: inc=%v ok=%v want nil,true", inc, ok)
	}
	if _, ok := resolveSupportScope("bogus-scope"); ok {
		t.Fatal("bogus scope accepted")
	}
	inc, ok := resolveSupportScope("tls")
	if !ok {
		t.Fatal("tls scope rejected")
	}
	// baseline + tls-specific are present; an out-of-scope collector is absent.
	for _, id := range []string{"tls", "logs", "config", "product", "health"} {
		if !inc[id] {
			t.Errorf("tls scope missing %q", id)
		}
	}
	if inc["governance"] {
		t.Error("tls scope should not include governance")
	}
}

// TestSupportScope_FiltersCollectors proves an incident-scoped build runs only the
// scope's collectors (+ baseline) and skips the rest with a scope note.
func TestSupportScope_FiltersCollectors(t *testing.T) {
	res, err := buildSupportBundle(context.Background(), support.L1, "tls", "")
	if err != nil {
		t.Fatalf("buildSupportBundle(tls): %v", err)
	}
	if res.Manifest.Scope.IncidentScope != "tls" {
		t.Fatalf("manifest scope=%q want tls", res.Manifest.Scope.IncidentScope)
	}
	byID := map[string]support.SectionEntry{}
	for _, s := range res.Manifest.Sections {
		byID[s.ID] = s
	}
	// In-scope collectors ran (ok/partial).
	for _, id := range []string{"tls", "logs", "config", "product", "health"} {
		s, ok := byID[id]
		if !ok || (s.Status != support.StatusOK && s.Status != support.StatusPartial) {
			t.Errorf("in-scope %q status=%q (want ok/partial)", id, s.Status)
		}
	}
	// Out-of-scope collectors were skipped with a scope note.
	for _, id := range []string{"governance", "upstream"} {
		s, ok := byID[id]
		if !ok {
			t.Errorf("out-of-scope %q missing from manifest", id)
			continue
		}
		if s.Status != support.StatusSkipped || !strings.Contains(s.Note, "scope=tls") {
			t.Errorf("out-of-scope %q status=%q note=%q (want skipped, scope=tls)", id, s.Status, s.Note)
		}
	}
}

func TestParseSupportLevel(t *testing.T) {
	cases := map[string]struct {
		want support.DebugLevel
		ok   bool
	}{
		"":  {support.L1, true},
		"0": {support.L0, true},
		"1": {support.L1, true},
		"2": {support.L2, true},
		"3": {support.L3, true},
		"4": {support.L4, true},
		"5": {support.L1, false},
		"x": {support.L1, false},
	}
	for in, exp := range cases {
		got, ok := parseSupportLevel(in)
		if got != exp.want || ok != exp.ok {
			t.Errorf("parseSupportLevel(%q)=(%d,%v) want (%d,%v)", in, got, ok, exp.want, exp.ok)
		}
	}
}

// TestSupportLevel_RuntimeGatedAtL2 proves the L2 runtime collector is skipped in
// a standard (L1) bundle and runs at L2 — the debug-level capture control.
func TestSupportLevel_RuntimeGatedAtL2(t *testing.T) {
	at := func(level support.DebugLevel) support.SectionEntry {
		res, err := buildSupportBundle(context.Background(), level, "standard", "")
		if err != nil {
			t.Fatalf("build L%d: %v", level, err)
		}
		for _, s := range res.Manifest.Sections {
			if s.ID == "runtime" {
				return s
			}
		}
		t.Fatalf("no runtime section at L%d", level)
		return support.SectionEntry{}
	}
	if s := at(support.L1); s.Status != support.StatusSkipped {
		t.Errorf("runtime at L1 status=%q want skipped", s.Status)
	}
	if s := at(support.L2); s.Status != support.StatusOK && s.Status != support.StatusPartial {
		t.Errorf("runtime at L2 status=%q want ok/partial", s.Status)
	}
}

// TestSupportLevel_RuntimeInScopedL2 is the Codex-780 regression: an incident-
// scoped bundle at L2 must still surface the level-gated runtime collector. Because
// the runner applies the scope gate before the level gate, runtime has to be a
// scope candidate (baseline) or it is dropped with a scope note before the level
// even matters. At L1 it is level-skipped; at L2 it runs — never scope-skipped.
func TestSupportLevel_RuntimeInScopedL2(t *testing.T) {
	find := func(level support.DebugLevel) support.SectionEntry {
		res, err := buildSupportBundle(context.Background(), level, "tls", "")
		if err != nil {
			t.Fatalf("build tls L%d: %v", level, err)
		}
		for _, s := range res.Manifest.Sections {
			if s.ID == "runtime" {
				return s
			}
		}
		t.Fatalf("no runtime section in tls-scoped L%d bundle", level)
		return support.SectionEntry{}
	}
	// Never scope-gated out of a scoped bundle.
	if s := find(support.L1); strings.Contains(s.Note, "scope=") {
		t.Fatalf("runtime scope-skipped in tls L1 (note=%q) — must be a scope candidate", s.Note)
	}
	if s := find(support.L1); s.Status != support.StatusSkipped {
		t.Errorf("runtime in tls L1 status=%q want skipped (level-gated)", s.Status)
	}
	if s := find(support.L2); s.Status != support.StatusOK && s.Status != support.StatusPartial {
		t.Errorf("runtime in tls L2 status=%q want ok/partial — L2 facts missing from scoped bundle", s.Status)
	}
}

// TestSupportScope_StandardRunsAll confirms the standard scope applies no filter.
func TestSupportScope_StandardRunsAll(t *testing.T) {
	res, err := buildSupportBundle(context.Background(), support.L1, "standard", "")
	if err != nil {
		t.Fatalf("buildSupportBundle(standard): %v", err)
	}
	for _, s := range res.Manifest.Sections {
		if strings.Contains(s.Note, "scope=") {
			t.Fatalf("standard scope skipped %q with %q — should run all", s.ID, s.Note)
		}
	}
}
