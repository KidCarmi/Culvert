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
	res, err := buildSupportBundle(context.Background(), support.L1, "tls")
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

// TestSupportScope_StandardRunsAll confirms the standard scope applies no filter.
func TestSupportScope_StandardRunsAll(t *testing.T) {
	res, err := buildSupportBundle(context.Background(), support.L1, "standard")
	if err != nil {
		t.Fatalf("buildSupportBundle(standard): %v", err)
	}
	for _, s := range res.Manifest.Sections {
		if strings.Contains(s.Note, "scope=") {
			t.Fatalf("standard scope skipped %q with %q — should run all", s.ID, s.Note)
		}
	}
}
