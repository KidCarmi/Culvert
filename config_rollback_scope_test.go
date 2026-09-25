package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// rollbackOffSurfaceMarker matches the source-comment phrasings this tree
// uses to declare that a handler's state is deliberately NOT on the
// config-version rollback surface.
var rollbackOffSurfaceMarker = regexp.MustCompile(
	`(?i)NOT (add |calling )?saveConfigVersion|out of the (config-version )?rollback surface|not in the rollback|excluded from the rollback|off the rollback surface|not on the config-version`)

// scanRollbackOffSurfaceMarkers returns every "file:func" (or "file:<file>"
// for a comment outside any function) in the root package whose comments
// carry an off-rollback marker. The registry and the version engine are
// excluded: they describe the surface rather than own state.
func scanRollbackOffSurfaceMarkers(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "config_surfaces.go" || f == "configversion.go" {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, cg := range af.Comments {
			if !rollbackOffSurfaceMarker.MatchString(cg.Text()) {
				continue
			}
			name := "<file>"
			for _, d := range af.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok {
					continue
				}
				if fd.Doc == cg || (cg.Pos() >= fd.Pos() && cg.End() <= fd.End()) {
					name = fd.Name.Name
				}
			}
			out[f+":"+name] = true
		}
	}
	return out
}

// TestRollbackScope_EveryOffSurfaceMarkerIsClaimed is the wall that keeps the
// rollback-scope answer from silently missing a new off-registry surface: any
// handler documented as "not on the rollback surface" must be claimed by an
// offRegistryRollbackExclusions entry, mapped to a registry row that the
// derivation reports, or recorded as runtime-only. Stale claims fail too.
func TestRollbackScope_EveryOffSurfaceMarkerIsClaimed(t *testing.T) {
	markers := scanRollbackOffSurfaceMarkers(t)
	if len(markers) < 10 {
		t.Fatalf("marker scan found only %d sites — the regexp or the scan has stopped matching", len(markers))
	}

	reported := map[string]bool{}
	for _, e := range rollbackExcludedConfigSurfaces() {
		reported[e.ID] = true
	}

	claimed := map[string]string{}
	for i := range offRegistryRollbackExclusions {
		for _, src := range offRegistryRollbackExclusions[i].sources {
			claimed[src] = offRegistryRollbackExclusions[i].ID
		}
	}
	for src, id := range rollbackMarkersCoveredByRegistry {
		if !reported[id] {
			t.Errorf("%s is mapped to registry row %q, which the rollback scope does not report", src, id)
		}
		claimed[src] = id
	}
	for src := range rollbackMarkersRuntimeOnly {
		claimed[src] = "runtime-only"
	}

	var unclaimed, stale []string
	for m := range markers {
		if _, ok := claimed[m]; !ok {
			unclaimed = append(unclaimed, m)
		}
	}
	for src := range claimed {
		if !markers[src] {
			stale = append(stale, src)
		}
	}
	sort.Strings(unclaimed)
	sort.Strings(stale)
	if len(unclaimed) > 0 {
		t.Errorf("off-rollback source markers not reflected in the rollback scope (add an offRegistryRollbackExclusions entry, a registry mapping, or a runtime-only note): %v", unclaimed)
	}
	if len(stale) > 0 {
		t.Errorf("rollback-scope claims name sites that no longer carry an off-rollback marker: %v", stale)
	}
}

// TestRollbackScope_OffRegistryEntriesAreReportedOnce pins that every
// off-registry exclusion reaches the response exactly once and never shadows
// a registry ID.
func TestRollbackScope_OffRegistryEntriesAreReportedOnce(t *testing.T) {
	seen := map[string]int{}
	for _, e := range rollbackExcludedConfigSurfaces() {
		seen[e.ID]++
		if e.Note == "" {
			t.Errorf("%q has no note", e.ID)
		}
	}
	for i := range offRegistryRollbackExclusions {
		if id := offRegistryRollbackExclusions[i].ID; seen[id] != 1 {
			t.Errorf("off-registry exclusion %q reported %d times, want 1", id, seen[id])
		}
	}
	for i := range configSurfaces {
		for j := range offRegistryRollbackExclusions {
			if configSurfaces[i].ID == offRegistryRollbackExclusions[j].ID {
				t.Errorf("off-registry ID %q collides with a registry row", configSurfaces[i].ID)
			}
		}
	}
}
