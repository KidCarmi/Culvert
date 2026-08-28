package main

// urlcat_bulk_cap_test.go — Blocker C (2D-B final correction §§9–11): the
// MaxHostsPerCategory invariant must hold on EVERY runtime bulk taxonomy
// path, not only the admin write paths. At the prior frozen candidate the
// three bulk installers (cluster snapshot apply, config import, config-
// version rollback) went through the unchecked ReplaceAll, so a 10,001-host
// category was accepted wholesale — these are the §22-C red-before proofs.
//
// Contract pinned here (whole-candidate semantics):
//   - an over-cap category REJECTS the whole bulk candidate — nothing is
//     installed, nothing is truncated, nothing partially applies;
//   - the live taxonomy keeps serving unchanged;
//   - the aggregate snapshot caps (maxSnapURLCategoryHosts) are NOT this
//     invariant — the per-category bound is enforced by the canonical
//     urlcat.ValidateEntries seam.

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// bulkCapOverCategory builds a category one host past the cap (10,001).
func bulkCapOverCategory(name string) CategoryEntry {
	hosts := make([]string, 10001)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%05d.%s.example", i, name)
	}
	return CategoryEntry{Name: name, Hosts: hosts}
}

func TestBulkCap_ClusterSnapshotApplyRejectsOverCapCategory(t *testing.T) {
	snapshotCatStore(t)
	catStore.ReplaceAll([]CategoryEntry{{Name: "keep", Hosts: []string{"keep.example.com"}}})

	snap := ConfigSnapshot{
		Version: 1,
		URLCategories: []CategoryEntry{
			{Name: "fine", Hosts: []string{"fine.example.com"}},
			bulkCapOverCategory("flood"),
		},
	}
	applyConfigSnapshot(snap)

	names := listCategoryNames(t)
	if len(names) != 1 || names[0] != "keep" {
		t.Fatalf("over-cap snapshot candidate must be rejected WHOLE (live taxonomy unchanged); live categories = %v", names)
	}

	// Control: a valid candidate still installs.
	applyConfigSnapshot(ConfigSnapshot{
		Version:       2,
		URLCategories: []CategoryEntry{{Name: "fine", Hosts: []string{"fine.example.com"}}},
	})
	names = listCategoryNames(t)
	if len(names) != 1 || names[0] != "fine" {
		t.Fatalf("valid snapshot candidate must install; live categories = %v", names)
	}
}

func TestBulkCap_ConfigImportRejectsOverCapCategory(t *testing.T) {
	for _, mode := range []string{"replace", "merge"} {
		t.Run(mode, func(t *testing.T) {
			csrTaxIsolate(t)
			csrTaxSeed()

			backup := &configBackup{
				Version:       1,
				URLCategories: []CategoryEntry{bulkCapOverCategory("flood")},
			}
			w := httptest.NewRecorder()
			apiConfigImport(w, jsonReq("POST", "/api/config/import?mode="+mode, backup))
			if w.Code != 400 {
				t.Fatalf("over-cap import must be refused with 400 (whole import, before any mutation); got %d: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "cannot contain more than") {
				t.Fatalf("refusal must name the cap; got: %s", w.Body.String())
			}
			names := listCategoryNames(t)
			if len(names) != 1 || names[0] != "tax-cat" {
				t.Fatalf("refused import must leave the live taxonomy unchanged; live categories = %v", names)
			}
		})
	}
}

func TestBulkCap_RollbackRefusesOverCapCategory(t *testing.T) {
	csrTaxIsolate(t)

	// Simulate a legacy capture: an over-cap category reached the live store
	// through a pre-correction bulk path, and a config version captured it.
	catStore.ReplaceAll([]CategoryEntry{bulkCapOverCategory("legacy-flood")})
	saveConfigVersion("bulk-cap-test", "seed-overcap")
	versions := configVersions.List()
	if len(versions) == 0 {
		t.Fatal("no config version captured")
	}
	target := versions[len(versions)-1].Version

	// The live store has since been repaired.
	catStore.ReplaceAll([]CategoryEntry{{Name: "clean", Hosts: []string{"clean.example.com"}}})

	w := httptest.NewRecorder()
	apiConfigVersions(w, jsonReq("POST", "/api/config/versions",
		map[string]any{"version": target}))
	if w.Code != 400 {
		t.Fatalf("rollback to a version carrying an over-cap category must be refused with 400 (nothing applied); got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "rollback refused") {
		t.Fatalf("refusal must be explicit; got: %s", w.Body.String())
	}
	names := listCategoryNames(t)
	if len(names) != 1 || names[0] != "clean" {
		t.Fatalf("refused rollback must leave the live taxonomy unchanged; live categories = %v", names)
	}
}
