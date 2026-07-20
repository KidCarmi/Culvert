package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAddBootstrapProvenance(t *testing.T) {
	orig := dataDir
	t.Cleanup(func() { dataDir = orig })
	dir := t.TempDir()
	dataDir = dir

	// Absent record → field omitted.
	out := map[string]any{}
	addBootstrapProvenance(out)
	if _, ok := out["bootstrap"]; ok {
		t.Fatal("no record should mean no bootstrap field")
	}

	// A valid record → surfaced with the expected fields.
	dec := bootstrapDecision{
		SchemaVersion:  bootstrapDecisionSchema,
		InstallChannel: "stable",
		CatalogChannel: "recommended",
		Repo:           "ghcr.io/kidcarmi/culvert",
		ImageRef:       "ghcr.io/kidcarmi/culvert@sha256:" + repeat64('a'),
		Digest:         "sha256:" + repeat64('a'),
		VersionID:      "2.0.0",
		CatalogVersion: 5,
	}
	b, _ := json.Marshal(dec)
	if err := os.WriteFile(filepath.Join(dir, bootstrapDecisionFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
	out = map[string]any{}
	addBootstrapProvenance(out)
	got, ok := out["bootstrap"].(bootstrapDecision)
	if !ok {
		t.Fatalf("bootstrap field missing/wrong type: %T", out["bootstrap"])
	}
	if got.Digest != dec.Digest || got.VersionID != "2.0.0" || got.CatalogVersion != 5 {
		t.Fatalf("unexpected surfaced decision: %+v", got)
	}

	// Malformed record → omitted (best-effort, never errors the handler).
	if err := os.WriteFile(filepath.Join(dir, bootstrapDecisionFile), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	out = map[string]any{}
	addBootstrapProvenance(out)
	if _, ok := out["bootstrap"]; ok {
		t.Fatal("malformed record must be omitted")
	}

	// A record missing the load-bearing image_ref → omitted.
	if err := os.WriteFile(filepath.Join(dir, bootstrapDecisionFile), []byte(`{"schema_version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out = map[string]any{}
	addBootstrapProvenance(out)
	if _, ok := out["bootstrap"]; ok {
		t.Fatal("a record with no image_ref must be omitted")
	}
}
