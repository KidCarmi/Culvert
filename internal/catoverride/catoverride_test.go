package catoverride

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// A fresh store initializes to an empty, valid override set.
func TestNew_DefaultIsEmpty(t *testing.T) {
	s := New()
	got := s.Get()
	if len(got.Added) != 0 || len(got.Recategorized) != 0 || len(got.Tombstones) != 0 {
		t.Fatalf("new store should be empty; got %+v", got)
	}
	if s.Path() != "" {
		t.Errorf("new store path should be empty; got %q", s.Path())
	}
}

// A valid override set round-trips through Save/Load unchanged (semantically).
func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.json")
	s := New()
	s.SetPathForTest(path)
	in := Overrides{
		Added:         map[string]string{"example.com": "AI"},
		Recategorized: map[string]string{"slack.com": "Messaging"},
		Tombstones:    []string{"tracker.example"},
	}
	if err := s.ReplaceAll(in); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	s2 := New()
	if err := s2.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(s.Get(), s2.Get()) {
		t.Errorf("round-trip mismatch:\n saved=%+v\n loaded=%+v", s.Get(), s2.Get())
	}
	// The persisted file carries the schema marker.
	b, _ := os.ReadFile(path)
	if !bytes.Contains(b, []byte(`"schema_version": 1`)) {
		t.Errorf("persisted envelope missing schema_version marker: %s", b)
	}
}

// A missing file is the normal first-run state (empty, no error).
func TestLoad_MissingFileIsEmpty(t *testing.T) {
	s := New()
	if err := s.Load(filepath.Join(t.TempDir(), "nope.json")); err != nil {
		t.Fatalf("missing file should not error; got %v", err)
	}
	if len(s.Get().Added) != 0 {
		t.Errorf("missing file should yield empty overrides")
	}
}

// ReplaceAll([]) clears every override (the store-level deletion-propagation
// counterpart to the later CP→DP wire wipe).
func TestReplaceAll_EmptyClears(t *testing.T) {
	s := New()
	if err := s.ReplaceAll(Overrides{Added: map[string]string{"a.example.com": "AI"}}); err != nil {
		t.Fatal(err)
	}
	if len(s.Get().Added) != 1 {
		t.Fatalf("precondition: expected 1 added")
	}
	if err := s.ReplaceAll(Overrides{}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	got := s.Get()
	if len(got.Added) != 0 || len(got.Recategorized) != 0 || len(got.Tombstones) != 0 {
		t.Errorf("ReplaceAll(empty) must clear; got %+v", got)
	}
}

// A file carrying an unknown JSON field is rejected (strict decode).
func TestLoad_UnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"overrides":{},"rogue":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := New().Load(path)
	if !errors.Is(err, ErrUnknownField) {
		t.Fatalf("expected ErrUnknownField; got %v", err)
	}
}

// A file whose schema is newer than this binary fails closed (downgrade guard).
func TestLoad_SchemaTooNewFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":2,"overrides":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New()
	err := s.Load(path)
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("expected ErrSchemaTooNew; got %v", err)
	}
	// Fail-closed: the store is not populated from an unsupported file.
	if len(s.Get().Added) != 0 {
		t.Errorf("schema-too-new must not populate the store")
	}
}

// A file whose overrides are invalid (e.g. a bare public suffix host) is rejected
// on load and leaves the store empty (all-or-nothing).
func TestLoad_InvalidOverridesRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"overrides":{"added":{"com":"AI"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := New().Load(path); err == nil {
		t.Fatalf("expected invalid-override rejection for a bare public suffix host")
	}
}

// ComposeView is pure: it does not mutate the feed, and equal inputs give equal
// outputs across repeated calls.
func TestComposeView_PureAndDeterministic(t *testing.T) {
	feed := map[string]string{
		"anthropic.com":       "AI",
		"slack.com":           "Collab",
		"ads.tracker.example": "Ads",
		"tracker.example":     "Ads",
	}
	feedCopy := map[string]string{}
	for k, v := range feed {
		feedCopy[k] = v
	}
	o := Overrides{
		Added:         map[string]string{"openai.com": "AI"},
		Recategorized: map[string]string{"slack.com": "Messaging"},
		Tombstones:    []string{"tracker.example"}, // suppresses tracker.example AND ads.tracker.example
	}
	v1 := ComposeView(feed, o)
	v2 := ComposeView(feed, o)
	if !reflect.DeepEqual(v1, v2) {
		t.Errorf("ComposeView not deterministic:\n v1=%+v\n v2=%+v", v1, v2)
	}
	if !reflect.DeepEqual(feed, feedCopy) {
		t.Errorf("ComposeView mutated the feed snapshot")
	}
	// Expected effective view.
	want := map[string]string{
		"anthropic.com": "AI",
		"slack.com":     "Messaging", // recategorized
		"openai.com":    "AI",        // added
		// tracker.example and ads.tracker.example suppressed by the tombstone
	}
	if !reflect.DeepEqual(v1, want) {
		t.Errorf("composed view mismatch:\n got=%+v\n want=%+v", v1, want)
	}
}

// Normalize accepts a clean set and canonicalizes hosts/categories.
func TestNormalize_ValidCanonicalizes(t *testing.T) {
	got, err := Normalize(Overrides{
		Added:      map[string]string{"  Example.COM. ": " AI "},
		Tombstones: []string{"Tracker.Example"},
	})
	if err != nil {
		t.Fatalf("valid set should normalize: %v", err)
	}
	if got.Added["example.com"] != "AI" {
		t.Errorf("host/category not canonicalized: %+v", got.Added)
	}
	if len(got.Tombstones) != 1 || got.Tombstones[0] != "tracker.example" {
		t.Errorf("tombstone not canonicalized: %+v", got.Tombstones)
	}
}

// Every override rejection class fails Normalize/Validate.
func TestNormalize_RejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		o    Overrides
		want error
	}{
		{"wildcard host", Overrides{Added: map[string]string{"*.example.com": "AI"}}, ErrInvalidHost},
		{"ip literal host", Overrides{Added: map[string]string{"10.0.0.1": "AI"}}, ErrInvalidHost},
		{"public suffix host", Overrides{Added: map[string]string{"co.uk": "AI"}}, ErrInvalidHost},
		{"path-bearing host", Overrides{Added: map[string]string{"example.com/x": "AI"}}, ErrInvalidHost},
		{"port host", Overrides{Added: map[string]string{"example.com:8443": "AI"}}, ErrInvalidHost},
		{"empty-label host", Overrides{Added: map[string]string{"a..b.com": "AI"}}, ErrInvalidHost},
		{"bad category", Overrides{Added: map[string]string{"example.com": "a\tb"}}, ErrInvalidCategory},
		{"dup added+recat", Overrides{
			Added:         map[string]string{"x.example.com": "AI"},
			Recategorized: map[string]string{"x.example.com": "Dev"},
		}, ErrDuplicateHost},
		{"tombstone clash", Overrides{
			Added:      map[string]string{"x.example.com": "AI"},
			Tombstones: []string{"x.example.com"},
		}, ErrTombstoneClash},
		{"category case collision", Overrides{
			Added:         map[string]string{"a.example.com": "AI"},
			Recategorized: map[string]string{"b.example.com": "ai"},
		}, ErrCategoryCase},
		{"ancestor/descendant cross-category", Overrides{
			Added:         map[string]string{"example.com": "AI"},
			Recategorized: map[string]string{"sub.example.com": "Dev"},
		}, ErrSuffixConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Normalize(tc.o)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v; got %v", tc.want, err)
			}
		})
	}
}

// Same host + same category across added is deduplicated, not rejected.
func TestNormalize_SameHostSameCategoryOK(t *testing.T) {
	if _, err := Normalize(Overrides{
		Added:         map[string]string{"example.com": "AI"},
		Recategorized: map[string]string{},
		Tombstones:    []string{"tracker.example", "Tracker.Example"}, // dup tombstone dedup'd
	}); err != nil {
		t.Fatalf("dup tombstone should dedup, not error: %v", err)
	}
}

// Duplicate tombstones collapse to one entry after normalization.
func TestNormalize_TombstoneDedup(t *testing.T) {
	got, err := Normalize(Overrides{Tombstones: []string{"a.example.com", "a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tombstones) != 1 {
		t.Errorf("expected 1 deduped tombstone; got %+v", got.Tombstones)
	}
}
