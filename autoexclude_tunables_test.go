package main

// autoexclude_tunables_test.go — F10 PR2: the resolver/validator and the durable
// persistence contract for the adaptive decryption-exclusion tunables. The feature
// stays DARK in PR2 — nothing reachable through normal administration writes these
// keys yet; only the settings LOAD path (sentinel-gated) applies them, and only a
// hand-edited file could reach it. These tests pin that path plus the bounds.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
)

// customTunables is a valid non-default set used across the persistence tests.
var customTunables = autoExcludeTunables{
	ConfirmN:      4,
	TTLSecs:       6 * 3600,
	PinnedTTLSecs: 30 * 60,
	WindowSecs:    5 * 60,
	MaxEntries:    1000,
}

// ── Resolver ──────────────────────────────────────────────────────────────

func TestResolveAutoExcludeTunables_ZeroMeansDefault(t *testing.T) {
	d := defaultAutoExcludeTunables()
	if got := resolveAutoExcludeTunables(autoExcludeTunables{}); got != d {
		t.Fatalf("all-zero resolved to %+v, want defaults %+v", got, d)
	}
	// Partial: only ConfirmN set ⇒ the rest fill from defaults.
	got := resolveAutoExcludeTunables(autoExcludeTunables{ConfirmN: 5})
	if got.ConfirmN != 5 || got.TTLSecs != d.TTLSecs || got.MaxEntries != d.MaxEntries {
		t.Fatalf("partial resolve %+v did not default the unset fields (defaults %+v)", got, d)
	}
}

// TestResolveAutoExcludeTunables_NegativeNotDefaulted — only a LITERAL zero resets
// to default; a negative is preserved so the validator rejects it (fail-closed),
// rather than being silently treated as omitted.
func TestResolveAutoExcludeTunables_NegativeNotDefaulted(t *testing.T) {
	got := resolveAutoExcludeTunables(autoExcludeTunables{TTLSecs: -1})
	if got.TTLSecs != -1 {
		t.Fatalf("negative must be preserved (not defaulted), got %d", got.TTLSecs)
	}
	if err := validateAutoExcludeTunables(got); err == nil {
		t.Fatal("a resolved set carrying a negative must FAIL validation (fail-closed)")
	}
}

// ── Validator (bounds contract) ──────────────────────────────────────────

func TestValidateAutoExcludeTunables(t *testing.T) {
	d := defaultAutoExcludeTunables()
	if err := validateAutoExcludeTunables(d); err != nil {
		t.Fatalf("defaults must validate, got %v", err)
	}
	if err := validateAutoExcludeTunables(resolveAutoExcludeTunables(customTunables)); err != nil {
		t.Fatalf("custom set must validate, got %v", err)
	}

	bad := []struct {
		name string
		in   autoExcludeTunables
	}{
		{"confirmN=1 defeats anti-poison", mut(d, func(x *autoExcludeTunables) { x.ConfirmN = 1 })},
		{"confirmN over max", mut(d, func(x *autoExcludeTunables) { x.ConfirmN = 11 })},
		{"ttl below min", mut(d, func(x *autoExcludeTunables) { x.TTLSecs = 59 })},
		{"ttl over max", mut(d, func(x *autoExcludeTunables) { x.TTLSecs = 169 * 3600 })},
		{"pinned below min", mut(d, func(x *autoExcludeTunables) { x.PinnedTTLSecs = 59 })},
		{"pinned exceeds ttl", mut(d, func(x *autoExcludeTunables) { x.PinnedTTLSecs = x.TTLSecs + 1 })},
		{"window below min", mut(d, func(x *autoExcludeTunables) { x.WindowSecs = 9 })},
		{"window over max", mut(d, func(x *autoExcludeTunables) { x.WindowSecs = 24*3600 + 1 })},
		{"maxEntries below min", mut(d, func(x *autoExcludeTunables) { x.MaxEntries = 255 })},
		{"maxEntries over ceiling 262144", mut(d, func(x *autoExcludeTunables) { x.MaxEntries = 262145 })},
	}
	for _, b := range bad {
		if err := validateAutoExcludeTunables(b.in); err == nil {
			t.Errorf("%s: expected a validation error, got nil (%+v)", b.name, b.in)
		}
	}
}

func mut(base autoExcludeTunables, f func(*autoExcludeTunables)) autoExcludeTunables {
	f(&base)
	return base
}

// ── Persistence round-trip ───────────────────────────────────────────────

// TestAutoExcludeTunables_PersistenceRoundTrip — Save writes the live values +
// sentinel; a simulated restart (fresh default cache) + Load restores them.
func TestAutoExcludeTunables_PersistenceRoundTrip(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{})
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)

	autoExclude().Reconfigure(customTunables.engineConfig())
	SaveAdminSettings()

	// The file carries the sentinel and the seconds-encoded values.
	var s AdminSettings
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("settings file not written: %v", err)
	}
	if json.Unmarshal(data, &s) != nil || !s.AutoExcludeTunablesSaved ||
		s.AutoExcludeConfirmN != 4 || s.AutoExcludeTTLSecs != 6*3600 || s.AutoExcludeMaxEntries != 1000 {
		t.Fatalf("persisted tunables wrong: saved=%v %+v", s.AutoExcludeTunablesSaved, s)
	}

	// Simulate a restart: fresh cache at defaults, then Load applies the persisted set.
	setAutoExclude(autoexclude.New(autoexclude.Config{}))
	if got := currentAutoExcludeTunables(); got != defaultAutoExcludeTunables() {
		t.Fatalf("pre-load cache should be at defaults, got %+v", got)
	}
	LoadAdminSettings(path)
	if got := currentAutoExcludeTunables(); got != customTunables {
		t.Fatalf("post-load tunables = %+v, want %+v", got, customTunables)
	}
}

// TestAutoExcludeTunables_FeatureOffByteIdentical — a settings file WITHOUT the
// tunable fields (sentinel false, i.e. any pre-feature file) leaves the engine
// defaults untouched. This is ADR-0010 invariant 1.
func TestAutoExcludeTunables_FeatureOffByteIdentical(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{})
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)

	// A pre-feature settings file: no autoexclude_* keys at all.
	if err := os.WriteFile(path, []byte(`{"log_level":"info"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	LoadAdminSettings(path)
	if got := currentAutoExcludeTunables(); got != defaultAutoExcludeTunables() {
		t.Fatalf("pre-feature file changed the tunables: %+v, want defaults", got)
	}
}

// TestAutoExcludeTunables_WritingZerosResetsToDefault — sentinel set but all tunable
// fields zero ⇒ each resolves to its default and is applied (the "reset" path).
func TestAutoExcludeTunables_WritingZerosResetsToDefault(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 7, MaxEntries: 999}) // non-default start
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)

	if err := os.WriteFile(path, []byte(`{"autoexclude_tunables_saved":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	LoadAdminSettings(path)
	if got := currentAutoExcludeTunables(); got != defaultAutoExcludeTunables() {
		t.Fatalf("zeros did not reset to defaults: %+v", got)
	}
}

// TestAutoExcludeTunables_InvalidPersistedIgnored — a hand-edited file with an
// out-of-bounds value (confirmN=1) is refused; the engine keeps its defaults
// (fail-closed) rather than applying a value the outer bounds forbid.
func TestAutoExcludeTunables_InvalidPersistedIgnored(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{})
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)

	// Two malformed files: an out-of-bounds positive (confirmN=1) and a NEGATIVE
	// (ttl=-1). Both must be refused wholesale, leaving engine defaults.
	for _, body := range []string{
		`{"autoexclude_tunables_saved":true,"autoexclude_confirm_n":1,"autoexclude_max_entries":500}`,
		`{"autoexclude_tunables_saved":true,"autoexclude_ttl_secs":-1,"autoexclude_confirm_n":4}`,
	} {
		setAutoExclude(autoexclude.New(autoexclude.Config{})) // reset to defaults per case
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		LoadAdminSettings(path)
		if got := currentAutoExcludeTunables(); got != defaultAutoExcludeTunables() {
			t.Fatalf("invalid persisted tunables were applied (%s): %+v, want defaults (fail-closed)", body, got)
		}
	}
}

// TestAutoExcludeTunables_OffExportAndRollback — the registry rows must keep the
// tunables OFF export, import, version-rollback, and CP→DP sync (node-local
// operational tuning). This asserts the config-surface contract directly.
func TestAutoExcludeTunables_OffExportAndRollback(t *testing.T) {
	want := map[string]bool{
		"autoexclude_confirm_n": true, "autoexclude_ttl_secs": true, "autoexclude_pinned_ttl_secs": true,
		"autoexclude_window_secs": true, "autoexclude_max_entries": true, "autoexclude_tunables_saved": true,
	}
	seen := map[string]bool{}
	for _, row := range configSurfaces {
		if !want[row.ID] {
			continue
		}
		seen[row.ID] = true
		if row.Export || row.Import || row.Rollback || row.Diffed || row.ClusterSynced || row.Sensitive {
			t.Errorf("%s must be AdminDurable-only (off export/import/rollback/diff/cluster/sensitive), got %+v", row.ID, row)
		}
		if !row.AdminDurable {
			t.Errorf("%s must be AdminDurable", row.ID)
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("registry row %q missing", id)
		}
	}
}

// TestAutoExcludeTunables_EngineConfigUnits — seconds → durations mapping is exact.
func TestAutoExcludeTunables_EngineConfigUnits(t *testing.T) {
	cfg := customTunables.engineConfig()
	if cfg.ConfirmN != 4 || cfg.TTL != 6*time.Hour || cfg.PinnedTTL != 30*time.Minute ||
		cfg.Window != 5*time.Minute || cfg.MaxEntries != 1000 {
		t.Fatalf("engineConfig units wrong: %+v", cfg)
	}
}
