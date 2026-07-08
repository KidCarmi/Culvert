package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// defaultAuthOutcome is the single authoritative persisted global Stage-1
// default; legacy unauth_mode is a READ-ONLY one-way migration input (Slice 5 —
// never written). These tests pin migration, idempotency, fail-closed handling
// of invalid values, the downgrade-fails-closed behavior, and the decoupled
// AuthEnabled()/IsConfigured() predicates. Pure persistence — no runtime path is
// exercised. All tests use LOCAL *Config instances, so there is no global cfg
// state to leak.

// writeEnvelope writes a ui_users.json body and returns a fresh loaded Config.
func loadEnvelope(t *testing.T, body string) *Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ui_users.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write envelope: %v", err)
	}
	c := &Config{}
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile: %v", err)
	}
	return c
}

// ── 1. Legacy config load (unauth_mode only / bare array) ────────────────────

func TestDAO_LegacyLoad(t *testing.T) {
	cases := map[string]struct {
		body string
		want AuthOutcome
	}{
		"unauth_mode true":        {`{"unauth_mode":true,"users":[]}`, OutcomeExempt},
		"unauth_mode false":       {`{"unauth_mode":false,"users":[]}`, OutcomeDefault},
		"unauth_mode absent":      {`{"users":[]}`, OutcomeDefault},
		"bare array (no setting)": {`[]`, OutcomeDefault},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := loadEnvelope(t, tc.body)
			if c.defaultAuthOutcome != tc.want {
				t.Errorf("defaultAuthOutcome = %q, want %q", c.defaultAuthOutcome, tc.want)
			}
			if (c.DefaultAuthOutcome() == OutcomeExempt) != (tc.want == OutcomeExempt) {
				t.Errorf("UnauthMode() = %v, want %v", (c.DefaultAuthOutcome() == OutcomeExempt), tc.want == OutcomeExempt)
			}
		})
	}
}

// ── 2. New config load (default_auth_outcome authoritative) ──────────────────

func TestDAO_NewLoad(t *testing.T) {
	cases := map[string]struct {
		body string
		want AuthOutcome
	}{
		"Exempt":  {`{"default_auth_outcome":"Exempt","users":[]}`, OutcomeExempt},
		"Default": {`{"default_auth_outcome":"Default","users":[]}`, OutcomeDefault},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := loadEnvelope(t, tc.body)
			if c.defaultAuthOutcome != tc.want {
				t.Errorf("defaultAuthOutcome = %q, want %q", c.defaultAuthOutcome, tc.want)
			}
		})
	}
}

// ── 3. Mixed config (both fields present) ────────────────────────────────────

func TestDAO_MixedConfig_DefaultAuthOutcomeWins(t *testing.T) {
	// Agree.
	if c := loadEnvelope(t, `{"default_auth_outcome":"Exempt","unauth_mode":true,"users":[]}`); c.defaultAuthOutcome != OutcomeExempt {
		t.Errorf("agree(Exempt): got %q", c.defaultAuthOutcome)
	}
	// Disagree — default_auth_outcome is authoritative; the legacy mirror is ignored.
	if c := loadEnvelope(t, `{"default_auth_outcome":"Default","unauth_mode":true,"users":[]}`); c.defaultAuthOutcome != OutcomeDefault {
		t.Errorf("disagree: default_auth_outcome must win, got %q", c.defaultAuthOutcome)
	}
	if c := loadEnvelope(t, `{"default_auth_outcome":"Exempt","unauth_mode":false,"users":[]}`); c.defaultAuthOutcome != OutcomeExempt {
		t.Errorf("disagree: default_auth_outcome must win, got %q", c.defaultAuthOutcome)
	}
}

// ── 4. Save/load round-trip ──────────────────────────────────────────────────

func TestDAO_SaveLoadRoundTrip(t *testing.T) {
	for _, open := range []bool{true, false} {
		dir := t.TempDir()
		path := filepath.Join(dir, "ui_users.json")
		c := &Config{}
		c.SetUIUsersFile(path)
		c.SetDefaultAuthOutcome(outcomeFor(open)) // sets defaultAuthOutcome + persists

		c2 := &Config{}
		c2.SetUIUsersFile(path)
		if err := c2.LoadUIUsersFile(); err != nil {
			t.Fatalf("reload: %v", err)
		}
		if (c2.DefaultAuthOutcome() == OutcomeExempt) != open {
			t.Errorf("round-trip open=%v: UnauthMode()=%v", open, (c2.DefaultAuthOutcome() == OutcomeExempt))
		}
		wantOutcome := OutcomeDefault
		if open {
			wantOutcome = OutcomeExempt
		}
		if c2.defaultAuthOutcome != wantOutcome {
			t.Errorf("round-trip open=%v: outcome=%q want %q", open, c2.defaultAuthOutcome, wantOutcome)
		}
	}
}

// outcomeFor maps an "open" bool to the global default (test convenience after
// the SetUnauthMode shim was removed in Slice 5).
func outcomeFor(open bool) AuthOutcome {
	if open {
		return OutcomeExempt
	}
	return OutcomeDefault
}

// Slice 5: the authoritative field is the ONLY field written; the legacy
// unauth_mode mirror is NEVER written (read-only import compat only).
func TestDAO_SaveWritesOnlyAuthoritativeField(t *testing.T) {
	read := func(open bool) map[string]any {
		dir := t.TempDir()
		path := filepath.Join(dir, "ui_users.json")
		c := &Config{}
		c.SetUIUsersFile(path)
		c.SetDefaultAuthOutcome(outcomeFor(open))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return m
	}
	for _, open := range []bool{true, false} {
		m := read(open)
		if m["default_auth_outcome"] != string(outcomeFor(open)) {
			t.Errorf("open=%v: default_auth_outcome = %v, want %v", open, m["default_auth_outcome"], outcomeFor(open))
		}
		if _, present := m["unauth_mode"]; present {
			t.Errorf("open=%v: unauth_mode mirror must NEVER be written (Slice 5), got present", open)
		}
	}
}

// ── 5. Import/export surface is NOT expanded ─────────────────────────────────

func TestDAO_ImportExportSurfaceUnchanged(t *testing.T) {
	// The auth posture lives only in the ui_users.json envelope. Slice 2 must
	// not add it to the export/import (configBackup) surface.
	data, err := json.Marshal(configBackup{})
	if err != nil {
		t.Fatalf("marshal configBackup: %v", err)
	}
	s := string(data)
	for _, forbidden := range []string{"default_auth_outcome", "unauth_mode", "defaultAuthOutcome", "DefaultAuthOutcome"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("configBackup must not carry %q (export/import surface must stay unchanged in Slice 2): %s", forbidden, s)
		}
	}
}

// ── 6. Migration idempotency ─────────────────────────────────────────────────

func TestDAO_MigrationIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ui_users.json")
	// Start from a legacy file (unauth_mode only).
	if err := os.WriteFile(path, []byte(`{"unauth_mode":true,"users":[]}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// load → save (first migration).
	c1 := &Config{}
	c1.SetUIUsersFile(path)
	if err := c1.LoadUIUsersFile(); err != nil {
		t.Fatalf("load1: %v", err)
	}
	if err := c1.SaveUIUsersFile(); err != nil {
		t.Fatalf("save1: %v", err)
	}
	bytes1, _ := os.ReadFile(path)

	// load → save again (must be a fixed point: identical bytes + value).
	c2 := &Config{}
	c2.SetUIUsersFile(path)
	if err := c2.LoadUIUsersFile(); err != nil {
		t.Fatalf("load2: %v", err)
	}
	if c2.defaultAuthOutcome != OutcomeExempt {
		t.Errorf("idempotency: value drifted to %q", c2.defaultAuthOutcome)
	}
	if err := c2.SaveUIUsersFile(); err != nil {
		t.Fatalf("save2: %v", err)
	}
	bytes2, _ := os.ReadFile(path)
	if string(bytes1) != string(bytes2) {
		t.Errorf("idempotency: bytes changed across save cycles:\n1: %s\n2: %s", bytes1, bytes2)
	}
}

// ── 7. Invalid / ambiguous values fail closed to Default ─────────────────────

func TestDAO_InvalidValuesFailClosed(t *testing.T) {
	bad := []string{"garbage", "open", " exempt ", "EXEMPT", "CredentialRequired", "SSORequired", "true", "1"}
	for _, v := range bad {
		t.Run(v, func(t *testing.T) {
			b, _ := json.Marshal(map[string]any{"default_auth_outcome": v, "users": []any{}})
			c := loadEnvelope(t, string(b))
			if c.defaultAuthOutcome != OutcomeDefault {
				t.Errorf("invalid %q must fail closed to Default, got %q", v, c.defaultAuthOutcome)
			}
		})
	}
	// Direct helper coverage: canonical values are accepted; padding is trimmed.
	if o, ok := normalizeDefaultAuthOutcome("  Exempt  "); o != OutcomeExempt || !ok {
		t.Errorf("padded canonical Exempt = (%q,%v), want (Exempt,true)", o, ok)
	}
	if o, ok := normalizeDefaultAuthOutcome(""); o != OutcomeDefault || ok {
		t.Errorf("empty = (%q,%v), want (Default,false)", o, ok)
	}
}

// ── Helper: resolveLoadedDefaultAuthOutcome branch coverage ──────────────────

func TestDAO_ResolveLoadedDefaultAuthOutcome(t *testing.T) {
	sp := func(s string) *string { return &s }
	cases := []struct {
		name string
		env  uiUsersFileEnvelope
		want AuthOutcome
	}{
		{"authoritative Exempt", uiUsersFileEnvelope{DefaultAuthOutcome: sp("Exempt")}, OutcomeExempt},
		{"authoritative Default", uiUsersFileEnvelope{DefaultAuthOutcome: sp("Default")}, OutcomeDefault},
		{"authoritative wins over mirror", uiUsersFileEnvelope{DefaultAuthOutcome: sp("Default"), UnauthMode: true}, OutcomeDefault},
		{"invalid fails closed", uiUsersFileEnvelope{DefaultAuthOutcome: sp("garbage"), UnauthMode: true}, OutcomeDefault},
		{"present-but-empty fails closed (not legacy fallthrough)", uiUsersFileEnvelope{DefaultAuthOutcome: sp(""), UnauthMode: true}, OutcomeDefault},
		{"absent key migrates from mirror (true)", uiUsersFileEnvelope{UnauthMode: true}, OutcomeExempt},
		{"absent key migrates from mirror (false)", uiUsersFileEnvelope{}, OutcomeDefault},
	}
	for _, tc := range cases {
		if got := resolveLoadedDefaultAuthOutcome(tc.env); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Present-but-empty default_auth_outcome must fail closed even when the legacy
// mirror is true — it must NOT reopen the proxy (Codex P2 / fail-closed contract).
func TestDAO_PresentButEmptyFailsClosed(t *testing.T) {
	c := loadEnvelope(t, `{"default_auth_outcome":"","unauth_mode":true,"users":[]}`)
	if c.defaultAuthOutcome != OutcomeDefault {
		t.Errorf("present-but-empty default_auth_outcome must fail closed to Default, got %q", c.defaultAuthOutcome)
	}
	if c.DefaultAuthOutcome() == OutcomeExempt {
		t.Error("present-but-empty must not reopen the proxy")
	}
}

// ── 8. Concurrent load / read / set is race-free (run with -race) ────────────

func TestDAO_ConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ui_users.json")
	if err := os.WriteFile(path, []byte(`{"default_auth_outcome":"Exempt","users":[]}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	c := &Config{}
	c.SetUIUsersFile(path)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				switch (n + j) % 4 {
				case 0:
					_ = c.LoadUIUsersFile()
				case 1:
					_ = (c.DefaultAuthOutcome() == OutcomeExempt)
				case 2:
					_ = c.AuthEnabled()
				case 3:
					c.SetDefaultAuthOutcome(outcomeFor(j%2 == 0))
				}
			}
		}(i)
	}
	wg.Wait()
}

// ── 9. Downgrade fails closed (Slice 5: no mirror written) ───────────────────

// Slice 5 stopped writing the legacy unauth_mode mirror. A pre-Slice-2 binary
// that only reads unauth_mode therefore sees it ABSENT (false) regardless of the
// open posture — i.e. a downgrade fails closed to Default (auth required). This
// is intentional: unauth_mode is a read-only forward-migration input, never a
// backward-compat write.
func TestDAO_DowngradeFailsClosed_NoMirror(t *testing.T) {
	type oldEnvelope struct {
		UnauthMode bool              `json:"unauth_mode"`
		Users      []json.RawMessage `json:"users"`
	}
	for _, open := range []bool{true, false} {
		dir := t.TempDir()
		path := filepath.Join(dir, "ui_users.json")
		c := &Config{}
		c.SetUIUsersFile(path)
		c.SetDefaultAuthOutcome(outcomeFor(open))

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var old oldEnvelope
		if err := json.Unmarshal(data, &old); err != nil {
			t.Fatalf("old-binary unmarshal must not error: %v", err)
		}
		if old.UnauthMode {
			t.Errorf("open=%v: a downgraded binary must read unauth_mode=false (mirror not written), got true", open)
		}
	}
}

// ── Slice 5: AuthEnabled() is decoupled from defaultAuthOutcome; IsConfigured() ─

func TestS5_AuthEnabledDecoupled_IsConfigured(t *testing.T) {
	// AuthEnabled() is credential-only: no user/provider ⇒ false regardless of
	// the global default (Exempt no longer makes it true — the SOCKS5 inversion
	// fix flows from this).
	c := &Config{}
	for _, o := range []AuthOutcome{OutcomeDefault, OutcomeExempt} {
		c.defaultAuthOutcome = o
		if c.AuthEnabled() {
			t.Errorf("no user/provider + %s ⇒ AuthEnabled() must be false", o)
		}
	}
	// A credential backend ⇒ AuthEnabled() true.
	if cu := (&Config{user: "admin"}); !cu.AuthEnabled() {
		t.Error("configured user ⇒ AuthEnabled() true")
	}

	// IsConfigured(): no backend + Default ⇒ false; no backend + Exempt ⇒ true
	// (open mode counts as configured); credential backend ⇒ true.
	c.defaultAuthOutcome = OutcomeDefault
	if c.IsConfigured() {
		t.Error("no backend + Default ⇒ IsConfigured() false")
	}
	c.defaultAuthOutcome = OutcomeExempt
	if !c.IsConfigured() {
		t.Error("no backend + Exempt ⇒ IsConfigured() true (open mode is configured)")
	}
	if cu := (&Config{user: "admin"}); !cu.IsConfigured() {
		t.Error("configured user ⇒ IsConfigured() true")
	}

	// SetDefaultAuthOutcome round-trips.
	c4 := &Config{}
	c4.SetDefaultAuthOutcome(OutcomeExempt)
	if c4.DefaultAuthOutcome() != OutcomeExempt {
		t.Errorf("SetDefaultAuthOutcome(Exempt): got %q", c4.DefaultAuthOutcome())
	}
	c4.SetDefaultAuthOutcome(OutcomeDefault)
	if c4.DefaultAuthOutcome() != OutcomeDefault {
		t.Errorf("SetDefaultAuthOutcome(Default): got %q", c4.DefaultAuthOutcome())
	}
}
