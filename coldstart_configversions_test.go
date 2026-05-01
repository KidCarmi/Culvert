package main

// D1.2b cold-start tests for /data/config_versions/v{N}.json.
//
// Pins behavior of loadConfigVersion (single-file load) and
// listConfigVersions (directory walk for the admin API). Two list-
// endpoint cases per the D1.2b scope decision; the rest cover the
// loader.
//
// One D1.2-flag finding pinned by these tests:
//
//   listConfigVersions silently skips files it cannot read or parse
//   (configversion.go:185-194). Corrupted snapshots disappear from
//   the operator-facing list with no error and no log line. An
//   operator trying to recover via the rollback API sees no
//   indication that vN exists but is unusable.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// withTempConfigVersionsDir redirects configVersionsDir to the given
// dir for the duration of the test, restoring the original value via
// t.Cleanup. Returns the dir for convenience.
func withTempConfigVersionsDir(t *testing.T, dir string) {
	t.Helper()
	orig := configVersionsDir
	configVersionsDir = dir
	t.Cleanup(func() { configVersionsDir = orig })
}

func writeVersionFile(t *testing.T, dir string, ver int, body string) {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("v%d.json", ver))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write v%d.json: %v", ver, err)
	}
}

func TestColdStart_ConfigVersions_MissingDir(t *testing.T) {
	withTempConfigVersionsDir(t, filepath.Join(t.TempDir(), "nonexistent"))
	if _, err := loadConfigVersion(1); err == nil {
		t.Fatal("expected error when dir does not exist")
	}
}

func TestColdStart_ConfigVersions_VersionFileMissing(t *testing.T) {
	withTempConfigVersionsDir(t, t.TempDir())
	if _, err := loadConfigVersion(1); err == nil {
		t.Fatal("expected error when v1.json does not exist")
	}
}

func TestColdStart_ConfigVersions_Load(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
		verify  func(t *testing.T, cb *configBackup)
	}{
		{
			name:    "empty_file",
			body:    "",
			wantErr: true,
		},
		{
			name:    "garbage_json",
			body:    "not json at all",
			wantErr: true,
		},
		{
			name:    "empty_object",
			body:    "{}",
			wantErr: false,
			verify: func(t *testing.T, cb *configBackup) {
				if cb == nil {
					t.Fatal("expected non-nil configBackup for `{}`")
				}
				// Zero-value configBackup is fine — no fields set.
			},
		},
		{
			name:    "envelope_missing_config_field",
			body:    `{"meta":{"version":7,"actor":"test"}}`,
			wantErr: false,
			verify: func(t *testing.T, cb *configBackup) {
				if cb == nil {
					t.Fatal("expected non-nil configBackup")
				}
				if cb.DefaultAction != "" {
					t.Errorf("DefaultAction = %q, want zero value", cb.DefaultAction)
				}
			},
		},
		{
			name:    "valid_envelope",
			body:    `{"meta":{"version":7,"actor":"test"},"config":{"defaultAction":"deny","blocklistMode":"block"}}`,
			wantErr: false,
			verify: func(t *testing.T, cb *configBackup) {
				if cb == nil {
					t.Fatal("expected non-nil configBackup")
				}
				if cb.DefaultAction != "deny" {
					t.Errorf("DefaultAction = %q, want deny", cb.DefaultAction)
				}
				if cb.BlocklistMode != "block" {
					t.Errorf("BlocklistMode = %q, want block", cb.BlocklistMode)
				}
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			withTempConfigVersionsDir(t, dir)
			writeVersionFile(t, dir, 7, tc.body)

			cb, err := loadConfigVersion(7)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %s, got nil", tc.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.verify != nil {
				tc.verify(t, cb)
			}
		})
	}
}

func TestColdStart_ConfigVersions_List_MissingDir(t *testing.T) {
	withTempConfigVersionsDir(t, filepath.Join(t.TempDir(), "nonexistent"))

	w := httptest.NewRecorder()
	listConfigVersions(w)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (handler returns empty list on missing dir)", w.Code)
	}
	var versions []ConfigVersion
	if err := json.NewDecoder(w.Body).Decode(&versions); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(versions) != 0 {
		t.Errorf("expected empty array on missing dir, got %d versions", len(versions))
	}
}

// TestColdStart_ConfigVersions_List_CorruptedFileSilentlySkipped pins the
// D1.2-flag behavior described at the top of this file: a vN.json that
// fails to parse is silently dropped from the list.
func TestColdStart_ConfigVersions_List_CorruptedFileSilentlySkipped(t *testing.T) {
	dir := t.TempDir()
	withTempConfigVersionsDir(t, dir)
	writeVersionFile(t, dir, 1, "this is not json")

	w := httptest.NewRecorder()
	listConfigVersions(w)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var versions []ConfigVersion
	if err := json.NewDecoder(w.Body).Decode(&versions); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// D1.2-flag: corrupted snapshot is silently skipped — no entry, no
	// error to the operator. Pinned for visibility.
	if len(versions) != 0 {
		t.Errorf("expected list to silently skip corrupted file, got %d entries", len(versions))
	}
}
