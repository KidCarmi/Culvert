package main

// D1.2b cold-start tests for the blocklist sidecar files (.mode,
// .manual, .exceptions). Reads run through Blocklist.Load.
//
// Two D1.2-flag findings pinned by these tests:
//
// Flag 1 — .mode silent fallback to "block" on any non-"allow" value
//   The loader at store.go:577-579 only recognizes the literal string
//   "allow" (after TrimSpace). Anything else — "block", "BLOCK",
//   "deny", "ALLOW", garbage, empty — silently leaves the mode at
//   default ("block"). Because the default IS "block" this is not a
//   security regression, but operators have no signal that their
//   intended config did not take effect.
//
// Flag 2 — .manual / .exceptions accept any line content as a
//   "hostname". Loader at store.go:583-590 / 593-600 trims whitespace
//   per line, skips blanks, and adds whatever's left. There is no
//   hostname validation. A line like "obviously not a host" becomes a
//   literal entry that will never match real traffic and will never be
//   reported as invalid.

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// freshBLForLoad returns a Blocklist with the maps Load needs to be
// able to assign into. Load itself initializes manual/exceptions but
// requires exact/wildcards (touched by other code paths) to be ready.
func freshBLForLoad() *Blocklist {
	return &Blocklist{exact: map[string]bool{}, wildcards: map[string]bool{}}
}

func writeOptional(t *testing.T, path string, body []byte) {
	t.Helper()
	if body == nil {
		return
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func sidecarKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestColdStart_BlocklistSidecars(t *testing.T) {
	cases := []struct {
		name       string
		mode       []byte // nil = do not write .mode
		manual     []byte // nil = do not write .manual
		exceptions []byte // nil = do not write .exceptions
		wantMode   string
		wantManual []string // sorted, nil-or-empty == empty
		wantExcept []string // sorted
	}{
		// ── .mode behavior ──────────────────────────────────────────
		{
			name:     "all_sidecars_absent_default_mode",
			wantMode: "block",
		},
		{
			name:     "mode_allow",
			mode:     []byte("allow"),
			wantMode: "allow",
		},
		{
			// D1.2-flag 1: literal "block" leaves mode at default. The
			// loader does not recognize "block" as a valid value — it
			// is the implicit default when nothing matches "allow".
			name:     "mode_literal_block_silent_default",
			mode:     []byte("block"),
			wantMode: "block",
		},
		{
			// D1.2-flag 1: garbage content silently keeps default.
			name:     "mode_garbage_silent_default",
			mode:     []byte("wat"),
			wantMode: "block",
		},
		{
			// D1.2-flag 1: case-sensitive — "ALLOW" does not match.
			name:     "mode_uppercase_silent_default",
			mode:     []byte("ALLOW"),
			wantMode: "block",
		},
		{
			name:     "mode_with_surrounding_whitespace",
			mode:     []byte("  allow\n"),
			wantMode: "allow",
		},
		{
			name:     "mode_empty_file",
			mode:     []byte{},
			wantMode: "block",
		},

		// ── .manual behavior ────────────────────────────────────────
		// (wantMode == "block" in all cases below — no .mode file written)
		{
			name:     "manual_absent",
			wantMode: "block",
		},
		{
			name:     "manual_empty_file",
			manual:   []byte{},
			wantMode: "block",
		},
		{
			name:     "manual_blank_lines_only",
			manual:   []byte("\n\n   \n\n"),
			wantMode: "block",
		},
		{
			name:       "manual_one_valid_host",
			manual:     []byte("evil.example.com\n"),
			wantMode:   "block",
			wantManual: []string{"evil.example.com"},
		},
		{
			// D1.2-flag 2: no hostname validation. Inner whitespace is
			// preserved (only outer whitespace is trimmed).
			name:       "manual_garbage_lines_accepted",
			manual:     []byte("  not a hostname  \n   foo bar baz  \n\n"),
			wantMode:   "block",
			wantManual: []string{"foo bar baz", "not a hostname"},
		},

		// ── .exceptions behavior ────────────────────────────────────
		{
			name:     "exceptions_absent",
			wantMode: "block",
		},
		{
			name:       "exceptions_empty_file",
			exceptions: []byte{},
			wantMode:   "block",
		},
		{
			name:       "exceptions_lowercased_on_load",
			exceptions: []byte("EVIL.COM\nGood.Net\n"),
			wantMode:   "block",
			wantExcept: []string{"evil.com", "good.net"},
		},
		{
			// D1.2-flag 2: same lack of validation as .manual. Combined
			// with lowercasing, an entry of "  STRANGE INPUT  " becomes
			// "strange input".
			name:       "exceptions_garbage_lowercased",
			exceptions: []byte("  STRANGE INPUT  \n"),
			wantMode:   "block",
			wantExcept: []string{"strange input"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			primary := filepath.Join(dir, "blocklist.txt")

			// Primary file must exist for Load to return without error.
			if err := os.WriteFile(primary, []byte{}, 0o600); err != nil {
				t.Fatalf("write primary: %v", err)
			}
			writeOptional(t, primary+".mode", tc.mode)
			writeOptional(t, primary+".manual", tc.manual)
			writeOptional(t, primary+".exceptions", tc.exceptions)

			b := freshBLForLoad()
			if err := b.Load(primary); err != nil {
				t.Fatalf("Load: %v", err)
			}

			if got := b.Mode(); got != tc.wantMode {
				t.Errorf("Mode() = %q, want %q", got, tc.wantMode)
			}

			gotManual := sidecarKeys(b.manual)
			wantManual := tc.wantManual
			if wantManual == nil {
				wantManual = []string{}
			}
			if !equalSlices(gotManual, wantManual) {
				t.Errorf(".manual = %v, want %v", gotManual, wantManual)
			}

			gotExcept := sidecarKeys(b.exceptions)
			wantExcept := tc.wantExcept
			if wantExcept == nil {
				wantExcept = []string{}
			}
			if !equalSlices(gotExcept, wantExcept) {
				t.Errorf(".exceptions = %v, want %v", gotExcept, wantExcept)
			}
		})
	}
}
