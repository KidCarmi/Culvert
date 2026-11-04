package main

import (
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Wall: a dependency bump must not change a GODEBUG default without review.
//
// The root go.mod `go` line is not only a language minimum — it selects the
// DEFAULT of every GODEBUG compatibility setting, and the compiler records the
// resulting non-base defaults in the binary as `DefaultGODEBUG`. So any module
// that requires a newer language version moves this module's `go` line and, with
// it, runtime security behavior — with nothing in CI comparing the two. That is
// what happened in PR #1790: sigstore-go v1.4.0 declares `go 1.27.0`, the `go`
// line went 1.26.6 → 1.27.0, and Go 1.27's change to
// `x509sslcertoverrideplatform` (default 0 → 1) let a `SSL_CERT_FILE` in the
// process environment displace the platform certificate verifier on the darwin
// and windows release binaries. toolchain_consistency_test.go did not catch it:
// it guards the `toolchain` line, which did not move.
//
// The checks below are deliberately two-sided, because the two sources answer
// different questions. go.mod says what this module CLAIMS to pin; the compiled
// DefaultGODEBUG says which defaults actually differ from the toolchain's own
// base defaults, and therefore which pins are load-bearing. A misspelled name
// is NOT one of the gaps between them — the go command refuses to load a go.mod
// with an unknown godebug setting ("unknown godebug ..."), verified against
// go1.27.3 — but a pin that a future toolchain makes the base default again
// silently stops differing, and a default that changes for a setting nobody
// pinned never appears in go.mod at all. The third check is the one that would
// have caught this window's regression. Each has a negative control that feeds
// it the disagreement it exists to reject.
// ─────────────────────────────────────────────────────────────────────────────

// reviewedGODEBUGPins is the EXACT set of GODEBUG defaults this module pins,
// not a minimum. A new pin must be added here with its rationale recorded in
// go.mod; a removed pin must be removed here. The list is an allowlist so that
// both directions — an unreviewed pin appearing and a reviewed pin vanishing —
// fail rather than only one of them.
//
//   - x509sslcertoverrideplatform=0: keep the platform certificate verifier
//     authoritative on darwin/windows, so SSL_CERT_FILE/SSL_CERT_DIR in the
//     environment cannot replace the trust anchors upstreamVerifyRoots uses to
//     verify upstream certificates on SSL-inspected tunnels. See go.mod.
var reviewedGODEBUGPins = map[string]string{
	"x509sslcertoverrideplatform": "0",
}

// parseGODEBUGList splits a `name=value,name=value` list, the shared form of
// the go.mod `godebug` directives and the compiled DefaultGODEBUG setting.
func parseGODEBUGList(list string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(list, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		name, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	return out
}

// parseGoModGODEBUG returns the pins a go.mod declares, from both the
// single-line (`godebug name=value`) and block (`godebug ( ... )`) forms. It
// takes the CONTENT rather than a path so the negative control below can feed
// it crafted files without moving the working directory out from under the
// rest of the package's tests.
func parseGoModGODEBUG(content string) map[string]string {
	out := map[string]string{}
	inBlock := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		switch {
		case inBlock && line == ")":
			inBlock = false
		case inBlock:
			for k, v := range parseGODEBUGList(line) {
				out[k] = v
			}
		case line == "godebug (":
			inBlock = true
		case strings.HasPrefix(line, "godebug "):
			for k, v := range parseGODEBUGList(strings.TrimPrefix(line, "godebug ")) {
				out[k] = v
			}
		}
	}
	return out
}

// goModGODEBUGPins returns the pins declared by the ROOT go.mod — the file the
// released binaries and this test binary are both built from.
func goModGODEBUGPins(t *testing.T) map[string]string {
	t.Helper()
	return parseGoModGODEBUG(string(mustRead(t, "go.mod")))
}

// compiledGODEBUGDefaults returns the DefaultGODEBUG the compiler recorded in
// THIS test binary — the defaults the released binaries are built with, since
// both come from the same root go.mod. Absent means "no setting differs from
// the toolchain's own base defaults", which is an empty map, not a skip.
func compiledGODEBUGDefaults(t *testing.T) map[string]string {
	t.Helper()
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("no build info: cannot read the compiled GODEBUG defaults")
	}
	for _, s := range bi.Settings {
		if s.Key == "DefaultGODEBUG" {
			return parseGODEBUGList(s.Value)
		}
	}
	return map[string]string{}
}

func formatPins(m map[string]string) string {
	kv := make([]string, 0, len(m))
	for k, v := range m {
		kv = append(kv, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(kv)
	return "[" + strings.Join(kv, " ") + "]"
}

// diffPins reports every name whose value differs between want and got,
// including names present in only one of them.
func diffPins(want, got map[string]string) []string {
	seen := map[string]bool{}
	var names []string
	for k := range want {
		seen[k] = true
		names = append(names, k)
	}
	for k := range got {
		if !seen[k] {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	var bad []string
	for _, n := range names {
		w, inWant := want[n]
		g, inGot := got[n]
		if inWant != inGot || w != g {
			bad = append(bad, fmt.Sprintf("%s: want %q (declared=%v), got %q (present=%v)", n, w, inWant, g, inGot))
		}
	}
	return bad
}

// TestGODEBUG_GoModDeclaresExactlyTheReviewedPins fails when go.mod gains a pin
// nobody reviewed or loses one that is still relied on.
func TestGODEBUG_GoModDeclaresExactlyTheReviewedPins(t *testing.T) {
	got := goModGODEBUGPins(t)
	if bad := diffPins(reviewedGODEBUGPins, got); len(bad) > 0 {
		t.Errorf("root go.mod godebug pins %s disagree with the reviewed set %s:\n  %s\n\n"+
			"Add or remove the pin in BOTH places, and record in go.mod why the default is not acceptable.",
			formatPins(got), formatPins(reviewedGODEBUGPins), strings.Join(bad, "\n  "))
	}
}

// TestGODEBUG_ReviewedPinsAreCompiledIn is the half go.mod cannot prove: that
// each pin is still load-bearing. DefaultGODEBUG records only the settings whose
// default DIFFERS from the toolchain's base defaults, so a pin that drops out of
// it is one the toolchain now defaults to on its own. That is not harmful, but it
// means the rationale recorded in go.mod no longer describes a behavior this
// module is holding in place, and the next person to read it would be misled.
// Failing here forces that re-read on the toolchain upgrade that caused it
// (roadmap/CI-REDESIGN.md §20), rather than years later.
func TestGODEBUG_ReviewedPinsAreCompiledIn(t *testing.T) {
	compiled := compiledGODEBUGDefaults(t)
	for name, want := range reviewedGODEBUGPins {
		got, ok := compiled[name]
		if !ok {
			t.Errorf("GODEBUG %q is pinned in go.mod but absent from the compiled DefaultGODEBUG %s — "+
				"this toolchain already defaults it to the pinned value, so the pin no longer holds anything "+
				"in place. Re-read the rationale in go.mod: either it still documents a default worth pinning "+
				"against a future change (keep both, and update this test), or the pin and its reviewedGODEBUGPins "+
				"entry should go.",
				name, formatPins(compiled))
			continue
		}
		if got != want {
			t.Errorf("GODEBUG %q compiled as %q, want the pinned %q", name, got, want)
		}
	}
}

// TestGODEBUG_CompiledDefaultsCarryNoUnreviewedSetting is the fail-closed
// direction: the compiled defaults must not differ from the toolchain's base
// defaults in any way the reviewed set does not account for. A future language
// bump that changes another setting's default lands here, which is exactly the
// review this window's bump bypassed.
func TestGODEBUG_CompiledDefaultsCarryNoUnreviewedSetting(t *testing.T) {
	compiled := compiledGODEBUGDefaults(t)
	for name, got := range compiled {
		if _, reviewed := reviewedGODEBUGPins[name]; !reviewed {
			t.Errorf("compiled DefaultGODEBUG carries unreviewed setting %s=%s (full set %s) — "+
				"a GODEBUG default changed without passing through reviewedGODEBUGPins",
				name, got, formatPins(compiled))
		}
	}
}

// ─── Negative controls: each check must reject the disagreement it guards ────

func TestGODEBUG_NegativeControl_ParserAndDiffRejectDisagreement(t *testing.T) {
	// The go.mod parser must see both directive forms, ignore comments, and not
	// invent pins — otherwise the check above passes on a file that declares
	// nothing.
	for _, tc := range []struct {
		name string
		mod  string
		want map[string]string
	}{
		{"single line", "module m\n\ngo 1.27.0\n\ngodebug x509sslcertoverrideplatform=0\n",
			map[string]string{"x509sslcertoverrideplatform": "0"}},
		{"block", "module m\n\ngodebug (\n\tx509sslcertoverrideplatform=0\n\ttlssha1=0\n)\n",
			map[string]string{"x509sslcertoverrideplatform": "0", "tlssha1": "0"}},
		{"commented out is not a pin", "module m\n\n// godebug x509sslcertoverrideplatform=0\n",
			map[string]string{}},
		{"trailing comment is stripped", "module m\n\ngodebug tlssha1=0 // why\n",
			map[string]string{"tlssha1": "0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if bad := diffPins(tc.want, parseGoModGODEBUG(tc.mod)); len(bad) > 0 {
				t.Errorf("parser disagreed: %s", strings.Join(bad, "; "))
			}
		})
	}

	// diffPins must flag all three disagreement shapes, or every check above is
	// vacuous. (The fourth shape a reader might expect it to cover — a misspelled
	// setting name — is unreachable: the go command refuses to load a go.mod
	// carrying an unknown godebug setting, so such a tree never builds at all.)
	for _, tc := range []struct {
		name      string
		want, got map[string]string
		wantFlag  bool
	}{
		{"identical", map[string]string{"a": "0"}, map[string]string{"a": "0"}, false},
		{"value drift", map[string]string{"a": "0"}, map[string]string{"a": "1"}, true},
		{"missing pin", map[string]string{"a": "0"}, map[string]string{}, true},
		{"extra pin", map[string]string{}, map[string]string{"a": "0"}, true},
	} {
		if flagged := len(diffPins(tc.want, tc.got)) > 0; flagged != tc.wantFlag {
			t.Errorf("diffPins(%s) flagged=%v, want %v", tc.name, flagged, tc.wantFlag)
		}
	}
}
