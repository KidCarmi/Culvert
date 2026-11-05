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
// pinned never appears in go.mod at all.
//
// That last gap has a shape that is easy to get backwards. Raising the `go` line
// to adopt a new default does not ADD an entry to DefaultGODEBUG — it REMOVES
// the compatibility entry that was holding the old default in place. Measured
// with go1.27.3 on a dependency-free module carrying this file's pin: `go 1.26.6`
// compiles `tracebacklabels=0,x509sslcertoverrideplatform=0`, `go 1.27.0`
// compiles `x509sslcertoverrideplatform=0` alone, and without the pin `go 1.27.0`
// compiles nothing at all. A check that only rejects UNREVIEWED entries is
// therefore green on exactly this window's regression. So the compiled set is
// compared, in both directions, against a reviewed baseline of the effective
// compatibility entries (reviewedGODEBUGBaseline), and the `go` line's language
// version is bound to the version that baseline was reviewed at
// (reviewedGODEBUGLanguage) — because a toolchain and `go` line raised together
// adopt the new release's defaults with no entry ever appearing or vanishing.
// Each check has a negative control that feeds it the disagreement it exists to
// reject.
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

// reviewedGODEBUGLanguage is the major.minor of the root go.mod `go` line at
// which reviewedGODEBUGBaseline and reviewedGODEBUGAdoptions were reviewed.
// GODEBUG defaults change only at minor releases, so a patch bump of the `go`
// line does not invalidate the review; a minor bump always does.
const reviewedGODEBUGLanguage = "1.27"

// reviewedGODEBUGBaseline is the EXACT compiled DefaultGODEBUG — every setting
// whose effective default differs from the toolchain's base default — that was
// reviewed at reviewedGODEBUGLanguage. It is the pins plus any compatibility
// entry the `go` line carries because it is older than the toolchain. An entry
// that appears is a default nobody reviewed; an entry that disappears is a NEW
// default silently adopted. Both fail.
var reviewedGODEBUGBaseline = map[string]string{
	"x509sslcertoverrideplatform": "0", // pinned; see reviewedGODEBUGPins and go.mod
}

// reviewedGODEBUGAdoptions records each compatibility entry that disappeared
// from the baseline at the last language bump — a new default deliberately
// accepted rather than pinned — with why accepting it is safe. It is the audit
// trail for a removal from reviewedGODEBUGBaseline; an adopted setting must not
// also be in the baseline.
var reviewedGODEBUGAdoptions = map[string]string{
	// Go 1.27 (Changed: 27): 0 → 1. Traceback FORMAT only — goroutine pprof
	// labels are printed in panic/crash tracebacks. Not a trust, crypto or
	// parsing setting. No non-test file in this tree sets goroutine labels; the
	// only dependency that does is grpc's server, behind an opt-in env setting,
	// with the RPC method name as the label value.
	"tracebacklabels": "1 (Go 1.27 default): traceback format only, no security effect",
}

// godebugReviewProcedure is appended to every baseline failure so the reader
// knows how to review the change, not just that one happened.
const godebugReviewProcedure = `
To review (do not just copy the new set into the baseline):
  1. Print the compiled set at the repository root:  go list -f '{{.DefaultGODEBUG}}' .
  2. For each setting named above — after a go line change, every setting in
     $(go env GOROOT)/src/internal/godebugs/table.go whose Changed release is
     after the reviewed language and up to the new one — read its Old value
     there and its entry in "go doc godebug" (https://go.dev/doc/godebug), and
     decide whether the new effective default is acceptable for this gateway's
     security posture.
  3. Not acceptable: pin the reviewed value with "godebug name=value" in the
     root go.mod, with its rationale there, and add it to reviewedGODEBUGPins.
     Acceptable and it disappeared: record it, with why, in
     reviewedGODEBUGAdoptions.
  4. Set reviewedGODEBUGBaseline to the exact compiled set and
     reviewedGODEBUGLanguage to the go.mod "go" line's major.minor, in
     godebug_pins_test.go.`

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
	var bad []string
	for _, n := range godebugNames(want, got) {
		w, inWant := want[n]
		g, inGot := got[n]
		if inWant != inGot || w != g {
			bad = append(bad, fmt.Sprintf("%s: want %q (declared=%v), got %q (present=%v)", n, w, inWant, g, inGot))
		}
	}
	return bad
}

// godebugBaselineDrift compares the compiled DefaultGODEBUG against the reviewed
// baseline and names the direction of every difference, because the two
// directions mean different things to the reviewer: an entry that APPEARED holds
// an old default nobody reviewed, and one that DISAPPEARED means the module now
// runs the toolchain's new default for that setting.
func godebugBaselineDrift(baseline, compiled map[string]string) []string {
	var drift []string
	for _, n := range godebugNames(baseline, compiled) {
		want, inBaseline := baseline[n]
		got, inCompiled := compiled[n]
		switch {
		case inBaseline && !inCompiled:
			drift = append(drift, fmt.Sprintf("DISAPPEARED %s (reviewed %s=%s): the compatibility entry is gone, so a NEW "+
				"default for %s was adopted without review", n, n, want, n))
		case !inBaseline && inCompiled:
			drift = append(drift, fmt.Sprintf("APPEARED %s=%s: a compatibility default nobody reviewed", n, got))
		case want != got:
			drift = append(drift, fmt.Sprintf("CHANGED %s: reviewed %q, compiled %q", n, want, got))
		}
	}
	return drift
}

// godebugNames returns the sorted union of the maps' setting names.
func godebugNames(maps ...map[string]string) []string {
	seen := map[string]bool{}
	var names []string
	for _, m := range maps {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				names = append(names, k)
			}
		}
	}
	sort.Strings(names)
	return names
}

// goModLanguage returns the major.minor of a go.mod's `go` directive — the part
// that selects GODEBUG defaults. Like parseGoModGODEBUG it takes the content so
// the negative control can feed it crafted files.
func goModLanguage(content string) (string, error) {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "go" {
			continue
		}
		parts := strings.SplitN(fields[1], ".", 3)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return "", fmt.Errorf("unparseable go directive %q", line)
		}
		return parts[0] + "." + parts[1], nil
	}
	return "", fmt.Errorf("no go directive")
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

// TestGODEBUG_CompiledDefaultsMatchReviewedBaseline is the check that catches a
// dependency raising the `go` line past a GODEBUG change: the compiled set must
// equal the reviewed baseline exactly. Had this existed with the go 1.26.6
// baseline (tracebacklabels=0, x509sslcertoverrideplatform=0), PR #1790 would
// have failed here with both entries DISAPPEARED.
func TestGODEBUG_CompiledDefaultsMatchReviewedBaseline(t *testing.T) {
	compiled := compiledGODEBUGDefaults(t)
	if drift := godebugBaselineDrift(reviewedGODEBUGBaseline, compiled); len(drift) > 0 {
		t.Errorf("compiled DefaultGODEBUG %s differs from the reviewed baseline %s (reviewed at go %s):\n  %s\n%s",
			formatPins(compiled), formatPins(reviewedGODEBUGBaseline), reviewedGODEBUGLanguage,
			strings.Join(drift, "\n  "), godebugReviewProcedure)
	}
}

// TestGODEBUG_GoLineMatchesReviewedLanguage covers the transition the baseline
// alone cannot see: raising the toolchain and the `go` line to the same new
// release together adopts every default that release changed, while
// DefaultGODEBUG — pins only, before and after — never moves.
func TestGODEBUG_GoLineMatchesReviewedLanguage(t *testing.T) {
	got, err := goModLanguage(string(mustRead(t, "go.mod")))
	if err != nil {
		t.Fatalf("root go.mod: %v", err)
	}
	if got != reviewedGODEBUGLanguage {
		t.Errorf("root go.mod go line is %s, but the GODEBUG baseline was reviewed at %s — the go line selects every "+
			"GODEBUG default, so each setting whose default changed in between was adopted without review.\n%s",
			got, reviewedGODEBUGLanguage, godebugReviewProcedure)
	}
}

// TestGODEBUG_ReviewRecordsAreConsistent keeps the three records from
// contradicting one another: every pin must be in the baseline at its pinned
// value (a pin is by definition a compiled entry), and an adopted default must
// be neither in the baseline nor pinned.
func TestGODEBUG_ReviewRecordsAreConsistent(t *testing.T) {
	for name, want := range reviewedGODEBUGPins {
		if got, ok := reviewedGODEBUGBaseline[name]; !ok || got != want {
			t.Errorf("pin %s=%s is missing from reviewedGODEBUGBaseline (has %q, present=%v)", name, want, got, ok)
		}
	}
	for name := range reviewedGODEBUGAdoptions {
		if _, ok := reviewedGODEBUGBaseline[name]; ok {
			t.Errorf("%s is recorded as an adopted default but is still in reviewedGODEBUGBaseline", name)
		}
		if _, ok := reviewedGODEBUGPins[name]; ok {
			t.Errorf("%s is recorded as an adopted default but is also pinned", name)
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

func TestGODEBUG_NegativeControl_BaselineRejectsAppearingAndDisappearingEntries(t *testing.T) {
	// The sets are the measured go1.27.3 DefaultGODEBUG values quoted in the
	// header, so the control replays the real transition rather than a toy one.
	go1266Pinned := map[string]string{"tracebacklabels": "0", "x509sslcertoverrideplatform": "0"}
	go1270Pinned := map[string]string{"x509sslcertoverrideplatform": "0"}
	go1270Unpinned := map[string]string{}

	for _, tc := range []struct {
		name               string
		baseline, compiled map[string]string
		wantDrift          []string // each must start one drift line, in order
	}{
		{"identical", go1270Pinned, go1270Pinned, nil},
		{"go line raised past a default: compat entry disappears", go1266Pinned, go1270Pinned,
			[]string{"DISAPPEARED tracebacklabels"}},
		{"this window's regression: unpinned security default adopted", go1266Pinned, go1270Unpinned,
			[]string{"DISAPPEARED tracebacklabels", "DISAPPEARED x509sslcertoverrideplatform"}},
		{"pin dropped against the current baseline", go1270Pinned, go1270Unpinned,
			[]string{"DISAPPEARED x509sslcertoverrideplatform"}},
		{"toolchain raised past the go line: compat entry appears", go1270Pinned, go1266Pinned,
			[]string{"APPEARED tracebacklabels=0"}},
		{"value changed", go1270Pinned, map[string]string{"x509sslcertoverrideplatform": "1"},
			[]string{"CHANGED x509sslcertoverrideplatform"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			drift := godebugBaselineDrift(tc.baseline, tc.compiled)
			if len(drift) != len(tc.wantDrift) {
				t.Fatalf("drift = %q, want %d line(s) starting %q", drift, len(tc.wantDrift), tc.wantDrift)
			}
			for i, prefix := range tc.wantDrift {
				if !strings.HasPrefix(drift[i], prefix) {
					t.Errorf("drift[%d] = %q, want prefix %q", i, drift[i], prefix)
				}
			}
		})
	}
}

func TestGODEBUG_NegativeControl_GoLineRejectsLanguageBump(t *testing.T) {
	// A minor bump must read as a different language; a patch bump or the short
	// form must not, or every patch-level dependency bump would demand a review
	// that cannot change any default.
	for _, tc := range []struct {
		name, mod, want string
		wantErr         bool
	}{
		{"patch form", "module m\n\ngo 1.27.0\n", "1.27", false},
		{"later patch", "module m\n\ngo 1.27.5\n", "1.27", false},
		{"short form", "module m\n\ngo 1.27\n", "1.27", false},
		{"minor bump", "module m\n\ngo 1.28.0\n", "1.28", false},
		{"toolchain line is not the go line", "module m\n\ntoolchain go1.28.1\ngo 1.27.0\n", "1.27", false},
		{"missing", "module m\n", "", true},
		{"garbled", "module m\n\ngo 1\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := goModLanguage(tc.mod)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Errorf("goModLanguage = %q, %v; want %q, err=%v", got, err, tc.want, tc.wantErr)
			}
		})
	}
	if got, _ := goModLanguage("module m\n\ngo 1.28.0\n"); got == reviewedGODEBUGLanguage {
		t.Errorf("a go 1.28.0 line compares equal to the reviewed language %s; the guard is vacuous", reviewedGODEBUGLanguage)
	}
}
