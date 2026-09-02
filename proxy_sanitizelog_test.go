package main

import (
	"math/rand"
	"strings"
	"sync"
	"testing"
)

// Correctness contracts for the single-pass sanitizeLog (proxy.go).
//
// The change is a COST change: it collapsed four full scans (three
// strings.ReplaceAll plus containsControl) into one, on the argument that the
// three replace passes were redundant with the fourth — \n, \r and \t are all
// < 0x20, and every branch mapped its match to the same byte, '_'.
//
// That argument is only worth as much as its proof, so the old implementation
// is kept here VERBATIM as the oracle and the two are compared over hand-picked
// divergence shapes, randomized inputs, and a fuzz target. The performance
// contract lives in proxy_sanitizelog_benchgate_test.go.

// legacySanitizeLog is the pre-change implementation, copied verbatim from
// proxy.go. It is the differential oracle and must not be "tidied": its value
// is that it is the exact code the new form claims to be equivalent to.
func legacySanitizeLog(s string) string {
	s = strings.ReplaceAll(s, "\n", "_")
	s = strings.ReplaceAll(s, "\r", "_")
	s = strings.ReplaceAll(s, "\t", "_")
	if !legacyContainsControl(s) {
		return s
	}
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7F {
			b[i] = '_'
			continue
		}
		b[i] = c
	}
	return string(b)
}

func legacyContainsControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7F {
			return true
		}
	}
	return false
}

// sanitizeLogDivergenceShapes are the inputs where a wrong single-pass rewrite
// would actually diverge, rather than a list of strings that happen to be
// clean. Each entry names the property it probes.
var sanitizeLogDivergenceShapes = []string{
	"",                    // empty: the fast path must not touch it
	"allow-corp-saas",     // clean short: the dominant hot-path shape
	"\n",                  // the one class the surviving ReplaceAll handles
	"\r",                  // handled by the fused scan, not by ReplaceAll
	"\t",                  // ditto
	"\x00",                // NUL: low end of the C0 range
	"\x1f",                // 0x1F: highest C0 control
	"\x20",                // SPACE: first byte that must SURVIVE
	"\x7f",                // DEL: the non-C0 member of the set
	"\x7e",                // '~': the byte just below DEL, must survive
	"\x80",                // high byte, must survive
	"\xff",                // top byte, must survive
	"\x1b[31mred\x1b[0m",  // ANSI escape (CWE-150) — the reason DEL/ESC are in scope
	"a\nb\rc\td\x01e",     // every replaced class in one string
	"\n\r\t",              // controls only, no survivors
	"lead\x01",            // control at the very end
	"\x01trail",           // control at the very start
	"a\x00\x00b",          // adjacent controls
	"héllo wörld",         // multi-byte UTF-8 must pass through byte-wise
	"h\néllo",             // control adjacent to a multi-byte rune
	"line1\nline2\nline3", // repeated newlines: the ReplaceAll multi-match path
	"www.example.com",
	"destFQDN=*.example.com destCat=Business destCountry=US,CA",
	strings.Repeat("segment/", 40),        // long clean: the scan-bound shape
	strings.Repeat("a", 300) + "\x01",     // long clean prefix then a control
	"\x01" + strings.Repeat("a", 300),     // control first, long tail
	strings.Repeat("a\x1bb", 100),         // dense controls
	strings.Repeat("\n", 64),              // ReplaceAll-heavy
	"user@corp.example",                   // identity shape
	"01JAQ62FKDRF3LSXZGOPMPBQ00",          // request-id shape
	"GET /path?q=1&r=2 HTTP/1.1",          // request-line shape
	"\x0b\x0c",                            // VT and FF: controls ReplaceAll never touched
	"tab\tsep\tvalues",                    // tab-only, the class that lost its ReplaceAll
	"cr\rlf\n",                            // CR before LF ordering
	"\r\n",                                // CRLF, the log-forging primitive
	strings.Repeat("\r\n", 50),            // repeated CRLF
	"mixed\x7fdel\x1besc\x00nul\ttab\r\n", // everything at once
}

// TestSanitizeLog_DifferentialAgainstLegacy is the correctness spine: the new
// single-pass form must agree with the verbatim old implementation on every
// shape where a wrong rewrite could diverge.
func TestSanitizeLog_DifferentialAgainstLegacy(t *testing.T) {
	for _, in := range sanitizeLogDivergenceShapes {
		want := legacySanitizeLog(in)
		if got := sanitizeLog(in); got != want {
			t.Errorf("sanitizeLog(%q) = %q, legacy = %q", in, got, want)
		}
	}
}

// TestSanitizeLog_DifferentialRandomized widens the differential to randomized
// inputs drawn from an alphabet weighted toward the boundary bytes, where an
// off-by-one in the C0/DEL predicate would show up.
func TestSanitizeLog_DifferentialRandomized(t *testing.T) {
	rng := rand.New(rand.NewSource(20260902)) //nolint:gosec // deterministic test corpus, not crypto
	// Boundary-weighted alphabet: the interesting bytes are the edges of the
	// control range, not uniform noise over 0..255.
	alphabet := []byte{
		0x00, 0x01, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x1B, 0x1F,
		0x20, 0x21, 0x41, 0x5F, 0x61, 0x7E, 0x7F, 0x80, 0xC3, 0xA9, 0xFF,
	}
	for n := 0; n < 20000; n++ {
		l := rng.Intn(40)
		b := make([]byte, l)
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		in := string(b)
		want := legacySanitizeLog(in)
		if got := sanitizeLog(in); got != want {
			t.Fatalf("sanitizeLog(%q) = %q, legacy = %q", in, got, want)
		}
	}
}

// TestSanitizeLog_LengthPreserved pins the property both forms rely on: every
// substitution is one byte for one byte, so callers that reason about offsets
// (or about a bounded log line) are unaffected.
func TestSanitizeLog_LengthPreserved(t *testing.T) {
	for _, in := range sanitizeLogDivergenceShapes {
		if got := sanitizeLog(in); len(got) != len(in) {
			t.Errorf("sanitizeLog(%q): len %d, want %d", in, len(got), len(in))
		}
	}
}

// TestSanitizeLog_NoControlByteSurvives is the security contract stated
// directly, independent of the oracle: whatever the implementation, no control
// byte may reach a log sink.
func TestSanitizeLog_NoControlByteSurvives(t *testing.T) {
	var all strings.Builder
	for c := 0; c < 256; c++ {
		all.WriteByte(byte(c))
	}
	got := sanitizeLog(all.String())
	for i := 0; i < len(got); i++ {
		if c := got[i]; c < 0x20 || c == 0x7F {
			t.Fatalf("control byte 0x%02X survived at offset %d", c, i)
		}
	}
	if len(got) != 256 {
		t.Fatalf("len = %d, want 256", len(got))
	}
}

// TestSanitizeLog_CleanInputIsReturnedUnchanged pins the fast path's identity
// behaviour — the property that makes it allocation-free.
func TestSanitizeLog_CleanInputIsReturnedUnchanged(t *testing.T) {
	for _, in := range []string{"", "allow-corp-saas", "www.example.com", strings.Repeat("x", 1024)} {
		if got := sanitizeLog(in); got != in {
			t.Errorf("sanitizeLog(%q) = %q, want unchanged", in, got)
		}
	}
}

// TestSanitizeLog_ConcurrentCallersAgree runs the sanitiser from many
// goroutines over shared input strings. sanitizeLog holds no state, and the
// single-pass form must not have introduced any: this is the race-detector's
// hook (`go test -race`) on a function reached from every request goroutine.
func TestSanitizeLog_ConcurrentCallersAgree(t *testing.T) {
	want := make([]string, len(sanitizeLogDivergenceShapes))
	for i, in := range sanitizeLogDivergenceShapes {
		want[i] = legacySanitizeLog(in)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 500; n++ {
				for i, in := range sanitizeLogDivergenceShapes {
					if got := sanitizeLog(in); got != want[i] {
						t.Errorf("concurrent sanitizeLog(%q) = %q, want %q", in, got, want[i])
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}

// TestSanitizeLog_DoesNotAliasCallerInput guards the one memory-safety hazard a
// single-pass rewrite can introduce: mutating in place. Go strings are
// immutable so this cannot compile as a direct write, but a future rewrite
// using unsafe or a shared buffer would break it, and the result must never
// share storage that a later call could rewrite.
func TestSanitizeLog_DoesNotAliasCallerInput(t *testing.T) {
	in := "a\x01b\x02c"
	first := sanitizeLog(in)
	second := sanitizeLog("z\x03y\x04x")
	if first != "a_b_c" {
		t.Fatalf("first = %q, want %q", first, "a_b_c")
	}
	if second != "z_y_x" {
		t.Fatalf("second = %q, want %q", second, "z_y_x")
	}
	if in != "a\x01b\x02c" {
		t.Fatalf("input mutated: %q", in)
	}
}

// FuzzSanitizeLog is the open-ended half of the differential. The two
// implementations must agree on ANY input, and no control byte may survive.
func FuzzSanitizeLog(f *testing.F) {
	for _, s := range sanitizeLogDivergenceShapes {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := sanitizeLog(s)
		if want := legacySanitizeLog(s); got != want {
			t.Fatalf("sanitizeLog(%q) = %q, legacy = %q", s, got, want)
		}
		if len(got) != len(s) {
			t.Fatalf("sanitizeLog(%q): len %d, want %d", s, len(got), len(s))
		}
		for i := 0; i < len(got); i++ {
			if c := got[i]; c < 0x20 || c == 0x7F {
				t.Fatalf("control byte 0x%02X survived at offset %d for input %q", c, i, s)
			}
		}
	})
}
