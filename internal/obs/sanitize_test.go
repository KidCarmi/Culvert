package obs

import (
	"math/rand"
	"strings"
	"testing"
)

// Differential + performance contract for the single-pass Sanitize.
//
// Sanitize is a deliberate independent COPY of package main's sanitizeLog (see
// the comment on Sanitize for why the duplication is kept), so it gets its own
// copy of the proof rather than borrowing one across the package boundary.

// legacySanitize is the pre-change implementation, copied verbatim. It is the
// differential oracle and must not be tidied.
func legacySanitize(s string) string {
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

var sanitizeShapes = []string{
	"", "clean-value", "\n", "\r", "\t", "\x00", "\x1f", "\x20", "\x7f", "\x7e",
	"\x80", "\xff", "\x1b[31mred\x1b[0m", "a\nb\rc\td\x01e", "\n\r\t", "\r\n",
	"lead\x01", "\x01trail", "a\x00\x00b", "héllo wörld", "h\néllo",
	"component/subsystem", strings.Repeat("segment/", 40),
	strings.Repeat("a", 300) + "\x01", "\x01" + strings.Repeat("a", 300),
	strings.Repeat("\r\n", 50), "\x0b\x0c", "mixed\x7fdel\x1besc\x00nul\ttab\r\n",
}

func TestSanitize_DifferentialAgainstLegacy(t *testing.T) {
	for _, in := range sanitizeShapes {
		if got, want := Sanitize(in), legacySanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, legacy = %q", in, got, want)
		}
	}
}

func TestSanitize_DifferentialRandomized(t *testing.T) {
	rng := rand.New(rand.NewSource(20260902)) //nolint:gosec // deterministic test corpus, not crypto
	alphabet := []byte{
		0x00, 0x01, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x1B, 0x1F,
		0x20, 0x21, 0x41, 0x5F, 0x61, 0x7E, 0x7F, 0x80, 0xC3, 0xA9, 0xFF,
	}
	for n := 0; n < 20000; n++ {
		b := make([]byte, rng.Intn(40))
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		in := string(b)
		if got, want := Sanitize(in), legacySanitize(in); got != want {
			t.Fatalf("Sanitize(%q) = %q, legacy = %q", in, got, want)
		}
	}
}

// TestSanitize_NoControlByteSurvives states the security contract directly,
// independent of the oracle.
func TestSanitize_NoControlByteSurvives(t *testing.T) {
	var all strings.Builder
	for c := 0; c < 256; c++ {
		all.WriteByte(byte(c))
	}
	got := Sanitize(all.String())
	for i := 0; i < len(got); i++ {
		if c := got[i]; c < 0x20 || c == 0x7F {
			t.Fatalf("control byte 0x%02X survived at offset %d", c, i)
		}
	}
	if len(got) != 256 {
		t.Fatalf("len = %d, want 256", len(got))
	}
}

// TestSanitize_CleanPathIsAllocationFree pins the property that makes Sanitize
// safe to call from hot paths: an ordinary value costs no heap.
func TestSanitize_CleanPathIsAllocationFree(t *testing.T) {
	for _, in := range []string{"", "clean-value", strings.Repeat("x", 4096)} {
		in := in
		if got := testing.AllocsPerRun(200, func() { sanitizeSink = Sanitize(in) }); got != 0 {
			t.Errorf("Sanitize(%d-byte clean input): %.1f allocs/op, want 0", len(in), got)
		}
	}
}

func FuzzSanitize(f *testing.F) {
	for _, s := range sanitizeShapes {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := Sanitize(s)
		if want := legacySanitize(s); got != want {
			t.Fatalf("Sanitize(%q) = %q, legacy = %q", s, got, want)
		}
		if len(got) != len(s) {
			t.Fatalf("Sanitize(%q): len %d, want %d", s, len(got), len(s))
		}
		for i := 0; i < len(got); i++ {
			if c := got[i]; c < 0x20 || c == 0x7F {
				t.Fatalf("control byte 0x%02X survived at offset %d for input %q", c, i, s)
			}
		}
	})
}

var sanitizeSink string

// BenchmarkSanitize is the before/after comparison, both forms in one run.
func BenchmarkSanitize(b *testing.B) {
	for _, sh := range []struct{ name, in string }{
		{"Clean15B", "component/name"},
		{"Empty", ""},
		{"Long270B", strings.Repeat("segment/", 34)},
		{"WithControls", "bad\nvalue\rwith\ttabs\x01"},
	} {
		b.Run(sh.name+"/after", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sanitizeSink = Sanitize(sh.in)
			}
		})
		b.Run(sh.name+"/before", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sanitizeSink = legacySanitize(sh.in)
			}
		})
	}
}
