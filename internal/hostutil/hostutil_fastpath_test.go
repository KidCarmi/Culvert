package hostutil

import (
	"net"
	"strings"
	"testing"

	"golang.org/x/net/idna"
)

// The already-canonical fast path in NormalizeHostStrict skips idna.ToASCII for
// hosts that are pure ASCII with no ACE ("xn--") label, on the grounds that
// ToASCII is the identity function on exactly those inputs. That claim is a
// property of x/net/idna's zero-option Punycode profile, not of our code, so it
// is pinned here differentially: every input the fast path CLAIMS is canonical
// is fed to the real idna.ToASCII and must come back byte-identical with a nil
// error. An upstream x/net change that tightened the Punycode profile would
// fail these tests rather than silently changing proxy normalization semantics.

// assertFastPathIsIdentity checks the load-bearing invariant for one input: if
// isCanonicalASCIIHost accepts it, idna.ToASCII must return it unchanged.
func assertFastPathIsIdentity(t *testing.T, lowered string) {
	t.Helper()
	if lowered == "" || !isCanonicalASCIIHost(lowered) {
		return // routed to the slow path; nothing to prove
	}
	got, err := idna.ToASCII(lowered)
	if err != nil {
		t.Errorf("fast path accepted %q but idna.ToASCII errored: %v — the fast path "+
			"would turn a REJECTED host into an accepted one (fail-open, RISK-013)", lowered, err)
		return
	}
	if got != lowered {
		t.Errorf("fast path accepted %q but idna.ToASCII rewrote it to %q — the fast path "+
			"would skip a real normalization", lowered, got)
	}
}

func TestNormalizeHostStrict_FastPathMatchesToASCII(t *testing.T) {
	cases := []string{
		// Plain hostnames — the case the fast path exists for.
		"example.com",
		"sub.cdn.assets.example.com",
		"a.b.c.d.e.f.g.h",
		"single",
		"1.example.com",
		// Hyphen shapes browsers accept and the Punycode profile does not police.
		"r3---sn-apo3qvuoxuxbt-j5pe.googlevideo.com",
		"-leading.example.com",
		"trailing-.example.com",
		"under_score.example.com",
		// Near-misses of the ACE prefix that must NOT be diverted to the slow path
		// incorrectly — and must still round-trip identically if they are accepted.
		"xnn--notace.example.com",
		"xn.example.com",
		"x.com",
		"axn--notlabelstart.example.com",
		// Genuine ACE labels — must be routed to the slow path.
		"xn--bcher-kva.example.com",
		"example.xn--bcher-kva",
		"xn--.com",
		// Degenerate label shapes.
		"a..b",
		".leading.dot",
		"a.",
		// IP literals (handled before the fast path, but must stay stable).
		"203.0.113.10",
		"2001:db8::1",
		"[2001:db8::1]",
		// Long input — no length policing in the Punycode profile.
		strings.Repeat("a", 300) + ".com",
		strings.Repeat("a.", 100) + "com",
	}
	for _, in := range cases {
		assertFastPathIsIdentity(t, strings.ToLower(strings.TrimSuffix(in, ".")))
	}
}

// TestNormalizeHostStrict_FastPathClassification pins WHICH inputs the fast path
// accepts, so an accidental widening (e.g. dropping the ACE test) is caught even
// if the identity property still happens to hold for the sample.
func TestNormalizeHostStrict_FastPathClassification(t *testing.T) {
	accepted := []string{"example.com", "a.b.c", "xnn--x.com", "xn.com", "", "-a-.com"}
	rejected := []string{"xn--bcher-kva.com", "a.xn--bcher-kva", "bücher.com", "exämple.com"}
	for _, h := range accepted {
		if !isCanonicalASCIIHost(h) {
			t.Errorf("isCanonicalASCIIHost(%q) = false, want true", h)
		}
	}
	for _, h := range rejected {
		if isCanonicalASCIIHost(h) {
			t.Errorf("isCanonicalASCIIHost(%q) = true, want false", h)
		}
	}
}

// TestNormalizeHostStrict_IPLiteralsAcceptedByConstruction pins the RISK-013
// guarantee that the strict gate accepts valid IP literals — bare and bracketed
// IPv6 included — and returns them verbatim. The guarantee is stated by the
// explicit net.ParseIP branch but is currently DELIVERED by the canonical-ASCII
// fast path, which runs first. This test is deliberately written against the
// public behaviour rather than either branch, so it keeps holding if the order
// changes and starts failing if a future narrowing of isCanonicalASCIIHost pushes
// IP literals into idna.ToASCII while the ParseIP guard is also removed.
func TestNormalizeHostStrict_IPLiteralsAcceptedByConstruction(t *testing.T) {
	literals := []string{
		"203.0.113.10", "192.0.2.1", "127.0.0.1", "255.255.255.255",
		"2001:db8::1", "[2001:db8::1]", "::1", "[::1]",
		"fe80::1", "[fe80::1]", "2001:0db8:0000:0000:0000:0000:0000:0001",
	}
	for _, lit := range literals {
		norm, ok := NormalizeHostStrict(lit)
		if !ok {
			t.Errorf("NormalizeHostStrict(%q) rejected a valid IP literal — the strict "+
				"dispatch gate would 400 legitimate IP-destination traffic", lit)
			continue
		}
		if want := strings.ToLower(lit); norm != want {
			t.Errorf("NormalizeHostStrict(%q) = %q, want %q verbatim — downstream matchers "+
				"expect the original literal shape", lit, norm, want)
		}
	}
}

// TestNormalizeHostStrict_EquivalentToPreFastPath proves the OBSERVABLE contract
// of NormalizeHostStrict is unchanged, by re-implementing the pre-optimization
// body and comparing both outputs (norm AND ok) on every input.
func TestNormalizeHostStrict_EquivalentToPreFastPath(t *testing.T) {
	for _, in := range fastPathCorpus() {
		wantNorm, wantOK := referenceNormalizeHostStrict(in)
		gotNorm, gotOK := NormalizeHostStrict(in)
		if gotNorm != wantNorm || gotOK != wantOK {
			t.Errorf("NormalizeHostStrict(%q) = (%q, %v), pre-fast-path reference = (%q, %v)",
				in, gotNorm, gotOK, wantNorm, wantOK)
		}
	}
}

// referenceNormalizeHostStrict is NormalizeHostStrict's body as it stood BEFORE
// the fast path was added — the oracle for the equivalence test above.
func referenceNormalizeHostStrict(host string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return host, true
	}
	if netParseIPOK(host) {
		return host, true
	}
	ascii, err := idna.ToASCII(host)
	if err != nil {
		return "", false
	}
	return strings.ToLower(ascii), true
}

// netParseIPOK mirrors the production IP-literal branch (bare + bracketed IPv6),
// which the fast path is deliberately placed AFTER and does not alter.
func netParseIPOK(host string) bool {
	return net.ParseIP(host) != nil || net.ParseIP(stripIPv6Brackets(host)) != nil
}

func fastPathCorpus() []string {
	return []string{
		"", ".", "..", "example.com", "EXAMPLE.COM", "Example.Com.",
		"sub.cdn.assets.example.com", "a..b", ".leading", "trailing.",
		"xn--bcher-kva.example.com", "XN--BCHER-KVA.EXAMPLE.COM",
		"bücher.example.com", "BÜCHER.example.com", "exämple.com",
		"xn--.com", "xn--a.com", "xnn--x.com", "xn.com", "x.com",
		"under_score.com", "-lead.com", "trail-.com",
		"203.0.113.10", "2001:db8::1", "[2001:db8::1]", "[::1]",
		"r3---sn-apo3qvuoxuxbt-j5pe.googlevideo.com",
		strings.Repeat("a", 300) + ".com", strings.Repeat("a.", 100) + "com",
		"日本.example.com", "xn--fsq.com", "münchen.de", "\x00.com", "a\x7f.com",
	}
}

// FuzzNormalizeHostStrict is the open-ended half of the equivalence proof: for
// ARBITRARY input, the optimized NormalizeHostStrict must agree with the
// pre-fast-path reference on both the normalized value and the ok flag. This is
// the gate that catches a fast-path widening the hand-written corpus misses.
func FuzzNormalizeHostStrict(f *testing.F) {
	for _, s := range fastPathCorpus() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, host string) {
		wantNorm, wantOK := referenceNormalizeHostStrict(host)
		gotNorm, gotOK := NormalizeHostStrict(host)
		if gotNorm != wantNorm || gotOK != wantOK {
			t.Fatalf("NormalizeHostStrict(%q) = (%q, %v), reference = (%q, %v)",
				host, gotNorm, gotOK, wantNorm, wantOK)
		}
		// The fast path must never turn a host the strict gate REJECTS into an
		// accepted one — that is the fail-open direction RISK-013 guards.
		if gotOK && !wantOK {
			t.Fatalf("fast path accepted %q that the strict gate rejects (fail-open)", host)
		}
	})
}
