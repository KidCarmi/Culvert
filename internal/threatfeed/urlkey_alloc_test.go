package threatfeed

// Gates for the allocation-free per-request URL key (Performance Guardian,
// 2026-11-21).
//
// The change is a COST change, not a policy change, and it has exactly two
// mechanisms — a guard in front of net.ParseIP, and a stack-rendered lookup key
// — so there are two things to hold:
//
//  1. the guard must be a SUPERSET of what net.ParseIP accepts, because a guard
//     that is narrower than ParseIP is a security defect: a private-IP
//     destination would stop being recognised as one and would start being
//     probed against the feed, which the private-IP exclusion exists to
//     prevent;
//  2. the key must not change, including when it is longer than the scratch
//     and spills to the heap, because two URLs sharing a key means one inherits
//     the other's verdict.
//
// The key-level differential against NormaliseURL (checkrequesturl_test.go,
// plus FuzzCheckRequestURL) already covers the key for every shape it reaches.
// What it cannot see is the spill, because nothing in its corpus is 320 bytes
// long, and it cannot see the allocation claim at all.

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
)

// ── 1. The guard is a superset ───────────────────────────────────────────────

// couldBeIPLiteralCorpus names the shapes worth a regression by name: each one
// either sits on a boundary of the proof in couldBeIPLiteral's contract or is a
// case where a naive scan would get the direction wrong.
var couldBeIPLiteralCorpus = []string{
	// real addresses — the guard MUST admit every one of these
	"1.2.3.4", "0.0.0.0", "255.255.255.255", "127.0.0.1", "10.0.0.1",
	"::1", "::", "2001:db8::1", "fe80::1", "::ffff:192.0.2.1",
	"64:ff9b::192.0.2.33", "2001:db8:0:0:0:0:2:1",
	// leading HEX digits before the first colon — the shape a first draft of
	// couldBeIPLiteral refused, which would have handed a link-local
	// destination to the feed
	"fe80::", "abcd::1", "ffff::", "dead:beef::1", "FE80::1", "ABCD::EF01",
	"a:b", "f::", "0:0:0:0:0:0:0:1",
	// zones and brackets: ParseIP rejects these, the guard may admit them
	"fe80::1%eth0", "[::1]", "[2001:db8::1]",
	// ordinary hostnames — the case the guard exists for
	"files.example.com", "example.com", "a", "xn--bcher-kva.example.com",
	"sub.domain.example.co.uk", "host-with-dash.example.com",
	"under_score.example.com",
	// digit-shaped hostnames and near-misses: the guard admits them and
	// ParseIP then refuses, which is correct and merely unoptimised
	"1.2.3", "1.2.3.4.5", "1.2.3.256", "01.2.3.4", "999.999.999.999",
	"...", ".", "1.", ".1", "123", "1234567890",
	// shapes that reach ParseAddr's '%' and fall-through arms
	"a%b", "%", "", "   ", "1.2.3.4 ", " 1.2.3.4",
	"host:8080", "1.2.3.4:80", "a:b:c",
	// non-ASCII
	"bücher.example.com", "\x00", "\xff\xfe",
}

// TestCouldBeIPLiteral_IsSupersetOfParseIP is the differential that makes the
// guard's contract checkable rather than argued. It asserts ONE direction only,
// and that asymmetry is the whole point: admitting a non-address is a missed
// optimisation, while refusing a real one is a security defect.
//
// It runs against the real net.ParseIP, so a future toolchain that WIDENS the
// accepted address syntax fails here instead of silently turning the guard into
// a filter.
func TestCouldBeIPLiteral_IsSupersetOfParseIP(t *testing.T) {
	for _, s := range couldBeIPLiteralCorpus {
		if net.ParseIP(s) != nil && !couldBeIPLiteral(s) {
			t.Errorf("couldBeIPLiteral(%q) = false but net.ParseIP parses it — "+
				"the guard is a FILTER, not a superset: a private-IP destination "+
				"would now be probed against the feed", s)
		}
	}
}

// TestCouldBeIPLiteral_ActuallyRejectsOrdinaryHostnames is the CONTROL. Every
// assertion above passes trivially if couldBeIPLiteral always returns true,
// which is also the cheapest way to "fix" a failure there — and it would delete
// the optimisation while leaving a green suite.
func TestCouldBeIPLiteral_ActuallyRejectsOrdinaryHostnames(t *testing.T) {
	for _, s := range []string{
		"files.example.com", "example.com", "a",
		"xn--bcher-kva.example.com", "sub.domain.example.co.uk",
	} {
		if couldBeIPLiteral(s) {
			t.Errorf("couldBeIPLiteral(%q) = true — the guard is not reached for "+
				"ordinary hostnames, so the ParseIP allocation is still paid", s)
		}
	}
}

// FuzzCouldBeIPLiteral is the open-ended half of the superset differential.
func FuzzCouldBeIPLiteral(f *testing.F) {
	for _, s := range couldBeIPLiteralCorpus {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if net.ParseIP(s) != nil && !couldBeIPLiteral(s) {
			t.Errorf("couldBeIPLiteral(%q) = false but net.ParseIP parses it", s)
		}
	})
}

// ── 2. The key is unchanged, including past the scratch ──────────────────────

// longPathURL builds an absolute-form URL whose canonical key exceeds n bytes,
// so appendParsedURLKey's append must grow past CheckRequestURL's scratch.
func longPathURL(tb testing.TB, host string, n int, tail string) *url.URL {
	tb.Helper()
	raw := "http://" + host + "/" + strings.Repeat("a", n) + tail
	u, err := url.Parse(raw)
	if err != nil {
		tb.Fatalf("parse: %v", err)
	}
	return u
}

// TestAppendParsedURLKey_SpillMatchesStringPath pins the SPILL against the
// authority. A key longer than urlKeyScratch leaves the stack buffer mid-append
// and continues on the heap; the bytes must be identical either side of that
// boundary, so the test walks lengths straddling it rather than picking one.
func TestAppendParsedURLKey_SpillMatchesStringPath(t *testing.T) {
	for _, n := range []int{1, urlKeyScratch - 40, urlKeyScratch - 1, urlKeyScratch, urlKeyScratch + 1, 4 * urlKeyScratch} {
		u := longPathURL(t, "spill.example.com", n, "")
		got, gotHost, handled := normaliseParsedURL(u)
		if !handled {
			t.Fatalf("n=%d: fast path declined an ordinary URL", n)
		}
		wantKey, wantHost := NormaliseURL(u.String())
		if got != wantKey || gotHost != wantHost {
			t.Errorf("n=%d: key diverges at the spill boundary — got (%q, %q), want (%q, %q)",
				n, got, gotHost, wantKey, wantHost)
		}
	}
}

// TestCheckRequestURL_SpilledKeysDoNotCollide is the security half of the
// spill: two destinations that differ only in their FINAL byte, both past the
// scratch, must not share a verdict. A truncating implementation passes every
// test above and fails this one.
func TestCheckRequestURL_SpilledKeysDoNotCollide(t *testing.T) {
	listed := longPathURL(t, "spill.example.com", 4*urlKeyScratch, "X")
	key, _ := NormaliseURL(listed.String())

	tf := New()
	tf.mu.Lock()
	tf.enabled = true
	tf.urls = map[string]entry{key: {Source: "urlhaus"}}
	tf.publishLocked()
	tf.mu.Unlock()

	if hit, src := tf.CheckRequestURL(listed); !hit || src != "urlhaus" {
		t.Errorf("the listed overlong URL = (%v, %q), want (true, \"urlhaus\") — "+
			"a spilled key must still MATCH its feed entry", hit, src)
	}
	neighbour := longPathURL(t, "spill.example.com", 4*urlKeyScratch, "Y")
	if hit, _ := tf.CheckRequestURL(neighbour); hit {
		t.Error("a URL differing only in its last byte inherited the listed URL's " +
			"verdict — the overlong key is being truncated")
	}
}

// ── 3. The allocation claim, armed ──────────────────────────────────────────

// TestCheckRequestURL_MissIsAllocationFree is the arming contract for the
// headline claim, and it is the only thing that holds it: a refactor that
// reintroduces a string conversion on the read path — handing the key to
// tf.lookup, say — is correct, memory-safe and verdict-preserving, and
// silently restores the allocation rate. Only this distinguishes the two.
//
// It asserts on the MISS, which is the case every allowed request takes. A hit
// is about to serve a block page and is welcome to allocate.
func TestCheckRequestURL_MissIsAllocationFree(t *testing.T) {
	tf := diffFeed(t)
	for _, raw := range []string{
		"http://files.example.com/downloads/report/q3-2026.pdf?token=abc123&v=2",
		"https://api.example.com/v1/users",
		"http://clean.example.com",
		"http://clean.example.com/",
		"http://93.184.216.34:8080/x", // public IP literal: the guard admits it, ParseIP succeeds
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		got := testing.AllocsPerRun(200, func() {
			if hit, _ := tf.CheckRequestURL(u); hit {
				t.Fatalf("unexpected hit for %q", raw)
			}
		})
		// A public IP literal still pays net.ParseIP's SUCCESS allocation (the
		// 16-byte net.IP), which is unrelated to this change and is not a
		// hostname destination. Named rather than hidden behind a loose bound.
		want := 0.0
		if raw == "http://93.184.216.34:8080/x" {
			want = 1.0
		}
		if got > want {
			t.Errorf("CheckRequestURL(%q) = %.0f allocs/op, want %.0f", raw, got, want)
		}
	}
}

// TestCheckRequestURL_AllocationFree_LegacyIsNot is the negative control for
// the control. It asserts the shape this change replaced DID allocate, so a
// future reader can see the gate above measures a real difference rather than a
// tautology — and so a toolchain change that folded the legacy arm would be
// caught instead of quietly flattering it.
func TestCheckRequestURL_AllocationFree_LegacyIsNot(t *testing.T) {
	tf := diffFeed(t)
	u, err := url.Parse("http://files.example.com/downloads/report/q3-2026.pdf?token=abc123&v=2")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// legacyNormaliseParsedURL is the pre-change body, kept alive here as the
	// baseline: the ungated net.ParseIP plus the concatenated key.
	legacy := testing.AllocsPerRun(200, func() {
		host := canonicalHost(u.Hostname())
		if ip := net.ParseIP(host); ip != nil {
			t.Fatal("unexpected IP literal")
		}
		norm := strings.ToLower(u.Scheme) + "://" + host + strings.ToLower(u.Path)
		norm = strings.TrimRight(norm, "/")
		if _, ok := tf.readState().urls[norm]; ok {
			t.Fatal("unexpected hit")
		}
	})
	if legacy < 2 {
		t.Errorf("the pre-change shape measured %.0f allocs/op, want >= 2 — the "+
			"allocation gate is comparing against a baseline the compiler has "+
			"folded, so it no longer measures this change", legacy)
	}
}

// ── 4. Concurrency ──────────────────────────────────────────────────────────

// BenchmarkFeedCheckRequestURL_MissAtScale is the concurrency arm at the widths
// this box can show. Read it against BenchmarkFeedCheckDomain_MissParallel, the
// standing control: the point of this change is that the URL check now costs
// about what the domain check costs, and both are lock-free reads of a
// published view, so neither should degrade as workers are added.
//
// THE SUB-BENCHMARK NAMES ARE MULTIPLES OF GOMAXPROCS, NOT GOROUTINE COUNTS.
// b.SetParallelism(n) runs n*GOMAXPROCS goroutines, so even "par=1x" is already
// as wide as the machine, and RunParallel's ns/op is wall time per op across
// ALL workers — which is why these figures sit well below the serial number.
// The serial cost is BenchmarkFeedCheckRequestURL_Miss; do not read "par=1x" as
// one goroutine. Saying so here because a first draft of this comment did.
func BenchmarkFeedCheckRequestURL_MissAtScale(b *testing.B) {
	tf := benchFeed(100000)
	for _, p := range []int{1, 2, 4} {
		b.Run(fmt.Sprintf("par=%dx", p), func(b *testing.B) {
			b.SetParallelism(p)
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				// Worker-local URL: sharing one *url.URL across workers would
				// measure the cache line it sits on, not the check.
				u, err := url.Parse("http://files.example.com/downloads/report/q3-2026.pdf?token=abc123&v=2")
				if err != nil {
					b.Fatalf("parse: %v", err)
				}
				var sink bool
				for pb.Next() {
					sink, _ = tf.CheckRequestURL(u)
				}
				if sink {
					b.Fatal("unexpected hit")
				}
			})
		})
	}
}
