package main

// Correctness contract for the SSL_INNER emitter (proxy_sslinner_line.go).
//
// The acceptance condition for replacing a logger.Printf with hand-rolled
// appends is BYTE-IDENTITY, because these lines are parsed downstream (SIEM
// forwarders, operator greps, and the edge-case lab's interception proof). So
// the pre-change format string is kept in-tree as sslInnerLineLegacy and is the
// differential oracle: every case below renders both ways and requires the bytes
// to match. sslInnerLineLegacy is a verbatim copy of the code that was removed.
// It is not called by production and must NOT be "kept in sync" with
// logSSLInnerRequest — its whole value is that it does not move.

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
)

// sslInnerLineLegacy is the pre-change render, frozen: the exact format string
// and argument list that proxy_tunnel.go and proxy_tunnel_h2.go both passed to
// logger.Printf. Do not update it.
func sslInnerLineLegacy(clientIP, method, hostOnly, path string, match *PolicyMatch) string {
	filterStr := "off"
	profileStr := ""
	if match != nil && match.Rule != nil && match.Rule.FileFiltering {
		filterStr = "on"
		profileStr = sanitizeLog(string(match.Rule.FileProfile))
	}
	return fmt.Sprintf("SSL_INNER %s %s %s%s (profile=%q filter=%s)",
		sanitizeLog(clientIP), sanitizeLog(method), sanitizeLog(hostOnly),
		sanitizeLog(boundRetainedPath(path)), profileStr, filterStr)
}

// captureSSLInnerLine renders through the PRODUCTION emitter by pointing the
// process logger at a buffer, so the test exercises logger.Output and the
// append chain exactly as the proxy does — not a re-implementation of it. The
// "[ssl-inner] " prefix is stripped so the comparison is on the line itself.
func captureSSLInnerLine(t *testing.T, clientIP, method, hostOnly, path string, match *PolicyMatch) string {
	t.Helper()
	var buf bytes.Buffer
	prev := logger
	logger = log.New(&buf, "", 0) // no flags: no timestamp to strip
	defer func() { logger = prev }()
	logSSLInnerRequest(clientIP, method, hostOnly, path, match)
	return strings.TrimSuffix(buf.String(), "\n")
}

func ruleWithProfile(profile string) *PolicyMatch {
	return &PolicyMatch{Rule: &PolicyRule{FileFiltering: true, FileProfile: FileProfileName(profile)}}
}

// sslInnerLineCases covers every branch of the emitter and the shapes the
// inspected-tunnel path actually produces, plus the hostile ones: control bytes
// in each sanitized operand (the CWE-117 barrier), non-ASCII (the
// appendQuotedForLog fallback into strconv.AppendQuote), a quote and a
// backslash in the profile name (the two ASCII characters the fast path
// excludes), the empty profile, and a path past the retention bound.
var sslInnerLineCases = []struct {
	name                             string
	clientIP, method, hostOnly, path string
	match                            *PolicyMatch
}{
	{"NoMatch", "10.1.2.3", "GET", "www.example.com", "/index.html", nil},
	{"MatchNoRule", "10.1.2.3", "GET", "www.example.com", "/index.html", &PolicyMatch{}},
	{"FilteringOff", "10.1.2.3", "POST", "api.example.com", "/v1/upload", &PolicyMatch{Rule: &PolicyRule{}}},
	{"FilteringOn", "10.1.2.3", "GET", "cdn.example.com", "/a.js", ruleWithProfile("executables")},
	{"EmptyProfileName", "10.1.2.3", "GET", "cdn.example.com", "/a.js", ruleWithProfile("")},
	{"IPv6Client", "2001:db8::1", "CONNECT", "www.example.com", "/", ruleWithProfile("archives")},
	{"EmptyPath", "10.1.2.3", "GET", "www.example.com", "", nil},
	{"RootPath", "10.1.2.3", "HEAD", "www.example.com", "/", nil},
	{"QueryInPath", "10.1.2.3", "GET", "s.example.com", "/p/a;b,c=d", nil},
	{"ControlsInPath", "10.1.2.3", "GET", "www.example.com", "/a\nb\rc\td\x01e\x7f", nil},
	{"ControlsInHost", "10.1.2.3", "GET", "ev\nil.example.com", "/x", nil},
	{"ControlsInIP", "10.1.2\n.3", "GET", "www.example.com", "/x", nil},
	{"ControlsInMethod", "10.1.2.3", "G\x01ET", "www.example.com", "/x", nil},
	{"ControlsInProfile", "10.1.2.3", "GET", "w.example.com", "/x", ruleWithProfile("ex\nec\x01s")},
	{"QuoteInProfile", "10.1.2.3", "GET", "w.example.com", "/x", ruleWithProfile(`a"b`)},
	{"BackslashInProfile", "10.1.2.3", "GET", "w.example.com", "/x", ruleWithProfile(`a\b`)},
	{"NonASCIIProfile", "10.1.2.3", "GET", "w.example.com", "/x", ruleWithProfile("exé-cutables")},
	{"NonASCIIHostAndPath", "10.1.2.3", "GET", "xn--bcher-kva.example", "/süß/ü.html", nil},
	{"InvalidUTF8Profile", "10.1.2.3", "GET", "w.example.com", "/x", ruleWithProfile("a\xffb")},
	{"InvalidUTF8Path", "10.1.2.3", "GET", "w.example.com", "/a\xffb", nil},
	{"LongPathPastBound", "10.1.2.3", "GET", "www.example.com", "/" + strings.Repeat("a", maxRetainedRequestPath+64), nil},
	{"PathExactlyAtBound", "10.1.2.3", "GET", "www.example.com", strings.Repeat("b", maxRetainedRequestPath), nil},
	{"LongPathGrowsCarrier", "10.1.2.3", "GET", "www.example.com", "/" + strings.Repeat("c", sslInnerLineInitialCap), nil},
	{"AllEmpty", "", "", "", "", nil},
}

// sslInnerAwkwardStrings are the values that must survive every operand
// position identically. Shapes, not lengths: control bytes (the CWE-117
// barrier), the two ASCII characters appendQuotedForLog's fast path excludes,
// non-ASCII and invalid UTF-8 (the strconv.AppendQuote fallback), a percent
// sign (which would be a format verb if any operand were ever interpolated into
// a format string), and the empty string.
var sslInnerAwkwardStrings = []string{
	"",
	"ordinary",
	"a\nb",
	"a\rb",
	"a\r\nb",
	"a\tb",
	"a\x00b",
	"a\x01b",
	"a\x1fb",
	"a\x7fb",
	`a"b`,
	`a\b`,
	`a"\"b`,
	"a%sb",
	"a%%b",
	"a b",
	"é",
	"süß",
	"a\xffb",
	"\xed\xa0\x80", // lone surrogate: invalid UTF-8
	"a\u00a0b",     // non-breaking space
	"}{",
	"=",
}

// TestSSLInnerLine_RenderIsByteIdentical is the acceptance condition for the
// append form, and it outranks every benchmark in this change. It renders every
// branch through the PRODUCTION emitter and through the frozen format string it
// replaced, and requires the bytes to match exactly.
func TestSSLInnerLine_RenderIsByteIdentical(t *testing.T) {
	for _, c := range sslInnerLineCases {
		t.Run(c.name, func(t *testing.T) {
			want := sslInnerLineLegacy(c.clientIP, c.method, c.hostOnly, c.path, c.match)
			got := captureSSLInnerLine(t, c.clientIP, c.method, c.hostOnly, c.path, c.match)
			if got != want {
				t.Errorf("SSL_INNER line diverged from the frozen format string\n got: %q\nwant: %q", got, want)
			}
		})
	}
}

// TestSSLInnerLine_AwkwardValueInEveryPosition drives each awkward value through
// every string operand in turn, so a mistake confined to one field cannot hide
// behind benign values in the others. This is the shape
// TestPolicyDecisionLine_RenderIsByteIdentical uses for the same reason.
func TestSSLInnerLine_AwkwardValueInEveryPosition(t *testing.T) {
	const (
		baseIP      = "192.168.11.207"
		baseMethod  = "GET"
		baseHost    = "cdn.example.com"
		basePath    = "/assets/app.js"
		baseProfile = "executables"
	)
	for _, v := range sslInnerAwkwardStrings {
		positions := []struct {
			what                             string
			clientIP, method, hostOnly, path string
			profile                          string
		}{
			{"clientIP", v, baseMethod, baseHost, basePath, baseProfile},
			{"method", baseIP, v, baseHost, basePath, baseProfile},
			{"host", baseIP, baseMethod, v, basePath, baseProfile},
			{"path", baseIP, baseMethod, baseHost, v, baseProfile},
			{"profile", baseIP, baseMethod, baseHost, basePath, v},
			{"all", v, v, v, v, v},
		}
		for _, pos := range positions {
			// Both filtering states: the profile operand only reaches the line
			// when FileFiltering is on, and the quoted-empty-profile branch is
			// what the off state renders.
			for _, filtering := range []bool{true, false} {
				match := &PolicyMatch{Rule: &PolicyRule{
					FileFiltering: filtering,
					FileProfile:   FileProfileName(pos.profile),
				}}
				want := sslInnerLineLegacy(pos.clientIP, pos.method, pos.hostOnly, pos.path, match)
				got := captureSSLInnerLine(t, pos.clientIP, pos.method, pos.hostOnly, pos.path, match)
				if got != want {
					t.Fatalf("line diverged (%s=%q, filtering=%v)\n got: %q\nwant: %q",
						pos.what, v, filtering, got, want)
				}
			}
		}
	}
}

// TestSSLInnerLine_PooledCarrierIsNotLeakedBetweenLines pins the pool
// discipline: a carrier is reset to length zero on every Get, so a long line
// cannot leave a tail that a shorter following line then emits. Without the
// [:0] reset this test fails with the previous line's suffix appended.
func TestSSLInnerLine_PooledCarrierIsNotLeakedBetweenLines(t *testing.T) {
	long := "/" + strings.Repeat("x", 600)
	for i := 0; i < 8; i++ {
		// Alternate long and short through the SAME pooled carrier.
		if gotLong := captureSSLInnerLine(t, "10.0.0.1", "GET", "h.example", long, nil); gotLong !=
			sslInnerLineLegacy("10.0.0.1", "GET", "h.example", long, nil) {
			t.Fatalf("long line %d diverged: %q", i, gotLong)
		}
		short := captureSSLInnerLine(t, "10.0.0.1", "GET", "h.example", "/a", nil)
		want := sslInnerLineLegacy("10.0.0.1", "GET", "h.example", "/a", nil)
		if short != want {
			t.Fatalf("short line %d carried a tail from the previous long line\n got: %q\nwant: %q", i, short, want)
		}
	}
}

// TestSSLInnerLine_OversizeCarrierIsNotPooled pins the capacity guard: a line
// past sslInnerLineMaxPooled must not be returned, or one 2 KiB-path request
// would leave every pooled carrier permanently oversized. Asserted through
// behavior — the following lines must still render correctly — plus the
// documented bound itself.
func TestSSLInnerLine_OversizeCarrierIsNotPooled(t *testing.T) {
	if sslInnerLineMaxPooled < sslInnerLineInitialCap {
		t.Fatalf("pool cap guard %d is below the starting capacity %d, so every carrier is discarded",
			sslInnerLineMaxPooled, sslInnerLineInitialCap)
	}
	huge := "/" + strings.Repeat("z", sslInnerLineMaxPooled+512)
	got := captureSSLInnerLine(t, "10.0.0.1", "GET", "h.example", huge, nil)
	if want := sslInnerLineLegacy("10.0.0.1", "GET", "h.example", huge, nil); got != want {
		t.Fatalf("oversize line diverged\n got: %q\nwant: %q", got, want)
	}
	// And the pool still works afterwards.
	got = captureSSLInnerLine(t, "10.0.0.1", "GET", "h.example", "/a", nil)
	if want := sslInnerLineLegacy("10.0.0.1", "GET", "h.example", "/a", nil); got != want {
		t.Fatalf("line after an oversize one diverged\n got: %q\nwant: %q", got, want)
	}
}

// TestSSLInnerLine_ConcurrentEmittersDoNotInterleave pins that the pooled
// carrier is per-emission, not shared state: an inspecting gateway emits this
// line from one goroutine per inner request (per H1 tunnel loop, per H2 stream),
// so a carrier handed to two emitters at once would splice two destinations into
// one line. Every captured line must be one of the expected whole lines.
func TestSSLInnerLine_ConcurrentEmittersDoNotInterleave(t *testing.T) {
	const goroutines, each = 8, 200
	hosts := []string{"a.example", "bb.example", "ccc.example", "dddd.example"}
	paths := []string{"/1", "/" + strings.Repeat("p", 300), "/333", "/" + strings.Repeat("q", 700)}

	want := map[string]bool{}
	for i := range hosts {
		want[sslInnerLineLegacy("10.0.0.1", "GET", hosts[i], paths[i], nil)] = true
	}

	var mu sync.Mutex
	var sink bytes.Buffer
	prev := logger
	logger = log.New(&lockedWriter{w: &sink, mu: &mu}, "", 0)
	defer func() { logger = prev }()

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				k := (g + i) % len(hosts)
				logSSLInnerRequest("10.0.0.1", "GET", hosts[k], paths[k], nil)
			}
		}(g)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSuffix(sink.String(), "\n"), "\n")
	if len(lines) != goroutines*each {
		t.Fatalf("got %d lines, want %d", len(lines), goroutines*each)
	}
	for i, ln := range lines {
		if !want[ln] {
			t.Fatalf("line %d is not a whole expected line (carrier shared across emitters?): %q", i, ln)
		}
	}
}

// lockedWriter serializes writes so the test observes whole lines even though
// the capture sink is a plain buffer.
type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// TestSSLInnerLine_EmitsOneLine pins that the emitter writes exactly one record.
// An append chain that let a raw newline through would forge a second log line,
// which is the whole point of the sanitizeLog barrier — so the control-byte
// cases above are checked for record COUNT as well as for content.
func TestSSLInnerLine_EmitsOneLine(t *testing.T) {
	for _, c := range sslInnerLineCases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := logger
			logger = log.New(&buf, "", 0)
			// Cleanup, not a bare restore: a panic in the emitter would
			// otherwise leave the process logger pointed at this test's buffer
			// for every test that runs after it, which under -shuffle is a
			// different set each run.
			t.Cleanup(func() { logger = prev })
			logSSLInnerRequest(c.clientIP, c.method, c.hostOnly, c.path, c.match)
			if n := bytes.Count(buf.Bytes(), []byte("\n")); n != 1 {
				t.Errorf("emitted %d newlines, want exactly 1 (a forged record): %q", n, buf.String())
			}
			if n := strings.Count(buf.String(), "SSL_INNER"); n != 1 {
				t.Errorf("emitted %d SSL_INNER tokens, want exactly 1: %q", n, buf.String())
			}
		})
	}
}

// TestSSLInnerLine_TypicalLineFitsStartingCapacity documents the sizing claim
// in proxy_sslinner_line.go rather than leaving it as prose: an ordinary
// inspected request's line must fit a fresh carrier, or the steady state pays a
// growth copy per line.
func TestSSLInnerLine_TypicalLineFitsStartingCapacity(t *testing.T) {
	line := sslInnerLineLegacy("192.168.11.207", "GET",
		"cdn.jsdelivr.net", "/npm/chart.js@4.4.1/dist/chart.umd.min.js", ruleWithProfile("executables"))
	if len(line) > sslInnerLineInitialCap {
		t.Errorf("typical SSL_INNER line is %d bytes, starting capacity is %d — the common case grows the carrier",
			len(line), sslInnerLineInitialCap)
	}
	t.Logf("typical line %d bytes, starting capacity %d", len(line), sslInnerLineInitialCap)
}

// FuzzSSLInnerLine drives the differential oracle on arbitrary operands. The
// corpus above is the shapes we thought of; this is the ones we did not.
func FuzzSSLInnerLine(f *testing.F) {
	for _, c := range sslInnerLineCases {
		profile := ""
		filtering := false
		if c.match != nil && c.match.Rule != nil {
			profile, filtering = string(c.match.Rule.FileProfile), c.match.Rule.FileFiltering
		}
		f.Add(c.clientIP, c.method, c.hostOnly, c.path, profile, filtering)
	}
	f.Fuzz(func(t *testing.T, clientIP, method, hostOnly, path, profile string, filtering bool) {
		// Bound the inputs so the fuzzer spends its budget on byte SHAPES rather
		// than on length: the retention bound is exercised by the corpus case.
		if len(clientIP)+len(method)+len(hostOnly)+len(path)+len(profile) > 4096 {
			t.Skip()
		}
		match := &PolicyMatch{Rule: &PolicyRule{FileFiltering: filtering, FileProfile: FileProfileName(profile)}}
		want := sslInnerLineLegacy(clientIP, method, hostOnly, path, match)
		got := captureSSLInnerLine(t, clientIP, method, hostOnly, path, match)
		if got != want {
			t.Fatalf("render diverged\n got: %q\nwant: %q", got, want)
		}
		// One record, always: a raw newline reaching the buffer would forge a
		// second log line, which is what the sanitizeLog barrier exists to stop.
		if strings.Contains(got, "\n") {
			t.Fatalf("rendered line contains a newline (forged record): %q", got)
		}
	})
}
