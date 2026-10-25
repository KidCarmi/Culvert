package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/KidCarmi/Culvert/internal/fileblock"
)

// ─── CHAOS-92 — the client-supplied request PATH, where it is retained ───
//
// Register row PX-22 / X-1. `r.URL.Path` reached the process log, a BUFFERED
// HTML response body and the request-log URI with no bound, on a stock install
// (the shipped fileblock.DefaultBlockedExts contains ".exe") and before
// authentication. Measured through the real handleRequest against the pre-fix
// tree: a 1 048 581-byte path wrote 1 048 636 bytes to the process log and
// served a 5 245 731-byte block page when filled with `'`, because
// html/template escapes it to `&#39;`. Wire-verified deliverable: that target
// arrives as r.URL.Path byte for byte through a real net/http server.
//
// The gates split the same way CHAOS-69's do. TestChaos92_Defect* FAIL against
// the pre-fix tree. TestChaos92_Control* prove the clamp did not break the
// plane it sits in — and one of them, ControlEnforcementStillSeesTheWholePath,
// is the load-bearing one: clamping the value a MATCHER decides on would be
// fail-open, because truncating the end of a path removes the extension a
// file-block rule matches.

// chaos92Path builds a path of exactly n bytes ending in ".exe", filled with
// fill. The extension is what makes the FILE_BLOCKED branch fire on a stock
// install, and the fill is what sets the block page's escaping multiplier.
func chaos92Path(n int, fill string) string {
	const tail = ".exe"
	body := n - 1 - len(tail)
	if body < 0 {
		body = 0
	}
	return "/" + strings.Repeat(fill, body) + tail
}

// chaos92CaptureLog swaps the process logger for a buffer and restores it.
func chaos92CaptureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = prev })
	return &buf
}

// chaos92Isolate resets the proxy globals, installs the SHIPPED default
// extension list (so every gate below measures a stock install rather than a
// hand-built one) and clears this sweep's process-global counter.
func chaos92Isolate(t *testing.T) {
	t.Helper()
	setupProxyTest(t)
	isolateLogRing(t)
	orig := fileBlocker
	fb := fileblock.NewBlocker()
	for _, ext := range fileblock.DefaultBlockedExts {
		fb.Add(ext)
	}
	fileBlocker = fb
	t.Cleanup(func() { fileBlocker = orig })
	resetRetainedPathStateForTest()
	t.Cleanup(resetRetainedPathStateForTest)
}

// chaos92Request drives the real handleRequest with a client-chosen path and
// returns the recorder plus the captured process log.
func chaos92Request(t *testing.T, path string) (*httptest.ResponseRecorder, *bytes.Buffer) {
	t.Helper()
	logBuf := chaos92CaptureLog(t)
	r := makeRequest("http://example.com/placeholder.exe", nil)
	r.URL.Path = path
	w := httptest.NewRecorder()
	handleRequest(w, r)
	return w, logBuf
}

// chaos92PackageSources returns the package's non-test .go files, read through
// ABSOLUTE paths anchored to the package source dir. A CWD-relative
// filepath.Glob/os.ReadFile here would be the exact hazard
// TestTestFileReadsAreCWDIndependent (static_read_wall_test.go) walls off: a
// concurrent os.Chdir makes the scan read the wrong tree and the gate flakes.
func chaos92PackageSources(t *testing.T) map[string]string {
	t.Helper()
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		out[name] = string(b)
	}
	if len(out) == 0 {
		t.Fatal("found no package sources — the anchor is wrong and the gates below are vacuous")
	}
	return out
}

// ───────────────────────── DEFECT GATES ─────────────────────────

// TestChaos92_DefectProcessLogStaysBounded is the first half of the primary
// gate: one unauthenticated request must not be able to choose how many bytes
// land in the rotating process log. Pre-fix a 1 MiB path wrote 1 048 636 bytes.
func TestChaos92_DefectProcessLogStaysBounded(t *testing.T) {
	chaos92Isolate(t)
	_, logBuf := chaos92Request(t, chaos92Path(1024*1024, "A"))

	// The line carries the clamped path plus the host, the client IP, the
	// extension and the marker. 8 KiB is loose enough not to be a restatement
	// of the constant and tight enough to fail by two orders of magnitude
	// against the pre-fix tree.
	if logBuf.Len() > 8*1024 {
		t.Errorf("process log = %d bytes from ONE request, want <= 8192 — the client is choosing the log volume", logBuf.Len())
	}
	if !strings.Contains(logBuf.String(), "FILE_BLOCKED") {
		t.Fatalf("the FILE_BLOCKED branch was not reached, so this gate proved nothing; log = %q", truncForMsg(logBuf.String()))
	}
	if !strings.Contains(logBuf.String(), "truncated") {
		t.Errorf("the log line does not say it was truncated — a clamped line that reads as complete is a new evidence defect; log = %q", truncForMsg(logBuf.String()))
	}
}

// TestChaos92_DefectBlockPageDoesNotAmplifyTheClientPath is the second and
// larger half: the block page renders the path through html/template, so the
// client picks the multiplier. Pre-fix, 1 MiB of `'` produced a 5 245 731-byte
// body — buffered in memory in full, then written back, per concurrent request.
func TestChaos92_DefectBlockPageDoesNotAmplifyTheClientPath(t *testing.T) {
	chaos92Isolate(t)
	// `'` is the worst case: html/template escapes it to the 5-byte `&#39;`,
	// and RFC 3986 lists it as a sub-delim so it needs no percent-encoding —
	// one wire byte buys five retained ones.
	w, _ := chaos92Request(t, chaos92Path(1024*1024, "'"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — the file-block branch was not reached, so this gate proved nothing", w.Code)
	}
	if w.Body.Len() > 64*1024 {
		t.Errorf("block page = %d bytes for a 1 MiB path, want <= 65536 — the response body is a client-chosen amplifier", w.Body.Len())
	}
}

// TestChaos92_DefectRequestLogURINeverRetainsAnUnboundedPath covers the third
// sink. LogEntry.URI reaches the in-memory ring, the persisted JSONL, the
// syslog/SIEM feed and the redaction pipeline, and policyLogURI is its single
// derivation.
func TestChaos92_DefectRequestLogURINeverRetainsAnUnboundedPath(t *testing.T) {
	chaos92Isolate(t)

	uri := policyLogURI("example.com", chaos92Path(1024*1024, "A"))
	if len(uri) > maxRetainedBlockPageURL {
		t.Errorf("policyLogURI returned %d bytes, want <= %d — an unbounded URI is retained in the ring, the JSONL and the SIEM feed", len(uri), maxRetainedBlockPageURL)
	}
	if !strings.HasPrefix(uri, "example.com/") {
		t.Errorf("uri = %q, want the host and the leading path preserved — a clamp that loses the destination loses the evidence", truncForMsg(uri))
	}

	// And end to end, through the recorder that populates the field.
	recordRequestLogOnly("1.2.3.4", "GET", "example.com", "OK", "r", "Allow", "alice", "inspect", uri, AuthLogFields{})
	entries := logGet()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}
	if len(entries[0].URI) > maxRetainedBlockPageURL {
		t.Errorf("retained LogEntry.URI = %d bytes, want <= %d", len(entries[0].URI), maxRetainedBlockPageURL)
	}
}

// TestChaos92_DefectPolicyProfileFileBlockIsBounded covers the SECOND
// file-block site, the one a matched policy rule's file profile reaches. A gate
// proven only against the global extension list would leave the policy-driven
// twin — same two sinks, different branch — unproven.
func TestChaos92_DefectPolicyProfileFileBlockIsBounded(t *testing.T) {
	chaos92Isolate(t)
	snapshotPolicyStoreForTest(t)
	// A rule that allows the destination but blocks executables by profile, so
	// the request reaches applyPolicyDecision's file-profile branch rather than
	// preDispatchBlocked's global list.
	fileBlocker = fileblock.NewBlocker() // global list empty: the profile must be what blocks
	policyStore.mu.Lock()
	policyStore.rules = []*PolicyRule{{
		Priority:      1,
		Name:          "allow-with-exe-profile",
		DestFQDN:      "*",
		Action:        ActionAllow,
		FileFiltering: true,
		FileProfile:   FileProfileExecutables,
	}}
	policyStore.mu.Unlock()
	setDefaultPolicyAction("allow")

	w, logBuf := chaos92Request(t, chaos92Path(1024*1024, "'"))
	if !strings.Contains(logBuf.String(), "FILE_BLOCKED (policy profile)") {
		t.Fatalf("the policy-profile branch was not reached, so this gate proved nothing; log = %q", truncForMsg(logBuf.String()))
	}
	if logBuf.Len() > 8*1024 {
		t.Errorf("process log = %d bytes, want <= 8192", logBuf.Len())
	}
	if w.Body.Len() > 64*1024 {
		t.Errorf("block page = %d bytes, want <= 65536", w.Body.Len())
	}
}

// TestChaos92_DefectEveryRetainingSinkGoesThroughTheClamp is the gate that
// outlives the five call sites. The finding is not "these lines are wrong", it
// is "nothing bounds this value", so a new sink added later would reintroduce
// it silently. This reads the package source and requires every log site that
// sanitizes a URL path to clamp it FIRST — clamping after sanitizeLog would
// bound the retained bytes but still pay the 1 MiB scan and copy.
func TestChaos92_DefectEveryRetainingSinkGoesThroughTheClamp(t *testing.T) {
	// A log site that sanitizes a URL path must clamp it INSIDE the
	// sanitizeLog argument, so the scan and its possible 1 MiB copy are bounded
	// too — clamping afterwards would bound the retained bytes and still pay
	// for the value in full.
	wrapped := regexp.MustCompile(`sanitizeLog\(boundRetainedPath\([^()]*\bURL\.Path\)\)`)
	var bad []string
	checked := 0
	for name, src := range chaos92PackageSources(t) {
		for i, line := range strings.Split(src, "\n") {
			if !strings.Contains(line, "sanitizeLog(") || !strings.Contains(line, "URL.Path") {
				continue
			}
			checked++
			if !wrapped.MatchString(line) {
				bad = append(bad, fmt.Sprintf("%s:%d: a URL path is sanitized without boundRetainedPath — the retained bytes are client-chosen", name, i+1))
			}
		}
	}
	sort.Strings(bad)
	if checked == 0 {
		t.Fatal("found no sanitizeLog site carrying a URL path at all — the pattern drifted and this gate is now vacuous")
	}
	if len(bad) > 0 {
		t.Errorf("%d of %d URL.Path log sites are unbounded:\n%s", len(bad), checked, strings.Join(bad, "\n"))
	}
}

// TestChaos92_DefectBlockPageClampIsTheChokepointNotTheCallSites pins the other
// half of the same structural claim: internal/blockpage.Serve must be reached
// only through the clamping wrapper, so a sixth block-page call site cannot
// bypass the bound by construction rather than by review.
func TestChaos92_DefectBlockPageClampIsTheChokepointNotTheCallSites(t *testing.T) {
	const chokepoint = "blockpage_vars.go"
	sources := chaos92PackageSources(t)
	var stray []string
	for name, src := range sources {
		n := strings.Count(src, "blockpage.Serve(")
		if n > 0 && name != chokepoint {
			stray = append(stray, fmt.Sprintf("%s calls blockpage.Serve directly (%d time(s))", name, n))
		}
	}
	sort.Strings(stray)
	if len(stray) > 0 {
		t.Errorf("block-page sinks bypass the clamp:\n%s\nEvery caller must go through serveBlockPage, which is where the CHAOS-92 clamp lives", strings.Join(stray, "\n"))
	}
	if n := strings.Count(sources[chokepoint], "blockpage.Serve("); n != 1 {
		t.Fatalf("%s has %d blockpage.Serve calls, want exactly 1 — the chokepoint moved and this gate is stale", chokepoint, n)
	}
	if !strings.Contains(sources[chokepoint], "boundRetainedBlockPageURL(url)") {
		t.Error("serveBlockPage does not clamp its url argument — every block-page sink is unbounded")
	}
}

// TestChaos92_DefectPathIsDeliverableAtOneMiBOverTheWire is the wire-realism
// control the SEC-REQID-2 correction exists to require: a bound justified by a
// length httptest can construct but the wire cannot deliver proves nothing.
// This drives a REAL net/http server over a REAL socket.
func TestChaos92_DefectPathIsDeliverableAtOneMiBOverTheWire(t *testing.T) {
	got := make(chan int, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- len(r.URL.Path)
	}))
	defer srv.Close()

	// (&net.Dialer{}).DialContext, not net.Dial: the noctx linter in
	// .golangci.yml rejects uncontextual I/O, and this is the idiom the sibling
	// wire test cited above (bootstrap_host_injection_test.go) already uses.
	c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// A deadline so a server that never answers fails this gate outright rather
	// than hanging until the package timeout — t.Context() cancels at test end
	// but does not interrupt a blocking Read already in flight on the conn.
	if err := c.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Raw `'`: a sub-delim (RFC 3986 §2.2), so no percent-encoding is needed
	// and one wire byte buys one retained byte — then five, after escaping.
	target := chaos92Path(1024*1024, "'")
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", target); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("no response to a 1 MiB request target: %v", err)
	}
	select {
	case n := <-got:
		if n != len(target) {
			t.Errorf("delivered r.URL.Path = %d bytes, sent %d — the measurement's premise is wrong", n, len(target))
		}
	default:
		t.Errorf("a 1 MiB request target did not reach the handler (%q) — if net/http starts refusing it, the gates above are measuring an unreachable case and the finding needs re-stating", strings.TrimSpace(line))
	}
}

// ───────────────────────── CONTROL GATES ─────────────────────────

// TestChaos92_ControlEnforcementStillSeesTheWholePath is the load-bearing
// control. The clamp is on RETENTION only; if it ever reached the matcher, a
// long path ending ".exe" would stop being blocked — a fail-open regression
// strictly worse than the amplification it would be fixing.
func TestChaos92_ControlEnforcementStillSeesTheWholePath(t *testing.T) {
	chaos92Isolate(t)
	w, logBuf := chaos92Request(t, chaos92Path(1024*1024, "A"))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 — a 1 MiB path ending .exe must still be FILE_BLOCKED", w.Code)
	}
	if !strings.Contains(logBuf.String(), "FILE_BLOCKED") {
		t.Error("no FILE_BLOCKED decision for a 1 MiB .exe path — the clamp reached the matcher and the gate is fail-OPEN")
	}
	if !strings.Contains(logBuf.String(), `(ext=".exe")`) {
		t.Errorf("the recorded extension is not .exe — the matcher saw a truncated path; log = %q", truncForMsg(logBuf.String()))
	}
}

// TestChaos92_ControlOrdinaryPathIsRetainedVerbatim proves the clamp is
// invisible to real traffic: an ordinary path must be byte-identical in every
// sink, with no marker and no counter movement.
func TestChaos92_ControlOrdinaryPathIsRetainedVerbatim(t *testing.T) {
	chaos92Isolate(t)
	const p = "/downloads/releases/v2.11.4/installer.exe"
	w, logBuf := chaos92Request(t, p)

	if !strings.Contains(logBuf.String(), p) {
		t.Errorf("the ordinary path is not in the log line verbatim; log = %q", truncForMsg(logBuf.String()))
	}
	if strings.Contains(logBuf.String(), "truncated") {
		t.Error("an ordinary path was reported as truncated")
	}
	if !strings.Contains(w.Body.String(), p) {
		t.Error("the block page does not name the ordinary path — the operator-facing page lost its evidence")
	}
	if got := policyLogURI("example.com", p); got != "example.com"+p {
		t.Errorf("policyLogURI = %q, want %q", got, "example.com"+p)
	}
	if n := retainedPathTruncated.Load(); n != 0 {
		t.Errorf("retainedPathTruncated = %d after ordinary traffic, want 0 — the counter is not a usable signal if normal traffic moves it", n)
	}
}

// TestChaos92_ControlBoundIsInclusiveAndAccounted pins the boundary exactly and
// proves a clamp is visible to an operator in aggregate, not only inline.
func TestChaos92_ControlBoundIsInclusiveAndAccounted(t *testing.T) {
	resetRetainedPathStateForTest()
	t.Cleanup(resetRetainedPathStateForTest)

	atCap := "/" + strings.Repeat("a", maxRetainedRequestPath-1)
	if len(atCap) != maxRetainedRequestPath {
		t.Fatalf("test fixture is %d bytes, want %d", len(atCap), maxRetainedRequestPath)
	}
	if got := boundRetainedPath(atCap); got != atCap {
		t.Errorf("a path of exactly maxRetainedRequestPath was clamped — the bound must be inclusive")
	}
	if n := retainedPathTruncated.Load(); n != 0 {
		t.Errorf("retainedPathTruncated = %d, want 0", n)
	}

	overCap := atCap + "b"
	got := boundRetainedPath(overCap)
	if got == overCap {
		t.Fatal("a path one byte over the bound was retained whole")
	}
	if !strings.HasPrefix(got, atCap) {
		t.Error("the clamp did not keep the leading bytes")
	}
	if want := fmt.Sprintf(retainedPathTruncationMarker, len(overCap)); !strings.HasSuffix(got, want) {
		t.Errorf("marker = %q, want suffix %q — an operator cannot tell how much was dropped", truncForMsg(got), want)
	}
	if n := retainedPathTruncated.Load(); n != 1 {
		t.Errorf("retainedPathTruncated = %d, want 1 — the clamp is invisible in aggregate", n)
	}
}

// TestChaos92_ControlCutLandsOnAUTF8Boundary pins the cut-site correction. A
// path arrives percent-decoded, so it can carry multi-byte runes; a cut through
// one would put invalid UTF-8 into a record that is JSON-encoded downstream,
// where encoding/json substitutes U+FFFD and changes the bytes an investigator
// reads.
func TestChaos92_ControlCutLandsOnAUTF8Boundary(t *testing.T) {
	resetRetainedPathStateForTest()
	t.Cleanup(resetRetainedPathStateForTest)

	// Straddle the cut with every multi-byte width, by shifting the run of
	// runes across the boundary one byte at a time.
	for _, r := range []string{"é" /*2*/, "€" /*3*/, "𐍈" /*4*/} {
		for shift := 0; shift < 4; shift++ {
			head := strings.Repeat("a", maxRetainedRequestPath-2+shift)
			p := "/" + head + strings.Repeat(r, 8)
			got := boundRetainedPath(p)
			marker := fmt.Sprintf(retainedPathTruncationMarker, len(p))
			kept := strings.TrimSuffix(got, marker)
			if kept == got {
				t.Fatalf("rune %q shift %d: no marker on a clamped value", r, shift)
			}
			if !utf8.ValidString(kept) {
				t.Errorf("rune %q shift %d: the clamp cut through a rune — retained %d bytes of invalid UTF-8", r, shift, len(kept))
			}
			if len(kept) > maxRetainedRequestPath {
				t.Errorf("rune %q shift %d: kept %d bytes, over the %d bound", r, shift, len(kept), maxRetainedRequestPath)
			}
		}
	}
}

// TestChaos92_ControlBlockPageBoundCoversTheComposedValue proves the chokepoint
// bounds whatever a caller passes, including a composition this package does
// not currently build — which is the reason the clamp is in the wrapper and not
// at the call sites.
func TestChaos92_ControlBlockPageBoundCoversTheComposedValue(t *testing.T) {
	resetRetainedPathStateForTest()
	t.Cleanup(resetRetainedPathStateForTest)

	w := httptest.NewRecorder()
	serveBlockPage(w, strings.Repeat("'", 1024*1024), "File Block", ".exe")
	if w.Body.Len() > 64*1024 {
		t.Errorf("block page = %d bytes from a composed 1 MiB url, want <= 65536", w.Body.Len())
	}
	if n := retainedPathTruncated.Load(); n != 1 {
		t.Errorf("retainedPathTruncated = %d, want 1", n)
	}
}

// TestChaos92_ControlMetricIsExported proves the counter has an operator-facing
// surface. A bound whose only evidence is an inline marker in a rotating log is
// not monitorable, which is the signal-inversion failure this register keeps
// recording.
func TestChaos92_ControlMetricIsExported(t *testing.T) {
	resetRetainedPathStateForTest()
	t.Cleanup(resetRetainedPathStateForTest)
	boundRetainedPath("/" + strings.Repeat("a", maxRetainedRequestPath+1))

	var sb strings.Builder
	liveFeedWritePrometheus(&sb)
	body := sb.String()
	if !strings.Contains(body, "culvert_retained_path_truncated_total 1") {
		t.Errorf("the /metrics output does not carry culvert_retained_path_truncated_total 1")
	}
	if !strings.Contains(body, "# TYPE culvert_retained_path_truncated_total counter") {
		t.Error("the series has no TYPE line")
	}
}

// TestChaos92_ControlCounterReachesTheAdminSurfacesToo extends ControlMetricIsExported
// to the two surfaces an operator without a metrics scraper actually has. The
// SEC-REQID-1 precedent is the right one to follow here and the CHAOS-69 one is
// not: an oversize AUTHORITY is refused with a 400, so the caller sees it, while
// a clamped path leaves a request that succeeded and a policy verdict formed on
// the whole value — nothing else changes that an admin would notice.
func TestChaos92_ControlCounterReachesTheAdminSurfacesToo(t *testing.T) {
	resetRetainedPathStateForTest()
	t.Cleanup(resetRetainedPathStateForTest)
	boundRetainedPath("/" + strings.Repeat("a", maxRetainedRequestPath+1))

	w := httptest.NewRecorder()
	r := adminCtx(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/stats", http.NoBody))
	apiStats(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("/api/stats status = %d", w.Code)
	}
	var stats map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatalf("decode /api/stats: %v", err)
	}
	if stats["retainedPathTruncated"] != float64(1) {
		t.Errorf("/api/stats retainedPathTruncated = %v, want 1 — an operator without a metrics scraper cannot see the probing", stats["retainedPathTruncated"])
	}

	// And the legacy panel that renders it, so the server-side field is not a
	// number nothing displays. The element id and the JSON key are the contract
	// between the two halves.
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`id="s-retained-path-truncated"`, "s.retainedPathTruncated"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("static/index.html does not carry %s — the counter has an API field with no UI surface", want)
		}
	}
}

// truncForMsg keeps a failure message readable. A gate for a write-amplification
// defect must not dump a megabyte into the test log to report itself — the §32
// rule, applied to this file's own output.
func truncForMsg(s string) string {
	if len(s) <= 200 {
		return s
	}
	return s[:200] + fmt.Sprintf("...[+%d B]", len(s)-200)
}
