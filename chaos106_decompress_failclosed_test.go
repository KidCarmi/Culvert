package main

// CHAOS-106 — the response path refuses a disproportionate expansion.
//
// internal/secscan owns the bound and its unit gates
// (decompress_ratio_chaos_test.go). These are the main-side half: the bound is
// only a defense if every caller that asks for an expansion actually FAILS
// CLOSED when it is refused. A caller that ignored the refusal and scanned the
// compressed bytes instead would turn the bound into a scanner bypass — the
// attacker would choose the ratio that silences the scanners.
//
// Both production response paths are covered, because the origin picks which
// one it is on: the SSL-inspect path (scanInspectBody, the primary SWG path)
// and the plain-HTTP path (scanHTTPResponseBody). Each gate carries its own
// negative control, since a change that blocked all compressed traffic would
// also pass the positive assertion.

import (
	"bytes"
	"compress/gzip"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// chaos106ScanWindow is wide enough to buffer the whole fixture below, so the
// refusal under test is the EXPANSION bound and never the scan window: a
// window-truncated gzip stream fails to decompress at all and would take the
// pre-existing fallback path instead, proving nothing.
const chaos106ScanWindow = 1 << 20

// chaos106Bomb returns a gzip stream of ~20 MiB of zeros. That compresses to
// roughly 20 KiB, which is both inside chaos106ScanWindow and past the point
// where secscan's small-response floor decides, so the ratio bound is what
// refuses it.
func chaos106Bomb(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(make([]byte, 20<<20)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if int64(buf.Len()) > chaos106ScanWindow {
		t.Fatalf("fixture compressed to %d bytes, past the %d scan window — the window would refuse it first",
			buf.Len(), int64(chaos106ScanWindow))
	}
	return buf.Bytes()
}

// chaos106Gzip returns a gzip stream of ordinary, honestly-compressible
// content: the negative control every gate below needs.
func chaos106Gzip(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// closeSpyBody records whether the pipeline closed the origin body. A refusal
// that leaked the upstream body would hold a connection and its buffers for
// the client's own timeout, which is the regime the refusal exists to avoid.
type closeSpyBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *closeSpyBody) Close() error { b.closed.Store(true); return nil }

// ─── SSL-inspect path (the primary SWG path) ─────────────────────────────────

func chaos106InspectFixture(t *testing.T, body []byte, encoding string) (*spyResponder, *closeSpyBody, scanBodyOutcome) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://cdn.example.com/payload.bin", http.NoBody)
	spyBody := &closeSpyBody{Reader: bytes.NewReader(body)}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":     []string{"application/octet-stream"},
			"Content-Encoding": []string{encoding},
		},
		ContentLength: int64(len(body)),
		Body:          spyBody,
	}
	br := &spyResponder{}
	out := scanInspectBody(req, req, resp, br, nil, ProxyIdentity{ClientIP: "198.51.100.44"}, "cdn.example.com", nil)
	return br, spyBody, out
}

func TestCHAOS106_ScanInspectBody_RefusesADisproportionateExpansion(t *testing.T) {
	withScanLimit(t, chaos106ScanWindow)

	before := secscan.Counters().DecompressBombs
	br, spyBody, out := chaos106InspectFixture(t, chaos106Bomb(t), "gzip")

	if out != scanBlocked {
		t.Fatalf("outcome = %v, want scanBlocked — the inspect path admitted a response no scanner could read", out)
	}
	if br.calls != 1 {
		t.Errorf("block emissions = %d, want exactly 1 through the responder choke point", br.calls)
	}
	if !spyBody.closed.Load() {
		t.Error("the origin body was not closed on the refusal path")
	}
	if got := secscan.Counters().DecompressBombs - before; got != 1 {
		t.Errorf("DecompressBombs delta = %d, want 1 — the refusal must be countable", got)
	}
}

// Negative control: ordinary compressed traffic still reaches the client, and
// the reassembled body is byte-identical to what the origin sent. Without this,
// a change that refused every Content-Encoding would pass the gate above.
func TestCHAOS106_ScanInspectBody_StillDeliversOrdinaryGzip(t *testing.T) {
	withScanLimit(t, chaos106ScanWindow)

	payload := bytes.Repeat([]byte("ordinary page content, honestly compressible\n"), 64)
	wire := chaos106Gzip(t, payload)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://cdn.example.com/page.html", http.NoBody)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":     []string{"application/octet-stream"},
			"Content-Encoding": []string{"gzip"},
		},
		ContentLength: int64(len(wire)),
		Body:          io.NopCloser(bytes.NewReader(wire)),
	}
	br := &spyResponder{}
	out := scanInspectBody(req, req, resp, br, nil, ProxyIdentity{ClientIP: "198.51.100.45"}, "cdn.example.com", nil)
	t.Cleanup(func() { _ = resp.Body.Close() })

	if out != scanClean {
		t.Fatalf("outcome = %v, want scanClean for ordinary gzip", out)
	}
	if br.calls != 0 {
		t.Errorf("block emissions = %d, want 0 — ordinary compressed traffic must not be blocked", br.calls)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reassembled body read: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Errorf("reassembled body is not the wire bytes: got %d, want %d", len(got), len(wire))
	}
}

// ─── Plain-HTTP path ─────────────────────────────────────────────────────────

func TestCHAOS106_ScanHTTPResponseBody_RefusesADisproportionateExpansion(t *testing.T) {
	withScanLimit(t, chaos106ScanWindow)

	wire := chaos106Bomb(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://files.example.com/archive.bin", http.NoBody)
	r.RemoteAddr = "198.51.100.46:5560"
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Encoding": []string{"gzip"}},
		ContentLength: -1, // chunked: the shape that skips every pre-check
		Body:          io.NopCloser(bytes.NewReader(wire)),
	}
	w := httptest.NewRecorder()

	before := secscan.Counters().DecompressBombs
	handled, readErr := scanHTTPResponseBody(w, r, resp, ProxyIdentity{})

	if !handled {
		t.Fatal("handled = false — the plain-HTTP path forwarded a response no scanner could read")
	}
	if readErr != nil {
		t.Errorf("upstreamReadErr = %v, want nil: a refusal is this node's decision, not an upstream fault, and must not charge the upstream breaker", readErr)
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if bytes.Contains(w.Body.Bytes(), wire[:16]) {
		t.Error("the refused response body leaked into the block page")
	}
	if got := secscan.Counters().DecompressBombs - before; got != 1 {
		t.Errorf("DecompressBombs delta = %d, want 1", got)
	}
}

func TestCHAOS106_ScanHTTPResponseBody_StillDeliversOrdinaryGzip(t *testing.T) {
	withScanLimit(t, chaos106ScanWindow)

	payload := bytes.Repeat([]byte("ordinary page content, honestly compressible\n"), 64)
	wire := chaos106Gzip(t, payload)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://files.example.com/page.html", http.NoBody)
	r.RemoteAddr = "198.51.100.47:5561"
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Encoding": []string{"gzip"}},
		ContentLength: -1,
		Body:          io.NopCloser(bytes.NewReader(wire)),
	}
	w := httptest.NewRecorder()

	handled, readErr := scanHTTPResponseBody(w, r, resp, ProxyIdentity{})
	if handled {
		t.Fatalf("ordinary gzip was handled (blocked); recorder status %d", w.Code)
	}
	if readErr != nil {
		t.Errorf("upstreamReadErr = %v, want nil", readErr)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reassembled body read: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Errorf("reassembled body is not the wire bytes: got %d, want %d", len(got), len(wire))
	}
}

// ─── The structural half ─────────────────────────────────────────────────────

// Every decompressForScan call site must handle the refusal. This is a SOURCE
// gate for the same reason cp_grpc_bind_chaos_test.go bans logFatalf
// structurally: a reintroduced caller that discarded the refusal with `_`
// would compile, pass every behavioural test above (which exercise only the
// two paths that exist today), and silently reopen the bypass. The compiler
// already forces a second return value to be received; what it cannot force
// is that the value be CONSULTED.
//
// It enumerates EVERY non-test file in the package rather than the list of
// files that call the seam today. A list is the shape that fails on the call
// site nobody has written yet: a future response path in a NEW file — an H3
// leg, a second CDR stage, a request-direction scan — that bound the refusal
// to `_` would appear in no list, so the wall would report a clean gate while
// the expansion bound was bypassed on that path. Discovery also removes the
// vacuous pass: chaos106RefusalFloor is asserted as a floor, so a wall that
// stops finding the call sites it was written for fails instead of passing.

// chaos106RefusalFloor names the files that must each still carry at least one
// conforming call site. It is a FLOOR, not a filter — every other non-test
// file in the package is checked the same way.
var chaos106RefusalFloor = []string{"proxy_tunnel.go", "proxy_http.go", "cdr_proxy.go"}

func TestCHAOS106_EveryDecompressCallSiteConsultsTheRefusal(t *testing.T) {
	// Anchored to the package directory via pkgSourceDir() rather than the
	// process CWD — the requirement static_read_wall_test.go enforces for
	// every structural wall.
	dir := pkgSourceDir()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir %q: %v", dir, err)
	}
	sites := map[string]int{}
	var violations []string
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		n, v := chaos106CallSiteViolations(fset, f)
		sites[name] = n
		violations = append(violations, v...)
	}
	for _, v := range violations {
		t.Errorf("CHAOS-106 expansion bound: %s", v)
	}
	for _, want := range chaos106RefusalFloor {
		if sites[want] == 0 {
			t.Errorf("%s no longer calls decompressForScan: either the response path moved (re-anchor chaos106RefusalFloor) or that path stopped consulting the expansion bound", want)
		}
	}
}

// chaos106CallSiteViolations reports how many decompressForScan call sites one
// parsed file holds, and which of them do not fail closed on the refusal. A
// conforming site assigns BOTH results, names the second one, and branches on
// that name inside the FUNCTION that holds the call.
//
// The branch is scoped to the enclosing function rather than to the file,
// because `bomb` is the name every conforming site already uses. Under a
// file-wide search the FIRST conforming site in a file licenses every later
// site in that file to bind the same name and never branch on it — so the wall
// reports a clean gate for a file that contains a live bypass. That is not a
// hypothetical shape: a second response path is most likely to be added to
// proxy_tunnel.go, which is exactly the file that already carries `if bomb {`.
// Proved in both directions by
// TestCHAOS106_CallSiteWallScopesTheBranchToItsOwnFunction.
func chaos106CallSiteViolations(fset *token.FileSet, f *ast.File) (sites int, violations []string) {
	conforming := map[token.Pos]bool{}
	refused := map[token.Pos]string{}

	// classify judges every call site in ONE function scope. A nested function
	// literal gets its own scope, so a refusal bound inside a closure is not
	// excused by an `if` on the same name in the enclosing function — that is a
	// different variable. A call site in no function at all (a package-level
	// var initializer) is classified by neither branch here and therefore
	// reaches the counting pass below as a violation, which is correct: there
	// is nothing there that could fail closed.
	var classify func(scope ast.Node)
	classify = func(scope ast.Node) {
		ast.Inspect(scope, func(n ast.Node) bool {
			if lit, ok := n.(*ast.FuncLit); ok && ast.Node(lit) != scope {
				classify(lit)
				return false
			}
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Rhs) != 1 {
				return true
			}
			call, ok := as.Rhs[0].(*ast.CallExpr)
			if !ok || !chaos106IsDecompressCall(call) {
				return true
			}
			if len(as.Lhs) != 2 {
				refused[call.Pos()] = "does not bind both results as (bytes, refused), so the refusal is not even received"
				return true
			}
			id, ok := as.Lhs[1].(*ast.Ident)
			switch {
			case !ok || id.Name == "_":
				refused[call.Pos()] = "discards the decompression refusal; a dropped refusal turns the CHAOS-106 expansion bound into a scanner bypass, with the attacker choosing the ratio that silences the scanners"
			case !chaos106BranchesOn(scope, id.Name):
				refused[call.Pos()] = "binds the refusal to " + id.Name + " but no `if` in the function that holds the call branches on it, so nothing fails closed"
			default:
				conforming[call.Pos()] = true
			}
			return true
		})
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
			classify(fd.Body)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !chaos106IsDecompressCall(call) {
			return true
		}
		sites++
		if conforming[call.Pos()] {
			return true
		}
		where := fset.Position(call.Pos()).String()
		if why, ok := refused[call.Pos()]; ok {
			violations = append(violations, where+": "+why)
			return true
		}
		violations = append(violations, where+": decompressForScan is called outside a two-value assignment, so no caller can consult the refusal")
		return true
	})
	return sites, violations
}

// chaos106IsDecompressCall reports whether call is a direct call of the
// package-level decompressForScan seam (security_scan.go).
func chaos106IsDecompressCall(call *ast.CallExpr) bool {
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == "decompressForScan"
}

// chaos106BranchesOn reports whether any if-condition within scope tests name.
// Kept permissive on the SHAPE of the condition (`if bomb`, `if bomb || x`) and
// on WHERE inside the scope it sits (a closure defined in the same function
// counts), and strict on its absence, which is the only thing that reopens the
// bypass. scope is one function body, not the file: see
// chaos106CallSiteViolations.
func chaos106BranchesOn(scope ast.Node, name string) bool {
	found := false
	ast.Inspect(scope, func(n ast.Node) bool {
		if found {
			return false
		}
		is, ok := n.(*ast.IfStmt)
		if !ok || is.Cond == nil {
			return true
		}
		ast.Inspect(is.Cond, func(c ast.Node) bool {
			if id, ok := c.(*ast.Ident); ok && id.Name == name {
				found = true
			}
			return !found
		})
		return true
	})
	return found
}

// TestCHAOS106_CallSiteWallRejectsADiscardedRefusal is the wall's own negative
// control. A structural gate that quietly stopped matching would read exactly
// like a clean one, so each banned shape is proved to fail it and the
// permitted shape is proved to pass — including the over-strictness control,
// since a wall that rejected the conforming shape would be removed rather than
// fixed.
func TestCHAOS106_CallSiteWallRejectsADiscardedRefusal(t *testing.T) {
	for _, tc := range []struct {
		name          string
		body          string
		wantViolation bool
	}{
		{"conforming", "scan, bomb := decompressForScan(b, ce)\n\tif bomb {\n\t\treturn\n\t}\n\t_ = scan", false},
		{"discarded", "scan, _ := decompressForScan(b, ce)\n\t_ = scan", true},
		{"bound-but-never-branched", "scan, bomb := decompressForScan(b, ce)\n\t_, _ = scan, bomb", true},
		{"single-value", "scan := decompressForScan(b, ce)\n\t_ = scan", true},
		{"inlined-into-another-call", "_ = len(decompressForScan(b, ce))", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "package main\n\nfunc chaos106Probe(b []byte, ce string) {\n\t" + tc.body + "\n}\n"
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "chaos106probe.go", src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			sites, violations := chaos106CallSiteViolations(fset, f)
			if sites != 1 {
				t.Fatalf("fixture must hold exactly one call site, the wall found %d", sites)
			}
			if got := len(violations) > 0; got != tc.wantViolation {
				t.Errorf("violation = %v (%v), want %v", got, violations, tc.wantViolation)
			}
		})
	}
}

// TestCHAOS106_CallSiteWallScopesTheBranchToItsOwnFunction is the control for
// the shape a merely discovery-based wall is still blind to: two call sites in
// ONE file, binding the refusal to the SAME name, where only the first fails
// closed.
//
// `bomb` is the name every conforming site in the tree already uses, so a
// branch search over the whole file means the first conforming site in a file
// vouches for every later one in it. The result is the worst failure a gate can
// have: the wall reports clean while the bypass it exists to ban is live. It is
// also the likeliest place for the next site to land — a second response leg
// (an H3 path, a second CDR stage, a request-direction scan) added to
// proxy_tunnel.go, proxy_http.go or cdr_proxy.go, each of which already carries
// `if bomb {` for its first site.
//
// Both directions are asserted: the bypass must be reported, and the
// conforming site beside it must NOT be, since a wall that flagged the
// compliant shape would be deleted rather than repaired.
func TestCHAOS106_CallSiteWallScopesTheBranchToItsOwnFunction(t *testing.T) {
	const src = `package main

func chaos106ProbeFailsClosed(b []byte, ce string) {
	scan, bomb := decompressForScan(b, ce)
	if bomb {
		return
	}
	_ = scan
}

func chaos106ProbeBypass(b []byte, ce string) {
	scan, bomb := decompressForScan(b, ce)
	_, _ = scan, bomb
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "chaos106probe.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	sites, violations := chaos106CallSiteViolations(fset, f)
	if sites != 2 {
		t.Fatalf("fixture must hold exactly two call sites, the wall found %d", sites)
	}
	if len(violations) != 1 {
		t.Fatalf("want exactly one violation (the non-branching site), got %d: %v", len(violations), violations)
	}
	// The reported site must be the bypass, not its compliant neighbour: a
	// wall that counted the right NUMBER of violations while naming the wrong
	// line would send the next editor to correct working code.
	if !strings.Contains(violations[0], "chaos106probe.go:12") {
		t.Errorf("violation names the wrong call site: %q (want the one on line 12, in chaos106ProbeBypass)", violations[0])
	}
	if !strings.Contains(violations[0], "no `if` in the function that holds the call") {
		t.Errorf("violation does not explain the function-scoped rule: %q", violations[0])
	}
}

// The refusal happens in THIS process even with -scan-svc-url set: the sidecar
// is handed already-expanded bytes, so its own stat_decompress_bombs is
// structurally 0. secScanStatusMap's remote branch merges the sidecar's
// /status, so without an explicit override that 0 reached the scan-status API
// and the Security panel tile while this node blocked every bomb.
func TestCHAOS106_RemoteStatusReportsTheLocalRefusalCounter(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// What a real sidecar reports: it never decompresses for the proxy.
		_, _ = io.WriteString(w, `{"enabled":true,"scan_svc_mode":"local","stat_decompress_bombs":0}`)
	}))
	t.Cleanup(sidecar.Close)

	orig := globalRemoteScanner
	globalRemoteScanner = &RemoteScanner{}
	globalRemoteScanner.Init(sidecar.URL)
	t.Cleanup(func() { globalRemoteScanner = orig })

	// A local refusal, so the counter of record is non-zero.
	if _, refused := decompressForScan(chaos106Bomb(t), "gzip"); !refused {
		t.Fatal("fixture was not refused")
	}
	before := secscan.Counters().DecompressBombs

	m := secScanStatusMap()
	if m["scan_svc_mode"] != "remote" {
		t.Fatalf("scan_svc_mode = %v, want remote — the remote branch was not exercised", m["scan_svc_mode"])
	}
	if m["scan_svc_degraded"] != false {
		t.Fatalf("scan_svc_degraded = %v — the sidecar status was not merged, so the override is untested", m["scan_svc_degraded"])
	}
	got, ok := m["stat_decompress_bombs"].(int64)
	if !ok {
		t.Fatalf("stat_decompress_bombs = %#v (%T), want this process's int64 counter, not the sidecar's",
			m["stat_decompress_bombs"], m["stat_decompress_bombs"])
	}
	if got < before || got == 0 {
		t.Errorf("stat_decompress_bombs = %d, want the local counter (>= %d, non-zero)", got, before)
	}

	// The other half of the remote branch: an unreachable sidecar must report
	// the same local counter.
	sidecar.Close()
	m = secScanStatusMap()
	if m["scan_svc_degraded"] != true {
		t.Fatalf("scan_svc_degraded = %v, want true with the sidecar closed", m["scan_svc_degraded"])
	}
	if got, ok := m["stat_decompress_bombs"].(int64); !ok || got < before {
		t.Errorf("unreachable sidecar: stat_decompress_bombs = %#v, want the local counter (>= %d)", m["stat_decompress_bombs"], before)
	}
}
