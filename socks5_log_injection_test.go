package main

import (
	"bufio"
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// SEC-SOCKS5-LOG-1 — the SOCKS5 destination is ATTACKER BYTES, and every log
// site that names it must sanitise it.
//
// The SOCKS5 request's DOMAINNAME field (RFC 1928 §4, ATYP 0x03) is a
// length-prefixed byte string read straight off the socket:
//
//	domain := make([]byte, lenBuf[0])
//	io.ReadFull(r, domain)
//	host = string(domain)
//
// Nothing validates those bytes. They may carry NUL, LF, CR, TAB, DEL, or an
// ANSI escape sequence. This is the ONE protocol Culvert serves where that is
// true: the HTTP and CONNECT paths inherit net/http's own request-line and
// header validation, which rejects control characters (proved below by
// TestHTTPHostHeader_RejectsMostControlCharacters, which also records the one
// byte it does NOT reject).
//
// The strict host-canonicalisation gate is NOT a second line of defence here,
// and that is the trap this file exists to close. normalizeHostStrict rejects
// only non-ASCII and malformed ACE labels; a pure-ASCII host carrying a
// newline passes it unchanged (TestNormalizeHostStrict_IsNotALogSanitiser).
// So a host reaching the blocklist / SSRF / dial / success log sites can still
// contain a line terminator.
//
// The process log is Culvert's forensic record — it is what `internal/logsink`
// drains to the rotating file and what the syslog SIEM forwarder carries — so
// an unsanitised destination lets an unauthenticated client FORGE log lines:
// fabricate a "SOCKS5 OK" for a destination it never reached, or bury a real
// block under injected noise. CWE-117 / OWASP A09:2021.
//
// The repo convention is one line (CLAUDE.md, "User input in logs"): wrap with
// sanitizeLog(s) and use the %q verb. Two sites in handleSOCKS5 already did
// exactly that (INVALID_HOST, SHUTTING_DOWN) while four did not — which is why
// this is an oversight to close rather than a posture to debate.
// ─────────────────────────────────────────────────────────────────────────────

// syncBuf is a mutex-guarded log sink: handleSOCKS5 writes from its own
// goroutine while the test reads.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// captureLoggerForTest redirects the process logger into a buffer for the test.
//
// Registration ORDER is load-bearing: t.Cleanup is LIFO, so this must be called
// BEFORE startSOCKS5Listener. That listener's cleanup drains every in-flight
// handler; registering it later means it runs FIRST, so no handler can still be
// writing when the logger global is restored (a real -race failure otherwise).
func captureLoggerForTest(t *testing.T) *syncBuf {
	t.Helper()
	prev := logger
	sink := &syncBuf{}
	logger = log.New(sink, "", 0)
	t.Cleanup(func() { logger = prev })
	return sink
}

// socks5ConnectRaw performs the no-auth greeting and issues a CONNECT for a
// DOMAINNAME carrying arbitrary bytes. It deliberately does NOT go through the
// typed helpers, because the whole point is to put bytes on the wire that no
// well-formed client would send.
func socks5ConnectRaw(t *testing.T, addr, host string, port uint16) {
	t.Helper()
	if len(host) > 255 {
		t.Fatalf("DOMAINNAME is a 1-byte length prefix; host of %d bytes cannot be sent", len(host))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil { // greeting, no-auth
		t.Fatalf("greeting write: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("greeting read: %v", err)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))} // #nosec G115 -- length checked above
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("request write: %v", err)
	}
	// Best-effort: read whatever reply comes back so the handler has run to the
	// point of logging before we inspect the buffer.
	reply := make([]byte, 10)
	_, _ = io.ReadFull(conn, reply)
}

// waitForLogContaining polls the captured log until marker appears, so the test
// never races the handler goroutine.
func waitForLogContaining(t *testing.T, sink *syncBuf, marker string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := sink.String(); strings.Contains(got, marker) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no log line containing %q within 5s; captured:\n%q", marker, sink.String())
	return ""
}

// controlBytePayloads are the destination shapes an attacker can actually put
// on the wire. Each is embedded MID-HOST: blocklist ingestion trims surrounding
// whitespace, so a payload that only decorated the ends would prove nothing.
var controlBytePayloads = []struct {
	name string
	host string
}{
	// The headline case: a line terminator forges a complete, plausible log line.
	{"newline_forges_a_line", "evil-a.example\nsocks5 ok 10.0.0.9 -> bank.example.com:443"},
	{"crlf_forges_a_line", "evil-b.example\r\nsocks5 ok 10.0.0.9 -> bank.example.com:443"},
	// CR alone rewrites the visible line on a terminal without adding one.
	{"bare_cr_overwrites", "evil-c.example\rsocks5 ok 10.0.0.9 -> bank.example.com:443"},
	// TAB corrupts field-delimited ingestion without forging a line.
	{"tab_breaks_field_split", "evil-d.example\tsocks5\tok"},
	// ANSI escapes rewrite an operator's terminal.
	{"ansi_escape", "evil-e.example\x1b[2K\x1b[31mcompromised"},
	// NUL truncates C-string consumers downstream of the log.
	{"nul_truncates", "evil-f.example\x00hidden-suffix"},
	// DEL is a control byte above the C0 block; sanitizeLog covers it too.
	{"del_byte", "evil-g.example\x7fhidden"},
}

// TestSOCKS5_DestinationLogsCannotForgeLogLines is the DEFECT GATE. It drives
// the real handleSOCKS5 with a hostile DOMAINNAME and requires that nothing the
// client chose reaches the process log as a raw control byte.
//
// The blocklist branch is used because it is the one destination log site a
// test can reach with NO dependency on DNS, the network, or a dial: bl is a
// test-owned store, so the verdict is deterministic on any runner.
func TestSOCKS5_DestinationLogsCannotForgeLogLines(t *testing.T) {
	for _, tc := range controlBytePayloads {
		t.Run(tc.name, func(t *testing.T) {
			setupProxyTest(t)
			sink := captureLoggerForTest(t) // BEFORE the listener: see captureLoggerForTest
			bl.Add(tc.host)
			if !bl.IsBlocked(tc.host) {
				t.Fatalf("precondition: %q must be blocked for this test to reach the BLOCKED log site", tc.host)
			}

			ln := startSOCKS5Listener(t)
			socks5ConnectRaw(t, ln.Addr().String(), tc.host, 443)

			got := waitForLogContaining(t, sink, "SOCKS5 BLOCKED")
			assertNoRawControlBytes(t, got)
			assertNoForgedLine(t, got)
		})
	}
}

// assertNoRawControlBytes requires that the captured log carry no control byte
// other than the '\n' the logger itself appends to terminate each record.
func assertNoRawControlBytes(t *testing.T, captured string) {
	t.Helper()
	for _, line := range strings.Split(captured, "\n") {
		for i := 0; i < len(line); i++ {
			if c := line[i]; c < 0x20 || c == 0x7f {
				t.Errorf("raw control byte %#x survived into the process log at offset %d of line %q\n"+
					"a client-chosen destination must be sanitised before it is logged (CWE-117): "+
					"wrap it with sanitizeLog and print it with %%q", c, i, line)
				return
			}
		}
	}
}

// assertNoForgedLine requires that every line of the captured log be one the
// proxy actually emitted — i.e. the attacker's payload never became a record of
// its own. Exactly one genuine line is expected, and it must carry one of the
// prefixes the emitting path legitimately produces ("SOCKS5 " by default).
func assertNoForgedLine(t *testing.T, captured string, prefixes ...string) {
	t.Helper()
	if len(prefixes) == 0 {
		prefixes = []string{"SOCKS5 "}
	}
	lines := 0
	for _, line := range strings.Split(captured, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines++
		emitted := false
		for _, p := range prefixes {
			if strings.HasPrefix(line, p) {
				emitted = true
				break
			}
		}
		if !emitted {
			t.Errorf("forged log record %q: the client's DOMAINNAME produced a line the proxy never emitted", line)
		}
	}
	if lines != 1 {
		t.Errorf("expected exactly 1 emitted log record, got %d; captured:\n%q", lines, captured)
	}
}

// blockingPlugin is a middleware that blocks everything, so the plugin branch
// of handleSOCKS5 is reachable from a test.
type blockingPlugin struct{}

func (blockingPlugin) Name() string                      { return "test-blocker" }
func (blockingPlugin) OnRequest(_, _, _ string) Decision { return DecisionBlock }
func (blockingPlugin) OnResponse(*http.Response)         {}

// TestSOCKS5_PluginBlockCannotForgeLogLines covers the INDIRECT log site.
//
// The plugin branch hands the raw destination to plugin.Decide, which emits it
// through obs.Printf — a plain fmt.Sprintf into the same process logger. So
// before the round-2 fix an unauthenticated client could still forge records
// whenever any registered middleware blocked, even though every direct log site
// in handleSOCKS5 was sanitised. Reported by Codex review on PR #1367.
func TestSOCKS5_PluginBlockCannotForgeLogLines(t *testing.T) {
	for _, tc := range controlBytePayloads {
		t.Run(tc.name, func(t *testing.T) {
			setupProxyTest(t)
			sink := captureLoggerForTest(t) // BEFORE the listener: see captureLoggerForTest
			prev := pluginReplace([]Middleware{blockingPlugin{}})
			t.Cleanup(func() { pluginReplace(prev) })

			ln := startSOCKS5Listener(t)
			socks5ConnectRaw(t, ln.Addr().String(), tc.host, 443)

			got := waitForLogContaining(t, sink, "Plugin[test-blocker] blocked")
			assertNoRawControlBytes(t, got)
			assertNoForgedLine(t, got, "Plugin[test-blocker] ")
		})
	}
}

// TestSOCKS5_DestinationLogsStillNameTheHost is the CONTROL. The cheapest way
// to pass the gate above is to stop logging the destination at all, which would
// be far worse than the defect: the operator would lose the only record of what
// a client asked for. An ordinary host must still be identifiable in the log.
func TestSOCKS5_DestinationLogsStillNameTheHost(t *testing.T) {
	setupProxyTest(t)
	sink := captureLoggerForTest(t)
	const host = "blocked.example.com"
	bl.Add(host)

	ln := startSOCKS5Listener(t)
	socks5ConnectRaw(t, ln.Addr().String(), host, 443)

	got := waitForLogContaining(t, sink, "SOCKS5 BLOCKED")
	if !strings.Contains(got, host) {
		t.Errorf("the BLOCKED log line must still name the destination; got %q", got)
	}
}

// TestSOCKS5_EveryDestinationLogSiteSanitises is the STRUCTURAL WALL, and it is
// deliberately not a behavioural test: only two of the six destination log
// sites in handleSOCKS5 are reachable without DNS or a live dial, so a
// behavioural suite can never cover the other four. This gate reads the source
// instead and holds for every site, reachable or not.
//
// The rule: inside handleSOCKS5, every argument a log call interpolates must be
// either clientIP (a net.SplitHostPort product of the kernel-supplied peer
// address — never client-chosen bytes) or a value routed through sanitizeLog.
func TestSOCKS5_EveryDestinationLogSiteSanitises(t *testing.T) {
	fset, fn := parseHandleSOCKS5(t)

	checked := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isLoggerCall(call) {
			return true
		}
		checked++
		assertLogArgsSanitised(t, fset, call)
		return true
	})

	// A selector typo that matched nothing would let this wall pass forever.
	if checked < 4 {
		t.Fatalf("the wall inspected only %d log calls in handleSOCKS5; it is no longer finding them", checked)
	}
}

// parseHandleSOCKS5 returns the AST of the handler both walls read.
func parseHandleSOCKS5(t *testing.T) (*token.FileSet, *ast.FuncDecl) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "socks5.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse socks5.go: %v", err)
	}
	var fn *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		if d, ok := n.(*ast.FuncDecl); ok && d.Name.Name == "handleSOCKS5" {
			fn = d
			return false
		}
		return true
	})
	if fn == nil {
		t.Fatal("handleSOCKS5 not found in socks5.go — these walls must be re-aimed, not deleted")
	}
	return fset, fn
}

// isLoggerCall reports whether call is logger.Printf / logger.Println.
func isLoggerCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "logger" {
		return false
	}
	return sel.Sel.Name == "Printf" || sel.Sel.Name == "Println"
}

// assertLogArgsSanitised requires every interpolated argument to be either
// clientIP — a net.SplitHostPort product of the kernel-supplied peer address,
// never client-chosen bytes — or a value routed through sanitizeLog.
//
// clientIP is the ONLY bare identifier admitted. Widening this set is how the
// defect comes back: add a name only with the argument for why those bytes
// cannot be client-chosen.
func assertLogArgsSanitised(t *testing.T, fset *token.FileSet, call *ast.CallExpr) {
	t.Helper()
	safeBare := map[string]bool{"clientIP": true}
	for i, arg := range call.Args {
		if i == 0 {
			continue // the format string is a source-literal
		}
		if id, ok := arg.(*ast.Ident); ok && safeBare[id.Name] {
			continue
		}
		expr := renderExpr(t, fset, arg)
		if !strings.Contains(expr, "sanitizeLog") {
			t.Errorf("handleSOCKS5 (%s): log argument %s is neither clientIP nor sanitised.\n"+
				"The SOCKS5 DOMAINNAME is raw attacker bytes; wrap it with sanitizeLog and use %%q (CWE-117).",
				fset.Position(call.Pos()), expr)
		}
	}
}

// renderExpr prints one AST expression back to source text.
func renderExpr(t *testing.T, fset *token.FileSet, e ast.Expr) string {
	t.Helper()
	var b bytes.Buffer
	if err := printer.Fprint(&b, fset, e); err != nil {
		t.Fatalf("render expression: %v", err)
	}
	return b.String()
}

// destinationSinks is the AUDITED set of functions handleSOCKS5 may hand the
// raw client-chosen destination to. Each entry records why that callee cannot
// forge a log record with those bytes.
//
// This list exists because the FIRST version of this file walled only DIRECT
// logger calls, and a reviewer found the raw host still reaching the process
// log INDIRECTLY: pluginDecision → plugin.Decide → obs.Printf, which is a plain
// fmt.Sprintf into the same logger. A wall scoped to one syntactic shape proves
// less than it appears to — the same lesson as "sanitising one argument of a
// call does not sanitise the call", one level up.
var destinationSinks = map[string]string{
	"normalizeHostStrict": "pure canonicalisation in internal/hostutil; logs nothing",
	"IsBlocked":           "internal/blocklist; its own host log lines already route through obs.Sanitize",
	"pluginDecision":      "plugin.Decide sanitises the destination before obs.Printf (SEC-SOCKS5-LOG-1 round 2)",
	"isPrivateHost":       "internal/ssrf; contains no logging at all",
	"recordRequest":       "structured JSONL — the encoder escapes control bytes",
	"socks5Relay":         "byte relay; its only destination sink is recordTunnelClose — structured JSONL",
	"JoinHostPort":        "net; string construction only",
	"DialContext":         "net.Dialer; the error it returns is sanitised at the log site",
	"sanitizeLog":         "the sanitiser itself",
	// CHAOS-69 destination-authority bound. All three receive the destination
	// only to MEASURE it, which is the whole design decision behind the bound's
	// log line: the LENGTH is what an operator needs to tell a probe from a
	// broken client, and a copy of the value — even a prefix — would reopen the
	// write amplification the bound exists to close.
	"canonicalHostOversize":     "proxy_host_bounds.go; a pure len() comparison on the normalized host — returns a bool, logs nothing, stores nothing",
	"noteOversizeHostRejection": "proxy_host_bounds.go; receives len(host), never the host: its log line carries the byte COUNT, the protocol and the peer IP only",
	"len":                       "builtin; yields an int, so the bytes cannot survive the call",
}

// TestSOCKS5_EveryDestinationSinkIsAudited is the SECOND wall, and it closes
// the class the first one could not see. It requires every function that
// receives the raw destination (host / target) inside handleSOCKS5 to appear in
// destinationSinks with a recorded reason. Adding a new sink — a metric, an
// audit call, another middleware hop — then fails the build until somebody
// states why those attacker-chosen bytes are safe in it.
func TestSOCKS5_EveryDestinationSinkIsAudited(t *testing.T) {
	fset, fn := parseHandleSOCKS5(t)
	// The normalized destination counts as raw. normalizeHostStrict is NOT a log
	// sanitiser — TestNormalizeHostStrict_IsNotALogSanitiser pins that as a FACT —
	// so normSOCKS5Host can still carry the control characters that forge a log
	// record. CHAOS-69 introduced that variable and it escaped this wall until the
	// stale registry entry for its deleted predecessor gave the omission away: the
	// wall flags unregistered CALLEES, never an unwatched VALUE, so a new
	// client-derived local is invisible to it by construction. Whoever adds the
	// next one must add it here too.
	raw := map[string]bool{"host": true, "target": true, "normSOCKS5Host": true}

	seen := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || isLoggerCall(call) { // log calls are the FIRST wall's business
			return true
		}
		if !callForwardsAny(call, raw) {
			return true
		}
		seen++
		name := calleeName(call)
		if _, audited := destinationSinks[name]; !audited {
			t.Errorf("handleSOCKS5 (%s): %s() receives the raw client-chosen destination but is not in destinationSinks.\n"+
				"Establish that it cannot emit those bytes unsanitised (CWE-117), then record the reason there.",
				fset.Position(call.Pos()), name)
		}
		return true
	})

	if seen < 5 {
		t.Fatalf("the sink wall matched only %d forwarding calls; it is no longer finding them", seen)
	}
}

// TestSOCKS5_DestinationSinkRegistryHasNoStaleEntries keeps the registry honest in
// the other direction. The wall above flags an unregistered CALLEE; it says nothing
// about an entry naming a function that no longer exists, so a rename or a deletion
// leaves a reason recorded for code that is gone while the replacement goes
// unaudited. CHAOS-69 did exactly that: it replaced destHostOversize with
// canonicalHostOversize, and the wall stayed green with the dead name registered and
// the live one missing.
//
// Declared names are collected by AST rather than by grepping for "func name(",
// because a sink can legitimately be a package-level VAR binding rather than a
// function declaration — pluginDecision is `pluginDecision = plugin.Decide`, and a
// textual check reports it as stale. Builtins and methods on other packages' types
// are exempt: they are not declared here at all.
func TestSOCKS5_DestinationSinkRegistryHasNoStaleEntries(t *testing.T) {
	exempt := map[string]bool{
		"len":          true, // builtin
		"IsBlocked":    true, // method on *blocklist.Store
		"JoinHostPort": true, // net
		"DialContext":  true, // method on *net.Dialer
	}

	declared := packageLevelDeclarations(t)

	for name := range destinationSinks {
		if exempt[name] {
			continue
		}
		if !declared[name] {
			t.Errorf("destinationSinks registers %q, but nothing by that name is declared in package main — "+
				"a rename or deletion left a recorded reason behind while its replacement goes unaudited", name)
		}
	}
}

// packageLevelDeclarations returns every package-level function and var/const
// name declared in package main's non-test sources.
//
// Extracted from the gate above rather than inlined: the AST walk's nested
// switch over declaration kinds pushed the test past the gocognit threshold (35
// of 30), which the _test.go exclusions do NOT cover — they exempt funlen, dupl,
// cyclop, errcheck and unparam only. Worth knowing before writing another
// AST-walking gate in a test file.
func packageLevelDeclarations(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	declared := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, perr := parser.ParseFile(fset, f, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", f, perr)
		}
		collectPackageDecls(af, declared)
	}
	if len(declared) < 100 {
		t.Fatalf("only %d package-level names collected; the AST walk is not finding declarations", len(declared))
	}
	return declared
}

// collectPackageDecls records af's package-level function and value names.
func collectPackageDecls(af *ast.File, into map[string]bool) {
	for _, d := range af.Decls {
		switch decl := d.(type) {
		case *ast.FuncDecl:
			if decl.Recv == nil { // package-level function, not a method
				into[decl.Name.Name] = true
			}
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for _, n := range vs.Names {
						into[n.Name] = true
					}
				}
			}
		}
	}
}

// callForwardsAny reports whether any argument of call mentions one of names.
func callForwardsAny(call *ast.CallExpr, names map[string]bool) bool {
	found := false
	for _, arg := range call.Args {
		ast.Inspect(arg, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && names[id.Name] {
				found = true
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

// calleeName returns the bare function name of a call (pkg/receiver stripped).
func calleeName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return "<unknown>"
}

// TestNormalizeHostStrict_IsNotALogSanitiser records the ROOT CAUSE as an
// executable fact, so a future reader cannot conclude that the strict
// canonicalisation gate in front of these log sites already neutralises the
// bytes. It does not: it rejects non-ASCII and malformed ACE labels, and is
// deliberately silent about control characters.
//
// This is NOT a request to change normalizeHostStrict. Making it reject control
// bytes would change which destinations the proxy serves — a policy decision
// with its own blast radius — while the defect here is only that a log site
// failed to sanitise what it prints.
func TestNormalizeHostStrict_IsNotALogSanitiser(t *testing.T) {
	for _, host := range []string{
		"evil.example\nforged",
		"evil.example\rforged",
		"evil.example\tforged",
		"evil.example\x1b[31mforged",
		"evil.example\x7fforged",
	} {
		norm, ok := normalizeHostStrict(host)
		if !ok {
			t.Fatalf("normalizeHostStrict(%q) rejected the host; this test's premise (and the log sites' exposure) has changed — re-derive the fix before relaxing anything", host)
		}
		if !strings.ContainsAny(norm, "\n\r\t\x1b\x7f") {
			t.Errorf("normalizeHostStrict(%q) = %q stripped the control byte; it is not supposed to, and the log sites must not rely on it", host, norm)
		}
	}
}

// TestHTTPHostHeader_RejectsMostControlCharacters pins WHY this finding is
// SOCKS5-specific — and, just as importantly, the one place it is not.
//
// net/http rejects a Host header or CONNECT authority carrying LF, CR, ESC or
// DEL, so the HTTP paths cannot forge a log line. It ACCEPTS a horizontal TAB
// (a legal HTTP field-value byte), which is why the shared scan-block log sites
// are sanitised too: they cannot forge a record, but they can corrupt
// field-delimited ingestion, and sanitizeLog is free.
func TestHTTPHostHeader_RejectsMostControlCharacters(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantAccept bool
	}{
		{"lf_rejected", "GET / HTTP/1.1\r\nHost: ev\nil.com\r\n\r\n", false},
		{"esc_rejected", "GET / HTTP/1.1\r\nHost: ev\x1bil.com\r\n\r\n", false},
		{"del_rejected", "GET / HTTP/1.1\r\nHost: ev\x7fil.com\r\n\r\n", false},
		{"connect_esc_rejected", "CONNECT ev\x1bil.com:443 HTTP/1.1\r\nHost: ev\x1bil.com:443\r\n\r\n", false},
		{"tab_accepted", "GET / HTTP/1.1\r\nHost: ev\til.com\r\n\r\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := readRequestForTest(tc.raw)
			if tc.wantAccept {
				if err != nil {
					t.Fatalf("expected net/http to accept %q, got %v", tc.raw, err)
				}
				if !strings.ContainsAny(req, "\t") {
					t.Fatalf("expected the TAB to survive into r.Host, got %q", req)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected net/http to REJECT %q, but it produced r.Host=%q — the HTTP paths would then share the SOCKS5 exposure", tc.raw, req)
			}
		})
	}
}

// TestScanBlockLogSitesAreSanitised covers the shared block-response helpers,
// which are reached from BOTH the plain-HTTP path and inside SSL-inspected
// tunnels. Their host argument is net/http-validated (so no line forgery), but
// a TAB does get through, and the sibling sites in proxy_tunnel.go already
// sanitise the same value.
func TestScanBlockLogSitesAreSanitised(t *testing.T) {
	const hostile = "scan\ttarget\x1b[31m.example.com"

	t.Run("scanBlockConn", func(t *testing.T) {
		sink := captureLoggerForTest(t)
		scanBlockConn(nopBlockResponder{}, hostile, "eicar", "clamav")
		assertNoRawControlBytes(t, sink.String())
	})

	t.Run("dpiBlock", func(t *testing.T) {
		sink := captureLoggerForTest(t)
		dpiBlock(nopBlockResponder{}, hostile, "pattern-name")
		assertNoRawControlBytes(t, sink.String())
	})
}

// TestDNSResolveFailureLogIsSanitised covers the CHAOS-64 resolver log site.
// Its `host` argument is already sanitised; its `err` argument was not, and a
// *net.DNSError carries the queried name verbatim — so the same bytes came back
// through the second argument. The site's own comment identifies the name as
// attacker-chosen, which is what makes this a gap rather than a judgement call.
func TestDNSResolveFailureLogIsSanitised(t *testing.T) {
	const hostile = "dns\ttarget\x1b[31m.example.com"

	prevLookup := lookupHostFn
	t.Cleanup(func() { lookupHostFn = prevLookup })
	lookupHostFn = func(_ context.Context, host string) ([]string, error) {
		// Shaped like the real thing: net.DNSError embeds the queried name.
		// Deliberately NOT IsNotFound — an NXDOMAIN is counted but never logged
		// (it is a healthy resolver), so it could not reach the log site at all.
		return nil, &net.DNSError{Err: "server misbehaving", Name: host, IsTemporary: true}
	}

	resetDNSResolveHealthForTest()
	t.Cleanup(resetDNSResolveHealthForTest)

	sink := captureLoggerForTest(t)
	_ = lookupPublicHostIP(hostile)

	got := sink.String()
	if !strings.Contains(got, "DNS resolution failed") {
		t.Fatalf("expected the resolver failure line to be emitted; captured %q", got)
	}
	assertNoRawControlBytes(t, got)
}

// nopBlockResponder swallows the block body; these tests assert on the log, not
// on the wire bytes (which are locked by the PR0 characterization tests).
type nopBlockResponder struct{}

func (nopBlockResponder) blockBeforeResponse(string, string) {}

// readRequestForTest parses raw as an HTTP request and returns r.Host, so the
// control-character verdict above comes from net/http itself rather than from a
// claim in a comment.
func readRequestForTest(raw string) (string, error) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return "", err
	}
	return req.Host, nil
}
