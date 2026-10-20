package main

// syslog_handle_publication_chaos_test.go — CHAOS-78, closing §42 OBS-1 of
// roadmap/CHAOS-ENGINEERING-REVIEW.md.
//
// globalSyslog was a plain *syslogWriter: written at runtime from the admin
// handler goroutine (InitSyslog via the apiSyslogConfig POST, and nil on the
// disable branch) and read unsynchronized on the proxy request path at
// persistLogEntry and on the audit SIEM hook. Three gates here, one per defect
// the sweep found, plus the structural walls that keep the publication
// discipline from eroding.
//
//  1. The RACE gate. The nil check and the dereference were separate
//     unsynchronized loads, so a request goroutine could pass the check and
//     then dereference the nil the disable branch had just stored. It is also
//     the gate for the subtler half: the engine sets its queue in startAsync
//     AFTER the struct literal and treats a nil queue as "deliver
//     synchronously" — a path holding the writer mutex across up to two 5 s
//     dials and two 5 s writes — so a plain pointer write's missing release
//     edge could drop a request goroutine onto it on a weakly ordered target
//     (this appliance ships linux/arm64). Both are data races, so -race is the
//     oracle for both.
//
//  2. The LEAK gate. InitSyslog overwrote the global without closing the
//     writer it displaced, and the engine's drainLoop exits ONLY via Close —
//     so every runtime SIEM retarget stranded a delivery goroutine and its
//     collector socket for the life of the process.
//
//  3. The WALLS. The handle must stay an atomic.Pointer, nothing outside
//     syslog.go may touch it directly, and no caller may write
//     syslogHandle().Method() — two calls in one expression are two loads and
//     reintroduce precisely the window the type closes.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// newTestCollector binds a real UDP socket and drains it, so InitSyslog's dial
// and the engine's writes both succeed against a live peer. Returns the
// "udp://host:port" address InitSyslog accepts.
func newTestCollector(t *testing.T) string {
	t.Helper()
	// Contextual I/O, per conventions.md and the noctx linter: the sibling
	// chaos tests use (&net.ListenConfig{}).Listen(t.Context(), ...) and this
	// is the packet-socket form of the same idiom.
	pc, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind test collector: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			if _, _, rerr := pc.ReadFrom(buf); rerr != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		pc.Close() //nolint:errcheck // test teardown
		<-done
	})
	return "udp://" + pc.LocalAddr().String()
}

// restoreSyslogHandle parks the ambient handle for the duration of a test and
// restores it afterwards, closing whatever the test left published. The global
// is process-wide, so a test that retargets it must put it back (house rule:
// setupProxyTest resets at test START and restores nothing).
func restoreSyslogHandle(t *testing.T) {
	t.Helper()
	prevSW, prevAddr, prevOK := syslogHandle(), syslogConfiguredAddr, syslogConfigured
	t.Cleanup(func() {
		if sw := setSyslogHandle(prevSW); sw != nil && sw != prevSW {
			_ = sw.Close()
		}
		syslogConfiguredAddr, syslogConfigured = prevAddr, prevOK
	})
}

// drainGoroutines counts the live syslog delivery goroutines by stack, which is
// exact where runtime.NumGoroutine() would only be suggestive: the leak this
// gate pins is one specific goroutine, and the test binary has many others
// coming and going.
func drainGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), "syslog.(*Writer).drainLoop")
		}
		buf = make([]byte, 2*len(buf))
	}
}

// TestChaos78_ReconfigureRacesTheRequestPath drives the real read sites
// (persistLogEntry, the audit SIEM hook) against the real write sites
// (InitSyslog's enable, apiSyslogConfig's disable) concurrently.
//
// Run under -race this fails on the pre-fix tree two ways: as a reported data
// race on globalSyslog, and — when the disable branch's nil lands between a
// reader's check and its dereference — as a nil-pointer panic on the request
// path. With the handle published through atomic.Pointer and every caller
// holding ONE loaded value, there is no race to report and no window to hit.
func TestChaos78_ReconfigureRacesTheRequestPath(t *testing.T) {
	restoreSyslogHandle(t)
	addr := newTestCollector(t)

	const readers = 8
	stop := make(chan struct{})
	var readersWG, writerWG sync.WaitGroup

	// Readers: the request-log chokepoint, as hot as the test can drive it.
	for i := 0; i < readers; i++ {
		readersWG.Add(1)
		go func(n int) {
			defer readersWG.Done()
			host := fmt.Sprintf("chaos78-%d.example.test", n)
			for {
				select {
				case <-stop:
					return
				default:
				}
				persistLogEntry("203.0.113.7", "GET", host, "OK", "r", "Allow",
					"", 0, 0, 0, "", "", AuthLogFields{})
			}
		}(i)
	}

	// The second read path is the audit SIEM hook, and it needs its own
	// goroutine — but a BOUNDED one. The audit ring holds audit.MaxRing (500)
	// entries and its own file says tests must not assert on length deltas;
	// flooding it here would silently evict entries other tests in this
	// package placed there. auditProbes well under the ring is enough to have
	// the hook running concurrently with the reconfigures, which is all this
	// gate needs from it.
	const auditProbes = 40
	readersWG.Add(1)
	go func() {
		defer readersWG.Done()
		for i := 0; i < auditProbes; i++ {
			select {
			case <-stop:
				return
			default:
			}
			auditAdd(AuditEntry{Action: "chaos78.probe", ObjectID: fmt.Sprintf("probe-%d", i)})
		}
	}()

	// Writer: the admin plane flipping forwarding on and off underneath them.
	// A fixed iteration count, so the test is bounded by work and not by a
	// sleep: the readers stop when the writer is done.
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		for i := 0; i < 60; i++ {
			if err := InitSyslog(addr, ""); err != nil {
				t.Errorf("InitSyslog(%q): %v", addr, err)
				return
			}
			if sw := setSyslogHandle(nil); sw != nil {
				_ = sw.Close()
			}
		}
	}()

	writerWG.Wait()
	close(stop)
	readersWG.Wait()

	// The writer's last act is a disable, so nothing should be published; a
	// non-nil handle here would mean a leaked writer, which the leak gate owns.
	if sw := syslogHandle(); sw != nil {
		_ = sw.Close()
		setSyslogHandle(nil)
		t.Error("a writer was still published after the reconfigure loop's final disable")
	}
}

// TestChaos78_RetargetLeaksNoDeliveryGoroutine pins the second defect.
// InitSyslog published the new writer over the old one and never closed it;
// drainLoop exits only via Close, so each retarget stranded one goroutine
// holding one collector socket, permanently. An operator moving the SIEM
// target a handful of times leaked a handful of both, with nothing to show it.
//
// Pre-fix this reports 8 extra delivery goroutines; post-fix exactly one is
// live (the final writer's) and the rest have exited.
func TestChaos78_RetargetLeaksNoDeliveryGoroutine(t *testing.T) {
	restoreSyslogHandle(t)

	// Start from a known-empty baseline so the assertion is absolute.
	if sw := setSyslogHandle(nil); sw != nil {
		_ = sw.Close()
	}
	baseline := drainGoroutines()

	const retargets = 8
	for i := 0; i < retargets; i++ {
		addr := newTestCollector(t)
		if err := InitSyslog(addr, ""); err != nil {
			t.Fatalf("retarget %d: InitSyslog(%q): %v", i, addr, err)
		}
	}

	// Close() is synchronous, so by here every displaced writer's drainLoop has
	// already returned; only the last writer's is live.
	if got := drainGoroutines(); got != baseline+1 {
		t.Errorf("after %d retargets: %d syslog delivery goroutines; want %d (baseline %d + the live writer).\n"+
			"Each retarget that does not close the writer it displaces strands one goroutine and one collector socket for the life of the process.",
			retargets, got, baseline+1, baseline)
	}

	// And the disable branch releases the last one.
	if sw := setSyslogHandle(nil); sw != nil {
		_ = sw.Close()
	}
	if got := drainGoroutines(); got != baseline {
		t.Errorf("after disable: %d syslog delivery goroutines; want the %d baseline", got, baseline)
	}
}

// syslogHandleViolations reports publication-discipline breaches across the
// given package-main files. Two rules, each the shape of a defect this sweep
// fixed:
//
//	(a) globalSyslogHandle must be declared atomic.Pointer[...] — a plain
//	    pointer reintroduces both the torn publication and the split
//	    check-then-deref;
//	(b) no file but syslog.go may name globalSyslogHandle at all (the accessors
//	    are the only door), and nobody anywhere may write
//	    syslogHandle().Method() — that is two loads in one expression, exactly
//	    the window the atomic closes.
func syslogHandleViolations(fset *token.FileSet, files []*ast.File) []string {
	var out []string
	declSeen := false
	for _, f := range files {
		name := filepath.Base(fset.Position(f.Pos()).Filename)
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.ValueSpec:
				seen, msgs := syslogHandleDeclViolations(name, node)
				declSeen = declSeen || seen
				out = append(out, msgs...)
			case *ast.Ident:
				out = append(out, syslogHandleIdentViolations(name, node)...)
			case *ast.SelectorExpr:
				out = append(out, syslogHandleDerefViolations(fset, name, node)...)
			}
			return true
		})
	}
	if !declSeen {
		out = append(out, "globalSyslogHandle declaration not found — the wall is anchored to a symbol that no longer exists")
	}
	return out
}

// syslogHandleDeclViolations is rule (a): the handle's declared type. Reports
// whether the declaration was seen at all, so the caller can fail when the
// symbol the wall is anchored to has disappeared.
func syslogHandleDeclViolations(file string, spec *ast.ValueSpec) (seen bool, out []string) {
	for _, id := range spec.Names {
		if id.Name != "globalSyslogHandle" {
			continue
		}
		seen = true
		idx, ok := spec.Type.(*ast.IndexExpr)
		if !ok {
			out = append(out, fmt.Sprintf("%s: globalSyslogHandle is not a generic atomic.Pointer — a plain handle reopens the torn publication and the split check-then-deref", file))
			continue
		}
		sel, ok := idx.X.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Pointer" {
			out = append(out, fmt.Sprintf("%s: globalSyslogHandle must be declared atomic.Pointer[syslogWriter]", file))
		}
	}
	return seen, out
}

// syslogHandleIdentViolations is the first half of rule (b): only syslog.go may
// name the handle; everyone else goes through the accessors.
func syslogHandleIdentViolations(file string, id *ast.Ident) (out []string) {
	if id.Name == "globalSyslogHandle" && file != "syslog.go" {
		out = append(out, fmt.Sprintf("%s: names globalSyslogHandle directly; go through syslogHandle/setSyslogHandle", file))
	}
	return out
}

// syslogHandleDerefViolations is the second half of rule (b): nobody may write
// syslogHandle().Method(). Two calls in one expression are two loads, which is
// exactly the window the atomic.Pointer closes.
func syslogHandleDerefViolations(fset *token.FileSet, file string, sel *ast.SelectorExpr) (out []string) {
	call, ok := sel.X.(*ast.CallExpr)
	if !ok {
		return nil
	}
	fn, ok := call.Fun.(*ast.Ident)
	if !ok || fn.Name != "syslogHandle" {
		return nil
	}
	return append(out, fmt.Sprintf("%s:%d: syslogHandle().%s is an unguarded deref of a fresh load; assign one value to a local and nil-test that",
		file, fset.Position(sel.Pos()).Line, sel.Sel.Name))
}

// TestChaos78_Wall_SyslogHandleIsPublishedAtomically parses package main at the
// package directory (not the process CWD) and enforces both rules, with
// negative controls proving each rule actually fires.
func TestChaos78_Wall_SyslogHandleIsPublishedAtomically(t *testing.T) {
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		files = append(files, f)
	}
	if v := syslogHandleViolations(fset, files); len(v) != 0 {
		t.Errorf("syslog handle publication discipline broken:\n  %s", strings.Join(v, "\n  "))
	}

	// Negative controls: the pre-fix declaration, a direct write from another
	// file, and the two-loads-in-one-expression deref.
	for _, tc := range []struct {
		name string
		src  string
		want string
	}{
		{
			name: "plain pointer declaration",
			src: `package main
var globalSyslogHandle *syslogWriter`,
			want: "not a generic atomic.Pointer",
		},
		{
			name: "direct write from another file",
			src: `package main
func apiSyslogConfig() { globalSyslogHandle.Store(nil) }`,
			want: "names globalSyslogHandle directly",
		},
		{
			name: "two loads in one expression",
			src: `package main
func persistLogEntry() {
	if syslogHandle() != nil {
		syslogHandle().WriteRequest(nil)
	}
}`,
			want: "unguarded deref of a fresh load",
		},
	} {
		negFset := token.NewFileSet()
		f, perr := parser.ParseFile(negFset, "neg.go", tc.src, 0)
		if perr != nil {
			t.Fatalf("%s: %v", tc.name, perr)
		}
		got := syslogHandleViolations(negFset, []*ast.File{f})
		found := false
		for _, line := range got {
			if strings.Contains(line, tc.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("negative control %q was not flagged (want a finding containing %q); got %v", tc.name, tc.want, got)
		}
	}
}

// TestChaos78_HandleTypeIsAtomicPointer is the compile-time companion to the
// AST wall: it fails to build, rather than to run, if the handle's type ever
// goes back to a plain pointer.
func TestChaos78_HandleTypeIsAtomicPointer(t *testing.T) {
	// The assertion is the PARAMETER type, not a typed var: staticcheck's
	// QF1011 would have us drop the type from `var _ *atomic.Pointer[...] = ...`,
	// and dropping it deletes the very thing being asserted. A parameter type
	// cannot be inferred away, so this keeps the build-time guarantee.
	requireAtomicSyslogHandle(&globalSyslogHandle)
	if syslogHandle() != globalSyslogHandle.Load() {
		t.Error("syslogHandle() must be a plain Load of the published handle")
	}
}

// requireAtomicSyslogHandle accepts only *atomic.Pointer[syslogWriter], so the
// package stops COMPILING if the handle regresses to a plain pointer.
func requireAtomicSyslogHandle(*atomic.Pointer[syslogWriter]) {}
