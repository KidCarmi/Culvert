package main

// cp_grpc_teardown_owner_chaos_test.go — CHAOS-71, Codex P2 4313548177 on
// #1556: "Serialize retired-server teardown with shutdown".
//
// grpc-go's stop() — the body behind both Stop and GracefulStop — holds the
// server mutex across handlersWG.Wait() on the graceful path. So while a
// handler is wedged, a GracefulStop that has seen its last connection go holds
// that mutex indefinitely, and any concurrent Stop() on the SAME server blocks
// on it. The supervisor's serve-end retirement was exactly such a Stop():
// Serve failed on its own, shutdown closed `stopping` just after the loop's
// check, cpListenerSupervisor.Stop entered GracefulStop, and the retirement
// then parked on the mutex — so the loop never closed `done` and the shutdown
// hook ran to its deadline (or the watchdog) instead of completing.
//
// The fix is a teardown CLAIM: exactly one owner stops a given server, decided
// atomically under the supervisor mutex (claimTeardown / Stop taking s.srv).

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// TestChaos71_RetirementAndShutdownNeverStopTheSameServer drives the reported
// interleaving through the real supervisor and the real shutdown entry point
// (stopControlPlaneListener):
//
//  1. a Data Plane RPC is wedged in its handler;
//  2. the bound listener fails underneath Serve (a fatal Accept error), so
//     Serve returns on its own and the loop passes its stopRequested check;
//  3. shutdown arrives in the retirement seam — after that check, before the
//     retirement's stop;
//  4. the Data Plane's transport goes away, which is what lets a racing
//     GracefulStop leave its conns wait and park in handlersWG.Wait() holding
//     the server mutex;
//  5. only then does the retirement stop run.
//
// Before the claim, step 3's Stop found the server still published and
// entered GracefulStop, and step 5's synchronous Stop() blocked on the mutex
// for as long as the handler stayed wedged: shutdown returned its context
// error and `done` never closed. With the claim the loop owns this server,
// Stop finds nothing to stop and waits on `done`, and the shutdown completes
// within its bound.
func TestChaos71_RetirementAndShutdownNeverStopTheSameServer(t *testing.T) {
	cpChaosSetup(t)
	cpInsecure(t)

	release := make(chan struct{})
	var releaseOnce sync.Once
	unwedge := func() { releaseOnce.Do(func() { close(release) }) }

	entered := make(chan struct{})
	var enterOnce sync.Once
	prevReg := cpRegisterGRPCServices
	cpRegisterGRPCServices = func(srv *grpc.Server) {
		prevReg(srv)
		srv.RegisterService(&grpc.ServiceDesc{
			ServiceName: "culvert.test.Wedged",
			HandlerType: (*controlPlaneServer)(nil),
			Methods: []grpc.MethodDesc{{
				MethodName: "Block",
				// Ignores its context, as a handler blocked in write(2) on a
				// wedged volume does.
				Handler: wrapUnary(func(context.Context, json.RawMessage) (json.RawMessage, error) {
					enterOnce.Do(func() { close(entered) })
					<-release
					return nil, status.Error(codes.Unavailable, "released")
				}),
			}},
		}, nil)
	}
	t.Cleanup(func() { cpRegisterGRPCServices = prevReg })

	var lnMu sync.Mutex
	var lns []net.Listener
	prevWrap := cpWrapListener
	cpWrapListener = func(ln net.Listener) net.Listener {
		lnMu.Lock()
		lns = append(lns, ln)
		lnMu.Unlock()
		return ln
	}
	t.Cleanup(func() { cpWrapListener = prevWrap })

	// The shutdown hook's own budget for this phase.
	shutdownBound := defaultShutdownBudget.Early

	var supP atomic.Pointer[cpListenerSupervisor]
	var ccP atomic.Pointer[grpc.ClientConn]
	stopErr := make(chan error, 1)
	stopTook := make(chan time.Duration, 1)
	var retireOnce sync.Once
	var retired atomic.Bool
	prevRetire := retireCPGRPCServer
	retireCPGRPCServer = func(srv *grpc.Server) {
		retired.Store(true)
		retireOnce.Do(func() {
			sup := supP.Load()
			// (3) Shutdown arrives after the loop's check, before its stop.
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), shutdownBound)
				defer cancel()
				start := time.Now()
				err := stopControlPlaneListener(ctx)
				stopTook <- time.Since(start)
				stopErr <- err
			}()
			// Not t.Fatal: this is the supervisor goroutine.
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
				sup.mu.Lock()
				stopped := sup.stopped
				sup.mu.Unlock()
				if stopped {
					break
				}
			}
			// (4) The Data Plane's transport goes. A GracefulStop racing this
			// retirement now sees len(conns) == 0 and parks in
			// handlersWG.Wait() holding the server mutex.
			if cc := ccP.Load(); cc != nil {
				_ = cc.Close()
			}
			time.Sleep(300 * time.Millisecond)
		})
		// (5) The retirement's stop.
		prevRetire(srv)
	}
	t.Cleanup(func() { retireCPGRPCServer = prevRetire })

	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	sup, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, nil)
	if err != nil {
		t.Fatalf("boot path: %v", err)
	}
	// Registered after the supervisor's cleanup, so it runs FIRST: a failing
	// run unwedges the handler before that cleanup waits on the loop.
	t.Cleanup(unwedge)
	supP.Store(sup)
	cpActivationMu.Lock()
	cpSupervisor = sup // what activateControlPlane arms; the shutdown hook reads it
	cpActivationMu.Unlock()

	cc, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodecV2(rawCodec{})))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	ccP.Store(cc)
	go func() {
		var out json.RawMessage
		_ = cc.Invoke(context.Background(), "/culvert.test.Wedged/Block", json.RawMessage(`{}`), &out)
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the wedged RPC never reached its handler")
	}
	if st := cc.GetState(); st != connectivity.Ready {
		t.Fatalf("client transport state %s, want READY", st)
	}

	// (2) The fatal Accept error, with the handler still wedged.
	lnMu.Lock()
	first := lns[0]
	lnMu.Unlock()
	_ = first.Close()

	select {
	case err := <-stopErr:
		took := <-stopTook
		if !retired.Load() {
			t.Fatal("the interleaving was not reached: the serve-end retirement never ran")
		}
		if err != nil {
			t.Fatalf("shutdown returned %v after %s: the serve-end retirement raced Stop's GracefulStop on the same "+
				"server and blocked on grpc-go's server mutex behind the wedged handler, so the supervisor never exited",
				err, took)
		}
		if took >= shutdownBound {
			t.Errorf("shutdown took %s, not within its %s bound", took, shutdownBound)
		}
	case <-time.After(shutdownBound + 10*time.Second):
		t.Fatal("shutdown never returned")
	}
	select {
	case <-sup.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the supervisor never closed done")
	}
	if sup.currentServer() != nil {
		t.Error("a server handle is still published after shutdown")
	}
}

// TestChaos71_TeardownClaimHasExactlyOneOwner pins the claim in both orders,
// deterministically: whichever of Stop and the loop takes a published server
// first owns its teardown, and the other never stops it. A server adopt never
// published is the loop's alone.
func TestChaos71_TeardownClaimHasExactlyOneOwner(t *testing.T) {
	newSup := func() *cpListenerSupervisor {
		s := &cpListenerSupervisor{stopping: make(chan struct{}), done: make(chan struct{})}
		close(s.done) // no loop: Stop returns once its own teardown is done
		return s
	}
	// stoppedByOther reports whether srv was stopped: Serve on a stopped server
	// returns ErrServerStopped at once; on a live one it serves until Stop.
	stoppedByOther := func(t *testing.T, srv *grpc.Server) bool {
		t.Helper()
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		served := make(chan error, 1)
		go func() { served <- srv.Serve(ln) }()
		select {
		case err := <-served:
			return err == grpc.ErrServerStopped
		case <-time.After(200 * time.Millisecond):
			srv.Stop()
			<-served
			return false
		}
	}

	t.Run("Stop claims first", func(t *testing.T) {
		s := newSup()
		a := &cpAttempt{srv: grpc.NewServer()}
		if !s.adopt(a) {
			t.Fatal("adopt refused before Stop")
		}
		if err := s.Stop(t.Context()); err != nil {
			t.Fatal(err)
		}
		if s.claimTeardown(a) {
			t.Error("the loop claimed a server Stop already owns — two concurrent stops of one server")
		}
		if !stoppedByOther(t, a.srv) {
			t.Error("Stop claimed the server but did not stop it")
		}
	})
	t.Run("the loop claims first", func(t *testing.T) {
		s := newSup()
		a := &cpAttempt{srv: grpc.NewServer()}
		if !s.adopt(a) {
			t.Fatal("adopt refused before Stop")
		}
		if !s.claimTeardown(a) {
			t.Fatal("the loop could not claim a published server nobody else claimed")
		}
		if err := s.Stop(t.Context()); err != nil {
			t.Fatal(err)
		}
		if stoppedByOther(t, a.srv) {
			t.Error("Stop stopped a server the loop had already claimed — two concurrent stops of one server")
		}
	})
	t.Run("never published", func(t *testing.T) {
		s := newSup()
		if err := s.Stop(t.Context()); err != nil {
			t.Fatal(err)
		}
		a := &cpAttempt{srv: grpc.NewServer()}
		if s.adopt(a) {
			t.Fatal("adopt accepted a server after Stop")
		}
		if !s.claimTeardown(a) {
			t.Error("an unpublished server has no owner — it leaks")
		}
		a.srv.Stop()
	})
}

// cpGRPCTeardownViolations scans package-main sources for the teardown-owner
// rule and returns one line per violation:
//
//   - Stop/GracefulStop on a *grpc.Server is referenced only by
//     teardownCPGRPCServer (the owner helper), gracefulStopBounded (the bounded
//     mechanism it reaches) and buildControlPlaneServer (a server that failed
//     its Listen and was never published, pinned by its own wall);
//   - the call graph into that helper is exact: gracefulStopBounded ←
//     stopControlPlaneServer ← teardownCPGRPCServer ← {Stop, releaseAttempt,
//     retireCPGRPCServer}, and retireCPGRPCServer ← releaseAttempt;
//   - both claim holders claim BEFORE tearing down: releaseAttempt calls
//     claimTeardown, and Stop assigns `s.srv = nil`, ahead of every teardown.
//
// Receivers are resolved syntactically (cpGRPCServerResolver).
func cpGRPCTeardownViolations(files []*ast.File) []string {
	sc := &cpTeardownScan{
		res:           newCPGRPCServerResolver(files),
		callers:       map[string]map[string]bool{},
		firstTeardown: map[string]token.Pos{},
		claimAt:       map[string]token.Pos{},
	}
	for _, f := range files {
		for _, decl := range f.Decls {
			owner := cpTopLevelName(decl)
			ast.Inspect(decl, func(n ast.Node) bool {
				sc.visit(owner, n)
				return true
			})
		}
	}
	return sc.report()
}

// cpIsGRPCServerType reports whether e is the type expression *grpc.Server.
func cpIsGRPCServerType(e ast.Expr) bool {
	st, ok := e.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := st.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "grpc" && sel.Sel.Name == "Server"
}

// cpGRPCServerResolver decides, syntactically, whether an expression is a
// *grpc.Server: an identifier declared with that type or assigned from a
// function returning one, or a selector naming a struct field of that type.
type cpGRPCServerResolver struct {
	fields  map[string]bool // struct fields of type *grpc.Server
	returns map[string]bool // functions whose first result is *grpc.Server
}

func newCPGRPCServerResolver(files []*ast.File) *cpGRPCServerResolver {
	r := &cpGRPCServerResolver{fields: map[string]bool{}, returns: map[string]bool{"NewServer": true}}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.StructType:
				for _, fld := range d.Fields.List {
					if !cpIsGRPCServerType(fld.Type) {
						continue
					}
					for _, nm := range fld.Names {
						r.fields[nm.Name] = true
					}
				}
			case *ast.FuncDecl:
				if res := d.Type.Results; res != nil && len(res.List) > 0 && cpIsGRPCServerType(res.List[0].Type) {
					r.returns[d.Name.Name] = true
				}
			}
			return true
		})
	}
	return r
}

func (r *cpGRPCServerResolver) isServer(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.SelectorExpr:
		return r.fields[x.Sel.Name]
	case *ast.CallExpr:
		return r.returns[cpTeardownCalleeName(x)]
	case *ast.Ident:
		if x.Obj == nil {
			return false
		}
		switch d := x.Obj.Decl.(type) {
		case *ast.Field:
			return cpIsGRPCServerType(d.Type)
		case *ast.ValueSpec:
			return d.Type != nil && cpIsGRPCServerType(d.Type)
		case *ast.AssignStmt:
			return r.assignedServer(d, x.Name)
		}
	}
	return false
}

// assignedServer reports whether name is bound to a *grpc.Server by d.
func (r *cpGRPCServerResolver) assignedServer(d *ast.AssignStmt, name string) bool {
	for i, l := range d.Lhs {
		if id, ok := l.(*ast.Ident); !ok || id.Name != name {
			continue
		}
		if len(d.Rhs) == len(d.Lhs) {
			return r.isServer(d.Rhs[i])
		}
		// v, w, ... := f(): only the first result of a server-returning f.
		return i == 0 && r.isServer(d.Rhs[0])
	}
	return false
}

// cpTeardownCalleeName names a call's function: a bare identifier, or any selector's
// final name.
func cpTeardownCalleeName(c *ast.CallExpr) string {
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// cpTeardownScan accumulates what cpGRPCTeardownViolations checks.
type cpTeardownScan struct {
	res           *cpGRPCServerResolver
	out           []string
	callers       map[string]map[string]bool // tracked callee -> callers
	firstTeardown map[string]token.Pos       // claim holder -> first teardown call
	claimAt       map[string]token.Pos       // claim holder -> first claim
}

var (
	cpTeardownStopOwners = map[string]bool{"teardownCPGRPCServer": true, "gracefulStopBounded": true, "buildControlPlaneServer": true}
	cpTeardownCallGraph  = map[string][]string{
		"gracefulStopBounded":    {"stopControlPlaneServer"},
		"stopControlPlaneServer": {"teardownCPGRPCServer"},
		"teardownCPGRPCServer":   {"Stop", "releaseAttempt", "retireCPGRPCServer"},
		"retireCPGRPCServer":     {"releaseAttempt"},
	}
)

func cpEarliest(m map[string]token.Pos, key string, p token.Pos) {
	if cur, ok := m[key]; !ok || p < cur {
		m[key] = p
	}
}

func (sc *cpTeardownScan) visit(owner string, n ast.Node) {
	switch x := n.(type) {
	case *ast.SelectorExpr:
		if (x.Sel.Name == "Stop" || x.Sel.Name == "GracefulStop") && !cpTeardownStopOwners[owner] && sc.res.isServer(x.X) {
			sc.out = append(sc.out, fmt.Sprintf("%s references %s on a *grpc.Server outside the teardown owner", owner, x.Sel.Name))
		}
	case *ast.CallExpr:
		sc.visitCall(owner, x)
	case *ast.AssignStmt:
		if owner == "Stop" && cpAssignsNilToSrv(x) {
			cpEarliest(sc.claimAt, owner, x.Pos())
		}
	}
}

func (sc *cpTeardownScan) visitCall(owner string, x *ast.CallExpr) {
	name := cpTeardownCalleeName(x)
	if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
		// Only the supervisor's own methods (receiver s) are tracked by name.
		if recv, ok := sel.X.(*ast.Ident); !ok || recv.Name != "s" {
			return
		}
	}
	isHolder := owner == "Stop" || owner == "releaseAttempt"
	if name == "claimTeardown" && owner == "releaseAttempt" {
		cpEarliest(sc.claimAt, owner, x.Pos())
	}
	if _, tracked := cpTeardownCallGraph[name]; !tracked {
		return
	}
	if sc.callers[name] == nil {
		sc.callers[name] = map[string]bool{}
	}
	sc.callers[name][owner] = true
	if isHolder && (name == "teardownCPGRPCServer" || name == "retireCPGRPCServer") {
		cpEarliest(sc.firstTeardown, owner, x.Pos())
	}
}

// cpAssignsNilToSrv matches `<x>.srv = nil`.
func cpAssignsNilToSrv(x *ast.AssignStmt) bool {
	if len(x.Lhs) != 1 || len(x.Rhs) != 1 {
		return false
	}
	sel, ok := x.Lhs[0].(*ast.SelectorExpr)
	id, isIdent := x.Rhs[0].(*ast.Ident)
	return ok && sel.Sel.Name == "srv" && isIdent && id.Name == "nil"
}

func (sc *cpTeardownScan) report() []string {
	out := append([]string(nil), sc.out...)
	for callee, want := range cpTeardownCallGraph {
		var got []string
		for c := range sc.callers[callee] {
			got = append(got, c)
		}
		sort.Strings(got)
		w := append([]string(nil), want...)
		sort.Strings(w)
		if strings.Join(got, ",") != strings.Join(w, ",") {
			out = append(out, fmt.Sprintf("%s callers = %v, want exactly %v", callee, got, w))
		}
	}
	for _, holder := range []string{"Stop", "releaseAttempt"} {
		td, ok := sc.firstTeardown[holder]
		if !ok {
			continue // reported by the call-graph check
		}
		if c, ok := sc.claimAt[holder]; !ok || c > td {
			out = append(out, fmt.Sprintf("%s tears a server down without first claiming it", holder))
		}
	}
	sort.Strings(out)
	return out
}

// TestChaos71_Wall_SupervisedGRPCServersHaveOneTeardownOwner is the structural
// half of the claim: no production path can call Stop or GracefulStop on a
// supervised server except through the one helper, reached only by a claim
// holder that claimed first. With a negative control proving the scanner sees
// the shape the review found.
func TestChaos71_Wall_SupervisedGRPCServersHaveOneTeardownOwner(t *testing.T) {
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
	if v := cpGRPCTeardownViolations(files); len(v) != 0 {
		t.Errorf("supervised gRPC server teardown has more than one owner:\n  %s", strings.Join(v, "\n  "))
	}

	// Negative controls: the unclaimed retirement the review found, and a
	// direct GracefulStop from the shutdown path.
	for _, src := range []string{
		`package main
import "google.golang.org/grpc"
type cpAttempt struct{ srv *grpc.Server }
func (s *cpListenerSupervisor) releaseAttempt() { a := s.cur; a.srv.Stop() }`,
		`package main
import "google.golang.org/grpc"
func (s *cpListenerSupervisor) Stop() { srv := s.currentServer(); srv.GracefulStop() }
func (s *cpListenerSupervisor) currentServer() *grpc.Server { return nil }`,
	} {
		f, perr := parser.ParseFile(token.NewFileSet(), "neg.go", src, 0)
		if perr != nil {
			t.Fatal(perr)
		}
		got := cpGRPCTeardownViolations(append(append([]*ast.File(nil), files...), f))
		found := false
		for _, line := range got {
			if strings.Contains(line, "outside the teardown owner") {
				found = true
			}
		}
		if !found {
			t.Errorf("the wall did not flag a direct stop outside the owner:\n%s", src)
		}
	}
}
