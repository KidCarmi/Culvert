package main

// cdr_rpc_reservation_wall_test.go — every CDR RPC call in production code is
// classified by whether it goes through the data-path breaker (PR #1611,
// Codex P2 on c89e1e7).
//
// The breaker's split had been drawn by CALLER (status/UI callers use the
// non-consuming picker), not by whether the caller issues an RPC.
// apiCDRTest is an admin handler but issues a REAL Sanitize, so concurrent
// admin tests ran alongside the recovery probe uncounted and unreported. The
// line the wall now draws is the RPC itself:
//
//   - Sanitize is the data-path RPC the breaker exists to protect. Every
//     production function that calls it must reserve through
//     cdrPickPooledReserved and defer the reservation's Release (and records
//     the outcome on its RPC paths).
//   - The control-plane RPCs (Health, RenewCert, RevokeClient, EnrollStatus)
//     are NOT gated by the data-path breaker and must not feed it: the health
//     poller is how an open instance is observed at all, renewal and
//     enrollment recovery must work during a Sanitize outage, and a Health
//     reply is not evidence that Sanitize recovered. Each call site is listed
//     below with its function so a new one is a review event, and none of
//     them may reserve.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
	"google.golang.org/grpc"
)

// cdrControlRPCSites is every production function allowed to issue a CDR
// control-plane RPC, with why it is outside the data-path breaker.
var cdrControlRPCSites = map[string]string{
	"apiCDRHealth":              "admin Health read; a Health reply must not close the Sanitize breaker",
	"revokeWithProof":           "admin revoke through a peer instance; control plane, not data path",
	"runRenewFor":               "cert renewal must work while Sanitize is failing",
	"resolveRenewingGeneration": "renewal recovery over EnrollStatus; control plane",
	"EnrollStatus":              "enrollment status over a bootstrap connection, before any pool member exists",
	"probeAllMembers":           "health poller: how an open instance is observed at all",
	"warmupCDRClient":           "startup Health warm-up of a freshly dialed client",
}

var cdrControlRPCMethods = map[string]bool{
	"Health": true, "RenewCert": true, "RevokeClient": true, "EnrollStatus": true,
}

// cdrRPCUse is one CDR RPC call found by the wall.
type cdrRPCUse struct {
	fn, method string
	pos        token.Position
}

// cdrFuncFacts is what the wall needs to know about one production function.
type cdrFuncFacts struct {
	reserves, defersRelease bool
}

// scanCDRRPCs walks every non-test cdr*.go file in package main and returns
// the RPC call sites and, per function, whether it reserves and defers a
// Release. Methods on *CDRClient itself (the RPC wrappers) are skipped: they
// are the RPCs, not callers of them.
func scanCDRRPCs(t *testing.T) (uses []cdrRPCUse, facts map[string]cdrFuncFacts) {
	t.Helper()
	entries, err := os.ReadDir(pkgSourceDir())
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	facts = map[string]cdrFuncFacts{}
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasPrefix(name, "cdr") || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(pkgSourceDir(), name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || isCDRClientMethod(fn) {
				continue
			}
			fnUses, ff := inspectCDRFunc(fset, fn)
			uses = append(uses, fnUses...)
			facts[fn.Name.Name] = ff
		}
	}
	return uses, facts
}

// inspectCDRFunc collects one function's CDR RPC calls and whether it
// reserves and defers a Release.
func inspectCDRFunc(fset *token.FileSet, fn *ast.FuncDecl) (uses []cdrRPCUse, ff cdrFuncFacts) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.DeferStmt:
			if sel, ok := x.Call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Release" {
				ff.defersRelease = true
			}
		case *ast.Ident:
			if x.Name == "cdrPickPooledReserved" {
				ff.reserves = true
			}
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok &&
				(sel.Sel.Name == "Sanitize" || cdrControlRPCMethods[sel.Sel.Name]) {
				uses = append(uses, cdrRPCUse{fn.Name.Name, sel.Sel.Name, fset.Position(x.Pos())})
			}
		}
		return true
	})
	return uses, ff
}

func isCDRClientMethod(fn *ast.FuncDecl) bool {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return false
	}
	star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	id, ok := star.X.(*ast.Ident)
	return ok && id.Name == "CDRClient"
}

// TestCDRRPC_EverySanitizeCallOwnsAReservation is the wall.
func TestCDRRPC_EverySanitizeCallOwnsAReservation(t *testing.T) {
	uses, facts := scanCDRRPCs(t)
	sanitize := 0
	for _, u := range uses {
		ff := facts[u.fn]
		if u.method == "Sanitize" {
			sanitize++
			if !ff.reserves || !ff.defersRelease {
				t.Errorf("%s: %s calls Sanitize without owning a breaker reservation "+
					"(reserves=%v, defers Release=%v) — a data-path RPC that bypasses the "+
					"half-open budget runs alongside the recovery probe and is never reported",
					u.pos, u.fn, ff.reserves, ff.defersRelease)
			}
			continue
		}
		if _, ok := cdrControlRPCSites[u.fn]; !ok {
			t.Errorf("%s: %s calls the control-plane RPC %s and is not classified in "+
				"cdrControlRPCSites — decide whether it belongs to the data-path breaker",
				u.pos, u.fn, u.method)
		}
		if ff.reserves {
			t.Errorf("%s: control-plane caller %s reserves a data-path probe it cannot "+
				"report a Sanitize outcome for", u.pos, u.fn)
		}
	}
	if sanitize < 2 {
		t.Fatalf("the wall found %d Sanitize calls, want at least the proxy path and the admin "+
			"test — it has gone vacuous", sanitize)
	}
	for fn := range cdrControlRPCSites {
		if _, ok := facts[fn]; !ok {
			t.Errorf("cdrControlRPCSites lists %s, which no longer exists — prune it", fn)
		}
	}
}

// blockingSluice holds every Sanitize until release is closed, so the test
// can keep the probe in flight while other admin tests arrive.
type blockingSluice struct {
	*fakeSluice
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingSluice) Sanitize(stream pb.SluiceService_SanitizeServer) error {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return s.fakeSluice.Sanitize(stream)
}

// startBlockingSluice is startFakeSluice for a blockingSluice.
func startBlockingSluice(t *testing.T, srv *blockingSluice) (client *CDRClient, stop func()) {
	t.Helper()
	return startFakeSluiceWithServer(t, func(s *grpc.Server) { pb.RegisterSluiceServiceServer(s, srv) })
}

// TestApiCDRTest_HalfOpenAdmitsOnlyTheBudgetAndRecordsTheOutcome: concurrent
// admin tests during half-open — at most the probe budget reach Sluice, the
// rest get a clear 503, and the admitted test's outcome closes the breaker.
func TestApiCDRTest_HalfOpenAdmitsOnlyTheBudgetAndRecordsTheOutcome(t *testing.T) {
	resetCDRState(t)
	srv := &blockingSluice{
		fakeSluice: &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_CLEAN}},
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	c, stop := startBlockingSluice(t, srv)
	defer stop()
	cdrClientMu.Lock()
	cdrActiveCfg = CDRConfig{Enabled: true, DefaultProfile: "default"}
	cdrClientMu.Unlock()
	cdrPoolInstallSingleForTest(c)
	defer cdrPool.shutdown()

	b := cdrPool.List()[0].Breaker
	now := time.Now()
	var clockMu sync.Mutex
	b.setNowFn(func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now })
	tripOpen(t, b)
	clockMu.Lock()
	now = now.Add(b.cfg.ResetTimeout + time.Second)
	clockMu.Unlock()

	post := func() *httptest.ResponseRecorder {
		r := newAdminRequest(http.MethodPost, "/api/cdr/test?filename=a.pdf", []byte("data"))
		r.Header.Set("Content-Type", "application/pdf")
		w := httptest.NewRecorder()
		apiCDRTest(w, r)
		return w
	}

	// The probe holder: admitted, then held inside Sluice.
	probe := make(chan *httptest.ResponseRecorder, 1)
	go func() { probe <- post() }()
	select {
	case <-srv.entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the first admin test never reached Sluice")
	}

	// Everyone else while the probe is in flight: refused, never reaching Sluice.
	const extra = 8
	var wg sync.WaitGroup
	codes := make(chan int, extra)
	for i := 0; i < extra; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- post().Code }()
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusServiceUnavailable {
			t.Errorf("REGRESSION: a concurrent admin test got %d while the half-open probe was "+
				"in flight, want 503 — it bypassed the probe budget", code)
		}
	}

	close(srv.release)
	w := <-probe
	if w.Code != http.StatusOK {
		t.Fatalf("the admitted admin test got %d: %s", w.Code, w.Body.String())
	}
	if b.State() != cbStateClosed {
		t.Fatalf("REGRESSION: breaker %s after the admitted admin test succeeded — its outcome "+
			"was not recorded", breakerStateName(b.State()))
	}
}
