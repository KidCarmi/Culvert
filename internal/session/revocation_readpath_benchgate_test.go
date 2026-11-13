//go:build benchgate

package session

// Performance-regression gate for the single-acquisition revocation read path
// (StatusFor, and Decode's use of it, in session.go).
//
// Correctness contracts live in revocation_readpath_test.go and run in the
// normal suite; this file holds the PERFORMANCE contract only, in the
// repository's benchgate convention:
//
//	go test -tags benchgate -run 'TestBenchGate_' -v ./internal/session/
//
// Two gates, deliberately of different kinds, and NEITHER is timing-based:
//
//   - The ALLOCATION gate is absolute and hardware-independent. The read path
//     runs on every authenticated proxy request, so an allocation here is
//     attacker-reachable garbage per request.
//   - The ACQUISITION-COUNT gate is STRUCTURAL: it reads the AST and requires
//     that StatusFor takes the list mutex exactly once and that Decode asks it
//     once rather than calling the two single-question methods.
//
// ── Why the acquisition gate is structural and not a timing ratio ────────────
//
// Because this repository has already learned that lesson three times and
// written it down — see proxy_sanitizelog_benchgate_test.go, internal/connlimit,
// internal/threatfeed and the latency histogram, where scaling-ratio gates were
// built, rejected and replaced with structural ones because "a gate that can
// flake gets muted".
//
// It applies with extra force here. The SIZE of the win is a function of how
// contended the lock is, which depends on the core count and the arrival rate:
// on the 4-core development box the two checks' own cost falls 1.5x serial and
// 1.7x parallel, while end-to-end `BenchmarkDecodeParallel` throughput is
// UNCHANGED, because at 4 cores the lock is only a few percent utilised and is
// not yet the limiter. The value of halving the acquisitions is HEADROOM — it
// doubles the core count at which this mutex becomes the authentication path's
// throughput ceiling — and headroom is precisely what a 4-core runner cannot
// measure. A ratio bound chosen on this box would mean something different on
// every other one.
//
// What IS measurable and hardware-independent is the number of acquisitions, so
// that is what the gate asserts. The measurements themselves live in
// revocation_readpath_bench_test.go, where a measurement belongs — reproducible
// on demand rather than asserted against a threshold that means different
// things on different machines.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestBenchGate_RevocationStatusAllocFree pins the read path at zero
// allocations, on the miss shape that every allowed request takes and on the
// hit shape an attacker replaying a logged-out cookie can drive.
func TestBenchGate_RevocationStatusAllocFree(t *testing.T) {
	const maxAllocs int64 = 0

	for _, arm := range []struct {
		name string
		fn   func(*testing.B)
	}{
		{"miss/serial", BenchmarkRevocationStatus_OneLock},
		{"miss/parallel", BenchmarkRevocationStatusParallel_OneLock},
		{"hit/parallel", BenchmarkRevocationStatusParallel_OneLockHit},
		{"no-subject/parallel", BenchmarkRevocationStatusParallel_OneLockNoSubject},
	} {
		res := testing.Benchmark(arm.fn)
		allocs := res.AllocsPerOp()
		t.Logf("%s: %d allocs/op, %d B/op, %d ns/op (bound %d allocs/op)",
			arm.name, allocs, res.AllocedBytesPerOp(), res.NsPerOp(), maxAllocs)
		if allocs > maxAllocs {
			t.Errorf("the revocation read path allocates %d/op on %s, bound %d — this runs on every authenticated proxy request",
				allocs, arm.name, maxAllocs)
		}
	}
}

// TestBenchGate_RevocationReadPathTakesOneLock is the structural gate.
//
// It pins the two properties the change consists of:
//
//  1. StatusFor acquires the list mutex exactly ONCE. Two acquisitions is the
//     shape it replaced, and splitting it again — for example by having it call
//     IsRevoked and IsUserRevoked rather than the *Locked bodies — would
//     silently restore the cost while keeping the signature.
//  2. Decode asks ONCE. Reintroducing an IsRevoked or IsUserRevoked call there
//     puts the second acquisition back on every authenticated request, which is
//     exactly the regression this gate exists to catch, and no allocation or
//     correctness test would notice.
func TestBenchGate_RevocationReadPathTakesOneLock(t *testing.T) {
	const file = "session.go"

	statusFor := parseMethodDecl(t, file, "RevocationList", "StatusFor")
	if n := countMutexLocks(statusFor, "Lock"); n != 1 {
		t.Errorf("StatusFor takes the list mutex %d times, want exactly 1 — "+
			"two acquisitions per authenticated request is the shape it replaced "+
			"(see the measurement on StatusFor); if it now delegates to IsRevoked/IsUserRevoked, "+
			"call the *Locked bodies instead", n)
	}
	if n := countMutexLocks(statusFor, "RLock"); n != 0 {
		t.Errorf("StatusFor takes %d read locks — an RWMutex on this field was measured ~20%% SLOWER "+
			"under contention than the exclusive mutex, because the critical section is one map lookup "+
			"and RLock/RUnlock are two atomic writes to the same cache line. See StatusFor's note", n)
	}

	decode := parseFuncDecl(t, file, "Decode")
	for _, banned := range []string{"IsRevoked", "IsUserRevoked"} {
		if n := countCalledMethods(decode, banned); n != 0 {
			t.Errorf("Decode calls %s %d times — that is a second acquisition of the revocation mutex "+
				"on every authenticated proxy request. Use StatusFor, which answers both questions under one",
				banned, n)
		}
	}
	if n := countCalledMethods(decode, "StatusFor"); n != 1 {
		t.Errorf("Decode calls StatusFor %d times, want exactly 1", n)
	}
}

// TestBenchGate_RevocationGateRejectsTheTwoLockShape is the negative control:
// a predicate that matches nothing would pass on any code, so the gate is run
// against a function that deliberately has the pre-change shape.
func TestBenchGate_RevocationGateRejectsTheTwoLockShape(t *testing.T) {
	fn := parseFuncDecl(t, "revocation_readpath_benchgate_oracle_test.go", "twoLockRevocationStatus")
	if n := countMutexLocks(fn, "Lock"); n != 2 {
		t.Fatalf("the acquisition-count predicate found %d acquisitions in the two-acquisition oracle, want 2 — "+
			"the predicate matches nothing and would pass on any code", n)
	}
	if n := countCalledMethods(fn, "IsRevoked"); n != 1 {
		t.Fatalf("the called-method predicate found %d IsRevoked calls in the oracle, want 1 — "+
			"the predicate matches nothing and would pass on any code", n)
	}
}

// ─── AST helpers ────────────────────────────────────────────────────────────

func parseSourceFile(t *testing.T, file string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return f
}

// parseFuncDecl returns the named top-level function's declaration.
func parseFuncDecl(t *testing.T, file, name string) *ast.FuncDecl {
	t.Helper()
	for _, d := range parseSourceFile(t, file).Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == name {
			return fd
		}
	}
	t.Fatalf("%s: func %s not found — if it was renamed or moved, update this gate rather than deleting it", file, name)
	return nil
}

// parseMethodDecl returns the named method on the named receiver type.
func parseMethodDecl(t *testing.T, file, recv, name string) *ast.FuncDecl {
	t.Helper()
	for _, d := range parseSourceFile(t, file).Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || fd.Name.Name != name {
			continue
		}
		if receiverTypeName(fd) == recv {
			return fd
		}
	}
	t.Fatalf("%s: method (%s).%s not found — if it was renamed or moved, update this gate rather than deleting it", file, recv, name)
	return nil
}

func receiverTypeName(fd *ast.FuncDecl) string {
	if len(fd.Recv.List) == 0 {
		return ""
	}
	expr := fd.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// countMutexLocks counts `<something>.mu.<method>()` calls in fn's body, which
// is how every acquisition of the revocation list mutex is spelled.
func countMutexLocks(fn *ast.FuncDecl, method string) int {
	n := 0
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != method {
			return true
		}
		if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "mu" {
			n++
		}
		return true
	})
	return n
}

// countCalledMethods counts calls whose selector is the given name, regardless
// of receiver.
func countCalledMethods(fn *ast.FuncDecl, name string) int {
	n := 0
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
			n++
		}
		return true
	})
	return n
}
