package connlimit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

// Structural wall for the one-critical-section contract.
//
// Behavioural coverage cannot reach this. The fail-open window the two-phase
// Release permitted needs Release A to be descheduled between its unlocked
// decrement and its re-lock while two further Acquire/Release cycles complete —
// an interleaving a test cannot schedule against the real implementation, which
// is why the defect proof in connlimit_critsec_test.go owns a verbatim legacy
// copy with an injected pause instead. Every behavioural test in this package
// keeps passing against the two-phase shape (verified), so without this wall a
// revert to it would land green.
//
// What is pinned is therefore the MECHANISM the correctness argument rests on:
// each of Acquire and Release takes its shard lock exactly once, so the lookup,
// the mutation and the conditional delete are indivisible. The repo precedent is
// sanitizeLog's scan-count gate — an AST assertion with its own control, chosen
// over a timing or behavioural form because it is deterministic under any load,
// with or without -race, on any hardware.

// shardLockOps counts sh.mu.Lock() / sh.mu.Unlock() calls in a function body,
// plus any atomic.Add/Load against a counter — the pre-fix shape's fingerprint.
type shardLockOps struct {
	locks, unlocks, counterAtomics int
}

func scanShardLockOps(t *testing.T, src, fnName string) shardLockOps {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var ops shardLockOps
	var found bool
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != fnName || fn.Body == nil {
			continue
		}
		found = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "Lock":
				if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "mu" {
					ops.locks++
				}
			case "Unlock":
				if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "mu" {
					ops.unlocks++
				}
			case "AddInt64", "LoadInt64":
				// atomic.AddInt64/LoadInt64 against the per-IP counter is the
				// pointer representation's fingerprint. The limiter-level
				// atomics (maxPerIP, enabled, rejected) are typed atomic.Int64 /
				// atomic.Bool and use .Load()/.Add(), so they do not match here.
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "atomic" {
					ops.counterAtomics++
				}
			}
			return true
		})
	}
	if !found {
		t.Fatalf("function %q not found — the wall's selector is stale and it is "+
			"no longer checking anything", fnName)
	}
	return ops
}

// readConnlimitSource returns this package's implementation source.
func readConnlimitSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("connlimit.go")
	if err != nil {
		t.Fatalf("read connlimit.go: %v", err)
	}
	return string(b)
}

func TestWall_ReleaseTakesTheShardLockExactlyOnce(t *testing.T) {
	src := readConnlimitSource(t)

	for _, fn := range []string{"Acquire", "Release"} {
		ops := scanShardLockOps(t, src, fn)
		if ops.locks != 1 {
			t.Errorf("%s takes sh.mu.Lock() %d times, want exactly 1.\n"+
				"More than one critical section is what let the pre-fix Release "+
				"delete a live connection's entry (see its doc and "+
				"TestRelease_LegacyTwoPhaseLosesALiveSlot) and it is the dominant "+
				"cost when traffic arrives from a single NAT egress.", fn, ops.locks)
		}
		if ops.unlocks < 1 {
			t.Errorf("%s never unlocks its shard (%d) — the lock must be released "+
				"on every path", fn, ops.unlocks)
		}
		if ops.counterAtomics != 0 {
			t.Errorf("%s performs %d atomic op(s) on the per-IP counter, want 0. "+
				"The counter is stored by value and every mutation is already "+
				"serialised by the shard lock; a pointer representation "+
				"reintroduces the stale-identity window and an allocation per "+
				"tracked IP.", fn, ops.counterAtomics)
		}
	}
}

// TestWall_RejectsTheVerbatimPreFixShape is the wall's CONTROL. A selector that
// silently matched nothing would satisfy every assertion above forever, so the
// predicate is run against a verbatim copy of the shipped-before bodies and
// required to REJECT them. Without this, a rename in the implementation would
// turn the wall into a no-op rather than a failure.
func TestWall_RejectsTheVerbatimPreFixShape(t *testing.T) {
	const preFix = `package connlimit

func (cl *ConnLimiter) Acquire(ip string) bool {
	sh := cl.shard(ip)
	sh.mu.Lock()
	ctr, ok := sh.conns[ip]
	if !ok {
		v := int64(0)
		ctr = &v
		sh.conns[ip] = ctr
	}
	n := atomic.AddInt64(ctr, 1)
	enabled := cl.enabled.Load()
	limit := cl.maxPerIP.Load()
	sh.mu.Unlock()

	if enabled && n > limit {
		sh.mu.Lock()
		if cur, exists := sh.conns[ip]; exists && cur == ctr {
			if atomic.AddInt64(ctr, -1) <= 0 {
				delete(sh.conns, ip)
			}
		}
		sh.mu.Unlock()
		cl.rejected.Add(1)
		return false
	}
	return true
}

func (cl *ConnLimiter) Release(ip string) {
	sh := cl.shard(ip)
	sh.mu.Lock()
	ctr, ok := sh.conns[ip]
	sh.mu.Unlock()
	if ok {
		if atomic.AddInt64(ctr, -1) <= 0 {
			sh.mu.Lock()
			if atomic.LoadInt64(ctr) <= 0 {
				delete(sh.conns, ip)
			}
			sh.mu.Unlock()
		}
	}
}
`
	rel := scanShardLockOps(t, preFix, "Release")
	if rel.locks != 2 {
		t.Errorf("the wall no longer sees the pre-fix Release's two lock "+
			"acquisitions (counted %d) — its selector is stale and it would pass "+
			"against the defect", rel.locks)
	}
	if rel.counterAtomics == 0 {
		t.Error("the wall no longer sees the pre-fix Release's counter atomics — " +
			"its selector is stale")
	}

	acq := scanShardLockOps(t, preFix, "Acquire")
	if acq.locks != 2 {
		t.Errorf("the wall no longer sees the pre-fix Acquire's two lock "+
			"acquisitions (counted %d)", acq.locks)
	}
}
