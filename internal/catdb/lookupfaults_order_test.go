package catdb

import (
	"go/ast"
	"go/parser"
	"go/token"
	"runtime"
	"sync"
	"testing"
)

// atomicCallOrder returns "field.Method" for every c.<field>.<Method>() call in
// the body of the named method of catdb.go, in source order.
func atomicCallOrder(t *testing.T, method string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "catdb.go", nil, 0)
	if err != nil {
		t.Fatalf("parse catdb.go: %v", err)
	}
	var calls []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != method || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if inner, ok := sel.X.(*ast.SelectorExpr); ok {
				calls = append(calls, inner.Sel.Name+"."+sel.Sel.Name)
			}
			return true
		})
	}
	if len(calls) == 0 {
		t.Fatalf("method %s not found or has no field calls", method)
	}
	return calls
}

func indexOf(calls []string, want string) int {
	for i, c := range calls {
		if c == want {
			return i
		}
	}
	return -1
}

// TestLookupFaults_DegradedImpliesACountedFault pins both halves of the
// ordering contract documented on LookupFaults. The invariant is
// degraded ⇒ memFaults ≥ 1: a scrape must never report a degraded store with
// "0 memory fault(s)". The race that breaks it is a window of a few
// instructions, so the source-order check is the deterministic gate and the
// stress run is the behavioural cross-check.
func TestLookupFaults_DegradedImpliesACountedFault(t *testing.T) {
	writer := atomicCallOrder(t, "noteMemFault")
	if a, c := indexOf(writer, "memFaults.Add"), indexOf(writer, "degraded.CompareAndSwap"); a < 0 || c < 0 || a > c {
		t.Fatalf("noteMemFault must Add to memFaults BEFORE latching degraded; calls in order: %v", writer)
	}
	reader := atomicCallOrder(t, "LookupFaults")
	if d, m := indexOf(reader, "degraded.Load"), indexOf(reader, "memFaults.Load"); d < 0 || m < 0 || d > m {
		t.Fatalf("LookupFaults must load degraded BEFORE memFaults; calls in order: %v", reader)
	}

	iterations := 2000
	if testing.Short() {
		iterations = 200
	}
	readers := runtime.GOMAXPROCS(0)
	if readers > 4 {
		readers = 4
	}
	for i := 0; i < iterations; i++ {
		c := &CommunityDB{}
		var wg sync.WaitGroup
		bad := make(chan uint64, readers)
		for r := 0; r < readers; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					_, mem, degraded := c.LookupFaults()
					if degraded {
						if mem == 0 {
							bad <- mem
						}
						return
					}
				}
			}()
		}
		if !c.noteMemFault() {
			t.Fatal("the first fault must latch degraded")
		}
		wg.Wait()
		close(bad)
		if _, broken := <-bad; broken {
			t.Fatalf("iteration %d: a reader saw degraded with memFaults == 0", i)
		}
	}
}
