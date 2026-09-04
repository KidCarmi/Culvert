package upstream

// authenticated_url_wall_test.go — structural proof for the 2F-C review
// blocker 6: the credential-bearing proxy URL is constructed by exactly one
// function (authenticatedURL) and that function is reached from exactly two
// narrowly scoped transport selectors — ProxyFunc (real requests) and
// probeProxySelector (health probes) — both of which run AFTER the entry's
// credential eligibility check. Any new caller fails this test.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWall_AuthenticatedURLIsConstructedOnlyInsideSelectors(t *testing.T) {
	allowed := map[string]bool{"ProxyFunc": true, "probeProxySelector": true}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "authenticatedURL" {
					return true
				}
				found++
				if !allowed[fn.Name.Name] {
					t.Errorf("%s: authenticatedURL is called from %s; only the transport selectors (ProxyFunc, probeProxySelector) may construct a credential-bearing URL", fset.Position(call.Pos()), fn.Name.Name)
				}
				return true
			})
		}
	}
	if found != 2 {
		t.Fatalf("expected exactly 2 authenticatedURL call sites (ProxyFunc + probeProxySelector), found %d", found)
	}
}

// The periodic loop labels its verdicts periodic and the seam never sees a
// password; the probe result stored on the entry is bounded state only.
func TestWall_PeriodicLoopLabelsSourceAndSeamIsCredentialFree(t *testing.T) {
	prev := ProbeTransport
	t.Cleanup(func() { ProbeTransport = prev })
	pool := &Pool{}
	if err := pool.Configure([]Entry{{URL: "http://svc:loop-pw@parent.test:3128"}}, 5, time.Minute); err != nil {
		t.Fatal(err)
	}
	probed := make(chan string, 4)
	ProbeTransport = func(a *url.URL) http.RoundTripper { probed <- a.String(); return fakeRT{status: 200} }
	ctx, cancel := context.WithCancel(context.Background())
	go RunHealthCheckLoop(ctx, pool, 5*time.Millisecond)
	select {
	case seen := <-probed:
		if strings.Contains(seen, "loop-pw") || strings.Contains(seen, "@") {
			t.Fatalf("seam must be credential-free, got %s", seen)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the periodic loop never probed")
	}
	cancel()
	// Wait for the verdict to land (the seam fires before setProbe).
	deadline := time.Now().Add(2 * time.Second)
	for {
		h := pool.List()[0].Health
		if h.Source == ProbePeriodic && h.Status == ProbeHealthy && h.LastProbeAt != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("health = %+v, want periodic/healthy", h)
		}
		time.Sleep(time.Millisecond)
	}
	if st := pool.List()[0]; strings.Contains(st.URL, "loop-pw") || strings.Contains(st.Probe.Reason, "loop-pw") {
		t.Fatalf("stored probe state must never carry the password: %+v", st)
	}
}
