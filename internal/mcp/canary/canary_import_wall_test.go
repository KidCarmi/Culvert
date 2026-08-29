package canary

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestCanaryPackageHoldsNoExecutionCapability is the compile-time firewall for the canary
// package (§6): it must hold NO path to the irreversible side effect, so it may never
// import the execution plane, the upstream client, or the materialize-capable credential
// broker. A pure readiness/scope/trust/budget engine reasons ABOUT those capabilities from
// caller-supplied facts; it must never be able to REACH them. If a future change makes the
// canary package import one of these, this build fails — arming Canary is a separately
// reviewed activation in the composition layer, never a dependency the decision engine
// acquires.
//
// Direct-import based (not transitive): the point is that the canary package's own source
// names none of these packages, so no symbol of theirs is in scope here. The root
// composition wall (mcp_execution_posture_test.go) separately pins that production wiring
// composes no live executor.
func TestCanaryPackageHoldsNoExecutionCapability(t *testing.T) {
	forbidden := map[string]string{ // #nosec G101 -- import paths + descriptions, not hardcoded credentials
		"github.com/KidCarmi/Culvert/internal/mcp/execution":            "the guarded-execution plane (Upstream.Call)",
		"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient":       "the upstream HTTPS client (real egress)",
		"github.com/KidCarmi/Culvert/internal/mcp/credentials/broker":   "the materialize-capable broker (real key material)",
		"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider": "a provider of key material",
	}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		// Scan the package's OWN sources, tests included — a test that reached the executor
		// would still put the symbol in the package's compilation.
		f, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		scanned++
		for _, imp := range f.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			if why, bad := forbidden[p]; bad {
				t.Errorf("%s imports %s — the canary package must hold no path to %s. "+
					"The readiness engine reasons about live capabilities from facts; it must never reach them.",
					name, p, why)
			}
		}
	}
	if scanned < 5 {
		t.Fatalf("only %d package files scanned; the import wall is not covering the package", scanned)
	}
}
