package admission

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// These restrictions are specific to this execution engine, not a proposed
// architecture framework. Changing one requires revisiting ADR-0039.
func boundaryViolations(source []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), "engine.go", source, 0)
	if err != nil {
		return []string{err.Error()}
	}
	var violations []string
	allowed := map[string]bool{"net": true, "net/netip": true, "sort": true, "sync": true, "sync/atomic": true, "time": true}
	for _, imp := range f.Imports {
		name, _ := strconv.Unquote(imp.Path.Value)
		if !allowed[name] {
			violations = append(violations, "application dependency: "+name)
		}
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "init" {
			violations = append(violations, "implicit initialization")
		}
		g, ok := decl.(*ast.GenDecl)
		if !ok || g.Tok != token.VAR {
			continue
		}
		for _, spec := range g.Specs {
			v := spec.(*ast.ValueSpec)
			// These two immutable empty views contain no runtime owner.
			for _, name := range v.Names {
				if name.Name != "emptyIPFilterView" && name.Name != "emptyRLExemptView" {
					violations = append(violations, "package state: "+name.Name)
				}
			}
		}
	}
	return violations
}

func TestAdmissionBoundary_NoApplicationDependenciesOrSharedState(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		source, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		checked++
		if got := boundaryViolations(source); len(got) != 0 {
			t.Errorf("%s: %v", entry.Name(), got)
		}
	}
	if checked == 0 {
		t.Fatal("no production files inspected")
	}
}

func TestAdmissionBoundary_RejectsRegressions(t *testing.T) {
	for name, source := range map[string]string{
		"shared timing":       "package admission; var grace = 1",
		"singleton":           "package admission; var global = new(RateLimiter)",
		"application logging": `package admission; import "github.com/KidCarmi/Culvert/internal/obs"`,
		"persistence":         `package admission; import "os"`,
		"implicit lifecycle":  "package admission; func init() {}",
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations([]byte(source))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
}
