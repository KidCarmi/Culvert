package backupstrip

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// These restrictions are specific to this sanitizer (ADR-0043). It transforms
// bytes that decide whether credential material reaches an archive, so it may
// not import the application, log, or hold mutable state. The only package
// variables permitted are the read-only error sentinels and the two read-only
// key tables, named explicitly; anything else is a boundary change.
var allowedPackageVars = map[string]bool{
	"upstreamSettingsCredentialKeys":     true,
	"upstreamBoundKeys":                  true,
	"errUpstreamSettingsDuplicateKey":    true,
	"errUpstreamSettingsKeyCase":         true,
	"errUpstreamSettingsV2Malformed":     true,
	"errUpstreamBackupPreparedDowngrade": true,
}

func boundaryViolations(name string, source []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return []string{err.Error()}
	}
	var violations []string
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if strings.Contains(path, ".") || path == "log" || path == "os" {
			violations = append(violations, "dependency: "+path)
		}
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "init" {
			violations = append(violations, "implicit initialization")
		}
		g, ok := decl.(*ast.GenDecl)
		if !ok || g.Tok != token.VAR {
			continue
		}
		for _, spec := range g.Specs {
			for _, n := range spec.(*ast.ValueSpec).Names {
				if !allowedPackageVars[n.Name] {
					violations = append(violations, "package state: "+n.Name)
				}
			}
		}
	}
	return violations
}

func TestBackupstripBoundary_NoApplicationDependenciesOrSharedState(t *testing.T) {
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
		if got := boundaryViolations(entry.Name(), source); len(got) != 0 {
			t.Errorf("%s: %v", entry.Name(), got)
		}
	}
	if checked < 2 {
		t.Fatalf("inspected %d production files, want at least doc.go and strip.go", checked)
	}
}

func TestBackupstripBoundary_RejectsRegressions(t *testing.T) {
	for name, source := range map[string]string{
		"logging":            `package backupstrip; import "log"`,
		"file io":            `package backupstrip; import "os"`,
		"application import": `package backupstrip; import "github.com/KidCarmi/Culvert/internal/obs"`,
		"package state":      "package backupstrip; var seen = map[string]int{}",
		"implicit lifecycle": "package backupstrip; func init() {}",
	} {
		t.Run(name, func(t *testing.T) {
			if len(boundaryViolations("regression.go", []byte(source))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
}

// Independently constructible: the engine has no instance, so two concurrent
// calls on different bodies must not influence one another.
func TestBackupstrip_CallsAreIndependent(t *testing.T) {
	a := []byte(`{"upstream_proxies_v2":{"entries":[{"id":"a","credential":{"ciphertext":"x","keyId":"k","authorityHash":"h"}}]}}`)
	b := []byte(`{}`)
	done := make(chan int, 2)
	for _, body := range [][]byte{a, b} {
		go func(body []byte) {
			_, n, err := Strip(body)
			if err != nil {
				n = -1
			}
			done <- n
		}(body)
	}
	got := map[int]bool{<-done: true, <-done: true}
	if !got[1] || !got[0] {
		t.Fatalf("unexpected strip counts: %v", got)
	}
}
