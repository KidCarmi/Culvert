package main

// CHAOS-63 actor-bound wall (Codex review, PR #1532). The audit Actor is
// bounded for RENDERING in exactly one place — addAuditEntry, which auditAdd
// points at — and nowhere else, because auditActor itself must stay the full
// principal (MCP four-eyes compares it for identity). The first version of the
// render bound lived only in auditEventDiffID, so every producer that builds an
// AuditEntry itself skipped it: the release DispatchService handed the full
// auditActor(r) straight to auditAdd. This wall makes that class structural:
//
//   - no non-test file in the module may reference internal/audit's Add except
//     inside addAuditEntry (calls, aliased imports, dot imports and function
//     values such as `sink: audit.Add` are all references), and
//   - auditAdd must be initialised to addAuditEntry.
//
// The behavioural tests below then prove the chokepoint bounds what reaches the
// ring, for the release dispatch producer and for the actor shapes the other
// producers hand it, with pass-through controls for ordinary actors.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	auditEnginePath        = "github.com/KidCarmi/Culvert/internal/audit"
	auditChokepointFunc    = "addAuditEntry"
	auditChokepointFile    = "store.go"
	auditChokepointVarName = "auditAdd"
)

// auditAddBypasses reports every reference to internal/audit's Add in one
// parsed file that is not inside the chokepoint function of the root store.go.
// isChokepointFile is true only for package main's store.go.
func auditAddBypasses(fset *token.FileSet, f *ast.File, isChokepointFile bool) []string {
	local := ""
	var out []string
	for _, imp := range f.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err != nil || p != auditEnginePath {
			continue
		}
		local = "audit"
		if imp.Name != nil {
			local = imp.Name.Name
		}
		if local == "." {
			// A dot import makes a bare `Add` the engine's: never allowed.
			out = append(out, fset.Position(imp.Pos()).String()+": dot import of internal/audit")
		}
	}
	if local == "" || local == "_" || local == "." {
		return out
	}
	for _, decl := range f.Decls {
		allowed := false
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == auditChokepointFunc && isChokepointFile {
			allowed = true
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Add" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == local && !allowed {
				out = append(out, fset.Position(sel.Pos()).String()+": "+local+".Add outside "+auditChokepointFunc)
			}
			return true
		})
	}
	return out
}

// auditAddVarTarget returns the identifier auditAdd is initialised to in f, or
// "" when f does not declare it.
func auditAddVarTarget(f *ast.File) (target string, declared bool) {
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if name.Name != auditChokepointVarName {
					continue
				}
				if i < len(vs.Values) {
					if id, ok := vs.Values[i].(*ast.Ident); ok {
						return id.Name, true
					}
				}
				return "", true
			}
		}
	}
	return "", false
}

// moduleGoSources returns every non-test .go file of the module rooted at the
// package directory, except the audit engine itself (which defines Add).
func moduleGoSources(t *testing.T) []string {
	t.Helper()
	root := pkgSourceDir()
	engineDir := filepath.Join(root, "internal", "audit")
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "testdata") {
				return filepath.SkipDir
			}
			if path == engineDir {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	return files
}

func TestAuditActorBoundWall_NoProducerBypassesTheChokepoint(t *testing.T) {
	root := pkgSourceDir()
	fset := token.NewFileSet()
	var bypasses []string
	scanned, importers := 0, 0
	varTarget, varFound := "", false
	for _, path := range moduleGoSources(t) {
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		scanned++
		rel, _ := filepath.Rel(root, path)
		isRootMain := filepath.Dir(path) == root && f.Name.Name == "main"
		for _, imp := range f.Imports {
			if imp.Path.Value == strconv.Quote(auditEnginePath) {
				importers++
			}
		}
		bypasses = append(bypasses, auditAddBypasses(fset, f, isRootMain && rel == auditChokepointFile)...)
		if isRootMain {
			if tgt, ok := auditAddVarTarget(f); ok {
				if varFound {
					t.Errorf("%s declared twice in package main (second in %s)", auditChokepointVarName, rel)
				}
				varTarget, varFound = tgt, true
			}
		}
	}
	// Non-vacuity: the walk must reach the module and the engine's importers.
	if scanned < 100 || importers == 0 {
		t.Fatalf("wall scanned %d files / %d internal/audit importers: the walk is vacuous", scanned, importers)
	}
	for _, b := range bypasses {
		t.Errorf("AuditEntry write bypasses the actor-bound chokepoint: %s — call auditAdd (which is %s) so the "+
			"rendered Actor is bounded; never pre-bound or truncate auditActor itself", b, auditChokepointFunc)
	}
	if !varFound {
		t.Fatalf("package main no longer declares %s: the chokepoint wall must be updated with it", auditChokepointVarName)
	}
	if varTarget != auditChokepointFunc {
		t.Errorf("%s is initialised to %q, want %s: every producer reaches the audit engine through it",
			auditChokepointVarName, varTarget, auditChokepointFunc)
	}
}

// TestAuditActorBoundWall_DetectorControls proves the detector is not vacuous:
// each violating shape is reported (negative controls), and the compliant
// shapes — the chokepoint itself, other engine functions, auditAdd producers —
// are not (positive controls).
func TestAuditActorBoundWall_DetectorControls(t *testing.T) {
	const hdr = "package main\n\nimport %s\"" + auditEnginePath + "\"\n\n"
	cases := []struct {
		name       string
		src        string
		chokepoint bool
		wantHits   int
	}{
		{"direct call", hdr + `func f() { audit.Add(audit.Entry{Actor: "x"}) }`, false, 1},
		{"function value", hdr + `var sink = audit.Add`, false, 1},
		{"struct field value", hdr + `type s struct{ f func(audit.Entry) }; var v = s{f: audit.Add}`, false, 1},
		{"aliased import", hdr + `func f() { aud.Add(aud.Entry{}) }`, false, 1},
		{"dot import", hdr + `func f() { Add(Entry{}) }`, false, 1},
		{"chokepoint name in another file", hdr + `func addAuditEntry(e audit.Entry) { audit.Add(e) }`, false, 1},
		{"method named like chokepoint", hdr + `type T struct{}; func (T) addAuditEntry(e audit.Entry) { audit.Add(e) }`, true, 1},
		{"CONTROL chokepoint", hdr + `func addAuditEntry(e audit.Entry) { audit.Add(e) }`, true, 0},
		{"CONTROL other engine func", hdr + `var g = audit.Get`, false, 0},
		{"CONTROL auditAdd producer", hdr + `var _ = audit.Get; func f() { auditAdd(audit.Entry{Actor: "x"}) }`, false, 0},
		{"CONTROL unrelated Add", "package main\n\nimport \"sync\"\n\nfunc f(w *sync.WaitGroup) { w.Add(1) }", false, 0},
	}
	for _, tc := range cases {
		src := tc.src
		switch tc.name {
		case "aliased import":
			src = strings.Replace(src, "%s", "aud ", 1)
		case "dot import":
			src = strings.Replace(src, "%s", ". ", 1)
		default:
			src = strings.Replace(src, "%s", "", 1)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, tc.name+".go", src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.name, err)
		}
		if got := auditAddBypasses(fset, f, tc.chokepoint); len(got) != tc.wantHits {
			t.Errorf("%s: detector reported %d bypasses %v, want %d", tc.name, len(got), got, tc.wantHits)
		}
	}

	// auditAdd target detection: the compliant declaration and a regression.
	for _, tc := range []struct{ src, want string }{
		{"package main\n\nvar (\n\tauditAdd = addAuditEntry\n\tauditGet = audit.Get\n)", auditChokepointFunc},
		{"package main\n\nvar auditAdd = rawAdd", "rawAdd"},
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "v.go", tc.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := auditAddVarTarget(f); !ok || got != tc.want {
			t.Errorf("auditAddVarTarget(%q) = %q,%v, want %q", tc.src, got, ok, tc.want)
		}
	}
}

// findAuditEntry returns the newest ring entry with the given action and object.
func findAuditEntry(t *testing.T, action, object string) AuditEntry {
	t.Helper()
	entries := auditGet()
	for i := range entries {
		if entries[i].Action == action && entries[i].Object == object {
			return entries[i]
		}
	}
	t.Fatalf("no %s audit entry for object %q", action, object)
	return AuditEntry{}
}

// TestAuditAdd_BoundsRenderedActorForEveryProducerShape drives the production
// auditAdd with the actor shapes producers hand it.
func TestAuditAdd_BoundsRenderedActorForEveryProducerShape(t *testing.T) {
	long := strings.Repeat("r", loginAuditActorMax*4)
	exact := strings.Repeat("k", loginAuditActorMax)
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	cases := []struct {
		name, actor, want string
	}{
		// auditActor's "name@ip": only the name is bounded, the address is kept.
		{"name@ipv4", long + "@198.51.100.130", boundAuditIdentity(long) + "@198.51.100.130"},
		{"name@ipv6", long + "@2001:db8::7", boundAuditIdentity(long) + "@2001:db8::7"},
		// sessionAdmin's bare name (HA, cluster, PAC Actor fallback).
		{"bare name", long, boundAuditIdentity(long)},
		// A suffix that is not an IP is not trusted as one: bound the whole value.
		{"email-like", long + "@example.com", boundAuditIdentity(long + "@example.com")},
		// CONTROLS: ordinary actors pass through verbatim.
		{"CONTROL ordinary", "keeper@198.51.100.131", "keeper@198.51.100.131"},
		{"CONTROL system", "system:cdr-enroll", "system:cdr-enroll"},
		{"CONTROL name at cap", exact + "@2001:db8::8", exact + "@2001:db8::8"},
		{"CONTROL bare ip", "198.51.100.132", "198.51.100.132"},
	}
	for _, tc := range cases {
		obj := "actor-bound-" + run + "-" + tc.name
		auditAdd(AuditEntry{TS: time.Now().UnixMilli(), Actor: tc.actor, Action: "test.audit_actor_bound", Object: obj})
		if got := findAuditEntry(t, "test.audit_actor_bound", obj).Actor; got != tc.want {
			t.Errorf("%s: rendered Actor = %q (%d bytes), want %q", tc.name, got, len(got), tc.want)
		}
	}
	// Distinct oversize identities sharing the bounded prefix and length must
	// still render distinctly (the digest), or their audit trails merge.
	a, b := collidingAdminNames()
	if boundAuditActor(a+"@198.51.100.133") == boundAuditActor(b+"@198.51.100.133") {
		t.Error("two distinct oversize administrators rendered to the same audit Actor")
	}
}

// TestReleaseDispatchAudit_ActorIsBoundedThroughProductionSink is the Codex
// P2 reproduction: release_api.go passes the FULL auditActor(r) into the
// DispatchService, whose entry helper builds the AuditEntry itself. With the
// production sink (NewDispatchService wires auditAdd) the rendered Actor must
// be bounded, while the actor the service was handed stays the full principal.
func TestReleaseDispatchAudit_ActorIsBoundedThroughProductionSink(t *testing.T) {
	svc, err := NewDispatchService(&fakeCatProvider{cat: mustLoad(t, validSource())}, DispatchConfig{ProxyRepo: dispatchRepo})
	if err != nil {
		t.Fatalf("NewDispatchService: %v", err)
	}
	svc.alert = func(string, AlertPayload) {} // only the audit sink is under test

	long := strings.Repeat("d", loginAuditActorMax*3)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/releases/dispatch", http.NoBody)
	r.RemoteAddr = "198.51.100.134:9999"
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, long))
	actor := auditActor(r)
	if actor != long+"@198.51.100.134" {
		t.Fatalf("auditActor must hand the service the full principal, got %d bytes", len(actor))
	}

	agent := "agent-actor-bound-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	target := DispatchTarget{ReleaseID: "rel_a"}
	rep := &DispatchReport{}
	svc.auditDispatch(actor, AgentEndpoint{Key: agent}, target, rep)

	var found bool
	entries := auditGet()
	for i := range entries {
		e := &entries[i]
		if e.Action != "release.dispatch" || !strings.Contains(e.Detail, "agent="+agent+" ") {
			continue
		}
		found = true
		if want := boundAuditIdentity(long) + "@198.51.100.134"; e.Actor != want {
			t.Errorf("release.dispatch Actor = %d bytes, want the bounded rendering %q", len(e.Actor), want)
		}
		if strings.Contains(e.Actor, long) {
			t.Error("release.dispatch retained the full oversize identity in the audit ring")
		}
	}
	if !found {
		t.Fatal("no release.dispatch entry reached the ring through the production sink")
	}
}
