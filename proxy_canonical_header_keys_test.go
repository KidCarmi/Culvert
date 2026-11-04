package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ── The contract ────────────────────────────────────────────────────────────
//
// Every HTTP header key this tree hands to Header.Get/Set/Del/Add/Values must
// already be spelled in textproto canonical form (first byte and every byte
// after a '-' upper, the rest lower).
//
// WHY IT IS A GATE AND NOT A STYLE PREFERENCE. Those methods canonicalise the
// key they are given. An already-canonical spelling is scanned and returned
// verbatim; any other spelling takes the slow path that copies the key into a
// []byte, rewrites the casing and ALLOCATES. So a non-canonical constant buys
// nothing and costs an allocation plus a re-derivation on every call — on the
// request path, per request, forever. The two shapes are wire-identical
// (TestCanonicalHeaderKeys_WireIdentical below proves it), which is exactly why
// nothing ever failed and the cost went unnoticed: "X-Real-IP" sat behind a
// comment claiming the constants were canonical through several performance
// sweeps of this very file.
//
// For the keys ALSO used as direct map indices — r.Header[hdrForwardedFor] in
// scrubForwardedHeaders reads the slice without canonicalising — the rule is
// load-bearing for CORRECTNESS too: a non-canonical spelling there misses the
// header outright. That is the failure this gate is really here to prevent.

// headerShaped matches a string that could be an HTTP field name. Anything else
// (a URL query key, a form field, a map key) is not this gate's business.
var headerShaped = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(-[A-Za-z0-9]+)*$`)

// headerNamedDecl matches an identifier that declares a header NAME, so the
// gate can check constants as well as inline literals. hdrRealIP reached
// Header.Get through a constant, so a literal-only gate would have missed it.
var headerNamedDecl = regexp.MustCompile(`(?i)^(hdr|header)[A-Z0-9_]`)

// headerMethods are the net/http Header accessors that canonicalise their key.
var headerMethods = map[string]bool{"Get": true, "Set": true, "Del": true, "Add": true, "Values": true}

// repoGoFiles walks the module for production Go files. _test.go is excluded
// deliberately: a test may pass a deliberately non-canonical spelling as a
// negative control, which is the point of the control (see
// internal/mcpacceptance/scenarios.go, whose raw map fixture mirrors the
// spelling a real client sends and must keep doing so).
func repoGoFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	skip := map[string]bool{"vendor": true, "testdata": true, "node_modules": true, ".git": true}
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if skip[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(out) < 200 {
		t.Fatalf("walked only %d production .go files; the walk is broken, so a clean "+
			"run would be vacuous", len(out))
	}
	return out
}

// receiverMentionsHeader reports whether a call's receiver expression names a
// header map. It keeps the gate off same-named accessors on unrelated types —
// url.Values.Get("page") would otherwise be flagged, since "page" is not
// canonical. Narrowing by receiver rather than by key shape is what makes the
// gate precise enough to be absolute: no allowlist, no count.
func receiverMentionsHeader(sel *ast.SelectorExpr) bool {
	return exprMentionsHeader(sel.X)
}

// exprMentionsHeader reports whether an expression names a header map. It is
// the same narrowing receiverMentionsHeader applies, hoisted so the direct
// map-index and delete() arms below can reuse the one definition rather than
// growing a second notion of "this is a header".
func exprMentionsHeader(e ast.Expr) bool {
	var sb strings.Builder
	var render func(ast.Expr)
	render = func(e ast.Expr) {
		switch v := e.(type) {
		case *ast.Ident:
			sb.WriteString(v.Name)
		case *ast.SelectorExpr:
			render(v.X)
			sb.WriteByte('.')
			sb.WriteString(v.Sel.Name)
		case *ast.CallExpr:
			render(v.Fun)
		case *ast.IndexExpr:
			render(v.X)
		case *ast.StarExpr:
			render(v.X)
		case *ast.ParenExpr:
			render(v.X)
		}
	}
	render(e)
	r := sb.String()
	return strings.Contains(r, "Header") || strings.Contains(r, "Trailer")
}

// nonCanonicalKey is one gate finding: where it is, how it is spelled, how it
// should be spelled, and whether it reached a Header accessor as a literal or
// through a declared constant.
type nonCanonicalKey struct {
	pos, got, want, kind string
}

// classifyKey decides whether one string literal is a non-canonical header key.
// It is the single place the canonicality question is asked.
func classifyKey(lit *ast.BasicLit) (nonCanonicalKey, bool) {
	if lit.Kind != token.STRING {
		return nonCanonicalKey{}, false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil || !headerShaped.MatchString(s) {
		return nonCanonicalKey{}, false
	}
	canon := textproto.CanonicalMIMEHeaderKey(s)
	if canon == s {
		return nonCanonicalKey{}, false
	}
	return nonCanonicalKey{got: s, want: canon}, true
}

// scanHeaderCall matches an inline literal handed to a Header accessor:
// r.Header.Get("X-Bad-ID"), w.Header().Set(...), t.Del(...) on a trailer.
func scanHeaderCall(fset *token.FileSet, node *ast.CallExpr) []nonCanonicalKey {
	sel, ok := node.Fun.(*ast.SelectorExpr)
	if !ok || !headerMethods[sel.Sel.Name] || len(node.Args) == 0 {
		return nil
	}
	if !receiverMentionsHeader(sel) {
		return nil
	}
	lit, ok := node.Args[0].(*ast.BasicLit)
	if !ok {
		return nil
	}
	k, bad := classifyKey(lit)
	if !bad {
		return nil
	}
	k.pos, k.kind = fset.Position(lit.Pos()).String(), "literal"
	return []nonCanonicalKey{k}
}

// scanHeaderDecl matches a DECLARED header-name constant. This arm is why the
// gate caught hdrRealIP at all: it reached Header.Get through a constant and
// never appeared as a literal at the call site, so a literal-only gate would
// have walked straight past the bug it exists to prevent.
func scanHeaderDecl(fset *token.FileSet, node *ast.ValueSpec) []nonCanonicalKey {
	var out []nonCanonicalKey
	for i, name := range node.Names {
		if !headerNamedDecl.MatchString(name.Name) || i >= len(node.Values) {
			continue
		}
		lit, ok := node.Values[i].(*ast.BasicLit)
		if !ok {
			continue
		}
		k, bad := classifyKey(lit)
		if !bad {
			continue
		}
		k.pos, k.kind = fset.Position(lit.Pos()).String(), "const "+name.Name
		out = append(out, k)
	}
	return out
}

// headerKeyDecls resolves an identifier used as a header key to the string
// literal of the declaration Go actually binds it to, so a key that reaches a
// header through a CONSTANT can be judged by the constant's VALUE instead of by
// its name.
//
// WHY THE NAME IS NOT ENOUGH. scanHeaderDecl matches declarations by the
// `hdr`/`header` naming convention, which is what caught hdrRealIP. But the
// convention is not enforced anywhere, and the gate's own stated purpose is
// the CORRECTNESS failure — a non-canonical key used as a direct map index
// misses the header outright. `realIPKey = "X-Real-IP"` used as
// r.Header[realIPKey] is that exact failure under a name the convention does
// not cover, so it must be judged by use, not by spelling of the identifier.
//
// WHY IT IS KEYED BY OBJECT, NOT BY NAME. A first version keyed the table by
// identifier name across the package, so an unrelated function's own
// `const realIPKey = "X-Real-Ip"` overwrote the package-level
// `const realIPKey = "X-Real-IP"` and silently excused both of its uses — and
// the reversed spellings convicted canonical ones (Codex review, PR #1795).
// go/types resolves each use to its declaring object by lexical scope, exactly
// as the compiler does, so a local can only ever judge its own uses.
type headerKeyDecls struct {
	uses map[*ast.Ident]types.Object
	lits map[types.Object]*ast.BasicLit
}

// lookup returns the literal id resolves to, if any. A nil table resolves
// nothing, which is the literal-only mode.
func (d *headerKeyDecls) lookup(id *ast.Ident) (*ast.BasicLit, bool) {
	if d == nil {
		return nil, false
	}
	obj, ok := d.uses[id]
	if !ok {
		return nil, false
	}
	lit, ok := d.lits[obj]
	return lit, ok
}

// collectHeaderKeyDecls type-checks one package (imports stubbed, as
// roster_facts_wall_test.go does: every identifier declared in the package
// still resolves exactly) and records each constant declared with a plain
// string literal, at any scope, plus each PACKAGE-LEVEL var so declared. A
// function-local var is left out: its value is whatever was last assigned,
// not its initializer. Scoped per PACKAGE because that is how Go resolves an
// identifier: a same-named constant in another package must not be able to
// convict — or to excuse — this one.
func collectHeaderKeyDecls(fset *token.FileSet, files []*ast.File) *headerKeyDecls {
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: stubImporter{}, Error: func(error) {}, FakeImportC: true}
	pkg, _ := conf.Check("headerkeys", fset, files, info) // errors: stubbed imports
	decls := &headerKeyDecls{uses: info.Uses, lits: map[types.Object]*ast.BasicLit{}}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if vs, ok := n.(*ast.ValueSpec); ok {
				decls.record(vs, info, pkg.Scope())
			}
			return true
		})
	}
	return decls
}

// record adds the string-literal declarations of one ValueSpec.
func (d *headerKeyDecls) record(vs *ast.ValueSpec, info *types.Info, pkgScope *types.Scope) {
	for i, name := range vs.Names {
		if i >= len(vs.Values) {
			continue
		}
		lit, ok := vs.Values[i].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		switch obj := info.Defs[name].(type) {
		case *types.Const:
			d.lits[obj] = lit
		case *types.Var:
			if obj.Parent() == pkgScope {
				d.lits[obj] = lit
			}
		}
	}
}

// fieldNameShaped is headerShaped PLUS a hyphen, and it is the second,
// independent signal the map-keyed arms require before convicting.
//
// WHY A SECOND SIGNAL IS NEEDED, AND WHY IT IS THIS ONE. The accessor arms are
// safe on receiver name alone because they also require a Get/Set/Del/Add/
// Values call, which only net/http's Header has. An INDEX expression carries no
// such method, so `something.Header[k]` is all the syntax there is — and this
// tree has non-HTTP maps spelled exactly that way: auth_oidc_flow.go reads
// `unverified.Header["kid"]` and `t.Header["alg"]` on a JOSE/JWT token, whose
// Header is a map[string]any of lowercase claim names. The first version of
// this arm convicted both. Distinguishing them properly needs net/http's real
// types, which the package check here deliberately does not load: its imports
// are stubbed, so it resolves this package's own identifiers but not the type
// of an imported map (loading them would mean type-checking the whole module
// and its dependencies from source inside a unit test).
//
// A hyphen separates the two populations cleanly: HTTP field names used as map
// keys here are multi-token ("X-Forwarded-For", "X-Real-Ip"); JOSE header
// parameters and ordinary lowercase map keys are single tokens ("kid", "alg").
//
// WHAT THIS GIVES UP, AND WHY THAT IS COVERED. A single-token HTTP field name
// misspelled as a direct index — r.Header["traceparent"], which is how the W3C
// spec writes it — is not caught HERE. It is caught by scanHeaderDecl, which
// judges every `hdr`/`header`-named declaration by value at its declaration
// regardless of how it is later used, and which is where this tree's
// single-token field names live (headerTraceparent, headerTracestate). The hole
// is therefore a bare single-token LITERAL indexed inline, with no declaration
// to catch it; that is the price of not type-checking, and it is recorded here
// rather than left for a reader to discover.
var fieldNameShaped = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(-[A-Za-z0-9]+)+$`)

// classifyHeaderKeyExpr judges one expression used AS a header key, whether it
// is written inline or reached through a constant. Every arm that reaches a map
// key rather than an accessor call passes requireFieldName, which demands the
// hyphen described above.
//
// A `hdr`/`header`-named declaration is deliberately skipped on the Ident path:
// scanHeaderDecl already reports it once, at its declaration, which is the
// actionable place to fix it. Reporting it again at every use would turn one
// fix into a wall of duplicate findings.
func classifyHeaderKeyExpr(fset *token.FileSet, e ast.Expr, decls *headerKeyDecls, requireFieldName bool) (nonCanonicalKey, bool) {
	accept := func(k nonCanonicalKey) bool {
		return !requireFieldName || fieldNameShaped.MatchString(k.got)
	}
	switch v := e.(type) {
	case *ast.BasicLit:
		k, bad := classifyKey(v)
		if !bad || !accept(k) {
			return nonCanonicalKey{}, false
		}
		k.pos, k.kind = fset.Position(v.Pos()).String(), "literal"
		return k, true
	case *ast.Ident:
		if headerNamedDecl.MatchString(v.Name) {
			return nonCanonicalKey{}, false
		}
		lit, ok := decls.lookup(v)
		if !ok {
			return nonCanonicalKey{}, false
		}
		k, bad := classifyKey(lit)
		if !bad || !accept(k) {
			return nonCanonicalKey{}, false
		}
		k.pos = fset.Position(v.Pos()).String()
		k.kind = v.Name + " (declared at " + fset.Position(lit.Pos()).String() + ")"
		return k, true
	}
	return nonCanonicalKey{}, false
}

// scanHeaderIndex matches a DIRECT map index on a header map:
// r.Header["X-Real-IP"], r.Header[realIPKey] = …, t.Trailer[k].
//
// This is the arm that covers the failure the gate exists for. Indexing a map
// does NOT canonicalise, so a non-canonical key here does not merely cost an
// allocation — it addresses a slot that textproto.ReadMIMEHeader never
// populates and Header.Set never writes, so the read returns nothing and the
// write is invisible to every accessor. On scrubForwardedHeaders that is a
// scrub that silently stops scrubbing: the private hop or the client-supplied
// identity header rides through to the upstream.
func scanHeaderIndex(fset *token.FileSet, node *ast.IndexExpr, decls *headerKeyDecls) []nonCanonicalKey {
	if !exprMentionsHeader(node.X) {
		return nil
	}
	k, bad := classifyHeaderKeyExpr(fset, node.Index, decls, true)
	if !bad {
		return nil
	}
	k.kind = "direct map index: " + k.kind
	return []nonCanonicalKey{k}
}

// scanHeaderDelete matches delete(r.Header, "X-Real-IP"). The builtin takes
// the map key unchanged, exactly like an index expression, so it fails the same
// way: a non-canonical key deletes nothing and the scrub reports success.
func scanHeaderDelete(fset *token.FileSet, node *ast.CallExpr, decls *headerKeyDecls) []nonCanonicalKey {
	id, ok := node.Fun.(*ast.Ident)
	if !ok || id.Name != "delete" || len(node.Args) != 2 {
		return nil
	}
	if !exprMentionsHeader(node.Args[0]) {
		return nil
	}
	k, bad := classifyHeaderKeyExpr(fset, node.Args[1], decls, true)
	if !bad {
		return nil
	}
	k.kind = "delete() map key: " + k.kind
	return []nonCanonicalKey{k}
}

// scanHeaderCallIdent covers a header ACCESSOR reached through a constant that
// the naming convention does not cover: r.Header.Get(realIPKey). Get/Set/Del
// canonicalise, so this one is cost rather than correctness — but the same
// constant is one edit away from an index expression, and the gate should not
// depend on which of the two a future caller picks.
func scanHeaderCallIdent(fset *token.FileSet, node *ast.CallExpr, decls *headerKeyDecls) []nonCanonicalKey {
	sel, ok := node.Fun.(*ast.SelectorExpr)
	if !ok || !headerMethods[sel.Sel.Name] || len(node.Args) == 0 {
		return nil
	}
	if !receiverMentionsHeader(sel) {
		return nil
	}
	if _, isIdent := node.Args[0].(*ast.Ident); !isIdent {
		return nil
	}
	k, bad := classifyHeaderKeyExpr(fset, node.Args[0], decls, false)
	if !bad {
		return nil
	}
	k.kind = "accessor key: " + k.kind
	return []nonCanonicalKey{k}
}

// scanFileForNonCanonicalKeys is the WHOLE matcher, and deliberately the only
// copy of it: both the tree gate and its self-check call this, so the
// self-check proves THIS code can still fail rather than proving a
// reimplementation of it can. A gate whose self-test exercises a parallel copy
// of the matching logic is the same trap as a bound that measures the wrong
// thing — which is the bug that motivated this whole file.
//
// decls carries the package's string constants so a key reaching a header
// through an identifier is judged by its VALUE. Pass nil to judge inline
// literals only.
func scanFileForNonCanonicalKeys(fset *token.FileSet, f *ast.File, decls *headerKeyDecls) []nonCanonicalKey {
	var out []nonCanonicalKey
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			out = append(out, scanHeaderCall(fset, node)...)
			out = append(out, scanHeaderCallIdent(fset, node, decls)...)
			out = append(out, scanHeaderDelete(fset, node, decls)...)
		case *ast.IndexExpr:
			out = append(out, scanHeaderIndex(fset, node, decls)...)
		case *ast.ValueSpec:
			out = append(out, scanHeaderDecl(fset, node)...)
		}
		return true
	})
	return out
}

// scanPackageForNonCanonicalKeys resolves one package's identifiers and runs
// the matcher over each of its files. The tree gate and the scope fixtures
// both call it, so the fixtures exercise the resolution the gate uses.
func scanPackageForNonCanonicalKeys(fset *token.FileSet, files []*ast.File) []nonCanonicalKey {
	decls := collectHeaderKeyDecls(fset, files)
	var out []nonCanonicalKey
	for _, f := range files {
		out = append(out, scanFileForNonCanonicalKeys(fset, f, decls)...)
	}
	return out
}

func TestCanonicalHeaderKeys_Tree(t *testing.T) {
	fset := token.NewFileSet()

	// Grouped by PACKAGE (directory plus package clause), because the constant
	// arm resolves an identifier the way Go does, and Go resolves identifiers
	// per package. Scanning file-by-file would miss every key declared in one
	// file of a package and used in another — which is the normal shape — and a
	// flat tree-wide table would let a same-named constant in an unrelated
	// package convict or excuse this one.
	byPkg := map[string][]*ast.File{}
	var pkgs []string
	for _, path := range repoGoFiles(t) {
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		k := filepath.Dir(path) + " " + f.Name.Name
		if _, seen := byPkg[k]; !seen {
			pkgs = append(pkgs, k)
		}
		byPkg[k] = append(byPkg[k], f)
	}
	sort.Strings(pkgs)

	var found []nonCanonicalKey
	for _, k := range pkgs {
		found = append(found, scanPackageForNonCanonicalKeys(fset, byPkg[k])...)
	}

	for _, b := range found {
		t.Errorf("%s: non-canonical header key %q (%s); use %q.\n"+
			"\tHeader.Get/Set/Del canonicalise the key, so %q allocates and re-derives on "+
			"every call while %q is returned verbatim. The two are wire-identical, so this "+
			"is pure cost — and for a key also used as a direct map index "+
			"(r.Header[...]) the non-canonical spelling misses the header entirely.",
			b.pos, b.got, b.kind, b.want, b.got, b.want)
	}
}

// TestCanonicalHeaderKeys_SelfCheck proves the gate can FAIL, by running the
// REAL matcher over a synthetic file with known positives and known negatives.
// A structural gate that silently stopped matching would be worse than no gate:
// it would read as a green guarantee of a property nothing was checking, which
// is exactly how "X-Real-IP" survived under a comment asserting canonicality.
func TestCanonicalHeaderKeys_SelfCheck(t *testing.T) {
	const src = `package p

import "net/http"

const hdrThing = "X-Real-IP"      // positive: non-canonical CONSTANT
const hdrFine = "Mcp-Session-Id"  // negative: canonical constant

// Named outside the hdr/header convention on purpose: the naming rule is not
// enforced anywhere, so the gate must judge these by VALUE at the point of use.
const realIPKey = "X-Real-IDENT"  // positive, three times below
const okKey = "X-Real-Ip"         // negative: canonical constant, any name
const notAHeader = "fail-closed"  // negative: never used as a header key

func f(r *http.Request) {
	_ = r.Header.Get("X-Bad-ID")        // positive: non-canonical literal
	_ = r.Header.Get("Mcp-Session-Id")  // negative: canonical literal

	// The correctness failure: indexing does NOT canonicalise.
	_ = r.Header["X-Bad-INDEX"]                     // positive
	r.Header["X-Bad-WRITE"] = []string{"v"}         // positive
	delete(r.Header, "X-Bad-DELETE")                // positive
	_ = r.Header["X-Good-Index"]                    // negative: canonical
	delete(r.Header, "X-Good-Delete")               // negative: canonical

	// Same three shapes reached through the non-conventionally-named constant.
	_ = r.Header[realIPKey]      // positive
	delete(r.Header, realIPKey)  // positive
	_ = r.Header.Get(realIPKey)  // positive
	_ = r.Header[okKey]          // negative
	_ = r.Header.Get(okKey)      // negative
	_ = notAHeader               // negative: not in a header context
}

func g(v interface{ Get(string) string }) {
	_ = v.Get("page") // negative: receiver is not a header map
}

func h(m map[string]string) {
	_ = m["fail-closed"]       // negative: receiver is not a header map
	delete(m, "fail-closed")   // negative: receiver is not a header map
}

// The real false positive the first version of the index arm produced, kept
// here as a standing negative control: a JOSE token's Header is a map of
// lowercase claim names and is spelled identically to an http.Header index.
func jose(tok struct{ Header map[string]any }) {
	_ = tok.Header["kid"]       // negative: single token, so not an HTTP field name
	_ = tok.Header["alg"]       // negative
	delete(tok.Header, "typ")   // negative
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	decls := collectHeaderKeyDecls(fset, []*ast.File{f})
	var got []string
	for _, k := range scanFileForNonCanonicalKeys(fset, f, decls) {
		got = append(got, k.got)
	}
	sort.Strings(got)

	// The "page" and map[string]string negatives are what keep the tree-wide
	// gate free of an allowlist: without the receiver check, url.Values.Get
	// ("page") and every ordinary hyphenated map key would be flagged.
	//
	// X-Real-IDENT appears FOUR times: the index, the delete, the accessor, and
	// once more because collectHeaderKeyDecls is value-based while the
	// hdr/header-named arm is name-based, and realIPKey is only reported at its
	// uses. Asserting the exact multiset is deliberate — a count that drifts is
	// how a structural gate stops matching without failing.
	want := []string{
		"X-Bad-DELETE", "X-Bad-ID", "X-Bad-INDEX", "X-Bad-WRITE",
		"X-Real-IDENT", "X-Real-IDENT", "X-Real-IDENT",
		"X-Real-IP",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("self-check detected %v, want %v: the gate's matching has drifted, so "+
			"TestCanonicalHeaderKeys_Tree passing proves nothing", got, want)
	}
}

// TestCanonicalHeaderKeys_IndexArmFailsClosed is the second direction of the
// proof for the arm this file was missing. The self-check above asserts an
// exact multiset, which proves the arm fires; this asserts the arm is what
// makes the difference, by running the REAL matcher with the resolver omitted
// and with it supplied over the one shape that caused the original bug.
//
// Kept separate from the self-check so that a future edit which quietly drops
// the index arm cannot be made to pass by adjusting one `want` list.
func TestCanonicalHeaderKeys_IndexArmFailsClosed(t *testing.T) {
	const src = `package p

import "net/http"

const realIPKey = "X-Real-IP"

func scrub(r *http.Request) {
	// Exactly scrubForwardedHeaders' shape, under a constant the hdr/header
	// naming arm does not cover. Indexing does not canonicalise, so this reads
	// a slot net/http never populates: the scrub silently stops scrubbing.
	if vals := r.Header[realIPKey]; len(vals) > 0 {
		delete(r.Header, realIPKey)
	}
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Without the package's constants the gate cannot see through the
	// identifier, which is precisely the state this fix replaced.
	if got := scanFileForNonCanonicalKeys(fset, f, nil); len(got) != 0 {
		t.Fatalf("with no resolver the gate should see nothing here, got %+v", got)
	}

	got := scanFileForNonCanonicalKeys(fset, f, collectHeaderKeyDecls(fset, []*ast.File{f}))
	if len(got) != 2 {
		t.Fatalf("want 2 findings (the index and the delete), got %d: %+v", len(got), got)
	}
	for _, k := range got {
		if k.got != "X-Real-IP" || k.want != "X-Real-Ip" {
			t.Errorf("finding %+v: want got=X-Real-IP want=X-Real-Ip", k)
		}
		if !strings.Contains(k.kind, "realIPKey") {
			t.Errorf("finding %+v must name the constant it resolved through", k)
		}
	}
}

// TestCanonicalHeaderKeys_WireIdentical is the differential oracle behind the
// whole change: for every key canonicalised here, the old and new spellings
// address the SAME header, both when we read a received request and when we
// build an outbound one. This is what makes the optimisation provably
// behaviour-preserving rather than argued to be.
func TestCanonicalHeaderKeys_WireIdentical(t *testing.T) {
	pairs := []struct{ old, canonical string }{
		{"X-Real-IP", "X-Real-Ip"},
		{"MCP-Protocol-Version", "Mcp-Protocol-Version"},
		{"DPoP", "Dpop"},
		{"ETag", "Etag"},
		{"X-GitHub-Api-Version", "X-Github-Api-Version"},
		{"X-aws-ec2-metadata-token-ttl-seconds", "X-Aws-Ec2-Metadata-Token-Ttl-Seconds"},
	}
	for _, p := range pairs {
		if c := textproto.CanonicalMIMEHeaderKey(p.old); c != p.canonical {
			t.Fatalf("%q canonicalises to %q, not the %q this change substituted",
				p.old, c, p.canonical)
		}
		if c := textproto.CanonicalMIMEHeaderKey(p.canonical); c != p.canonical {
			t.Fatalf("substituted key %q is itself not canonical (-> %q)", p.canonical, c)
		}

		// Written under the OLD spelling, readable under the NEW one and vice
		// versa — Set canonicalises the stored key, so there was only ever one
		// map slot.
		for _, writeWith := range []string{p.old, p.canonical} {
			h := http.Header{}
			h.Set(writeWith, "v")
			if got := h.Get(p.old); got != "v" {
				t.Errorf("Set(%q) then Get(%q) = %q, want %q", writeWith, p.old, got, "v")
			}
			if got := h.Get(p.canonical); got != "v" {
				t.Errorf("Set(%q) then Get(%q) = %q, want %q", writeWith, p.canonical, got, "v")
			}
			// One slot, stored canonically: that is why the wire form is
			// unchanged, since Header.Write emits the map key.
			if _, ok := h[p.canonical]; !ok {
				t.Errorf("Set(%q) did not store under canonical key %q; map=%v",
					writeWith, p.canonical, h)
			}
			if len(h) != 1 {
				t.Errorf("Set(%q) produced %d map keys, want 1: %v", writeWith, len(h), h)
			}
		}

		// Del addresses the same slot under either spelling.
		for _, delWith := range []string{p.old, p.canonical} {
			h := http.Header{}
			h.Set(p.canonical, "v")
			h.Del(delWith)
			if got := h.Get(p.canonical); got != "" {
				t.Errorf("Del(%q) left %q = %q", delWith, p.canonical, got)
			}
		}
	}
}

// TestCanonicalHeaderKeys_ScrubStillScrubs pins the behaviour that the hot-path
// constant actually serves: the X-Real-IP scrub must keep removing a private
// hop and keep a public one, addressed through the canonicalised constant.
func TestCanonicalHeaderKeys_ScrubStillScrubs(t *testing.T) {
	cases := []struct {
		name, set, wantAfter string
	}{
		{"private is removed", "10.1.2.3", ""},
		{"loopback is removed", "127.0.0.1", ""},
		{"public survives", "203.0.113.9", "203.0.113.9"},
		{"unparseable is removed", "not-an-ip", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Written with the pre-change spelling on purpose: a real client
			// sends whatever casing it likes, and the scrub must still see it.
			for _, writeWith := range []string{"X-Real-IP", "X-Real-Ip", "x-real-ip"} {
				r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://t.example.com/", http.NoBody)
				if err != nil {
					t.Fatalf("new request: %v", err)
				}
				r.Header.Set(writeWith, tc.set)
				scrubForwardedHeaders(r)
				if got := r.Header.Get(hdrRealIP); got != tc.wantAfter {
					t.Errorf("set via %q: after scrub %s = %q, want %q",
						writeWith, hdrRealIP, got, tc.wantAfter)
				}
			}
		})
	}
}

// scanSyntheticPackage parses srcs (file name → source) as ONE package and runs
// the same package-level matcher the tree gate runs over it.
func scanSyntheticPackage(t *testing.T, srcs map[string]string) []nonCanonicalKey {
	t.Helper()
	names := make([]string, 0, len(srcs))
	for name := range srcs {
		names = append(names, name)
	}
	sort.Strings(names)
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(names))
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, srcs[name], parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	return scanPackageForNonCanonicalKeys(fset, files)
}

// TestCanonicalHeaderKeys_LexicalScope pins Codex P2 4448734747 on PR #1795:
// an identifier must resolve to the declaration Go would bind it to, not to
// any same-named declaration elsewhere in the package. A name-keyed table let
// an unrelated function-local constant overwrite a package-level one, so the
// local could both EXCUSE a non-canonical package key (direction 1) and
// CONVICT a canonical one (direction 2).
func TestCanonicalHeaderKeys_LexicalScope(t *testing.T) {
	const scrub = `package p

import "net/http"

func scrub(r *http.Request) {
	if vals := r.Header[realIPKey]; len(vals) > 0 {
		delete(r.Header, realIPKey)
	}
}
`
	// The package-level declaration lives in its own file and the shadowing
	// local in a later one, so the cross-file path is exercised as well.
	pkgConst := func(v string) string {
		return "package p\n\nconst realIPKey = " + strconv.Quote(v) + "\n"
	}
	localConst := func(v string) string {
		return "package p\n\nfunc unrelated() string {\n\tconst realIPKey = " + strconv.Quote(v) + "\n\treturn realIPKey\n}\n"
	}
	keys := func(found []nonCanonicalKey) []string {
		var got []string
		for _, k := range found {
			got = append(got, k.got)
		}
		sort.Strings(got)
		return got
	}

	t.Run("local canonical constant does not excuse a package-level one", func(t *testing.T) {
		got := keys(scanSyntheticPackage(t, map[string]string{
			"a_keys.go": pkgConst("X-Real-IP"), "b_scrub.go": scrub, "c_unrelated.go": localConst("X-Real-Ip"),
		}))
		if want := []string{"X-Real-IP", "X-Real-IP"}; !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v (the index and the delete)", got, want)
		}
	})
	t.Run("local non-canonical constant does not convict a package-level one", func(t *testing.T) {
		if got := keys(scanSyntheticPackage(t, map[string]string{
			"a_keys.go": pkgConst("X-Real-Ip"), "b_scrub.go": scrub, "c_unrelated.go": localConst("X-Real-IP"),
		})); len(got) != 0 {
			t.Fatalf("canonical package-level key falsely rejected: %v", got)
		}
	})
	t.Run("a local constant judges only its own uses", func(t *testing.T) {
		got := keys(scanSyntheticPackage(t, map[string]string{
			"a_keys.go": pkgConst("X-Real-Ip"),
			"b_scrub.go": `package p

import "net/http"

func shadowed(r *http.Request) {
	const realIPKey = "X-Shadow-IP"
	_ = r.Header[realIPKey]
}

func outer(r *http.Request) {
	_ = r.Header[realIPKey]
}
`,
		}))
		if want := []string{"X-Shadow-IP"}; !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v (only the shadowing local's own use)", got, want)
		}
	})
}
