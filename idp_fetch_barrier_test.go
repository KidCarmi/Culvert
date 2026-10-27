package main

// idp_fetch_barrier_test.go — the SAML/OIDC metadata fetchers must BOTH carry
// the go/request-forgery barrier, and must BOTH build their request from the
// PARSED url rather than from the raw string beside it.
//
// This pair has now produced four findings by being fixed one half at a time:
// the guard moved inline on SAML and not OIDC; the fetch-result adjudication
// on one and not the other; the bounded private-host check on one and not the
// other; and finally the regexp barrier plus `metaURL.String()` on SAML alone,
// which left `fetchOIDCDiscoveryOverNetwork` passing its RAW parameter to
// http.NewRequestWithContext and raised a CRITICAL CodeQL
// "uncontrolled data used in network request" on the PR that shipped the SAML
// fix.
//
// The individual fixes are correct and none of them generalised, so this wall
// pins the PROPERTY on both functions at once: whoever adds a third metadata
// fetcher, or edits one of these two, fails here rather than in a CodeQL run
// after merge.
//
// It is STRUCTURAL rather than behavioural on purpose. Functionally the old
// OIDC shape was sound — `u` was parsed FROM `wellKnown`, so the scheme and
// host checks did apply to the URL actually fetched — so no behavioural test
// could see the defect. What was wrong was that the value handed onward was
// not the value that had been checked (CHAOS-69 round 5's measure-vs-use
// rule), which is visible only in the shape of the code and to static
// analysis.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

type idpFetcherUnderWall struct {
	file  string
	fn    string
	param string // the raw, caller-supplied URL parameter
}

var idpFetchersUnderWall = []idpFetcherUnderWall{
	{file: "auth_saml.go", fn: "fetchSAMLMetadataOverNetwork", param: "raw"},
	{file: "auth_oidc_flow.go", fn: "fetchOIDCDiscoveryOverNetwork", param: "wellKnown"},
}

func TestWall_IdPMetadataFetchersCarryTheRequestForgeryBarrier(t *testing.T) {
	checked := 0
	for _, f := range idpFetchersUnderWall {
		if checkIdPFetchBarrier(t, f) {
			checked++
		}
	}
	if checked != len(idpFetchersUnderWall) {
		t.Fatalf("wall inspected %d of %d fetchers", checked, len(idpFetchersUnderWall))
	}
}

// idpFetchShape is what the wall reads out of one fetcher's body.
type idpFetchShape struct {
	barrierPos     token.Pos
	requestPos     token.Pos
	rawReachesSink bool
}

// readIdPFetchShape walks one fetcher and reports where its barrier and its
// request are, and whether the raw parameter reaches the request.
func readIdPFetchShape(body *ast.BlockStmt, param string) idpFetchShape {
	var sh idpFetchShape
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch {
		// The CodeQL-recognised sanitiser: Regexp.MatchString on the raw value.
		case sel.Sel.Name == "MatchString" && len(call.Args) == 1 && identIs(call.Args[0], param):
			if !sh.barrierPos.IsValid() {
				sh.barrierPos = call.Pos()
			}
		// The sink.
		case sel.Sel.Name == "NewRequestWithContext" && len(call.Args) == 4:
			sh.requestPos = call.Pos()
			if identIs(call.Args[2], param) {
				sh.rawReachesSink = true
			}
		}
		return true
	})
	return sh
}

// checkIdPFetchBarrier asserts the wall's three properties on one fetcher and
// reports whether it was found and inspected at all.
func checkIdPFetchBarrier(t *testing.T, f idpFetcherUnderWall) bool {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, f.file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", f.file, err)
	}
	fn := findFuncDecl(parsed, f.fn)
	if fn == nil || fn.Body == nil {
		t.Fatalf("%s: %s not found — if it was renamed, update this wall rather than "+
			"deleting the entry: an unpinned fetcher is how this defect recurs", f.file, f.fn)
	}

	sh := readIdPFetchShape(fn.Body, f.param)
	if !sh.barrierPos.IsValid() {
		t.Errorf("%s: %s does not apply a Regexp.MatchString barrier to its %q parameter. "+
			"An inline url.Parse + isPrivateHostContext guard is NOT enough: CodeQL is not "+
			"established to model that wrapper, and this exact request was flagged critical "+
			"(go/request-forgery) with the guard in place. Mirror samlMetadataURLShape.",
			f.file, f.fn, f.param)
	}
	if !sh.requestPos.IsValid() {
		t.Errorf("%s: %s builds no http.NewRequestWithContext — if the request moved, this "+
			"wall no longer covers it", f.file, f.fn)
		return true
	}
	if sh.rawReachesSink {
		t.Errorf("%s: %s passes its RAW %q parameter to http.NewRequestWithContext. Every "+
			"check in this function measures the PARSED url, so the value actually fetched "+
			"would sit outside all of them. Pass the parsed url's .String() instead.",
			f.file, f.fn, f.param)
	}
	if sh.barrierPos.IsValid() && sh.barrierPos > sh.requestPos {
		t.Errorf("%s: %s applies its barrier AFTER building the request; a sanitiser "+
			"downstream of the sink protects nothing", f.file, f.fn)
	}
	return true
}

func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Name != nil && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

func identIs(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}
