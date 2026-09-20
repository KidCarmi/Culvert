package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The FRESHNESS walls (blocker #11, §17).
//
// mcp_peer_refresh_wall_test.go pins who may GATHER peer evidence. These pin what may be done
// with it once gathered — because a fact is only as trustworthy as the narrowest path that can
// produce a `true`, and every one of these gates is about a path no behavioural test can
// enumerate: a future call site that hands the verdict a hand-built input, one that samples its
// own clock, or one that forwards a literal instead of the resolver's answer.
//
// Every wall here is ANTI-VACUOUS BY CONSTRUCTION. Each requires its legitimate site to be FOUND
// and fails when the scan matches nothing, because a scan matching zero sites is the exact shape
// of a gate that has silently stopped reading the tree it claims to check.
//
// None of them merely counts a field name. Each one constrains what the named thing is allowed
// to BE — the caller set, the source of the evidence, the source of the clock, or the shape of
// the value being forwarded.

// TestPeerFreshWall_VerdictHasExactlyOneProductionCaller pins that the freshness question is
// asked in exactly one place, from the one coherent capture.
//
// The verdict is a pure function, so a second caller would not be a bug in itself — it would be a
// second definition of what the activation believes about the peer, built from whatever inputs
// that caller happened to assemble. The whole design of blocker #11 rests on the evidence coming
// from the SAME registry+catalog snapshot the permit and credential rows were decided against;
// an independently-assembled input would quietly break that coherence while every behavioural
// test kept passing.
//
// When the runtime's pre-send re-check lands it will be a SECOND legitimate caller. Add it here
// with the argument for why its input is also one coherent capture — do not relax the wall.
func TestPeerFreshWall_VerdictHasExactlyOneProductionCaller(t *testing.T) {
	assertExactCallers(t, "EvaluatePeerObservedFresh", map[string]string{
		"mcp_canary_policy_permit.go:canaryExactRequestFacts": "" +
			"The activation-time resolver. Its input is built by buildExactPermitInput from the " +
			"single reconciled registry+catalog capture that also decided the permit and " +
			"credential rows, so all three facts necessarily describe one state of the node.",
		"mcp_live_gate.go:boundaryPeerFreshness": "" +
			"The SEND-BOUNDARY re-check (blocker #11 runtime half). Its input is the same " +
			"liveTrustPrecheck capture the approval check beside it uses, so the evidence and " +
			"the target it describes come from one snapshot of pointer-published inventory. It " +
			"exists because freshness is the one authority that expires with no state change at " +
			"all: an observation can satisfy the activation preflight and lapse while the " +
			"request waits on credential materialization, the durable commit and an upstream " +
			"pool slot. Sharing this verdict rather than writing a second one is the point — " +
			"two definitions of fresh would make the effective bound whichever ran last.",
	})
}

// TestPeerFreshWall_EvidenceComesFromTheCapturedRecord pins WHERE the evidence is read from.
//
// canary.PeerObservationFacts is the only carrier of peer evidence into the verdict. This wall
// requires that every production construction of it is in the resolver AND that its fields are
// read out of the captured catalog record — not from a parameter, a helper's return value, or
// anything else a caller could choose. Without this, the type's guarantee is only that evidence
// has the right SHAPE, never that it was actually observed.
func TestPeerFreshWall_EvidenceComesFromTheCapturedRecord(t *testing.T) {
	// The reasoned construction sites. Both lift the evidence out of a capture rather than
	// assembling it; neither may invent a value. A THIRD entry here needs the same argument.
	wantFiles := map[string]string{
		"mcp_canary_policy_permit.go": "the activation resolver, from the reconciled capture",
		"mcp_live_gate.go":            "the send-boundary precheck, from the loadTarget snapshot",
	}
	found := 0
	for _, path := range productionGoFiles(t) {
		src, err := os.ReadFile(path) //nolint:gosec // repo-local walk, not caller input
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, src, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		rel := filepath.ToSlash(path)
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "PeerObservationFacts" {
				return true
			}
			line := fset.Position(lit.Pos()).Line
			if _, ok := wantFiles[rel]; !ok {
				t.Errorf("%s:%d constructs canary.PeerObservationFacts. Peer evidence may only be "+
					"lifted out of the captured catalog record by the activation resolver; any "+
					"other construction site is a way to assert evidence instead of reading it.",
					rel, line)
				return true
			}
			found++
			// Every field must be read off the captured record, so the evidence cannot be
			// anything the caller chose.
			for _, e := range lit.Elts {
				kv, ok := e.(*ast.KeyValueExpr)
				if !ok {
					t.Errorf("%s:%d — positional PeerObservationFacts literal; keyed fields are "+
						"required so this wall can check where each value came from.", rel, line)
					continue
				}
				if !readsCapturedObservation(kv.Value) {
					t.Errorf("%s:%d — field %s is not read from the captured record's Observed "+
						"evidence. The freshness fact must describe what the peer was seen to "+
						"advertise, never a value assembled at the call site.",
						rel, fset.Position(kv.Pos()).Line, exprName(kv.Key))
				}
			}
			return true
		})
	}
	if found < len(wantFiles) {
		t.Fatalf("found %d production construction(s) of canary.PeerObservationFacts; the reasoned "+
			"set has %d. Either an evidence path was deleted or this scan has stopped matching "+
			"one; both mean this wall now proves less than it claims. Expected: %v",
			found, len(wantFiles), wantFiles)
	}
}

// readsCapturedObservation reports whether e ultimately reads `<record>.Observed.<field>`, in any
// wrapping conversion (string(...), for instance).
func readsCapturedObservation(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		inner, ok := v.X.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		// `rec.Observed.X` at the activation resolver, `ti.observed.X` at the boundary precheck.
		// One fact, spelled as each capture struct exports it — the exported catalog record field
		// and the unexported carrier on toolTrustTargetInput. Any OTHER name is a different
		// value, which is what this wall is for.
		return inner.Sel.Name == "Observed" || inner.Sel.Name == "observed"
	case *ast.CallExpr:
		// A conversion such as string(rec.Observed.Identity).
		if len(v.Args) == 1 {
			return readsCapturedObservation(v.Args[0])
		}
	}
	return false
}

func exprName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return "?"
}

// TestPeerFreshWall_NeitherSideSamplesItsOwnClock pins §10's one-clock-sample rule structurally.
//
// The pure verdict and the resolver must both take `now` as a value. A clock sampled inside
// either would make two facts in one readiness evaluation able to describe two different
// instants, and — worse for testing — would make the freshness boundary unreachable, so the
// inclusive-boundary behaviour could never be pinned at all.
//
// This is a reach check rather than a behavioural one because the behavioural version can only
// cover the call paths someone thought to drive; a file that cannot NAME the clock cannot read it
// on any path.
func TestPeerFreshWall_NeitherSideSamplesItsOwnClock(t *testing.T) {
	for _, rel := range []string{
		"internal/mcp/canary/peerfresh.go",
		"mcp_canary_policy_permit.go",
	} {
		path := filepath.Join(pkgSourceDir(), rel)
		src, err := os.ReadFile(path) //nolint:gosec // fixed in-repo path
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(src)
		if strings.Contains(text, "time.Now(") {
			t.Errorf("%s samples a clock. Freshness is evaluated against the ONE instant the "+
				"readiness evaluation was handed; a second sample lets two facts in one verdict "+
				"describe two different moments, and makes the freshness boundary untestable.", rel)
		}
		// Anti-vacuity: the file must actually be the one that reasons about the instant.
		if !strings.Contains(text, "Now") {
			t.Fatalf("%s no longer mentions the evaluation instant at all — this wall now guards "+
				"nothing. Move it with the code or delete it.", rel)
		}
	}
}

// TestPeerFreshWall_ForwardingSitesCarryTheResolverAnswer pins the chain from the resolver to the
// readiness table.
//
// The fact crosses three structs on its way (exactRequestFacts → the two activation inputs →
// canary.Facts), and each hop is an ordinary struct-literal field. A hop that assigned a literal
// `true` — or a different field — would satisfy the readiness row with something that is not the
// resolver's answer, and no behavioural test that drives the resolver would notice, because the
// resolver would still be computing the right value and simply not be the one being read.
//
// So the constraint is on the VALUE, not on the name: every production assignment to this field
// must forward a selector, never a constant.
func TestPeerFreshWall_ForwardingSitesCarryTheResolverAnswer(t *testing.T) {
	const field = "FirstCanaryPeerObservedFresh"
	assigns := 0
	for _, path := range productionGoFiles(t) {
		src, err := os.ReadFile(path) //nolint:gosec // repo-local walk, not caller input
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, src, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		rel := filepath.ToSlash(path)
		check := func(pos token.Pos, val ast.Expr) {
			assigns++
			if msg := forwardedValueProblem(val, field); msg != "" {
				t.Errorf("%s:%d %s", rel, fset.Position(pos).Line, msg)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.KeyValueExpr:
				if id, ok := v.Key.(*ast.Ident); ok && id.Name == field {
					check(v.Pos(), v.Value)
				}
			case *ast.AssignStmt:
				for i, lhs := range v.Lhs {
					s, ok := lhs.(*ast.SelectorExpr)
					if !ok || s.Sel.Name != field || i >= len(v.Rhs) {
						continue
					}
					check(v.Pos(), v.Rhs[i])
				}
			}
			return true
		})
	}
	// The chain has four hops today: the preflight bridge's construction, the bridge's
	// assignment into canary.Facts, and the two activation-input forwarding sites in
	// mcp_rollout.go. Fewer than that means a hop stopped carrying the fact.
	if assigns < 4 {
		t.Fatalf("found only %d production assignment(s) of %s; the resolver→readiness chain has "+
			"four hops. A missing hop means the readiness row is reading a zero value — which is "+
			"fail-closed, but silently so, and this wall must fail rather than let it pass "+
			"unnoticed.", assigns, field)
	}
}

// forwardedValueProblem reports why val is not an acceptable forwarding of the freshness fact, or
// "" when it is. Split out of the wall's AST walk so each function does one job — the walk finds
// the assignments, this decides about one.
func forwardedValueProblem(val ast.Expr, field string) string {
	sel, ok := val.(*ast.SelectorExpr)
	if !ok {
		return "assigns " + field + " from something other than a forwarded value. Every hop must " +
			"carry the resolver's answer; a constant here would satisfy the readiness row without " +
			"any peer having been observed."
	}
	if n := sel.Sel.Name; n != field && n != "PeerObservedFresh" {
		return "assigns " + field + " from \"" + n + "\". A hop that forwards a DIFFERENT fact " +
			"would make the readiness row report something other than peer freshness."
	}
	return ""
}
