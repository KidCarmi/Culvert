package runtime

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// DEBT-011 — the MCP anti-drift wall.
//
// Six of the fifteen findings in the 2026-08-24 backend review were the SAME
// shape: a control designed, documented, validated at construction, unit-tested in
// isolation — and never invoked by the request path. RequestDeadline bounded only
// admission; AuthConcurrency, DPoPConcurrency, AdmissionBudget, MaxObservations
// and CleanupPerOp had zero enforcement call sites; protocol.Adapter was declared
// and never called. Package tests pass either way, so nothing caught it.
//
// This file is the wall for the Limits surface: every bound must DECLARE who
// enforces it, and the declaration is checked against the real syntax tree. A
// bound cannot be added without an owner, an "enforced" claim cannot be made
// without a call site, and a "reserved" claim cannot hide a silent use.
//
// It is deliberately AST-based rather than grep-based: a string search matches
// comments and test files, which is how a documentation-only control passes for a
// real one.

// enforcement is how a Limits bound is honoured.
type enforcement int

const (
	// enforcedHere — the accessor is READ by this package's production code, and
	// that read is what applies the bound.
	enforcedHere enforcement = iota
	// delegated — the invariant is genuinely enforced, but by a lower-level control
	// that owns it. The accessor may be unread here; Owner names what does enforce
	// it, and the row must say why this layer does not.
	delegated
	// reserved — NOT enforced anywhere. Permitted only with a recorded reason and a
	// linked decision. A reserved bound must NOT be read by production code, so it
	// cannot quietly become load-bearing without this row changing.
	reserved
)

// limitOwner declares the enforcement owner of one Limits accessor.
type limitOwner struct {
	Field  string
	Status enforcement
	Owner  string // where the bound is applied, or which control owns the invariant
	Reason string // required for delegated and reserved
}

// limitOwnership is the DECLARED ownership of every Limits bound. Adding an
// accessor without adding a row here fails TestLimitsWall_EveryBoundHasAnOwner.
var limitOwnership = []limitOwner{
	{Field: "MaxConns", Status: enforcedHere, Owner: "Listener.bind → newLimitListener"},
	{Field: "MaxConcurrent", Status: enforcedHere, Owner: "newListener → l.sem; newConnBudget"},
	{Field: "QueueDepth", Status: enforcedHere, Owner: "newListener → l.queue"},
	{Field: "MaxBodyBytes", Status: enforcedHere, Owner: "extractRequest (MaxBytesReader) + pipeline.readBody"},
	{Field: "MaxHeaderBytes", Status: enforcedHere, Owner: "http.Server.MaxHeaderBytes"},
	{Field: "ReadHeaderTimeout", Status: enforcedHere, Owner: "http.Server.ReadHeaderTimeout"},
	{Field: "ReadTimeout", Status: enforcedHere, Owner: "http.Server.ReadTimeout"},
	{Field: "WriteTimeout", Status: enforcedHere, Owner: "http.Server.WriteTimeout"},
	{Field: "IdleTimeout", Status: enforcedHere, Owner: "http.Server.IdleTimeout"},
	{Field: "RequestDeadline", Status: enforcedHere, Owner: "ServeHTTP deadline ctx → pipeline.checkBudget + acquireSlot"},
	{Field: "SessionTTL", Status: enforcedHere, Owner: "Listener.sweepLoop cadence"},
	{Field: "ShutdownTimeout", Status: enforcedHere, Owner: "Listener.stop drain bound"},
	{Field: "AuthConcurrency", Status: enforcedHere, Owner: "pipeline.authSem via acquireSlot"},
	{Field: "DPoPConcurrency", Status: enforcedHere, Owner: "pipeline.dpopSem via acquireSlot (gated by dpopVerificationRuns)"},

	{
		Field: "MaxSessions", Status: delegated,
		Owner: "internal/mcp/session.Manager (limits.Limits.MaxSessions, enforced in manager.Open)",
		Reason: "The session cap belongs to the protocol kernel, which owns the session table. " +
			"ListenerConfig.SessionLimits carries the kernel bound; this runtime field is the " +
			"listener-facing mirror and must not add a second, divergent cap.",
	},
	{
		Field: "MaxOutstanding", Status: delegated,
		Owner: "internal/mcp/session (limits.Limits.MaxOutstandingPerSession, enforced in session/ops.go)",
		Reason: "Outstanding-request accounting is per (session, direction) and lives with the " +
			"session state machine. A listener-level total would double-count and could not " +
			"attribute a violation to a session.",
	},
	{
		Field: "HandshakeTimeout", Status: delegated,
		Owner: "net/http Server.tlsHandshakeTimeout = max(ReadHeaderTimeout, ReadTimeout)",
		Reason: "net/http bounds the TLS handshake itself from the read timeouts, which are set " +
			"from this same Limits set. A separate deadline here could only ever be looser or " +
			"redundant, never tighter.",
	},
	{
		Field: "MaxResponseBytes", Status: delegated,
		Owner: "internal/mcp/upstreamclient.Limits.MaxResponseBytes (readBounded)",
		Reason: "The observe runtime generates every response itself from bounded, internally " +
			"constructed values, so there is no attacker-sized response to bound here. The " +
			"attacker-controlled case is the UPSTREAM leg, where it is enforced. If the runtime " +
			"ever returns upstream content, this row must become enforcedHere.",
	},

	{
		Field: "AdmissionBudget", Status: reserved,
		Owner: "NONE — no per-source admission exists",
		Reason: "RISK-026. Documented as a per-source token bucket, but admission has no source " +
			"identity and runs before authentication, so one source can occupy the whole worker " +
			"pool. Implementing it requires a deployment-topology decision (per-TCP-peer vs " +
			"per-principal vs two-tier) that cannot be made in code. See " +
			"docs/design/mcp/ADR-PROPOSAL-mcp-admission-fairness.md. The per-connection budget " +
			"added for OVN-07 removes the HTTP/2 amplification but is NOT per-source fairness.",
	},
	{
		Field: "MaxObservations", Status: reserved,
		Owner: "NONE — bounded transitively by MaxConcurrent",
		Reason: "Observe records are emitted synchronously on the request goroutine, so in-flight " +
			"records cannot exceed the worker pool. The field would only become meaningful if the " +
			"sink became asynchronous, at which point this row must become enforcedHere.",
	},
	{
		Field: "CleanupPerOp", Status: reserved,
		Owner: "NONE — sweep is bounded by the live session set",
		Reason: "The sweeper walks sessions the manager already caps at MaxSessions, so the scan " +
			"is bounded without this knob. It exists for a future incremental sweep. " +
			"internal/mcp/limits.CredentialLimits.MaxCleanupPerOp is a DIFFERENT, enforced bound.",
	},
}

// limitsAccessors returns every exported no-argument method on Limits, read from
// the syntax tree rather than from a hand-maintained list.
func limitsAccessors(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Clean("limits.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse limits.go: %v", err)
	}
	out := map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || !fn.Name.IsExported() {
			continue
		}
		if len(fn.Type.Params.List) != 0 {
			continue // not an accessor
		}
		recv := fn.Recv.List[0].Type
		if id, ok := recv.(*ast.Ident); ok && id.Name == "Limits" {
			out[fn.Name.Name] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("no Limits accessors found: the wall is not looking at the right type")
	}
	return out
}

// productionCallees returns the set of Limits methods invoked anywhere in this
// package's NON-TEST sources.
//
// It is TYPE-AWARE, not name-based. `MaxSessions()` exists on BOTH runtime.Limits
// and the protocol kernel's limits.Limits, and the runtime legitimately reads the
// kernel one — a name-based wall reports that as the runtime bound being enforced
// here, which is exactly the false confidence this file exists to prevent. (The
// wall caught this in itself on its first run.)
//
// Test files are excluded on purpose: a bound exercised only by its own unit test
// is precisely the defect this wall is for.
func productionCallees(t *testing.T) map[string]bool {
	t.Helper()
	calleeOnce.Do(func() { calleeSet = computeProductionCallees(t) })
	if len(calleeSet) == 0 {
		t.Fatal("no runtime.Limits method calls resolved: the wall cannot see the production " +
			"call sites, so its enforcement claims would be vacuous")
	}
	return calleeSet
}

// The type-check is expensive (it resolves the dependency tree from source), so it
// runs once per package test binary.
var (
	calleeOnce sync.Once
	calleeSet  map[string]bool
)

func computeProductionCallees(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Clean(name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	info := &types.Info{Selections: make(map[*ast.SelectorExpr]*types.Selection)}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil), Error: func(error) {}}
	// Type errors are tolerated: the wall only needs the selections it could
	// resolve, and a partial type-check still resolves the ones that matter. A
	// selection it CANNOT resolve is reported as not-called, which fails closed
	// (an "enforced" claim without a resolvable call site is a failure).
	_, _ = conf.Check("github.com/KidCarmi/Culvert/internal/mcp/runtime", fset, files, info)

	out := map[string]bool{}
	for sel, selection := range info.Selections {
		if selection.Kind() != types.MethodVal {
			continue
		}
		recv := selection.Recv()
		if ptr, ok := recv.(*types.Pointer); ok {
			recv = ptr.Elem()
		}
		named, ok := recv.(*types.Named)
		if !ok {
			continue
		}
		obj := named.Obj()
		if obj.Name() != "Limits" || obj.Pkg() == nil ||
			obj.Pkg().Path() != "github.com/KidCarmi/Culvert/internal/mcp/runtime" {
			continue
		}
		out[sel.Sel.Name] = true
	}
	return out
}

// Every Limits bound must declare an enforcement owner, and every declaration must
// name a real bound. A knob added without a row, or a row for a knob that no
// longer exists, fails here.
func TestLimitsWall_EveryBoundHasAnOwner(t *testing.T) {
	accessors := limitsAccessors(t)
	declared := map[string]bool{}
	for _, row := range limitOwnership {
		if declared[row.Field] {
			t.Fatalf("%s is declared twice", row.Field)
		}
		declared[row.Field] = true
		if !accessors[row.Field] {
			t.Fatalf("ownership declared for %q, which is not a Limits accessor", row.Field)
		}
		if row.Owner == "" {
			t.Fatalf("%s declares no owner", row.Field)
		}
		if row.Status != enforcedHere && strings.TrimSpace(row.Reason) == "" {
			t.Fatalf("%s is %v but records no reason", row.Field, row.Status)
		}
	}
	for name := range accessors {
		if !declared[name] {
			t.Fatalf("Limits.%s() has no ownership row: every bound must declare who enforces it, "+
				"or be recorded as delegated/reserved with a reason", name)
		}
	}
}

// An "enforced here" claim must be backed by a real production call site. This is
// the half that would have caught AuthConcurrency, DPoPConcurrency and
// RequestDeadline before they shipped as documentation.
func TestLimitsWall_EnforcedBoundsAreActuallyRead(t *testing.T) {
	called := productionCallees(t)
	for _, row := range limitOwnership {
		if row.Status != enforcedHere {
			continue
		}
		if !called[row.Field] {
			t.Fatalf("Limits.%s() is declared enforced by %q but is never read by this "+
				"package's production code — it is a configuration knob with no effect",
				row.Field, row.Owner)
		}
	}
}

// A "reserved" claim must be honest: a bound recorded as unenforced must not be
// silently read by production code. Otherwise the register would understate what
// the system actually does, which is the mirror image of the original defect.
func TestLimitsWall_ReservedBoundsAreNotSecretlyUsed(t *testing.T) {
	called := productionCallees(t)
	for _, row := range limitOwnership {
		if row.Status != reserved {
			continue
		}
		if called[row.Field] {
			t.Fatalf("Limits.%s() is recorded as reserved/unenforced but production code reads it: "+
				"update its ownership row to enforcedHere and name the call site", row.Field)
		}
	}
}

// Delegated bounds must name a real lower-level owner, and must not ALSO be
// enforced here — two enforcement points for one invariant is how they diverge.
func TestLimitsWall_DelegatedBoundsNameTheirOwner(t *testing.T) {
	called := productionCallees(t)
	for _, row := range limitOwnership {
		if row.Status != delegated {
			continue
		}
		if !strings.Contains(row.Owner, ".") {
			t.Fatalf("Limits.%s() is delegated but its owner %q does not name a concrete control",
				row.Field, row.Owner)
		}
		if called[row.Field] {
			t.Fatalf("Limits.%s() is delegated to %q but is ALSO read here: one invariant with two "+
				"enforcement points will drift", row.Field, row.Owner)
		}
	}
}
