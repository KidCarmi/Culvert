package policy

import "testing"

// FuzzCompile drives the strict parser + compiler with arbitrary bytes. The engine
// must NEVER panic and must NEVER produce a snapshot whose default posture permits.
// A compiled snapshot must always default-deny and be internally consistent.
func FuzzCompile(f *testing.F) {
	seeds := []string{
		"",
		"{}",
		"null",
		gwSnap(""),
		gwSnap(`{"id":"R","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`),
		gwSnap(`{"id":"R","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"request_access","conditions":[{"field":"tool.name","op":"glob","value":"read_*"}]}`),
		mgmtSnap(`{"id":"M","priority":1,"action":"ALLOW","reason":"MCP.MANAGEMENT.TENANT_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`),
		`{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"ALLOW","rules":[]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	lim := DefaultLimits()
	f.Fuzz(func(t *testing.T, doc []byte) {
		snap, err := Compile(doc, CreatedMeta{}, lim)
		if err != nil {
			if snap != nil {
				t.Fatal("compile error returned a non-nil snapshot")
			}
			return
		}
		// A compiled snapshot must always default-deny and be capability-consistent.
		if snap.DefaultAction() != ActionDeny {
			t.Fatalf("compiled snapshot default action = %v, must be DENY", snap.DefaultAction())
		}
		if !snap.Capability().Valid() {
			t.Fatal("compiled snapshot has an invalid capability")
		}
		if snap.Hash() == "" {
			t.Fatal("compiled snapshot has an empty hash")
		}
		// Re-compiling the same bytes must be deterministic (same hash).
		snap2, err2 := Compile(doc, CreatedMeta{}, lim)
		if err2 != nil || snap2.Hash() != snap.Hash() {
			t.Fatalf("non-deterministic compile: err=%v hash %s vs %s", err2, snap.Hash(), snap2.Hash())
		}
	})
}

// FuzzEvaluate drives the evaluator with an arbitrary document AND arbitrary input
// perturbations. It must never panic, and every result must fail closed on error.
func FuzzEvaluate(f *testing.F) {
	f.Add([]byte(gwSnap(`{"id":"R","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"tool.name","op":"prefix","value":"read"}],"obligations":{"logging":"standard"}}`)), "read_file", uint8(0), uint8(0))
	f.Add([]byte(gwSnap("")), "", uint8(3), uint8(2))
	e := NewEngine(DefaultLimits())
	f.Fuzz(func(t *testing.T, doc []byte, toolName string, driftSel, classSel uint8) {
		snap, err := Compile(doc, CreatedMeta{}, DefaultLimits())
		if err != nil {
			return // only exercise the evaluator with a valid snapshot
		}
		in := gwInput()
		in.Tool.Name = toolName
		in.Operation.Operand = toolName
		in.Tool.Drift = fuzzDrift(driftSel)
		in.Operation.Class = fuzzClass(classSel)

		d, tr, evErr := e.Evaluate(snap, &in)
		// Invariant: on any error the decision must fail closed (never ALLOW-class).
		if evErr != nil && d.IsAllowClass() {
			t.Fatalf("error path permitted: %v (%v)", d.Action, evErr)
		}
		// Invariant: the decision reason is always present + well-formed.
		if d.Reason == "" || !d.Reason.Valid() {
			t.Fatalf("decision carries an invalid reason: %q", d.Reason)
		}
		// Invariant: the trace never leaks the raw tool name.
		for _, ent := range tr.Entries {
			if toolName != "" && (ent.Label == toolName || ent.ConditionID == toolName) {
				t.Fatalf("trace leaked the raw tool name %q", toolName)
			}
		}
	})
}

// FuzzGlob drives the anchored glob compiler + matcher. It must never panic, never
// backtrack pathologically, and reject the forbidden `**` construct.
func FuzzGlob(f *testing.F) {
	f.Add("read_*", "read_file")
	f.Add("*", "anything")
	f.Add("a?c", "abc")
	f.Add("a**b", "axb")
	lim := DefaultLimits()
	f.Fuzz(func(t *testing.T, pattern, subject string) {
		g, err := compileGlob(pattern, lim)
		if err != nil {
			return
		}
		// A compiled glob must be a total function over any subject (no panic, no hang).
		_ = g.match(subject)
	})
}

func fuzzDrift(sel uint8) DriftClass {
	switch sel % 4 {
	case 1:
		return DriftUnknownTool
	case 2:
		return DriftPrivilegeExpansion
	case 3:
		return DriftSemanticDrift
	default:
		return DriftNoMaterialChange
	}
}

func fuzzClass(sel uint8) OperationClass {
	switch sel % 5 {
	case 1:
		return OpWrite
	case 2:
		return OpDestructive
	case 3:
		return OpControl
	case 4:
		return OpDiscovery
	default:
		return OpRead
	}
}
