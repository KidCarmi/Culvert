package contracts

import (
	"strings"
	"testing"
	"testing/fstest"
)

const goodTest = "package x\n\nfunc TestGuard(t *testing.T) {\n\tif got() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n\nfunc TestOther(t *testing.T) {}\n"

func tree(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for name, body := range files {
		m[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

func baseContract() Contract {
	return Contract{
		ID: "POL-001", Area: "policy", Invariant: "first match wins", Status: StatusEnforced,
		Authority: "policy engine", Code: []string{"policy.go"}, Validation: "unit",
		Compatibility: "rule order is persisted", Tests: []TestRef{{File: "policy_test.go", Name: "TestGuard"}},
		Transitions: Transitions{Forbidden: []string{"a later rule overriding an earlier match"}},
	}
}

func reg(cs ...Contract) *Registry {
	return &Registry{Version: 1, Protected: []string{"internal/contracts/**"}, Contracts: cs}
}

var goodTree = tree(map[string]string{"policy.go": "package x\n", "policy_test.go": goodTest})

func TestValidate_SoundRegistryHasNoProblems(t *testing.T) {
	if p := Validate(reg(baseContract()), goodTree); len(p) != 0 {
		t.Fatalf("unexpected problems: %v", p)
	}
}

// Each case breaks exactly one thing a registry must guarantee.
func TestValidate_RejectsEachDefect(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*Contract)
		tree   fstest.MapFS
		want   string
	}{
		"enforced without a test":  {func(c *Contract) { c.Tests = nil }, goodTree, "names no test"},
		"test function missing":    {func(c *Contract) { c.Tests[0].Name = "TestGone" }, goodTree, "is not defined"},
		"test file missing":        {func(c *Contract) { c.Tests[0].File = "gone_test.go" }, goodTree, "is missing"},
		"code path matches none":   {func(c *Contract) { c.Code = []string{"nope.go"} }, goodTree, "matches no file"},
		"no code path":             {func(c *Contract) { c.Code = nil }, goodTree, "no code paths"},
		"bad id":                   {func(c *Contract) { c.ID = "policy1" }, goodTree, "does not match"},
		"no forbidden transition":  {func(c *Contract) { c.Transitions.Forbidden = nil }, goodTree, "no forbidden transition"},
		"open without a question":  {func(c *Contract) { c.Status = StatusOpen }, goodTree, "no question"},
		"open marked approved":     {func(c *Contract) { c.Status, c.Question, c.OwnerApproved = StatusOpen, "q?", true }, goodTree, "cannot be owner_approved"},
		"contract test that skips": {func(*Contract) {}, tree(map[string]string{"policy.go": "package x\n", "policy_test.go": "package x\n\nfunc TestGuard(t *testing.T) {\n\tt.Skip(\"later\")\n}\n"}), "can skip itself"},
	} {
		t.Run(name, func(t *testing.T) {
			c := baseContract()
			tc.mutate(&c)
			p := strings.Join(Validate(reg(c), tc.tree), "\n")
			if !strings.Contains(p, tc.want) {
				t.Fatalf("problems %q do not mention %q", p, tc.want)
			}
		})
	}
}

func TestValidate_DuplicateAndRetiredConflicts(t *testing.T) {
	r := reg(baseContract(), baseContract())
	r.Retired = []Record{{ID: "POL-001", Reason: ""}}
	p := strings.Join(Validate(r, goodTree), "\n")
	for _, want := range []string{"duplicate id", "no reason", "still present"} {
		if !strings.Contains(p, want) {
			t.Errorf("problems %q do not mention %q", p, want)
		}
	}
}

func TestParse_UnknownFieldIsAnError(t *testing.T) {
	if _, err := Parse([]byte("version: 1\ncontracts:\n  - id: POL-001\n    testz: []\n")); err == nil {
		t.Fatal("a misspelled field was accepted")
	}
}

func TestAssess_NoBaseRegistryIsBootstrap(t *testing.T) {
	im := Assess(nil, reg(baseContract()), goodTree, []string{"contracts/registry.yaml"})
	if len(im.Weakened)+len(im.Recorded)+len(im.Touched) != 0 {
		t.Fatalf("bootstrap should report nothing: %+v", im)
	}
}

func TestAssess_UnrelatedChangeIsFree(t *testing.T) {
	im := Assess(reg(baseContract()), reg(baseContract()), goodTree, []string{"README.md"})
	if len(im.Weakened)+len(im.Recorded)+len(im.Touched) != 0 {
		t.Fatalf("an unrelated change must not involve any contract: %+v", im)
	}
}

func TestAssess_TouchingContractCodeIsReportedNotBlocked(t *testing.T) {
	im := Assess(reg(baseContract()), reg(baseContract()), goodTree, []string{"policy.go"})
	if len(im.Touched) != 1 || im.Touched[0] != "POL-001" {
		t.Fatalf("Touched = %v, want [POL-001]", im.Touched)
	}
	if len(im.Weakened)+len(im.Recorded) != 0 {
		t.Fatalf("an implementation change with intact tests must not block: %+v", im)
	}
}

// The bypass this exists to stop: change the implementation, delete the test,
// and edit the registry in the same change so head looks consistent.
func TestAssess_BaseRegistryIsTheReference(t *testing.T) {
	base := reg(baseContract())
	headC := baseContract()
	headC.Tests = []TestRef{{File: "policy_test.go", Name: "TestOther"}} // swapped for a weaker test
	headTree := tree(map[string]string{"policy.go": "package x\n", "policy_test.go": "package x\n\nfunc TestOther(t *testing.T) {}\n"})
	if p := Validate(reg(headC), headTree); len(p) != 0 {
		t.Fatalf("precondition: head registry is self-consistent, got %v", p)
	}
	im := Assess(base, reg(headC), headTree, []string{"policy.go", "policy_test.go", "contracts/registry.yaml"})
	// Two findings now: the reference was dropped, and the function is gone.
	got := strings.Join(im.Weakened, "\n")
	for _, want := range []string{"TestGuard is not defined", "TestGuard (policy_test.go) dropped"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Weakened = %v, want it to mention %q", im.Weakened, want)
		}
	}
}

func TestAssess_SilentWeakeningsFail(t *testing.T) {
	skipTree := tree(map[string]string{"policy.go": "package x\n", "policy_test.go": "package x\n\nfunc TestGuard(t *testing.T) {\n\tt.Skip()\n}\n"})
	for name, tc := range map[string]struct {
		head *Registry
		tree fstest.MapFS
		want string
	}{
		"contract removed":    {reg(), goodTree, "removed from the registry"},
		"status downgraded":   {reg(func() Contract { c := baseContract(); c.Status, c.Question = StatusOpen, "q?"; return c }()), goodTree, "status downgraded"},
		"invariant rewritten": {reg(func() Contract { c := baseContract(); c.Invariant = "last match wins"; return c }()), goodTree, "invariant text changed"},
		"code path dropped":   {reg(func() Contract { c := baseContract(); c.Code = []string{"policy_test.go"}; return c }()), goodTree, "code paths dropped"},
		"test made skippable": {reg(baseContract()), skipTree, "can skip itself"},
		"self-approval":       {reg(func() Contract { c := baseContract(); c.OwnerApproved = true; return c }()), goodTree, "marked owner_approved"},
	} {
		t.Run(name, func(t *testing.T) {
			im := Assess(reg(baseContract()), tc.head, tc.tree, nil)
			if got := strings.Join(im.Weakened, "\n"); !strings.Contains(got, tc.want) {
				t.Fatalf("Weakened %q does not mention %q", got, tc.want)
			}
		})
	}
}

// A recorded change passes the gate and is listed in the summary; no approval.
func TestAssess_RecordedChangeIsListedNotRefused(t *testing.T) {
	head := reg()
	head.Retired = []Record{{ID: "POL-001", Reason: "replaced by POL-002"}}
	im := Assess(reg(baseContract()), head, goodTree, nil)
	if len(im.Weakened) != 0 {
		t.Fatalf("a recorded retirement is not a silent weakening: %v", im.Weakened)
	}
	if len(im.Recorded) != 1 {
		t.Fatalf("Recorded = %v, want the retirement", im.Recorded)
	}
	// The automated gate replaces a reviewer with the record's reason, so the
	// summary line must carry it.
	if !strings.Contains(im.Recorded[0], "reason: replaced by POL-002") {
		t.Fatalf("Recorded = %q, want the record's reason in the summary line", im.Recorded[0])
	}
}

func TestAssess_ProtectedPathEditIsListed(t *testing.T) {
	im := Assess(reg(baseContract()), reg(baseContract()), goodTree, []string{"internal/contracts/contracts.go"})
	if len(im.Weakened) != 0 || len(im.Recorded) != 1 || !strings.Contains(im.Recorded[0], "internal/contracts/contracts.go") {
		t.Fatalf("want one listed protected-path edit and no failure, got %+v", im)
	}
}

// Adding a contract is silent; shrinking the protected list is listed.
func TestAssess_RegistryAdditionsAreSilentButGovernanceEditsAreListed(t *testing.T) {
	added := baseContract()
	added.ID = "POL-002"
	im := Assess(reg(baseContract()), reg(baseContract(), added), goodTree, []string{"contracts/registry.yaml"})
	if len(im.Weakened)+len(im.Recorded) != 0 {
		t.Fatalf("adding a contract must report nothing: %+v", im)
	}
	unprotected := reg(baseContract())
	unprotected.Protected = nil
	if im := Assess(reg(baseContract()), unprotected, goodTree, nil); len(im.Weakened) != 0 || len(im.Recorded) != 1 {
		t.Fatalf("removing a protected path must be listed, not refused: %+v", im)
	}
}

// A record left in the file by an earlier change must not excuse a
// later, unrecorded weakening of the same contract.
func TestAssess_StaleRecordDoesNotExcuseANewWeakening(t *testing.T) {
	base := reg(baseContract())
	base.Amended = []Record{{ID: "POL-001", Reason: "an old change"}}
	head := reg(func() Contract { c := baseContract(); c.Invariant = "last match wins"; return c }())
	head.Amended = base.Amended
	im := Assess(base, head, goodTree, nil)
	if len(im.Weakened) != 1 {
		t.Fatalf("Weakened = %v, want the unrecorded invariant change", im.Weakened)
	}
}

// Step one of a two-step bypass: unlist a test while leaving the function in
// place, so that a later change can delete it with nothing registered.
func TestAssess_DroppingARegisteredTestIsAWeakening(t *testing.T) {
	base := baseContract()
	base.Tests = append(base.Tests, TestRef{File: "policy_test.go", Name: "TestOther"})
	head := baseContract() // keeps TestGuard, silently drops TestOther
	if p := Validate(reg(head), goodTree); len(p) != 0 {
		t.Fatalf("precondition: head registry is self-consistent, got %v", p)
	}
	im := Assess(reg(base), reg(head), goodTree, []string{"contracts/registry.yaml"})
	if len(im.Weakened) != 1 || !strings.Contains(im.Weakened[0], "TestOther") {
		t.Fatalf("Weakened = %v, want the dropped TestOther reference", im.Weakened)
	}
}

// A contract amended once must be amendable again: an older record kept as
// history must not turn a new, recorded change into an unrecorded one.
func TestAssess_SecondAmendmentOfTheSameContractIsAccepted(t *testing.T) {
	base := reg(baseContract())
	base.Amended = []Record{{ID: "POL-001", Reason: "first change"}}
	head := reg(func() Contract { c := baseContract(); c.Invariant = "last match wins"; return c }())
	head.Amended = append(append([]Record{}, base.Amended...), Record{ID: "POL-001", Reason: "second change"})
	im := Assess(base, head, goodTree, nil)
	if len(im.Weakened) != 0 {
		t.Fatalf("a newly recorded change must not count as unrecorded: %v", im.Weakened)
	}
	if len(im.Recorded) != 1 {
		t.Fatalf("Recorded = %v, want the second amendment", im.Recorded)
	}
}

// A registered test that is disabled without being deleted: the text
// "func TestGuard(" is still in the file, but nothing by that name runs.
func TestCheckTest_DisabledDeclarationsAreNotTests(t *testing.T) {
	for name, src := range map[string]string{
		"wrapped in a block comment": "package x\n\n/*\nfunc TestGuard(t *testing.T) {\n\tt.Fatal(\"x\")\n}\n*/\n",
		"named only in a string":     "package x\n\nvar s = `\nfunc TestGuard(t *testing.T) {}\n`\n",
		"turned into a method":       "package x\n\ntype T struct{}\n\nfunc (T) TestGuard(t *testing.T) {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			tr := tree(map[string]string{"policy.go": "package x\n", "policy_test.go": src})
			ref := TestRef{File: "policy_test.go", Name: "TestGuard"}
			if msg := checkTest(tr, ref); !strings.Contains(msg, "is not defined") {
				t.Fatalf("checkTest = %q, want the test reported as not defined", msg)
			}
			// And through the gate: base registered it, head disabled it.
			im := Assess(reg(baseContract()), reg(baseContract()), tr, []string{"policy_test.go"})
			if len(im.Weakened) == 0 {
				t.Fatal("disabling a registered test was not reported as a weakening")
			}
		})
	}
}

// A skip call that is itself commented out does not make a test skippable; one
// inside a subtest closure does.
func TestCheckTest_SkipDetectionReadsCodeNotText(t *testing.T) {
	ref := TestRef{File: "policy_test.go", Name: "TestGuard"}
	commented := tree(map[string]string{"policy_test.go": "package x\n\nfunc TestGuard(t *testing.T) {\n\t// t.Skip(\"old\")\n\tt.Fatal(\"x\")\n}\n"})
	if msg := checkTest(commented, ref); msg != "" {
		t.Errorf("a commented-out skip was reported: %q", msg)
	}
	nested := tree(map[string]string{"policy_test.go": "package x\n\nfunc TestGuard(t *testing.T) {\n\tt.Run(\"a\", func(t *testing.T) { t.SkipNow() })\n}\n"})
	if msg := checkTest(nested, ref); !strings.Contains(msg, "can skip itself") {
		t.Errorf("a skip inside a subtest was missed: %q", msg)
	}
}

// A registered test whose file the default build excludes never runs, even
// though its declaration and assertions are untouched.
func TestCheckTest_BuildExcludedFilesAreNotRun(t *testing.T) {
	body := "package x\n\nfunc TestGuard(t *testing.T) {\n\tt.Fatal(\"x\")\n}\n"
	for name, tc := range map[string]struct {
		file, src string
		excluded  bool
	}{
		"go:build ignore":       {"policy_test.go", "//go:build ignore\n\n" + body, true},
		"custom tag":            {"policy_test.go", "//go:build benchgate\n\n" + body, true},
		"legacy +build line":    {"policy_test.go", "// +build ignore\n\n" + body, true},
		"other-OS filename":     {"policy_windows_test.go", body, true},
		"negated custom tag":    {"policy_test.go", "//go:build !benchgate\n\n" + body, false},
		"linux-only constraint": {"policy_test.go", "//go:build linux\n\n" + body, false},
		"no constraint":         {"policy_test.go", body, false},
	} {
		t.Run(name, func(t *testing.T) {
			tr := tree(map[string]string{tc.file: tc.src})
			msg := checkTest(tr, TestRef{File: tc.file, Name: "TestGuard"})
			if got := strings.Contains(msg, "excluded from the default build"); got != tc.excluded {
				t.Fatalf("excluded = %v, want %v (checkTest = %q)", got, tc.excluded, msg)
			}
		})
	}
	// Through the gate: base registered the test, head tagged its file out.
	tr := tree(map[string]string{"policy.go": "package x\n", "policy_test.go": "//go:build ignore\n\n" + body})
	im := Assess(reg(baseContract()), reg(baseContract()), tr, []string{"policy_test.go"})
	if len(im.Weakened) == 0 {
		t.Fatal("excluding a registered test's file from the build was not reported as a weakening")
	}
}
