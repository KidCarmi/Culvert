// Package contracts loads and checks the product contracts registry
// (contracts/registry.yaml): the list of customer-observable invariants, the
// code that implements each one, and the tests that must fail if it breaks.
//
// It answers two questions, both mechanically:
//
//   - Validate: is the registry itself sound? Every enforced contract names
//     tests that exist and are not skipped, and code paths that exist.
//   - Impact: comparing a base revision's registry to the head tree, was a
//     contract weakened? The BASE registry is the reference, so editing the
//     registry in the same change as the implementation cannot hide it.
//
// The package makes no decision about whether a contract change is right. It
// only makes the change impossible to land unnoticed: an unrecorded weakening
// fails, and a recorded one is listed in the gate summary with its reason. No
// human approval is part of the gate. See docs/engineering/PRODUCT-CONTRACTS.md.
package contracts

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

// Status values. A contract is either enforced by tests or open: recorded
// because it matters, but contradictory or undecided, so nothing may claim it
// as an approved rule yet.
const (
	StatusEnforced = "enforced"
	StatusOpen     = "open"
)

// TestRef names one test function that must fail if the contract breaks.
type TestRef struct {
	File string `yaml:"file"`
	Name string `yaml:"name"`
}

// Transitions lists the state changes a contract allows and forbids.
type Transitions struct {
	Permitted []string `yaml:"permitted"`
	Forbidden []string `yaml:"forbidden"`
}

// Contract is one registry entry.
type Contract struct {
	ID            string      `yaml:"id"`
	Area          string      `yaml:"area"`
	Invariant     string      `yaml:"invariant"`
	Status        string      `yaml:"status"`
	OwnerApproved bool        `yaml:"owner_approved"`
	Authority     string      `yaml:"authority"`
	Code          []string    `yaml:"code"`
	Configs       []string    `yaml:"configs"`
	Transitions   Transitions `yaml:"transitions"`
	Tests         []TestRef   `yaml:"tests"`
	Validation    string      `yaml:"validation"`
	Compatibility string      `yaml:"compatibility"`
	Question      string      `yaml:"question"`
}

// Record is an explicit, reviewable statement that a contract was changed or
// removed on purpose.
type Record struct {
	ID     string `yaml:"id"`
	Reason string `yaml:"reason"`
}

// Registry is the whole file.
type Registry struct {
	Version   int        `yaml:"version"`
	Protected []string   `yaml:"protected"`
	Contracts []Contract `yaml:"contracts"`
	Amended   []Record   `yaml:"amended"`
	Retired   []Record   `yaml:"retired"`
}

// Parse decodes a registry. Unknown fields are an error, so a typo in a field
// name cannot silently drop a requirement.
func Parse(data []byte) (*Registry, error) {
	var r Registry
	if err := yaml.UnmarshalWithOptions(data, &r, yaml.DisallowUnknownField()); err != nil {
		return nil, fmt.Errorf("contracts: parse registry: %w", err)
	}
	return &r, nil
}

var (
	idPattern        = regexp.MustCompile(`^[A-Z]{2,5}-\d{3}$`)
	validValidations = map[string]bool{"unit": true, "integration": true, "e2e": true}
)

// Validate checks the registry against the tree. It returns every problem
// found, sorted, so one run reports them all.
func Validate(r *Registry, tree fs.FS) []string {
	var p []string
	if r.Version != 1 {
		p = append(p, fmt.Sprintf("version %d is not supported (want 1)", r.Version))
	}
	seen := map[string]bool{}
	for i := range r.Contracts {
		c := &r.Contracts[i]
		if !idPattern.MatchString(c.ID) {
			p = append(p, fmt.Sprintf("contract #%d: id %q does not match AREA-NNN", i+1, c.ID))
			continue
		}
		if seen[c.ID] {
			p = append(p, c.ID+": duplicate id")
		}
		seen[c.ID] = true
		p = append(p, validateContract(c, tree)...)
	}
	for _, rec := range append(append([]Record{}, r.Amended...), r.Retired...) {
		if strings.TrimSpace(rec.Reason) == "" {
			p = append(p, rec.ID+": amended/retired record has no reason")
		}
	}
	for _, rec := range r.Retired {
		if seen[rec.ID] {
			p = append(p, rec.ID+": listed as retired but still present in contracts")
		}
	}
	sort.Strings(p)
	return p
}

func validateContract(c *Contract, tree fs.FS) []string {
	var p []string
	bad := func(format string, a ...any) { p = append(p, c.ID+": "+fmt.Sprintf(format, a...)) }
	for name, v := range map[string]string{"area": c.Area, "invariant": c.Invariant, "authority": c.Authority, "compatibility": c.Compatibility} {
		if strings.TrimSpace(v) == "" {
			bad("%s is empty", name)
		}
	}
	if len(c.Code) == 0 {
		bad("no code paths: changes to it could never be detected")
	}
	for _, g := range c.Code {
		if !globExists(tree, g) {
			bad("code path %q matches no file", g)
		}
	}
	p = append(p, validateStatus(c)...)
	for _, t := range c.Tests {
		if msg := checkTest(tree, t); msg != "" {
			bad("%s", msg)
		}
	}
	return p
}

// validateStatus checks the fields that depend on the contract's status.
func validateStatus(c *Contract) []string {
	var p []string
	bad := func(format string, a ...any) { p = append(p, c.ID+": "+fmt.Sprintf(format, a...)) }
	switch c.Status {
	case StatusEnforced:
		if len(c.Tests) == 0 {
			bad("enforced but names no test")
		}
		if !validValidations[c.Validation] {
			bad("validation %q is not unit, integration or e2e", c.Validation)
		}
		if len(c.Transitions.Forbidden) == 0 {
			bad("enforced but lists no forbidden transition")
		}
	case StatusOpen:
		if strings.TrimSpace(c.Question) == "" {
			bad("open but states no question for the owner")
		}
		if c.OwnerApproved {
			bad("open contracts cannot be owner_approved")
		}
	default:
		bad("status %q is not enforced or open", c.Status)
	}
	return p
}

// globExists reports whether a code-path pattern matches something in the
// tree. "dir/**" means everything under dir.
func globExists(tree fs.FS, g string) bool {
	if dir, ok := strings.CutSuffix(g, "/**"); ok {
		info, err := fs.Stat(tree, dir)
		return err == nil && info.IsDir()
	}
	m, err := fs.Glob(tree, g)
	return err == nil && len(m) > 0
}

// checkTest reports why a test reference is not usable, or "".
func checkTest(tree fs.FS, t TestRef) string {
	if !strings.HasSuffix(t.File, "_test.go") {
		return fmt.Sprintf("test file %q is not a _test.go file", t.File)
	}
	src, err := fs.ReadFile(tree, path.Clean(t.File))
	if err != nil {
		return fmt.Sprintf("test file %q is missing", t.File)
	}
	// Parse the file rather than search its text: a test wrapped in a block
	// comment, or named only in a string, still matches a text search but is
	// not a test that runs.
	file, err := parser.ParseFile(token.NewFileSet(), t.File, src, parser.SkipObjectResolution)
	if err != nil {
		return fmt.Sprintf("test file %q does not parse: %v", t.File, err)
	}
	decl := testDecl(file, t.Name)
	if decl == nil {
		return fmt.Sprintf("test %s is not defined in %s", t.Name, t.File)
	}
	if callsSkip(decl) {
		return fmt.Sprintf("test %s in %s can skip itself (t.Skip): a contract test must run", t.Name, t.File)
	}
	return ""
}

// testDecl returns the top-level function (not method) called name that has a
// body, or nil.
func testDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == name && fd.Body != nil {
			return fd
		}
	}
	return nil
}

// callsSkip reports whether the function body calls a Skip, Skipf or SkipNow
// method anywhere, including inside a closure or subtest.
func callsSkip(fd *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return !found
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			switch sel.Sel.Name {
			case "Skip", "Skipf", "SkipNow":
				found = true
			}
		}
		return !found
	})
	return found
}

// Impact is the result of comparing a base registry with the head tree.
type Impact struct {
	// Touched lists contracts whose code paths include a changed file. It is
	// information for the reviewer, not a failure.
	Touched []string
	// Weakened lists contract changes that happened without an explicit
	// record. Always a failure.
	Weakened []string
	// Recorded lists intentional changes, reported in the summary but never a
	// failure: contracts changed or removed with a new amended/retired record,
	// and edits to protected paths (the gate's own files).
	Recorded []string
}

// Assess compares base (the registry at the merge base; nil when the base has
// none) with head and the head tree. changed is the list of files the change
// touches, relative to the repository root.
func Assess(base, head *Registry, tree fs.FS, changed []string) Impact {
	var im Impact
	if base == nil {
		return im // first introduction of the registry: nothing to compare
	}
	headByID := map[string]*Contract{}
	for i := range head.Contracts {
		headByID[head.Contracts[i].ID] = &head.Contracts[i]
	}
	// Records already in the base were written for earlier changes. Only one this change ADDS (a new id+reason pair) explains it, so
	// kept history neither excuses a new weakening nor blocks a later one.
	inBase := map[Record]bool{}
	for _, rec := range append(append([]Record{}, base.Amended...), base.Retired...) {
		inBase[rec] = true
	}
	// newReasons maps a contract ID to the reasons of the records this change
	// adds for it. The reason is printed with the change, so the summary says
	// why a weakening was accepted, not only what changed.
	newReasons := map[string][]string{}
	for _, rec := range append(append([]Record{}, head.Amended...), head.Retired...) {
		if !inBase[rec] {
			newReasons[rec.ID] = append(newReasons[rec.ID], strings.TrimSpace(rec.Reason))
		}
	}
	for i := range base.Contracts {
		b := &base.Contracts[i]
		why := weakening(b, headByID[b.ID], tree)
		switch {
		case len(why) == 0:
		case len(newReasons[b.ID]) > 0:
			im.Recorded = append(im.Recorded, b.ID+": "+strings.Join(why, "; ")+
				" (reason: "+strings.Join(newReasons[b.ID], "; ")+")")
		default:
			for _, w := range why {
				im.Weakened = append(im.Weakened, b.ID+": "+w+" (no new amended/retired record)")
			}
		}
		if touches(b.Code, changed) {
			im.Touched = append(im.Touched, b.ID)
		}
	}
	im.Recorded = append(im.Recorded, governanceEdits(base, head, changed)...)
	sort.Strings(im.Touched)
	sort.Strings(im.Weakened)
	sort.Strings(im.Recorded)
	return im
}

// governanceEdits lists changes to the gate itself: the protected list and the
// protected files. They are reported, not refused, so they never pass unseen.
//
// The registry file is deliberately not a protected path: adding an entry must
// stay cheap, and removing or rewording one is caught by the base comparison.
func governanceEdits(base, head *Registry, changed []string) []string {
	var out []string
	if gone := covered(base.Protected, head.Protected); len(gone) > 0 {
		out = append(out, "protected paths removed: "+strings.Join(gone, ", "))
	}
	for _, f := range changed {
		if touches(base.Protected, []string{f}) {
			out = append(out, "protected path changed: "+f)
		}
	}
	return out
}

// weakening lists the ways head no longer upholds base contract b.
func weakening(b, h *Contract, tree fs.FS) []string {
	if h == nil {
		return []string{"removed from the registry"}
	}
	var why []string
	if b.Status == StatusEnforced && h.Status != StatusEnforced {
		why = append(why, "status downgraded from enforced")
	}
	if b.OwnerApproved && !h.OwnerApproved {
		why = append(why, "owner approval removed")
	}
	if !b.OwnerApproved && h.OwnerApproved {
		why = append(why, "marked owner_approved")
	}
	if strings.TrimSpace(b.Invariant) != strings.TrimSpace(h.Invariant) {
		why = append(why, "invariant text changed")
	}
	if len(covered(b.Code, h.Code)) > 0 {
		why = append(why, "code paths dropped: "+strings.Join(covered(b.Code, h.Code), ", "))
	}
	// Dropping a test from the list is a weakening even while the function
	// still exists: once unlisted, a later change could delete it unseen.
	listed := map[TestRef]bool{}
	for _, t := range h.Tests {
		listed[t] = true
	}
	for _, t := range b.Tests {
		if !listed[t] {
			why = append(why, fmt.Sprintf("test %s (%s) dropped from the contract", t.Name, t.File))
		}
	}
	// The BASE test list is the reference: every test that protected the
	// contract before must still exist and run, whatever head's list says.
	for _, t := range b.Tests {
		if msg := checkTest(tree, t); msg != "" {
			why = append(why, msg)
		}
	}
	return why
}

// covered returns the entries of base missing from head.
func covered(base, head []string) []string {
	in := map[string]bool{}
	for _, h := range head {
		in[h] = true
	}
	var missing []string
	for _, b := range base {
		if !in[b] {
			missing = append(missing, b)
		}
	}
	return missing
}

func touches(globs, files []string) bool {
	for _, f := range files {
		for _, g := range globs {
			if ok, _ := path.Match(g, f); ok {
				return true
			}
			if strings.HasSuffix(g, "/**") && strings.HasPrefix(f, strings.TrimSuffix(g, "**")) {
				return true
			}
		}
	}
	return false
}
