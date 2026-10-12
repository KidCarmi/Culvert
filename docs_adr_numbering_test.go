package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestADRNumberingNoCollisions is the CI-enforced half of the reservation-convention
// recommendation raised by the Language & Terminology Governance routine after the
// identical "two documents claim the same ADR-NNNN number" defect recurred four times
// (T-16, T-46, T-47, and the ADR-0034 collision fixed alongside this test — see
// docs/engineering/TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-08.md). Every prior occurrence
// was caught only by a human/AI review pass grepping the tree after the fact; this test
// makes the same check a merge-blocking part of the existing root `go test ./...` run
// (already required by pr-fast-gate.yml), so a PR that reintroduces a duplicate header
// fails BEFORE merge instead of days later.
//
// Two directories carry `# ADR-NNNN: ...` headers: docs/adr/ (adopted architecture
// decisions) and docs/support/rfc/ (proposed, not-yet-adopted RFC-track documents that
// happen to self-title themselves "ADR-NNNN" — see docs/support/rfc/0019 through 0022
// and 0036). Both share ONE numbering space: a bare "ADR-0018" citation elsewhere in the
// repo is ambiguous unless the number maps to exactly one document, regardless of which
// of the two directories holds it.
//
// This test does NOT allocate or reserve numbers for future PRs — it only rejects two
// EXISTING files claiming the same number at merge time, which is the cheapest point to
// catch it (before either branch's number choice has propagated into cross-references,
// GUI copy, or other ADRs' "Relates to" lines).
func TestADRNumberingNoCollisions(t *testing.T) {
	byNumber := adrDocumentOwners(t)

	var collidingNumbers []string
	for num, owners := range byNumber {
		if len(owners) > 1 {
			collidingNumbers = append(collidingNumbers, num)
		}
	}
	sort.Strings(collidingNumbers)

	for _, num := range collidingNumbers {
		files := append([]string(nil), byNumber[num]...)
		sort.Strings(files)
		t.Errorf("ADR-%s is claimed by %d documents (must be exactly 1): %v — renumber the newer/less-established "+
			"one to the next number confirmed clean against every '# ADR-NNNN' header in docs/adr/ and "+
			"docs/support/rfc/, and update its downstream citations", num, len(files), files)
	}
}

// adrDocumentOwners maps each ADR number to the document files that claim it in
// their title. It is the ONE scan of the shared docs/adr + docs/support/rfc
// numbering space: the collision wall above and the citation wall below must
// agree on what "an ADR document exists" means, and a second copy of this scan
// is how the two drift into disagreeing.
func adrDocumentOwners(t *testing.T) map[string][]string {
	t.Helper()

	headerRe := regexp.MustCompile(`^#\s*ADR-(\d+)\b`)
	byNumber := map[string][]string{}

	dirs := []string{
		filepath.Join("docs", "adr"),
		filepath.Join("docs", "support", "rfc"),
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".md" {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path) // #nosec G304 -- fixed, repo-relative doc directories only
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			num := ""
			// The document's title is its first Markdown heading line, wherever it
			// falls — an RFC's leading "> STATUS: ..." blockquote (and any blank
			// lines around it) is skipped implicitly because it never starts with
			// "#". Stopping at the FIRST heading (rather than scanning the whole
			// file for any ADR-NNNN-shaped line) avoids a false match on a "Relates
			// to: ADR-0016" body line further down; not capping the scan at a fixed
			// line count (a prior version capped at 8 and a Codex review on the PR
			// that introduced this test caught that a longer front-matter block
			// would push the real heading past the cap and make the gate silently
			// skip the file) means front matter of any length is still followed
			// through to the real title.
			if line := firstMarkdownHeading(data); line != "" {
				if m := headerRe.FindStringSubmatch(line); m != nil {
					num = m[1]
				}
			}
			if num == "" {
				continue // not every docs/adr file self-titles "ADR-NNNN" in its header (e.g. ADR-FE-*)
			}
			byNumber[num] = append(byNumber[num], path)
		}
	}
	return byNumber
}

// TestADRCitationsInSourceResolve is the OTHER half of the numbering contract.
//
// The collision wall above polices the documents. Nothing polices the
// CITATIONS, and a source comment is where an ADR number is read by the next
// engineer deciding whether a contract may change: "(ADR-0037)" beside
// shutdownRegistry is how a reviewer finds the decision that says the engine
// owns phase execution and main owns the hooks. A citation that resolves to no
// document sends that reader nowhere, and the renumbering that produces one is
// routine — docs/engineering/TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-08.md
// renumbered an RFC precisely to clear a collision, and the governance review
// that recommended this file's collision gate asked for the downstream
// citations to be updated with it.
//
// SCOPE, stated so the next reader does not over-trust this gate: it proves a
// cited number EXISTS, not that it is the RIGHT one. A renumber that frees a
// number which a later document then takes turns a stale citation into a
// citation that still resolves — to the wrong decision — and no mechanical
// check can see that. That is exactly what happened to runtime_shutdown.go,
// which cited ADR-0036 for the shutdown registry after the shutdown ADR moved
// to 0037, while 0036 names the unrelated AI-evidence boundary; it was found
// by reading, and fixed in the same change as this test. Keep reading.
//
// Test files are excluded: they legitimately build synthetic "# ADR-0099"
// fixtures (TestFirstMarkdownHeading_NoLineCountCap below) that name no real
// decision and must not be read as citations.
func TestADRCitationsInSourceResolve(t *testing.T) {
	owners := adrDocumentOwners(t)
	citationRe := regexp.MustCompile(`ADR-(\d{4})`)

	var checked int
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G304 -- repo-relative .go files discovered by this walk
		if err != nil {
			return err
		}
		for _, m := range citationRe.FindAllStringSubmatch(string(data), -1) {
			num := m[1]
			checked++
			if len(owners[num]) == 0 {
				t.Errorf("%s cites ADR-%s, which no document in docs/adr/ or docs/support/rfc/ claims "+
					"in its title — either the decision was renumbered and this citation was left "+
					"behind (update it to the number the document carries now), or the ADR was never "+
					"written (drop the citation rather than point a reader at nothing)", path, num)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree for ADR citations: %v", err)
	}
	if checked == 0 {
		t.Fatal("wall inspected no ADR citations — the scan stopped matching non-test Go source")
	}
}

// TestFirstMarkdownHeading_NoLineCountCap pins the fix for a Codex review finding on
// the PR that introduced this file: an earlier version capped its scan at the first 8
// physical lines, so a document with 8+ lines of front matter before its real heading
// was silently treated as unnumbered and dropped out of the collision check entirely —
// exactly the kind of gap that would let a fifth ADR-numbering collision (see T-16,
// T-46, T-47, T-48) slip past a gate built specifically to catch it.
func TestFirstMarkdownHeading_NoLineCountCap(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 20; i++ {
		sb.WriteString("> front matter line that is not a heading\n")
	}
	sb.WriteString("# ADR-0099: heading pushed past any small fixed line cap\n")
	sb.WriteString("\nbody text\n")

	got := firstMarkdownHeading([]byte(sb.String()))
	want := "# ADR-0099: heading pushed past any small fixed line cap"
	if got != want {
		t.Fatalf("firstMarkdownHeading with 21 lines of front matter = %q, want %q", got, want)
	}
}

// firstMarkdownHeading returns the first line of data (trimmed) that starts with
// "#", scanning the WHOLE file — no line-count cap, so front matter of any length
// before the real title is followed through rather than silently truncated past.
func firstMarkdownHeading(data []byte) string {
	start := 0
	for i := 0; i <= len(data); i++ {
		if i == len(data) || data[i] == '\n' {
			line := strings.TrimSpace(string(data[start:i]))
			if strings.HasPrefix(line, "#") {
				return line
			}
			start = i + 1
		}
	}
	return ""
}
