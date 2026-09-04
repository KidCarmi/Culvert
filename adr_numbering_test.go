package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Anti-drift wall for architecture-decision-record numbering.
//
// docs/adr/ and docs/support/rfc/ share one numbering namespace: both use a
// `# ADR-NNNN` self-title (the RFC track has never used its own prefix), and
// nothing before this test enforced that the number is unique across the two
// directories. Two independent PR streams computing "the next free number" by
// grepping the tree at merge time have collided on the SAME number four times
// (docs/engineering/TERMINOLOGY-GOVERNANCE-REVIEW-2026-{07-19,08-24,08-25,09-04}.md
// — docs/adr/'s own 0008-0011 range held two independent decision tracks, then
// ADR-0018, then ADR-0032, then ADR-0034), each time discovered only by a later
// manual terminology-governance pass reading the whole tree, and each time
// re-numbering whichever document
// hadn't yet reached ACCEPTED status. A just-freed number left behind by one of
// those fixes has proven exactly as attractive to the next concurrent stream as
// a genuinely fresh one, so "fix it after the fact" was no longer keeping pace.
// This test is the CI-enforced mechanism the 08-25 review recommended in lieu
// of a fifth manual fix: it fails the build the moment a PR introduces a
// duplicate `# ADR-NNNN` header, before the collision can land on main at all.
func TestADRNumbering_NoDuplicateAcrossADRAndRFCTracks(t *testing.T) {
	headerRE := regexp.MustCompile(`^#\s+ADR-(\d+)\b`)

	type claim struct {
		path  string
		title string
	}
	byNumber := map[string][]claim{}

	for _, dir := range []string{"docs/adr", "docs/support/rfc"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			// The header lives in the first few lines; docs/support/rfc/
			// files carry a "PROPOSED — NOT ADOPTED" banner before it.
			lines := strings.Split(string(data), "\n")
			for i, line := range lines {
				if i > 10 {
					break
				}
				if m := headerRE.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
					byNumber[m[1]] = append(byNumber[m[1]], claim{path: path, title: strings.TrimSpace(line)})
					break
				}
			}
		}
	}

	var numbers []string
	for n := range byNumber {
		numbers = append(numbers, n)
	}
	sort.Strings(numbers)

	for _, n := range numbers {
		claims := byNumber[n]
		if len(claims) <= 1 {
			continue
		}
		sort.Slice(claims, func(i, j int) bool { return claims[i].path < claims[j].path })
		var b strings.Builder
		b.WriteString("ADR-" + n + " is claimed by more than one document:\n")
		for _, c := range claims {
			b.WriteString("  " + c.path + ": " + c.title + "\n")
		}
		b.WriteString("Renumber whichever document has not reached ACCEPTED status to the next number that is free across BOTH docs/adr/ and docs/support/rfc/, and update its downstream citations.")
		t.Error(b.String())
	}
}
