package main

// docs_adr_numbering_test.go — guards against duplicate architecture-decision-
// record numbers (docs/adr/ ACCEPTED decisions and the docs/support/rfc/
// proposed-track documents that also self-title as "# ADR-NNNN").
//
// This is a process-level fix recommended by the terminology-governance
// routine after the identical defect recurred FOUR times (T-16: 0008-0011 vs
// the main sequence; T-46: first 0018 collision; T-47: 0032 collision, fixed
// within a day of T-46; a fourth 0034 collision, fixed alongside this test).
// Root cause every time: two independent PR streams each computed "the next
// free number" by grepping the tree at merge time, with nothing to stop two
// branches from claiming the same number concurrently. This test is the
// mechanical guard that stops a fifth recurrence — it fails CI the moment a
// PR introduces a duplicate "# ADR-NNNN" header, rather than waiting for the
// next terminology-governance pass to notice.

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

var adrHeaderPattern = regexp.MustCompile(`^#\s*ADR-(\d{4})\b`)

// adrHeaderNumber scans a markdown file for its "# ADR-NNNN" self-declared
// number. Returns "" if the file carries no such header (e.g. ADR-0001's own
// process document, or a non-ADR file that happens to live alongside them).
func adrHeaderNumber(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := adrHeaderPattern.FindStringSubmatch(sc.Text()); m != nil {
			return m[1]
		}
	}
	return ""
}

func TestADRNumbersAreUnique(t *testing.T) {
	dirs := []string{"docs/adr", "docs/support/rfc"}
	byNumber := map[string][]string{}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".md" {
				continue
			}
			path := filepath.Join(dir, e.Name())
			num := adrHeaderNumber(t, path)
			if num == "" {
				continue
			}
			byNumber[num] = append(byNumber[num], path)
		}
	}

	var numbers []string
	for num := range byNumber {
		numbers = append(numbers, num)
	}
	sort.Strings(numbers)

	for _, num := range numbers {
		files := byNumber[num]
		if len(files) > 1 {
			sort.Strings(files)
			t.Errorf("ADR-%s is claimed by %d files, must be exactly 1: %v — "+
				"give one of them the next number confirmed clean against every "+
				"\"# ADR-NNNN\" header in the repository (see docs/engineering/"+
				"TERMINOLOGY-GOVERNANCE-REVIEW-*.md for the established precedent: "+
				"the ACCEPTED docs/adr/ decision keeps the number, a still-"+
				"PROPOSED docs/support/rfc/ document is renumbered)", num, len(files), files)
		}
	}
}
