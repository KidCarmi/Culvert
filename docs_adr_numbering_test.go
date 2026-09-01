package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestDocsADRNumberingIsUnique guards against the recurring "ADR-number
// collision" defect class documented in docs/engineering/
// TERMINOLOGY-GOVERNANCE-REVIEW-*.md (T-16, T-46, T-47, T-48): two
// independent PR streams each compute "the next free number" by grepping the
// tree at the moment they need one, with no reservation mechanism, so two
// branches can claim the identical `# ADR-NNNN` number. Every prior
// occurrence was caught only by a manual documentation review, sometimes
// within a day of the previous fix creating the just-freed slot. This test
// makes the check mechanical and CI-enforced instead of review-cadence-
// dependent — the fix the reviews have recommended after each recurrence.
//
// It scans every Markdown file's own `# ADR-NNNN` self-declaration header
// (docs/adr/ for accepted architecture decisions; docs/support/rfc/ also
// self-titles this way for not-yet-adopted proposals sharing the same
// numbering space, per the T-16/T-46/T-47/T-48 history) and fails if any
// four-digit number is claimed by more than one file. Only the header line
// counts — a body citation of another decision's number (e.g. "Relates to
// ADR-0016") is prose, not a self-declaration, and must not be mistaken for
// one.
func TestDocsADRNumberingIsUnique(t *testing.T) {
	headerRE := regexp.MustCompile(`^#\s*ADR-([0-9]{4})\b`)

	claimants := map[string][]string{} // ADR number -> declaring file paths
	err := filepath.WalkDir("docs", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			m := headerRE.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			num := m[1]
			claimants[num] = append(claimants[num], path)
			break // only the file's own declared title counts
		}
		return scanner.Err()
	})
	if err != nil {
		t.Fatalf("walking docs/ for ADR headers: %v", err)
	}

	var numbers []string
	for num := range claimants {
		numbers = append(numbers, num)
	}
	sort.Strings(numbers)

	for _, num := range numbers {
		files := claimants[num]
		if len(files) <= 1 {
			continue
		}
		sort.Strings(files)
		t.Errorf("ADR-%s is claimed as a self-declared header by %d files (must be exactly one):\n  %s\n"+
			"Renumber all but one file to the next number confirmed clean against every "+
			"`# ADR-NNNN` header in the repository (see docs/engineering/TERMINOLOGY-GOVERNANCE-REVIEW-*.md "+
			"for the established precedent: the established/ACCEPTED decision keeps its number, "+
			"the not-yet-adopted document is renumbered).",
			num, len(files), strings.Join(files, "\n  "))
	}
}

// TestDocsADRNumberingHeaderFormat is a light sanity check that the scanner
// above is actually finding headers, so a future Markdown reformat that
// silently breaks the `# ADR-NNNN` convention doesn't make
// TestDocsADRNumberingIsUnique pass vacuously.
func TestDocsADRNumberingHeaderFormat(t *testing.T) {
	headerRE := regexp.MustCompile(`^#\s*ADR-([0-9]{4})\b`)
	count := 0
	err := filepath.WalkDir("docs", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		f, ferr := os.Open(path)
		if ferr != nil {
			return ferr
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if headerRE.MatchString(strings.TrimSpace(scanner.Text())) {
				count++
				break
			}
		}
		return scanner.Err()
	})
	if err != nil {
		t.Fatalf("walking docs/ for ADR headers: %v", err)
	}
	const minExpected = 30 // well below the current count; guards against a scanner regression, not a headcount
	if count < minExpected {
		t.Fatalf("found only %d files with a `# ADR-NNNN` header, expected at least %d — "+
			"the header convention may have changed and TestDocsADRNumberingIsUnique would pass vacuously",
			count, minExpected)
	}
}
