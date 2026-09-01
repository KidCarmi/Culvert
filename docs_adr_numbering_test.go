package main

import (
	"bufio"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// adrHeaderRE matches a Markdown file's own self-declared ADR title (a
// level-1 heading). A body citation of another decision's number (e.g.
// "Relates to ADR-0016") never starts a line with "# ", so it is never
// mistaken for a self-declaration.
var adrHeaderRE = regexp.MustCompile(`^#\s*ADR-(\d{4})\b`)

// scanADRHeaders walks docs/ through a root-scoped, symlink-TOCTOU-safe
// os.Root (rather than raw path strings re-joined after WalkDir hands them
// back — the gosec G122 concern) and returns, for every Markdown file, the
// ADR number it self-declares in its own first matching heading (if any).
// claimants maps an ADR number to every file that declares it; fileCount is
// the number of files with at least one such heading.
func scanADRHeaders(t *testing.T) (claimants map[string][]string, fileCount int) {
	t.Helper()

	root, err := os.OpenRoot("docs")
	if err != nil {
		t.Fatalf("opening docs/ as a scoped root: %v", err)
	}
	defer root.Close()

	claimants = map[string][]string{}
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		f, ferr := root.Open(path)
		if ferr != nil {
			return ferr
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			m := adrHeaderRE.FindStringSubmatch(strings.TrimSpace(scanner.Text()))
			if m == nil {
				continue
			}
			num := m[1]
			claimants[num] = append(claimants[num], "docs/"+path)
			fileCount++
			break // only the file's own declared title counts
		}
		return scanner.Err()
	})
	if err != nil {
		t.Fatalf("walking docs/ for ADR headers: %v", err)
	}
	return claimants, fileCount
}

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
// four-digit number is claimed by more than one file.
func TestDocsADRNumberingIsUnique(t *testing.T) {
	claimants, _ := scanADRHeaders(t)

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
	_, fileCount := scanADRHeaders(t)
	const minExpected = 30 // well below the current count; guards against a scanner regression, not a headcount
	if fileCount < minExpected {
		t.Fatalf("found only %d files with a `# ADR-NNNN` header, expected at least %d — "+
			"the header convention may have changed and TestDocsADRNumberingIsUnique would pass vacuously",
			fileCount, minExpected)
	}
}
