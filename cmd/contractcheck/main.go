// Command contractcheck checks the product contracts registry.
//
//	contractcheck validate
//	    Check contracts/registry.yaml against the working tree.
//
//	contractcheck impact -base <rev>
//	    Compare the registry at <rev> with the working tree and the files
//	    changed since <rev>. Exit 1 when a contract was weakened without a new
//	    amended/retired record. Recorded contract changes and edits to
//	    protected paths are listed, not refused: the gate is fully automated.
//
// Run from the repository root. See docs/engineering/PRODUCT-CONTRACTS.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/KidCarmi/Culvert/internal/contracts"
)

const registryPath = "contracts/registry.yaml"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: contractcheck validate | impact -base <rev> [...]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "validate":
		err = runValidate()
	case "impact":
		err = runImpact(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "contractcheck:", err)
		os.Exit(1)
	}
}

func loadHead() (*contracts.Registry, error) {
	data, err := os.ReadFile(registryPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", registryPath, err)
	}
	return contracts.Parse(data)
}

func runValidate() error {
	head, err := loadHead()
	if err != nil {
		return err
	}
	problems := contracts.Validate(head, os.DirFS("."))
	for _, p := range problems {
		fmt.Println("PROBLEM", p)
	}
	if len(problems) > 0 {
		return fmt.Errorf("%d problem(s) in %s", len(problems), registryPath)
	}
	fmt.Printf("%s: %d contract(s) sound\n", registryPath, len(head.Contracts))
	return nil
}

func runImpact(args []string) error {
	fs := flag.NewFlagSet("impact", flag.ContinueOnError)
	base := fs.String("base", "", "base revision to compare against (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *base == "" {
		return errors.New("impact: -base is required")
	}
	head, err := loadHead()
	if err != nil {
		return err
	}
	baseReg, err := loadBase(*base)
	if err != nil {
		return err
	}
	changed, err := changedFiles(*base)
	if err != nil {
		return err
	}
	im := contracts.Assess(baseReg, head, os.DirFS("."), changed)

	if baseReg == nil {
		fmt.Println("The base revision has no registry: this change introduces it. Nothing to compare.")
		return nil
	}
	if len(im.Touched) > 0 {
		fmt.Println("Contracts whose code this change touches (review these; their tests still stand):")
		for _, id := range im.Touched {
			fmt.Println("  -", id)
		}
	} else {
		fmt.Println("No contract code paths are touched by this change.")
	}
	for _, w := range im.Weakened {
		fmt.Println("WEAKENED", w)
	}
	if len(im.Weakened) > 0 {
		return fmt.Errorf("%d contract(s) weakened without a record. If the change is intended, add an "+
			"`amended` or `retired` entry with a reason to %s", len(im.Weakened), registryPath)
	}
	for _, n := range im.Recorded {
		fmt.Println("RECORDED", n)
	}
	return nil
}

// loadBase returns the registry at rev, or nil when rev has none. The contract
// list and protected paths are taken from here, so a change cannot hide a
// weakening by editing the registry in the same change.
func loadBase(rev string) (*contracts.Registry, error) {
	out, err := exec.CommandContext(context.Background(), "git", "show", rev+":"+registryPath).Output() // #nosec G204 -- fixed binary; rev is the CI-resolved base
	if err != nil {
		if _, lsErr := exec.CommandContext(context.Background(), "git", "cat-file", "-e", rev+"^{commit}").Output(); lsErr != nil { // #nosec G204 -- as above
			return nil, fmt.Errorf("base revision %q is not a resolvable commit: %w", rev, lsErr)
		}
		return nil, nil //nolint:nilnil // a base without a registry is a real, distinct state
	}
	return contracts.Parse(out)
}

// changedFiles lists every path that differs between rev and the working tree.
//
// Two flags are load-bearing for the protected-path check:
//
//   - --no-renames: with rename detection (git's default) a moved file is
//     reported under its NEW path only, so moving the gate workflow out of a
//     protected path would not name the protected path.
//     Without it a move is a delete of the old path plus an add of the new one.
//   - -z: without it git C-quotes a path holding non-ASCII bytes
//     ("dir/z\303\251.go"), which no longer matches its protected glob. NUL
//     separation prints every path verbatim, spaces included.
func changedFiles(rev string) ([]string, error) {
	out, err := exec.CommandContext(context.Background(), "git", "diff", "--name-only", "--no-renames", "-z", rev, "--").Output() // #nosec G204 -- fixed binary; rev is the CI-resolved base
	if err != nil {
		return nil, fmt.Errorf("git diff %s: %w", rev, err)
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}
