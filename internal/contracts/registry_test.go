package contracts

import (
	"os"
	"testing"
)

// TestRegistry_IsSoundAgainstThisTree is the gate that runs on every change:
// the checked-in registry must parse, and every enforced contract must name
// code that exists and tests that exist and run. It lives in the ordinary test
// suite so no separate workflow is needed for it to be enforced.
func TestRegistry_IsSoundAgainstThisTree(t *testing.T) {
	const root = "../.."
	data, err := os.ReadFile(root + "/contracts/registry.yaml")
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	r, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Contracts) == 0 {
		t.Fatal("registry has no contracts")
	}
	for _, problem := range Validate(r, os.DirFS(root)) {
		t.Error(problem)
	}
}
