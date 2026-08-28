package urlcat

// urlcat_bulk_cap_test.go — Blocker C engine seam (2D-B final correction
// §§9–10): ValidateEntries is the canonical full-set per-category cap check
// and ReplaceAllChecked is the checked bulk installer — whole-candidate
// reject, never truncation, never a partial install.

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func capHosts(n int, tag string) []string {
	hosts := make([]string, n)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%05d.%s.example", i, tag)
	}
	return hosts
}

func TestValidateEntries_RejectsOverCapAndNamesTheCategory(t *testing.T) {
	err := ValidateEntries([]Entry{
		{Name: "fine", Hosts: capHosts(3, "fine")},
		{Name: "flood", Hosts: capHosts(MaxHostsPerCategory+1, "flood")},
	})
	if !errors.Is(err, ErrTooManyHosts) {
		t.Fatalf("want ErrTooManyHosts, got %v", err)
	}
	if got := err.Error(); !strings.Contains(got, `"flood"`) {
		t.Fatalf("error must name the offending category; got %q", got)
	}
}

func TestValidateEntries_AcceptsExactlyAtCap(t *testing.T) {
	if err := ValidateEntries([]Entry{{Name: "edge", Hosts: capHosts(MaxHostsPerCategory, "edge")}}); err != nil {
		t.Fatalf("exactly-at-cap must be accepted: %v", err)
	}
}

func TestReplaceAllChecked_RejectsWholeCandidateAndKeepsServing(t *testing.T) {
	s := New([]*Entry{{Name: "keep", Hosts: []string{"keep.example.com"}}})
	before := s.ContentFingerprint()

	err := s.ReplaceAllChecked([]Entry{
		{Name: "fine", Hosts: []string{"fine.example.com"}},
		{Name: "flood", Hosts: capHosts(MaxHostsPerCategory+1, "flood")},
	})
	if !errors.Is(err, ErrTooManyHosts) {
		t.Fatalf("want ErrTooManyHosts, got %v", err)
	}
	all := s.All()
	if len(all) != 1 || all[0].Name != "keep" {
		t.Fatalf("a rejected candidate must change NOTHING (no partial install of the fine category); got %d entries", len(all))
	}
	if got := s.ContentFingerprint(); got != before {
		t.Fatalf("a rejected candidate must not move the semantic revision: %q -> %q", before, got)
	}
}

func TestReplaceAllChecked_InstallsValidCandidate(t *testing.T) {
	s := New(nil)
	if err := s.ReplaceAllChecked([]Entry{{Name: "a", Hosts: capHosts(2, "a")}}); err != nil {
		t.Fatalf("valid candidate: %v", err)
	}
	if all := s.All(); len(all) != 1 || all[0].Name != "a" {
		t.Fatalf("valid candidate must install; got %+v", all)
	}
}
