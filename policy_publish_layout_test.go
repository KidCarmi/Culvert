package main

import (
	"testing"
	"unsafe"
)

// Structural regression gate for the publication layout contract in
// sortLocked. It is structural rather than timed deliberately: the property
// being pinned is worth exactly ONE allocation per rule out of the ~3 a
// definition clone costs, so a wall-clock or allocation-count bound would have
// a thin margin and would flake or rot. The assertion below has no margin at
// all — the published definitions either are carved from one array or they are
// not.
//
// The performance rationale, and the measurements that justify it, are on
// sortLocked itself.

// ruleAddr reads a published definition's address for the layout assertion
// below. The unsafe conversion is a read-only address comparison in a test: it
// dereferences nothing, retains nothing, and converts nothing back to a
// pointer. It is also the only way to express "these definitions are one
// array", which is the whole property this gate exists to pin.
func ruleAddr(r *PolicyRule) uintptr {
	return uintptr(unsafe.Pointer(r)) //nolint:gosec // G103: test-only address read for the publication-layout gate; no dereference, no retention
}

// TestPolicyPublish_RevisionIsOneContiguousArray asserts that every definition
// in a published revision sits in one backing array, at ascending addresses
// with a one-struct stride, in the same order the evaluation scan walks them.
func TestPolicyPublish_RevisionIsOneContiguousArray(t *testing.T) {
	const n = 64
	ps := &PolicyStore{}
	ps.ReplaceAll(buildPublishInput(n))

	ps.mu.RLock()
	rules := ps.rules
	ps.mu.RUnlock()

	if len(rules) != n {
		t.Fatalf("published %d rules, want %d", len(rules), n)
	}
	stride := unsafe.Sizeof(PolicyRule{})
	base := ruleAddr(rules[0])
	for i, rule := range rules {
		got := ruleAddr(rule)
		want := base + uintptr(i)*stride
		if got != want {
			t.Fatalf("published definition %d is not at its slot in the revision's backing array:\n"+
				"  address %#x, want %#x (base %#x + %d * %d)\n"+
				"sortLocked must clone the revision into ONE []PolicyRule in publication order; a\n"+
				"per-rule allocation costs one extra allocation per rule on every policy edit,\n"+
				"config-version restore and cluster config sync — all of which hold the writer lock\n"+
				"that every policy evaluation needs.", i, got, want, base, i, stride)
		}
	}
}

// TestPolicyPublish_OrderingIsUnchangedByTheLayout is the behavioral control
// for the same change: the revision is ordered BEFORE the clone now, so pin
// that publication still yields ascending priority — including for the
// out-of-order input the previous shape sorted after cloning.
func TestPolicyPublish_OrderingIsUnchangedByTheLayout(t *testing.T) {
	in := []PolicyRule{
		{Priority: 30, Name: "third", DestFQDN: "c.example.invalid", Action: ActionAllow},
		{Priority: 10, Name: "first", DestFQDN: "a.example.invalid", Action: ActionDrop},
		{Priority: 20, Name: "second", DestFQDN: "b.example.invalid", Action: ActionAllow},
	}
	ps := &PolicyStore{}
	ps.ReplaceAll(in)

	got := ps.List()
	want := []string{"first", "second", "third"}
	if len(got) != len(want) {
		t.Fatalf("published %d rules, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Name != want[i] {
			t.Fatalf("rule %d is %q, want %q (publication must stay in ascending priority)", i, got[i].Name, want[i])
		}
		if got[i].Priority != (i+1)*10 {
			t.Fatalf("rule %d has priority %d, want %d", i, got[i].Priority, (i+1)*10)
		}
	}

	// The precompute must still land on the published definitions, not on
	// pre-clone copies: normFQDN is what the hot path reads instead of
	// re-normalizing DestFQDN per request.
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	for i, rule := range ps.rules {
		if rule.normFQDN == "" {
			t.Fatalf("published definition %d (%q) carries no precomputed normFQDN", i, rule.Name)
		}
		if rule.counters == nil {
			t.Fatalf("published definition %d (%q) carries no counters cell", i, rule.Name)
		}
	}
}
