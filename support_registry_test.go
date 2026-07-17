package main

import (
	"sort"
	"testing"

	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/support"
)

// The M2 "three parity walls" — all BLOCKING via `go test ./...` in the
// pr-fast-gate -race run (no separate CI job; a failure here fails the gate):
//
//  1. data_surfaces (data_surfaces_test.go)      — every COLLECTED struct field
//     carries an explicit redact:"..." DataClass (fail-closed classification).
//  2. secret-leak (support_test.go TestNoSecretInBundle) — a real bundle built
//     over the full registered roster leaks no credential SHAPE and records
//     fail_closed, with every section class_max <= INTERNAL.
//  3. collector-registry (this file)             — every registered collector
//     obeys its Meta contract and the roster is LOCKED, so a collector cannot be
//     added or removed (or its ceiling loosened) without a deliberate,
//     reviewed change. Mirrors the uiRoutes/config-surface count-lock discipline.

// m2CollectorRoster is the locked set of registered collector IDs. Adding or
// removing a collector is a deliberate change: update this list AND ensure the
// collector's section struct is in data_surfaces_test.go collectedStructs.
var m2CollectorRoster = []string{
	// M1 core + health + recovery
	"product", "diagnostics", "health", "readiness", "crash",
	// M1 reused-accessor
	"config", "policy", "audit", "metrics", "logs",
	// M2 breadth (PR4)
	"tls", "config_versions", "governance",
	// M2 breadth (PR5)
	"upstream", "cdr", "scan",
}

func TestM2Wall_RosterLocked(t *testing.T) {
	got := make([]string, 0)
	for _, c := range support.Collectors() {
		got = append(got, c.Meta().ID)
	}
	sort.Strings(got)
	want := append([]string(nil), m2CollectorRoster...)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("collector roster changed: have %v (%d), locked list %v (%d) — update m2CollectorRoster + data_surfaces collectedStructs",
			got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("collector roster mismatch at %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestM2Wall_CollectorContract(t *testing.T) {
	seenPath := map[string]string{}
	for _, c := range support.Collectors() {
		m := c.Meta()
		t.Run(m.ID, func(t *testing.T) {
			if m.ID == "" {
				t.Fatal("empty collector ID")
			}
			// snake_case id, used verbatim as the section id.
			for _, r := range m.ID {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
					t.Fatalf("collector ID %q is not snake_case", m.ID)
				}
			}
			if want := "sections/" + m.ID + ".json"; m.Path != want {
				t.Fatalf("collector %q path=%q want %q (convention)", m.ID, m.Path, want)
			}
			if prev, dup := seenPath[m.Path]; dup {
				t.Fatalf("duplicate section path %q (%q and %q)", m.Path, prev, m.ID)
			}
			seenPath[m.Path] = m.ID
			// The asserted ceiling must never exceed the shareable ceiling — a
			// section that could exceed INTERNAL would be dropped by the runner,
			// so declaring a higher ceiling is a contract error.
			if m.MaxClass > redaction.ShareableCeiling {
				t.Fatalf("collector %q MaxClass=%v exceeds shareable ceiling %v", m.ID, m.MaxClass, redaction.ShareableCeiling)
			}
			if m.ByteBudget <= 0 {
				t.Fatalf("collector %q has non-positive ByteBudget %d", m.ID, m.ByteBudget)
			}
			if m.Timeout <= 0 {
				t.Fatalf("collector %q has non-positive Timeout %v", m.ID, m.Timeout)
			}
			if m.SchemaVersion < 1 {
				t.Fatalf("collector %q has SchemaVersion %d (< 1)", m.ID, m.SchemaVersion)
			}
			if m.MinLevel < support.L0 || m.MinLevel > support.L4 {
				t.Fatalf("collector %q MinLevel %d out of range", m.ID, m.MinLevel)
			}
		})
	}
}

// TestM2Wall_EverySectionWithinCeiling is the runtime proof of wall #2's class
// invariant across the FULL roster: a real standard bundle's every section is
// PUBLIC or INTERNAL (never SENSITIVE/SECRET), by construction of the redactor.
func TestM2Wall_EverySectionWithinCeiling(t *testing.T) {
	res := buildRealBundle(t)
	if len(res.Manifest.Sections) < len(m2CollectorRoster) {
		t.Fatalf("bundle has %d sections, roster has %d — a collector silently dropped?",
			len(res.Manifest.Sections), len(m2CollectorRoster))
	}
	for _, s := range res.Manifest.Sections {
		switch s.ClassMax {
		case "", "PUBLIC", "INTERNAL":
			// "" = skipped/failed section (no bytes written) — acceptable.
		default:
			t.Fatalf("section %q class_max=%q exceeds INTERNAL (redaction ceiling breach)", s.ID, s.ClassMax)
		}
	}
}
