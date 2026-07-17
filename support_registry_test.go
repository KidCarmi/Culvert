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
	// M3 runtime capture (L2)
	"runtime",
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
// invariant across the FULL roster: every collector at L1 must ACTUALLY EMIT a
// section (ok/partial + bytes) and that section must be PUBLIC or INTERNAL. It
// deliberately does NOT accept an empty class_max: the runner pre-seeds a failed/
// skipped section with class_max=PUBLIC and no payload, so accepting "" would let
// a silently-failed or dropped L1 collector pass — defeating the proof.
func TestM2Wall_EverySectionWithinCeiling(t *testing.T) {
	res := buildRealBundle(t) // L1 standard bundle
	byID := map[string]support.SectionEntry{}
	for _, s := range res.Manifest.Sections {
		byID[s.ID] = s
	}
	minLevel := map[string]support.DebugLevel{}
	for _, c := range support.Collectors() {
		minLevel[c.Meta().ID] = c.Meta().MinLevel
	}
	for _, id := range m2CollectorRoster {
		s, ok := byID[id]
		if !ok {
			t.Fatalf("roster collector %q produced no manifest section", id)
		}
		// A collector whose MinLevel is above L1 is legitimately level-gated in the
		// standard bundle — it must appear as a skipped entry, wired but not run.
		if minLevel[id] > support.L1 {
			if s.Status != support.StatusSkipped {
				t.Fatalf("L%d collector %q status=%q (want skipped in an L1 bundle)", minLevel[id], id, s.Status)
			}
			continue
		}
		// Every L0/L1 collector must actually run and write bytes — not be silently
		// skipped/failed/unavailable or empty.
		if s.Status != support.StatusOK && s.Status != support.StatusPartial {
			t.Fatalf("roster collector %q status=%q (want ok/partial) — silently absent from the bundle", id, s.Status)
		}
		if s.SHA256 == "" || s.SizeBytes == 0 {
			t.Fatalf("roster collector %q emitted no section payload (sha=%q size=%d)", id, s.SHA256, s.SizeBytes)
		}
		switch s.ClassMax {
		case "PUBLIC", "INTERNAL":
			// within the shareable ceiling
		default:
			t.Fatalf("section %q class_max=%q not within the INTERNAL ceiling", id, s.ClassMax)
		}
	}
}
