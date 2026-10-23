package main

// Equivalence proof for the generic decEnumOr against the interface shape it
// replaced (see the contract comment above decEnumOr in
// decryption_observability.go, and the cost measured in
// decryption_observability_bench_test.go).
//
// The change is a COST change, not a behaviour change: the same two methods run
// in the same order against the same values, only without boxing them into an
// interface first. These tests exist so that claim is pinned rather than
// asserted — a future edit that "simplifies" the constraint, reorders the
// Valid/String calls, or swaps a fallback would fail here rather than silently
// emit an out-of-vocabulary token onto a SIEM record.
//
// decEnumOrLegacy and legacyOutcomeToBlock (decryption_observability_bench_test.go)
// are the ORACLE: a verbatim copy of the pre-change bodies. They are also the
// benchmark baseline, so one frozen copy serves both and cannot drift from what
// the benchmark compares against.

import (
	"reflect"
	"testing"

	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// TestDecEnumOr_MatchesInterfaceProjection walks every member of every closed
// enum set, plus the zero value and a cast non-member, and requires the generic
// and the interface shape to agree exactly.
//
// The zero value and the cast non-member are the cases that matter: they are the
// ones that exercise the FALLBACK arm, which is the whole point of the helper
// (an under-populated outcome must coerce to a sentinel, never reach a record as
// "" or a raw token). A test over valid members alone would pass against a
// decEnumOr that had lost its fallback entirely.
func TestDecEnumOr_MatchesInterfaceProjection(t *testing.T) {
	// Each closure covers one concrete type: the generic requires v and fallback
	// to share a type, so the comparison cannot be written generically over a
	// []decEnum without reintroducing the boxing under test.
	checks := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"Outcome", func(t *testing.T) {
			vals := append([]decryptobs.Outcome{"", "not-a-member"}, decryptobs.AllOutcomes...)
			for _, v := range vals {
				assertSame(t, "Outcome", string(v),
					decEnumOr(v, decryptobs.OutcomeNotDecrypted),
					decEnumOrLegacy(v, decryptobs.OutcomeNotDecrypted))
			}
		}},
		{"DecisionSource", func(t *testing.T) {
			vals := append([]decryptobs.DecisionSource{"", "not-a-member"}, decryptobs.AllDecisionSources...)
			for _, v := range vals {
				assertSame(t, "DecisionSource", string(v),
					decEnumOr(v, decryptobs.DecisionNonTLSFallback),
					decEnumOrLegacy(v, decryptobs.DecisionNonTLSFallback))
			}
		}},
		{"TLSVersion", func(t *testing.T) {
			vals := append([]decryptobs.TLSVersion{"", "not-a-member"}, decryptobs.AllTLSVersions...)
			for _, v := range vals {
				assertSame(t, "TLSVersion", string(v),
					decEnumOr(v, decryptobs.TLSVersionUnknown),
					decEnumOrLegacy(v, decryptobs.TLSVersionUnknown))
			}
		}},
		{"ALPN", func(t *testing.T) {
			// ALPN's empty string is a VALID member, so it takes the v arm, not the
			// fallback arm — the one enum where "" must NOT coerce.
			vals := append([]decryptobs.ALPN{"", "not-a-member"}, decryptobs.AllALPN...)
			for _, v := range vals {
				assertSame(t, "ALPN", string(v),
					decEnumOr(v, decryptobs.ALPNNone),
					decEnumOrLegacy(v, decryptobs.ALPNNone))
			}
		}},
		{"CertVerify", func(t *testing.T) {
			vals := append([]decryptobs.CertVerify{"", "not-a-member"}, decryptobs.AllCertVerify...)
			for _, v := range vals {
				assertSame(t, "CertVerify", string(v),
					decEnumOr(v, decryptobs.CertVerifyNotChecked),
					decEnumOrLegacy(v, decryptobs.CertVerifyNotChecked))
			}
		}},
		{"FailStage", func(t *testing.T) {
			vals := append([]decryptobs.FailStage{"", "not-a-member"}, decryptobs.AllFailStages...)
			for _, v := range vals {
				assertSame(t, "FailStage", string(v),
					decEnumOr(v, decryptobs.FailStageNone),
					decEnumOrLegacy(v, decryptobs.FailStageNone))
			}
		}},
		{"FailCategory", func(t *testing.T) {
			vals := append([]decryptobs.FailCategory{"", "not-a-member"}, decryptobs.AllFailCategories...)
			for _, v := range vals {
				assertSame(t, "FailCategory", string(v),
					decEnumOr(v, decryptobs.FailCategoryNone),
					decEnumOrLegacy(v, decryptobs.FailCategoryNone))
			}
		}},
	}
	for _, c := range checks {
		t.Run(c.name, c.run)
	}
}

func assertSame(t *testing.T, typ, in, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("decEnumOr[%s](%q) = %q, interface shape returns %q — the generic rewrite "+
			"changed the projected wire value; this helper is the ADR-0011 bounded-vocabulary "+
			"guard, so a divergence puts an out-of-vocabulary token on a SIEM record", typ, in, got, want)
	}
}

// TestToBlock_MatchesInterfaceProjection is the whole-record differential: the
// production toBlock against a verbatim pre-change copy, over the two fixtures
// the real constructors produce plus the empty outcome.
//
// The per-helper test above proves each field's projection; this one proves the
// RECORD — that every enum field is still routed through the helper with the
// SAME fallback. A pairing mistake (Outcome coerced to a FailStage sentinel) is
// invisible to the per-helper test and is exactly what the single type parameter
// now makes a compile error, so this is the regression test for the property the
// type system took over.
func TestToBlock_MatchesInterfaceProjection(t *testing.T) {
	cases := []struct {
		name string
		o    DecryptionOutcome
	}{
		{"inspected", decBenchInspected},
		{"bypassed", decBenchBypassed},
		// The empty outcome is the under-populated shape the helper exists for:
		// every field must come back as its sentinel, and both shapes must agree
		// on which sentinel.
		{"empty", DecryptionOutcome{}},
		// A cast non-member in every enum slot at once — the "future caller
		// under-populates the struct" case the contract comment names.
		{"all-invalid", DecryptionOutcome{
			Outcome:        decryptobs.Outcome("bogus"),
			DecisionSource: decryptobs.DecisionSource("bogus"),
			TLSVersion:     decryptobs.TLSVersion("bogus"),
			ALPN:           decryptobs.ALPN("bogus"),
			CertVerify:     decryptobs.CertVerify("bogus"),
			FailStage:      decryptobs.FailStage("bogus"),
			FailCategory:   decryptobs.FailCategory("bogus"),
			Host:           "files.example.com",
			SNI:            "files.example.com",
		}},
	}
	for _, tc := range cases {
		for _, redact := range []bool{false, true} {
			got := tc.o.toBlock(redact)
			want := legacyOutcomeToBlock(tc.o, redact)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("toBlock(%s, redact=%v) diverged from the pre-change projection:\n got  %+v\n want %+v",
					tc.name, redact, *got, *want)
			}
		}
	}
}

// TestToBlock_StillCoercesOutOfVocabularyValues is the CONTROL.
//
// Both differentials above compare two implementations against each other, so
// they would both pass if the coercion were deleted from BOTH — the oracle is a
// copy, and a copy of a broken function is a consistent broken function. This
// test asserts the PROPERTY directly against the production path: a cast
// non-member must not survive onto the record.
func TestToBlock_StillCoercesOutOfVocabularyValues(t *testing.T) {
	b := DecryptionOutcome{
		Outcome:        decryptobs.Outcome("bogus"),
		DecisionSource: decryptobs.DecisionSource("bogus"),
		TLSVersion:     decryptobs.TLSVersion("bogus"),
		CertVerify:     decryptobs.CertVerify("bogus"),
		FailStage:      decryptobs.FailStage("bogus"),
		FailCategory:   decryptobs.FailCategory("bogus"),
	}.toBlock(false)

	for name, got := range map[string]string{
		"outcome":        b.Outcome,
		"decisionSource": b.DecisionSource,
		"tlsVersion":     b.TLSVersion,
		"certVerify":     b.CertVerify,
		"failStage":      b.FailStage,
		"failCategory":   b.FailCategory,
	} {
		if got == "bogus" {
			t.Errorf("toBlock passed the out-of-vocabulary %s through verbatim (%q) — the "+
				"ADR-0011 bounded-vocabulary coercion is gone, not merely faster", name, got)
		}
		if got == "" {
			t.Errorf("toBlock emitted an EMPTY %s — an unset enum must coerce to its sentinel, "+
				"never to \"\"", name)
		}
	}
}
