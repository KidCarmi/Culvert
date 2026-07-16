package decryptobs

import "testing"

// pinEnum is the exhaustiveness guard: it asserts that a closed set exactly equals the
// hardcoded canonical list (value AND order), that every member reports Valid() and
// round-trips through String(), and that there are no duplicates. `want` is written out
// literally — NOT derived from the same slice under test — so adding, removing, or
// reordering a const without updating this pin fails the build. This is the
// autoexclude.allReasons / uiRoutes drift-guard discipline (ADR-0011 §2.2).
func pinEnum[T ~string](t *testing.T, name string, set []T, want []string, valid func(T) bool, str func(T) string) {
	t.Helper()
	if len(set) != len(want) {
		t.Fatalf("%s: len(All)=%d, want %d — an enum value was added/removed without updating this pin", name, len(set), len(want))
	}
	seen := make(map[string]bool, len(set))
	for i, v := range set {
		got := string(v)
		if got != want[i] {
			t.Errorf("%s[%d] = %q, want %q (value or ordering drift)", name, i, got, want[i])
		}
		if str(v) != got {
			t.Errorf("%s: %q.String() = %q, want %q", name, got, str(v), got)
		}
		if !valid(v) {
			t.Errorf("%s: member %q reports Valid()=false", name, got)
		}
		if seen[got] {
			t.Errorf("%s: duplicate value %q in the set", name, got)
		}
		seen[got] = true
	}
	// A value outside the set is never valid (guards Valid against a stub that returns true).
	if valid(T("__definitely_not_a_member__")) {
		t.Errorf("%s: Valid() accepted a non-member", name)
	}
}

func TestEnum_Outcome(t *testing.T) {
	pinEnum(t, "Outcome", AllOutcomes, []string{
		"inspected", "bypass_manual", "bypass_learned", "rescued", "failed", "not_decrypted",
	}, Outcome.Valid, Outcome.String)
}

func TestEnum_DecisionSource(t *testing.T) {
	pinEnum(t, "DecisionSource", AllDecisionSources, []string{
		"policy_inspect", "manual_ssl_bypass", "autoexclude_cache", "autoexclude_rescue",
		"no_fail_open_502", "cert_verify_block", "non_tls_fallback",
	}, DecisionSource.Valid, DecisionSource.String)
}

func TestEnum_FailStage(t *testing.T) {
	pinEnum(t, "FailStage", AllFailStages, []string{
		"none", "tcp_connect", "client_hello", "upstream_handshake", "cert_verify",
		"client_leaf_reject", "relay",
	}, FailStage.Valid, FailStage.String)
}

func TestEnum_FailCategory(t *testing.T) {
	// 10 values; the set deliberately mirrors PAN-OS Decryption Error-Index classes.
	pinEnum(t, "FailCategory", AllFailCategories, []string{
		"none", "certificate", "protocol", "version", "cipher", "client_cert_required",
		"client_pinned", "resource", "timeout", "other",
	}, FailCategory.Valid, FailCategory.String)
}

func TestEnum_CertVerify(t *testing.T) {
	pinEnum(t, "CertVerify", AllCertVerify, []string{
		"not_checked", "verified", "skipped", "untrusted_issuer", "expired",
		"hostname_mismatch", "unknown",
	}, CertVerify.Valid, CertVerify.String)
}

func TestEnum_TLSVersion(t *testing.T) {
	pinEnum(t, "TLSVersion", AllTLSVersions, []string{"1.2", "1.3", "unknown"},
		TLSVersion.Valid, TLSVersion.String)
}

func TestEnum_ALPN(t *testing.T) {
	pinEnum(t, "ALPN", AllALPN, []string{"", "h2", "http/1.1"}, ALPN.Valid, ALPN.String)
}

// TestEnum_ALPNEmptyIsValidMember pins the one non-obvious rule: the empty string is a
// VALID ALPN member ("no ALPN negotiated"), not an "unset" sentinel. Per ADR-0011 §2.1
// it serializes explicitly when the dec block is present, so Valid("") must be true —
// distinct from a genuinely-unknown value.
func TestEnum_ALPNEmptyIsValidMember(t *testing.T) {
	if !ALPNNone.Valid() {
		t.Fatal("ALPNNone (empty string) must be a valid member")
	}
	if ALPN("garbage").Valid() {
		t.Fatal("a non-member ALPN must be invalid")
	}
}

// TestEnum_NoneSentinelsAreFirstAndValid pins that the "no failure / not applicable"
// sentinels are the canonical zero-position of the failure enums — the value a
// successfully-decisioned (non-failing) session carries. §2.1 requires these to
// serialize explicitly (non-omitempty) so a fail-close session shows none, not absence.
func TestEnum_NoneSentinelsAreFirstAndValid(t *testing.T) {
	if AllFailStages[0] != FailStageNone || !FailStageNone.Valid() {
		t.Error("FailStageNone must be the first, valid FailStage")
	}
	if AllFailCategories[0] != FailCategoryNone || !FailCategoryNone.Valid() {
		t.Error("FailCategoryNone must be the first, valid FailCategory")
	}
	if !OutcomeNotDecrypted.Valid() || !CertVerifyNotChecked.Valid() || !TLSVersionUnknown.Valid() {
		t.Error("the not-applicable sentinels must be valid members")
	}
}
