package main

// m7_contract_sync_test.go — M7 Slice 2.5 contract-consistency wall.
//
// This is a DOCUMENTATION-PREDICATE test (same shape as docs_saml_test.go): it
// reads the binding M7 design (roadmap/M7-proactive-telemetry-plan.md) and
// fails if any of the locked TAC 2.5-A contract decisions regresses. It changes
// no production behavior; it only pins the design text to the contract that is
// already implemented and tested in KidCarmi/tac-platform.
//
// Each guard below maps to one of the nine regressions the Slice 2.5 mission
// enumerates. They deliberately combine POSITIVE controls (the decision must be
// stated) with MUTATION SEEDS (the inverted spelling must be absent), so a test
// cannot stay green while the decision is silently inverted — a weak substring
// check that survives inversion is explicitly disallowed by the mission.
//
// The fixture-identity guard is the strongest kind: it does not echo static
// literals, it reads the REAL fixture bytes, recomputes size + SHA-256, parses
// schema_version + registry_hash, and asserts the design records exactly those
// live values — so the doc cannot drift from the merged producer fixture.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// m7PlanRelPath is the binding design document under contract.
const m7PlanRelPath = "roadmap/M7-proactive-telemetry-plan.md"

// readM7Plan returns the raw design bytes and a whitespace-normalized copy
// (runs of any whitespace, including newlines, collapsed to a single space).
// Multi-line contract sentences are matched against the normalized text so a
// benign line re-wrap cannot break a guard; format-sensitive tokens (e.g. the
// literal placeholder "<RFC3339 UTC>") are matched against the raw text.
func readM7Plan(t *testing.T) (raw, norm string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pkgSourceDir(), filepath.FromSlash(m7PlanRelPath)))
	if err != nil {
		t.Fatalf("read %s: %v", m7PlanRelPath, err)
	}
	raw = string(b)
	norm = regexp.MustCompile(`\s+`).ReplaceAllString(raw, " ")
	return raw, norm
}

// parseFencedMemberBlock extracts the member names from the plain (no-language)
// fenced code block that immediately follows `anchor` in the design. The design
// pins each envelope's closed set as a one-member-per-line fence right after the
// "exactly these N members" sentence, so parsing THAT scoped block — rather than
// searching the whole document — is what lets the wall detect (a) a member
// dropped from the list that still appears elsewhere in the doc (e.g. `algorithm`
// in the error taxonomy) and (b) a member placed in the wrong envelope. Both are
// invisible to a global substring scan.
func parseFencedMemberBlock(t *testing.T, doc, anchor string) []string {
	t.Helper()
	ai := strings.Index(doc, anchor)
	if ai < 0 {
		t.Fatalf("member-set anchor %q not found in design", anchor)
	}
	rest := doc[ai+len(anchor):]
	open := strings.Index(rest, "```")
	if open < 0 {
		t.Fatalf("no fenced code block after anchor %q", anchor)
	}
	rest = rest[open+3:]
	// Skip the rest of the fence's opening line (an optional language tag).
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[nl+1:]
	}
	end := strings.Index(rest, "```")
	if end < 0 {
		t.Fatalf("unterminated fenced code block after anchor %q", anchor)
	}
	var members []string
	for _, line := range strings.Split(rest[:end], "\n") {
		if s := strings.TrimSpace(line); s != "" {
			members = append(members, s)
		}
	}
	return members
}

// assertExactMemberSet compares a parsed member block against the expected set,
// order-independent, with exact membership (no missing, no extra, no wrong-set).
func assertExactMemberSet(t *testing.T, envelope string, got, want []string) {
	t.Helper()
	gotSet := map[string]bool{}
	for _, m := range got {
		if gotSet[m] {
			t.Errorf("%s member set lists %q more than once", envelope, m)
		}
		gotSet[m] = true
	}
	wantSet := map[string]bool{}
	for _, m := range want {
		wantSet[m] = true
		if !gotSet[m] {
			t.Errorf("%s member set is missing required member %q (removed from the scoped list)", envelope, m)
		}
	}
	for m := range gotSet {
		if !wantSet[m] {
			t.Errorf("%s member set contains unexpected member %q (wrong envelope or an undeclared addition)", envelope, m)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%s member set has %d members, want exactly %d", envelope, len(got), len(want))
	}
}

// mustContain / mustNotContain are the positive-control / mutation-seed halves.
func mustContain(t *testing.T, hay, needle, why string) {
	t.Helper()
	if !strings.Contains(hay, needle) {
		t.Errorf("%s: design must state %q\n(missing positive control — the locked decision was weakened or removed)", why, needle)
	}
}

func mustNotContain(t *testing.T, hay, needle, why string) {
	t.Helper()
	if strings.Contains(hay, needle) {
		t.Errorf("%s: design must NOT contain %q\n(mutation seed present — the locked decision was inverted)", why, needle)
	}
}

// ── 1 & 2. Closed top-level member sets; a new member needs a new schema_version ──

func TestM7Contract_ClosedMemberSetsNotArbitraryAdditivity(t *testing.T) {
	raw, norm := readM7Plan(t)

	// Positive controls — the closed-set rule must be stated for BOTH envelopes,
	// and adding any top-level member must require a new schema_version.
	mustContain(t, norm, "the **outer** top-level member set is **closed**", "schema evolution")
	mustContain(t, norm, "the **inner** top-level member set is **closed**", "schema evolution")
	mustContain(t, norm, "Adding **any** new top-level member requires a **new `schema_version`**", "schema evolution")
	mustContain(t, norm, "Additive evolution within schema version 3 is allowed **only inside the governed `metrics` map**", "schema evolution")
	// A newer unsupported version is rejected cleanly, not parsed optimistically.
	mustContain(t, norm, "is rejected **cleanly**", "schema evolution")

	mustContain(t, norm, "**exactly these eight members**", "outer member count")
	mustContain(t, norm, "**exactly these six members**", "inner member count")

	// The exact closed member sets must be pinned in their OWN scoped fenced
	// block — parsed and compared as a set, not searched across the whole doc.
	// This detects a member dropped from a list but still present elsewhere
	// (e.g. `algorithm` in the error taxonomy) and a member in the wrong
	// envelope — both invisible to a global substring scan (Codex #973 P2).
	outer := parseFencedMemberBlock(t, raw, "these eight members**, no more and no fewer:")
	assertExactMemberSet(t, "outer envelope", outer, []string{
		"envelope_version", "key_id", "algorithm", "ciphertext",
		"ciphertext_sha256", "sample_id", "schema_version", "registry_hash",
	})
	inner := parseFencedMemberBlock(t, raw, "these six members**, no more and no fewer:")
	assertExactMemberSet(t, "inner plaintext", inner, []string{
		"schema_version", "registry_hash", "generated_at",
		"sample_epoch", "sequence", "metrics",
	})

	// Mutation seeds — the three exact pre-decision spellings that presented
	// version 3 as arbitrarily additive. None may return as an ACTIVE claim.
	// (The one legitimate residual mention is inside the "this supersedes any
	// earlier ... wording" note, which is line-wrapped and never matches these.)
	mustNotContain(t, norm, "Versioned; additive-only within a major.", "additivity inversion")
	mustNotContain(t, norm, "additive-only within a major `schema_version`", "additivity inversion")
	mustNotContain(t, norm, "Additive-only wire/schema within a major", "additivity inversion")
}

// ── unknown MEMBER (400) is not the same as unknown VERSION (422) ──

func TestM7Contract_UnknownMemberIsNotUnknownVersion(t *testing.T) {
	_, norm := readM7Plan(t)
	mustContain(t, norm, "unknown top-level member under a known `schema_version`", "400 vs 422")
	mustContain(t, norm, "**distinct**", "400 vs 422")
	// The two cases must not be flattened into one meaning.
	mustNotContain(t, norm, "unknown top-level member is the same as an unsupported version", "400 vs 422")
}

// ── 3 & 4. Raw-byte idempotency is settled (not an open 2.5-D decision), and
//          semantic JSON equivalence is NOT duplicate equality. ──

func TestM7Contract_RawByteIdempotencyIsSettled(t *testing.T) {
	_, norm := readM7Plan(t)

	mustContain(t, norm, "dedupe key = (authenticated appliance identity, sample_id)", "idempotency")
	mustContain(t, norm, "identical SHA-256 of the exact raw serialized request body", "idempotency")
	mustContain(t, norm, "=> 200 accepted, duplicate:true", "idempotency")
	mustContain(t, norm, "different raw-body SHA-256", "idempotency")
	mustContain(t, norm, "=> 409 conflict", "idempotency")
	mustContain(t, norm, "**settled, non-negotiable**", "idempotency")
	mustContain(t, norm, "Semantic JSON equivalence is **irrelevant**", "idempotency")
	// Seal-once operational steps must be present.
	mustContain(t, norm, "**never** rebuild, reseal, or reserialize a pending sample", "seal-once")

	// Mutation seeds — idempotency must not be framed as an OPEN/undecided
	// question, and canonicalized-JSON equality must not be framed as the basis.
	// (The design legitimately mentions canonicalization only to DENY it, so the
	// seeds target the openness framing, not the bare noun phrase.)
	for _, seed := range []string{
		"remains an open 2.5-D decision",
		"is an open 2.5-D decision",
		"still an open 2.5-D",
		"open question of raw bytes",
		"to be decided in 2.5-D",
		"idempotency over canonicalized JSON",
		"canonicalized JSON is the idempotency key",
	} {
		mustNotContain(t, norm, seed, "idempotency-open inversion")
	}
}

// ── 5. "wrong tenant" must not return as a client-selected attribution case. ──

func TestM7Contract_NoClientSelectedTenant(t *testing.T) {
	raw, norm := readM7Plan(t)

	// 401 and 403 must be split, with 403 = authenticated-but-forbidden.
	mustContain(t, norm, "credential authentication failed", "401")
	mustContain(t, norm, "authenticated, but administratively forbidden", "403")
	mustContain(t, norm, "no trusted tenant or appliance identity", "attribution")
	mustContain(t, norm, "no client-selected target tenant", "attribution")

	// Mutation seeds — the pre-decision spellings that treated the body as
	// selecting a tenant / bundled 401 and 403 into one authz row.
	mustNotContain(t, raw, "| `401`/`403` |", "wrong-tenant inversion")
	mustNotContain(t, norm, "bad/expired credential, wrong tenant, not entitled", "wrong-tenant inversion")
	mustNotContain(t, norm, "wrong-tenant credential cannot submit as another appliance", "wrong-tenant inversion")
	mustNotContain(t, norm, "`403` on wrong-tenant", "wrong-tenant inversion")
}

// ── 6. generated_at is canonical UTC RFC3339Nano ("Z"), not ambiguous. ──

func TestM7Contract_GeneratedAtCanonicalForm(t *testing.T) {
	raw, norm := readM7Plan(t)

	mustContain(t, norm, "t.UTC().Format(time.RFC3339Nano)", "generated_at")
	mustContain(t, norm, "trailing `Z`", "generated_at")
	// Alternate spellings must be named as NON-canonical, not accepted.
	mustContain(t, norm, "are **not** producer-canonical", "generated_at")

	// Mutation seed — the ambiguous placeholder the field used before.
	mustNotContain(t, raw, `"generated_at": "<RFC3339 UTC>"`, "generated_at inversion")
	mustNotContain(t, raw, "<RFC3339 UTC>", "generated_at inversion")
}

// ── 7. The stale support_health_uptime_bucket name must not be authoritative. ──

func TestM7Contract_UptimeMetricNameIsShipped(t *testing.T) {
	raw, _ := readM7Plan(t)

	mustContain(t, raw, "support_uptime_bucket", "uptime metric")
	// The stale spelling must not reappear anywhere in the binding design.
	mustNotContain(t, raw, "support_health_uptime_bucket", "uptime metric inversion")

	// Cross-check: the authoritative id is exactly the one the shipped registry
	// and the golden fixture carry — so a rename in code is caught here too.
	found := false
	for i := range supportMetricRegistry {
		if supportMetricRegistry[i].ID == "support_uptime_bucket" {
			found = true
		}
		if supportMetricRegistry[i].ID == "support_health_uptime_bucket" {
			t.Errorf("registry ships id %q — the design and registry must agree on support_uptime_bucket", "support_health_uptime_bucket")
		}
	}
	if !found {
		t.Errorf("registry does not ship support_uptime_bucket — design/registry drift")
	}
}

// ── 8. The recorded fixture identity must match the REAL merged producer bytes. ──

func TestM7Contract_FixtureIdentityMatchesRealBytes(t *testing.T) {
	raw, _ := readM7Plan(t)

	fb, err := os.ReadFile(filepath.Join(pkgSourceDir(), filepath.FromSlash("testdata/telemetry/v1/inner_sample.json")))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	// Size + SHA-256 are computed from the live bytes, not echoed.
	sum := sha256.Sum256(fb)
	gotSHA := hex.EncodeToString(sum[:])
	mustContain(t, raw, fmt.Sprintf("%d bytes", len(fb)), "fixture size record")
	mustContain(t, raw, gotSHA, "fixture SHA-256 record")

	// schema_version + registry_hash are parsed from the live fixture.
	var parsed struct {
		SchemaVersion int    `json:"schema_version"`
		RegistryHash  string `json:"registry_hash"`
	}
	if err := json.Unmarshal(fb, &parsed); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	// Spacing-tolerant: the record aligns fields with runs of spaces.
	svRe := regexp.MustCompile(`schema_version:\s+` + fmt.Sprintf("%d", parsed.SchemaVersion) + `\b`)
	if !svRe.MatchString(raw) {
		t.Errorf("fixture provenance: design must record schema_version %d in the producer-contract record", parsed.SchemaVersion)
	}
	mustContain(t, raw, parsed.RegistryHash, "fixture registry_hash record")

	// The producer provenance (PR + repo) must be recorded (spacing-tolerant).
	mustContain(t, raw, "producer repository: KidCarmi/Culvert", "fixture provenance")
	if !regexp.MustCompile(`producer PR:\s+#938`).MatchString(raw) {
		t.Errorf("fixture provenance: design must record producer PR #938 in the producer-contract record")
	}

	// The design must be explicit that this fixture alone does not unblock Slice 3.
	_, norm := readM7Plan(t)
	mustContain(t, norm, "This fixture alone does not unblock Culvert Slice 3", "fixture scope")
}

// ── 9. The design must not claim TAC auth/crypto/ingestion or Slice 3 is done. ──

func TestM7Contract_TACStateAccurate(t *testing.T) {
	_, norm := readM7Plan(t)

	// The still-owed TAC work must be recorded as NOT implemented.
	for _, notDone := range []string{
		"TAC 2.5-B — credential identity + server-side attribution | **Not implemented**",
		"TAC 2.5-C — key resolution, digest verification, decryption, sealed interop vectors | **Not implemented**",
		"TAC 2.5-D — idempotent transactional ingestion | **Not implemented**",
		"Culvert Slice 3 — sender, spool, retry, egress | **Blocked**",
	} {
		mustContain(t, norm, notDone, "TAC status")
	}
	mustContain(t, norm, "The telemetry gateway is therefore **not yet functional**", "TAC status")
	// The completed contract layer must be recorded as complete (not overclaimed
	// beyond the contract), so the status is neither stale-absent nor overstated.
	mustContain(t, norm, "TAC 2.5-A — strict contract, fixture consumption, stabilized opaque carrier API | **Complete**", "TAC status")

	// Mutation seeds — overclaims that TAC is functional or Slice 3 shipped.
	for _, seed := range []string{
		"the telemetry gateway is functional",
		"TAC-side decryption is implemented",
		"Slice 3 is complete",
		"Slice 3 is unblocked",
		"Slice 3 — Bounded telemetry delivery (ONLY EGRESS SLICE) | **Complete**",
	} {
		mustNotContain(t, norm, seed, "TAC overclaim inversion")
	}
}
