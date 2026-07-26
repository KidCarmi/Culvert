package main

// support_telemetry_golden_fixture_test.go — M7 Slice 2.5-A1: the versioned,
// PRODUCER-OWNED inner-plaintext telemetry golden fixture
// (roadmap/M7-proactive-telemetry-plan.md §3.3/§13).
//
// Culvert is the PRODUCER of the M7 §3.3 inner sealed plaintext, so Culvert —
// not the consuming TAC gateway — owns its golden fixture. The fixture bytes
// checked in at testdata/telemetry/v1/inner_sample.json are the EXACT output of
// the real production serialization path:
//
//	supportmetrics.Registry.BuildSample(now, epoch, sequence)
//	json.Marshal(supportmetrics.Sample)   // → Sample.MarshalJSON
//
// Nothing here re-implements, mirrors, or hand-writes the wire shape: a change
// to Sample.MarshalJSON, to the sampleWire tags, to SchemaVersion, to the
// registry_hash encoding, to the governed descriptor schema, or to the
// telemetry-eligible metric set produces a deterministic byte-inequality
// failure that forces an intentional, coordinated cross-repository update.
//
// SCOPE (A1 is deliberately narrow — this is NOT Slice 3): no network, no outer
// envelope, no encryption, no TAC key, no bearer credential, no sender, no
// spool, no retry, no idempotency, no persistence, no background worker, no new
// API route. TestTelemetryGoldenFixtureA1HasNoEgress is the wall.
//
// PRODUCER OWNERSHIP: the fixture is built from a CLONE of the live production
// registry (supportMetricRegistry, support_telemetry_registry.go) with every
// governed descriptor field — ID, Type, PrivacyClass, InSupportBundle,
// TelemetryEligible, TelemetryReason, Buckets — preserved byte-for-byte, and
// ONLY each Read callback swapped for a fixed deterministic value. That is
// exactly what makes the fixture's registry_hash the REAL production hash:
// Registry.Hash() never invokes Read (internal/supportmetrics/hash.go), so
// swapping Read cannot move the hash. Note the hash covers the §8 SUBSET of
// the governed schema — ID, Type, PrivacyClass, TelemetryEligible, Buckets —
// and deliberately NOT InSupportBundle or TelemetryReason; those two are
// preserved by the clone as well, and asserted separately by
// TestTelemetryGoldenFixturePreservesGovernedDescriptorFields (editing a
// TelemetryReason justification is therefore NOT a wire-contract change).
// A toy registry would produce a different hash, and
// TestTelemetryGoldenFixtureRegistryHashIsProduction proves this one does not.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/supportmetrics"
)

// ─── Cross-repository copy contract metadata ────────────────────────────────
//
// This metadata describes the fixture; it is deliberately NOT inside the
// fixture JSON, because none of it is part of the §3.3 wire protocol. The
// later tac-platform 2.5-A change copies the exact fixture BYTES and verifies
// telemetryGoldenFixtureSHA256 against its own copy. Both repositories stay
// hermetic: no submodule, no network fetch, no cross-repo test dependency.
// See testdata/telemetry/v1/README.md for the operator/consumer-facing copy.
const (
	// telemetryGoldenFixtureVersion is the fixture's own version, independent
	// of supportmetrics.SchemaVersion: a new fixture VARIANT (different fixed
	// values) would be v2 even at the same wire schema version.
	telemetryGoldenFixtureVersion = "v1"

	// telemetryGoldenFixtureProducerRepo is the repository that OWNS and
	// generates these bytes. tac-platform consumes a copy; it must never
	// invent its own inner-plaintext fixture.
	telemetryGoldenFixtureProducerRepo = "KidCarmi/Culvert"

	// telemetryGoldenFixtureProducerBaseline is the Culvert main-branch commit
	// whose REGISTRY SCHEMA produced these bytes — the provenance a
	// cross-repository contract review needs. It is the branch point, so it
	// does NOT itself contain the fixture; `registry_hash` is the reproducible
	// schema identity, this is the human-readable pointer to it.
	telemetryGoldenFixtureProducerBaseline = "a689cc59cf9e62955338026a85e3b1dcf104ae12"

	// telemetryGoldenFixtureSHA256 is the lowercase-hex SHA-256 of the EXACT
	// fixture bytes. This is the value the tac-platform copy verifies.
	telemetryGoldenFixtureSHA256 = "22df6ee3b323b46332e0073be7925886d6d15121a781165f8ba79b6657549005"

	// telemetryGoldenFixtureRegistryHash is the real production
	// supportMetricRegistry.Hash() at the baseline above. Recorded here so a
	// governed schema change (descriptor added/removed, type/privacy/
	// eligibility flip, bucket-ladder edit) fails LOUDLY here rather than
	// silently re-deriving.
	telemetryGoldenFixtureRegistryHash = "061fe684aaabb895e87130943649ef37e450cc62e9d63c6c9d7fddfce73b15a7"

	// telemetryGoldenFixtureSchemaVersion is the governed wire-schema version
	// the fixture was generated at. Pinned literally (not read from the
	// package) so a SchemaVersion bump cannot slip through unnoticed.
	telemetryGoldenFixtureSchemaVersion = 3
)

// ─── Fixed fixture inputs (declared once, used by every test below) ─────────

const (
	// telemetryGoldenFixtureGeneratedAtRaw is the exact JSON string Go's
	// time.Time marshaller must produce for the fixed instant. Asserting the
	// RAW encoding (not just the decoded instant) is what catches a timestamp
	// PRECISION drift — e.g. a future ".000Z" or offset representation would
	// decode to the same instant but is a different wire byte sequence.
	telemetryGoldenFixtureGeneratedAtRaw = "2026-07-24T12:00:00Z"

	// telemetryGoldenFixtureEpoch is a fixed, well-formed §5 sample_epoch:
	// exactly 32 lowercase hex characters (128 bits). It is a literal test
	// constant — never read from process state — and carries no appliance
	// identity by construction.
	telemetryGoldenFixtureEpoch = "0123456789abcdef0123456789abcdef"

	// telemetryGoldenFixtureSequence is the fixed §5 per-epoch delivery
	// sequence number.
	telemetryGoldenFixtureSequence = 42
)

// telemetryGoldenFixtureRelPath is the fixture's repository-relative path.
const telemetryGoldenFixtureRelPath = "testdata/telemetry/v1/inner_sample.json"

// telemetryGoldenFixtureTestFile is this file's own name.
const telemetryGoldenFixtureTestFile = "support_telemetry_golden_fixture_test.go"

// telemetryGoldenFixtureSourceGlob matches the whole A1 surface, not just this
// one file: a follow-up A1 file would otherwise get NO wall at all — the Slice
// 1/2 globs skip `_test.go`, and a single-filename constant would not name it.
//
// Deliberately NOT the wider `support_telemetry_*_test.go`: that would scan
// support_telemetry_noegress_test.go, whose marker tables spell out every
// outbound/goroutine/sleep call-site verbatim, so the wall would match its own
// vocabulary and fail always.
const telemetryGoldenFixtureSourceGlob = "support_telemetry_golden_fixture*_test.go"

// a1SourceFiles returns every file on the A1 surface. It fails rather than
// returning an empty set, so a renamed file cannot silently disarm the walls.
func a1SourceFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(pkgSourceDir(), telemetryGoldenFixtureSourceGlob))
	if err != nil {
		t.Fatalf("glob %s: %v", telemetryGoldenFixtureSourceGlob, err)
	}
	if len(files) == 0 {
		t.Fatalf("glob %q matched no files — the A1 no-egress wall is not guarding anything", telemetryGoldenFixtureSourceGlob)
	}
	sort.Strings(files)
	return files
}

// telemetryGoldenFixtureWriterFunc is the ONE function permitted to touch the
// filesystem on the A1 surface.
const telemetryGoldenFixtureWriterFunc = "writeTelemetryGoldenFixtureTo"

// telemetryGoldenFixtureRegenerateEnv is the explicit developer opt-in for
// regeneration. Ordinary `go test` runs never set it, so ordinary test
// execution can never rewrite a repository file.
const telemetryGoldenFixtureRegenerateEnv = "CULVERT_TELEMETRY_FIXTURE_REGENERATE"

// telemetryGoldenFixtureOptedIn reports whether the developer EXPLICITLY opted
// into regeneration.
//
// Only affirmative values count. A conventional DISABLED value — `0`, `false`,
// `no`, `off` — must NOT arm the writer: a mere presence check would treat
// `CULVERT_TELEMETRY_FIXTURE_REGENERATE=false` in a developer's shell as
// consent, and an ordinary `go test ./...` would then silently overwrite the
// checked-in fixture (dirtying the checkout and masking real fixture drift) —
// exactly the silent rewrite the opt-in exists to prevent. Anything
// unrecognized is treated as NOT opted in, so the failure direction is always
// "refuse to write".
func telemetryGoldenFixtureOptedIn() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(telemetryGoldenFixtureRegenerateEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// telemetryGoldenFixtureCIEnvs are the environment markers that mean "this is
// an automated run". Regeneration hard-refuses when any is set, even WITH the
// opt-in, so a stray env var in a workflow can never mutate the fixture in CI.
var telemetryGoldenFixtureCIEnvs = []string{"CI", "GITHUB_ACTIONS", "CONTINUOUS_INTEGRATION", "BUILD_NUMBER"}

// telemetryGoldenFixtureValues is the deterministic value each production
// descriptor's Read callback is replaced with. Every value is a literal —
// nothing here reads mutable global appliance state (certMgr, policyStore,
// startTime, …), which is what makes the fixture reproducible on any machine
// at any time.
//
// The set deliberately exercises MIXED valid states, per the §3.3 contract:
// health gauges at both 1 and 0, and non-zero coarse bucket values. No NaN, no
// infinity, no undocumented metric — BuildSample rejects non-finite values and
// TestTelemetryGoldenFixtureValuesCoverExactlyTheProductionRegistry rejects a
// stale entry.
var telemetryGoldenFixtureValues = map[string]float64{
	"support_health_ca_ready":              1, // health gauge at 1
	"support_health_clamav_ready":          0, // health gauge at 0
	"support_health_yara_ready":            1,
	"support_health_policy_loaded":         1,
	"support_health_session_ready":         1,
	"support_health_config_snapshot_valid": 0, // second health gauge at 0
	"support_health_ca_expiry_bucket":      2, // non-zero bucket (le30d)
	"support_uptime_bucket":                3, // non-zero bucket (ge30d)
}

// ─── Fixture construction (the real production path, nothing re-implemented) ─

// telemetryGoldenFixtureInstant is the fixed UTC generation timestamp.
func telemetryGoldenFixtureInstant() time.Time {
	return time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
}

// telemetryGoldenFixtureRegistry returns a CLONE of the live production
// registry with every governed descriptor field preserved and ONLY each Read
// callback replaced by a deterministic literal.
//
// It must never mutate supportMetricRegistry: the clone is a fresh backing
// array (make+copy), and Descriptor is a value type, so assigning clone[i].Read
// cannot reach the production slice. Buckets is a *BucketLadder deliberately
// SHARED by pointer with production — the ladder is read-only and participates
// in Registry.Hash(), so sharing it is what proves the fixture commits to the
// production thresholds rather than to a copy that could drift.
func telemetryGoldenFixtureRegistry(t *testing.T) supportmetrics.Registry {
	t.Helper()
	clone := make(supportmetrics.Registry, len(supportMetricRegistry))
	copy(clone, supportMetricRegistry)
	for i := range clone {
		v, ok := telemetryGoldenFixtureValues[clone[i].ID]
		if !ok {
			t.Fatalf("no deterministic fixture value for production metric %q — a descriptor was added to supportMetricRegistry without a coordinated fixture update (see %s)",
				clone[i].ID, telemetryGoldenFixtureRelPath)
		}
		clone[i].Read = func() float64 { return v }
	}
	return clone
}

// telemetryGoldenFixtureSample builds the fixture sample through the real
// producer: Registry.BuildSample with the fixed inputs.
func telemetryGoldenFixtureSample(t *testing.T) supportmetrics.Sample {
	t.Helper()
	s, err := telemetryGoldenFixtureRegistry(t).BuildSample(
		telemetryGoldenFixtureInstant(),
		telemetryGoldenFixtureEpoch,
		telemetryGoldenFixtureSequence,
	)
	if err != nil {
		t.Fatalf("BuildSample over the cloned production registry: %v", err)
	}
	return s
}

// telemetryGoldenFixtureBytes produces the authoritative fixture bytes via the
// production serializer. json.Marshal on a Sample dispatches to
// Sample.MarshalJSON (internal/supportmetrics/sample.go), which serializes the
// Sample's OWN internal state — so these bytes are the exact §3.3 inner sealed
// plaintext a future Slice 3 sender would seal.
func telemetryGoldenFixtureBytes(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(telemetryGoldenFixtureSample(t))
	if err != nil {
		t.Fatalf("json.Marshal(supportmetrics.Sample): %v", err)
	}
	return b
}

// telemetryGoldenFixtureAbsPath resolves the fixture through pkgSourceDir()
// (runtime.Caller-anchored) rather than the process working directory, so a
// concurrent test's os.Chdir cannot flake it.
func telemetryGoldenFixtureAbsPath() string {
	return filepath.Join(pkgSourceDir(), filepath.FromSlash(telemetryGoldenFixtureRelPath))
}

// readTelemetryGoldenFixture reads the checked-in fixture VERBATIM. No
// TrimSpace, no normalization, no re-encode — the bytes on disk are the
// contract.
func readTelemetryGoldenFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(telemetryGoldenFixtureAbsPath())
	if err != nil {
		t.Fatalf("read golden fixture %s: %v (regenerate with %s=1 go test -run TestTelemetryGoldenFixtureRegenerate .)",
			telemetryGoldenFixtureRelPath, err, telemetryGoldenFixtureRegenerateEnv)
	}
	return b
}

// ─── 1. Byte-for-byte equality with the real producer ───────────────────────

// TestTelemetryGoldenFixtureMatchesProducerBytes is the primary regression
// wall: the checked-in fixture must be EXACTLY what json.Marshal produces for
// the sample built by the real production path. bytes.Equal — no TrimSpace, no
// semantic comparison, no re-encoding. A change to the wire shape, a field
// spelling, the JSON number representation, the timestamp representation, the
// registry schema, or the eligible metric set fails here deterministically.
func TestTelemetryGoldenFixtureMatchesProducerBytes(t *testing.T) {
	got := telemetryGoldenFixtureBytes(t)
	want := readTelemetryGoldenFixture(t)
	if !bytes.Equal(got, want) {
		t.Fatalf("golden fixture drift — the production serializer no longer reproduces %s.\n"+
			"  producer (%d bytes): %s\n"+
			"  fixture  (%d bytes): %s\n"+
			"Candidate causes: an intentional wire/registry change, or a toolchain change to encoding/json\n"+
			"(number or time.Time encoding, e.g. GOEXPERIMENT=jsonv2) — both are genuine wire-byte changes.\n"+
			"If this change is INTENTIONAL it is a cross-repository wire-contract change: regenerate with\n"+
			"  %s=1 go test -run TestTelemetryGoldenFixtureRegenerate .\n"+
			"and update the copied fixture + recorded SHA-256 in %s in the SAME coordinated change.",
			telemetryGoldenFixtureRelPath, len(got), got, len(want), want,
			telemetryGoldenFixtureRegenerateEnv, telemetryGoldenFixtureProducerRepo)
	}
}

// TestTelemetryGoldenFixtureIsCompactJSON proves the fixture is the compact
// json.Marshal encoding, not a pretty-printed or newline-terminated variant —
// the two most common ways a checked-in JSON fixture silently stops being
// byte-identical to its producer.
func TestTelemetryGoldenFixtureIsCompactJSON(t *testing.T) {
	b := readTelemetryGoldenFixture(t)
	if len(b) == 0 {
		t.Fatal("fixture is empty")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, b); err != nil {
		t.Fatalf("fixture is not valid JSON: %v", err)
	}
	if !bytes.Equal(b, compact.Bytes()) {
		t.Errorf("fixture is not the compact encoding json.Marshal produces (pretty-print or stray whitespace):\n got: %s\nwant: %s", b, compact.Bytes())
	}
	if b[len(b)-1] == '\n' || b[len(b)-1] == '\r' {
		t.Error("fixture ends with a newline — json.Marshal emits no trailing byte, and the comparison does not TrimSpace")
	}
	if bytes.ContainsAny(b, "\n\r\t") {
		t.Error("fixture contains a newline/tab — json.Marshal emits none")
	}
}

// ─── 2. Producer-ownership walls (real registry, real hash) ─────────────────

// TestTelemetryGoldenFixtureRegistryHashIsProduction is the anti-toy-registry
// wall. Registry.Hash() hashes ONLY the governed descriptor schema and never
// invokes Read (internal/supportmetrics/hash.go), so a clone whose Read
// callbacks were swapped MUST hash identically to production. If it does not,
// the fixture was built from something that is not the production schema.
func TestTelemetryGoldenFixtureRegistryHashIsProduction(t *testing.T) {
	fixtureHash := telemetryGoldenFixtureRegistry(t).Hash()
	prodHash := supportMetricRegistry.Hash()
	if fixtureHash != prodHash {
		t.Fatalf("fixture registry hash %q != production supportMetricRegistry.Hash() %q — the fixture is NOT built from the production schema", fixtureHash, prodHash)
	}
	if fixtureHash != telemetryGoldenFixtureRegistryHash {
		t.Fatalf("production registry_hash changed: got %q, fixture metadata records %q.\n"+
			"A governed schema change (descriptor added/removed, type/privacy/eligibility flip, bucket-ladder edit) is a cross-repository contract change — regenerate the fixture and coordinate the %s copy.",
			fixtureHash, telemetryGoldenFixtureRegistryHash, telemetryGoldenFixtureProducerRepo)
	}
}

// TestTelemetryGoldenFixturePreservesGovernedDescriptorFields proves the clone
// changed NOTHING except Read: every governed field is compared field-by-field
// against production, and the Buckets ladder is compared by POINTER identity
// (the ladder is the same value Read evaluates against and the same value the
// hash commits to — a copied ladder could drift, a shared pointer cannot).
func TestTelemetryGoldenFixturePreservesGovernedDescriptorFields(t *testing.T) {
	clone := telemetryGoldenFixtureRegistry(t)
	if len(clone) != len(supportMetricRegistry) {
		t.Fatalf("clone has %d descriptors, production has %d", len(clone), len(supportMetricRegistry))
	}
	for i := range clone {
		c, p := &clone[i], &supportMetricRegistry[i]
		if c.ID != p.ID {
			t.Errorf("descriptor %d: ID %q != production %q", i, c.ID, p.ID)
		}
		if c.Type != p.Type {
			t.Errorf("descriptor %q: Type %v != production %v", p.ID, c.Type, p.Type)
		}
		if c.PrivacyClass != p.PrivacyClass {
			t.Errorf("descriptor %q: PrivacyClass %v != production %v", p.ID, c.PrivacyClass, p.PrivacyClass)
		}
		if c.InSupportBundle != p.InSupportBundle {
			t.Errorf("descriptor %q: InSupportBundle %v != production %v", p.ID, c.InSupportBundle, p.InSupportBundle)
		}
		if c.TelemetryEligible != p.TelemetryEligible {
			t.Errorf("descriptor %q: TelemetryEligible %v != production %v", p.ID, c.TelemetryEligible, p.TelemetryEligible)
		}
		if c.TelemetryReason != p.TelemetryReason {
			t.Errorf("descriptor %q: TelemetryReason %q != production %q", p.ID, c.TelemetryReason, p.TelemetryReason)
		}
		if c.Buckets != p.Buckets {
			t.Errorf("descriptor %q: Buckets ladder is not the SAME *BucketLadder as production — a copied ladder can drift from the hashed one", p.ID)
		}
	}
}

// TestTelemetryGoldenFixtureDoesNotMutateProductionRegistry proves cloning is
// non-destructive: the production registry's hash, length, and live Read
// behavior are unchanged after the fixture is built. Without this, a fixture
// helper could silently pin the whole process's telemetry to fixed values.
func TestTelemetryGoldenFixtureDoesNotMutateProductionRegistry(t *testing.T) {
	beforeHash := supportMetricRegistry.Hash()
	beforeLen := len(supportMetricRegistry)
	beforeReads := make([]string, beforeLen)
	origReads := make([]func() float64, beforeLen)
	for i := range supportMetricRegistry {
		beforeReads[i] = readFuncIdentity(supportMetricRegistry[i].Read)
		origReads[i] = supportMetricRegistry[i].Read
	}
	// If a leak DID happen, restore production rather than leaving the whole
	// process pinned to fixed values — otherwise every later test's outcome
	// would depend on shuffle order instead of on the actual defect.
	t.Cleanup(func() {
		for i := range supportMetricRegistry {
			if i < len(origReads) {
				supportMetricRegistry[i].Read = origReads[i]
			}
		}
	})

	_ = telemetryGoldenFixtureBytes(t)

	if got := supportMetricRegistry.Hash(); got != beforeHash {
		t.Errorf("building the fixture changed supportMetricRegistry.Hash(): %q → %q", beforeHash, got)
	}
	if got := len(supportMetricRegistry); got != beforeLen {
		t.Errorf("building the fixture changed supportMetricRegistry length: %d → %d", beforeLen, got)
	}
	for i := range supportMetricRegistry {
		if got := readFuncIdentity(supportMetricRegistry[i].Read); got != beforeReads[i] {
			t.Errorf("building the fixture replaced supportMetricRegistry[%d] (%q) Read callback — the clone leaked into production",
				i, supportMetricRegistry[i].ID)
		}
	}
}

// readFuncIdentity returns a comparable identity for a Read callback. Go
// forbids comparing funcs directly, so this resolves the func value's symbol
// NAME rather than its raw code pointer: reflect's Pointer() is explicitly not
// guaranteed to identify a function uniquely (two closures from one func
// literal share a pointer), which would make the leak check a false pass the
// moment a future registry built its Reads from a shared factory. The symbol
// name distinguishes readSupport* from the fixture clone's closure regardless.
func readFuncIdentity(f func() float64) string {
	if f == nil {
		return ""
	}
	p := reflect.ValueOf(f).Pointer()
	if fn := runtime.FuncForPC(p); fn != nil {
		return fn.Name()
	}
	return fmt.Sprintf("pc:%d", p)
}

// TestTelemetryGoldenFixtureValuesCoverExactlyTheProductionRegistry pins the
// deterministic value table to the production descriptor set: no missing entry
// (caught at clone time) and no stale leftover entry for a removed metric.
func TestTelemetryGoldenFixtureValuesCoverExactlyTheProductionRegistry(t *testing.T) {
	prod := map[string]bool{}
	for i := range supportMetricRegistry {
		prod[supportMetricRegistry[i].ID] = true
	}
	for id := range telemetryGoldenFixtureValues {
		if !prod[id] {
			t.Errorf("telemetryGoldenFixtureValues has a stale entry %q that is no longer a production descriptor", id)
		}
	}
	for id := range prod {
		if _, ok := telemetryGoldenFixtureValues[id]; !ok {
			t.Errorf("production descriptor %q has no deterministic fixture value", id)
		}
	}
}

// TestTelemetryGoldenFixtureValuesAreValuesProductionCanActuallyEmit constrains
// every fixed value to the range its production Read closure can produce:
//   - a bucketed metric must be a legal integral index into the SAME production
//     ladder the registry hash commits to (so shrinking a ladder cannot leave
//     the fixture asserting an out-of-range bucket);
//   - a non-bucketed gauge must be 0 or 1 (every production health closure in
//     support_telemetry_registry.go returns exactly 0 or 1).
//
// Without the second half, the canonical cross-repository fixture could publish
// a value production can never emit — which a TAC consumer might legitimately
// code against.
func TestTelemetryGoldenFixtureValuesAreValuesProductionCanActuallyEmit(t *testing.T) {
	for i := range supportMetricRegistry {
		d := &supportMetricRegistry[i]
		v, ok := telemetryGoldenFixtureValues[d.ID]
		if !ok {
			t.Errorf("production metric %q has no deterministic fixture value", d.ID)
			continue
		}
		if v != math.Trunc(v) {
			t.Errorf("metric %q fixture value %v is not integral — every production closure emits an integral gauge or bucket index", d.ID, v)
		}
		if d.Buckets == nil {
			if v != 0 && v != 1 {
				t.Errorf("metric %q fixture value %v is not 0 or 1 — an unbucketed support-health gauge can only be 0 or 1", d.ID, v)
			}
			continue
		}
		if maxIdx := float64(len(d.Buckets.Labels) - 1); v < 0 || v > maxIdx {
			t.Errorf("metric %q fixture value %v is outside its ladder range [0,%v] — the bucket ladder changed", d.ID, v, maxIdx)
		}
	}
}

// ─── 3. Strict decode: exact shape, schema binding, value safety ────────────

// telemetryGoldenFixtureWire is the strict decode target: exactly the six §3.3
// top-level fields. Combined with DisallowUnknownFields this rejects any
// ADDITIONAL field; the explicit presence check in
// TestTelemetryGoldenFixtureExactTopLevelKeys rejects any MISSING one. Metrics decodes to json.Number so a string/object/array/bool metric
// value fails at decode rather than being silently coerced.
type telemetryGoldenFixtureWire struct {
	SchemaVersion int                    `json:"schema_version"`
	RegistryHash  string                 `json:"registry_hash"`
	GeneratedAt   time.Time              `json:"generated_at"`
	SampleEpoch   string                 `json:"sample_epoch"`
	Sequence      uint64                 `json:"sequence"`
	Metrics       map[string]json.Number `json:"metrics"`
}

func decodeTelemetryGoldenFixture(t *testing.T) telemetryGoldenFixtureWire {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(readTelemetryGoldenFixture(t)))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var w telemetryGoldenFixtureWire
	if err := dec.Decode(&w); err != nil {
		t.Fatalf("strict decode of the fixture failed: %v", err)
	}
	if dec.More() {
		t.Fatal("fixture has trailing content after the JSON document")
	}
	return w
}

// TestTelemetryGoldenFixtureExactTopLevelKeys pins the §3.3 top-level shape:
// exactly schema_version, registry_hash, generated_at, sample_epoch, sequence,
// metrics — no missing field and no additional field. This is also the wall
// that keeps OUTER-envelope fields (envelope_version, key_id, algorithm,
// ciphertext, ciphertext_sha256, sample_id) out of the inner plaintext.
func TestTelemetryGoldenFixtureExactTopLevelKeys(t *testing.T) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(readTelemetryGoldenFixture(t), &raw); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	want := []string{"schema_version", "registry_hash", "generated_at", "sample_epoch", "sequence", "metrics"}
	wantSet := map[string]bool{}
	for _, k := range want {
		wantSet[k] = true
		if _, ok := raw[k]; !ok {
			t.Errorf("fixture is missing required §3.3 top-level field %q", k)
		}
	}
	for k := range raw {
		if !wantSet[k] {
			t.Errorf("fixture has unexpected top-level field %q — the inner plaintext is exactly the six §3.3 fields", k)
		}
	}
	// Strict decode is the independent proof of the same contract.
	_ = decodeTelemetryGoldenFixture(t)
}

// telemetryGoldenFixtureOuterEnvelopeFields are the §3.2 OUTER transport
// envelope fields. A1 ships the INNER plaintext only; any of these appearing
// here would mean outer-envelope/sealing work leaked into this slice.
var telemetryGoldenFixtureOuterEnvelopeFields = []string{
	"envelope_version", "key_id", "algorithm", "ciphertext", "ciphertext_sha256", "sample_id",
}

// TestTelemetryGoldenFixtureHasNoOuterEnvelopeFields walls the A1/2.5-C
// boundary: the sealed outer envelope is deferred, so none of its fields may
// appear at any nesting level of the inner plaintext.
func TestTelemetryGoldenFixtureHasNoOuterEnvelopeFields(t *testing.T) {
	keys := telemetryGoldenFixtureAllJSONKeys(t)
	for _, banned := range telemetryGoldenFixtureOuterEnvelopeFields {
		if keys[banned] {
			t.Errorf("fixture contains outer-envelope field %q — A1 is the INNER plaintext only; the sealed envelope is deferred to TAC 2.5-C", banned)
		}
	}
}

// TestTelemetryGoldenFixtureSchemaBinding — schema_version is exactly
// supportmetrics.SchemaVersion AND exactly the literal recorded in the
// cross-repository metadata; registry_hash is exactly the live production
// registry hash AND the recorded literal.
func TestTelemetryGoldenFixtureSchemaBinding(t *testing.T) {
	w := decodeTelemetryGoldenFixture(t)
	if w.SchemaVersion != supportmetrics.SchemaVersion {
		t.Errorf("fixture schema_version = %d, supportmetrics.SchemaVersion = %d", w.SchemaVersion, supportmetrics.SchemaVersion)
	}
	if w.SchemaVersion != telemetryGoldenFixtureSchemaVersion {
		t.Errorf("fixture schema_version = %d, recorded contract metadata = %d — a wire-schema bump is a coordinated cross-repository change",
			w.SchemaVersion, telemetryGoldenFixtureSchemaVersion)
	}
	if w.RegistryHash != supportMetricRegistry.Hash() {
		t.Errorf("fixture registry_hash = %q, live supportMetricRegistry.Hash() = %q", w.RegistryHash, supportMetricRegistry.Hash())
	}
	if w.RegistryHash != telemetryGoldenFixtureRegistryHash {
		t.Errorf("fixture registry_hash = %q, recorded contract metadata = %q", w.RegistryHash, telemetryGoldenFixtureRegistryHash)
	}
}

// TestTelemetryGoldenFixtureMetricKeySetIsExactlyTheEligibleSet — the fixture's
// metric key set equals EXACTLY the current telemetry-eligible production
// descriptor set: every eligible metric present exactly once (JSON objects
// cannot repeat a key after decode, and the raw-byte count check below proves
// it structurally too), and no ineligible metric present.
func TestTelemetryGoldenFixtureMetricKeySetIsExactlyTheEligibleSet(t *testing.T) {
	w := decodeTelemetryGoldenFixture(t)

	eligible := map[string]bool{}
	for _, d := range supportMetricRegistry.Eligible() {
		if eligible[d.ID] {
			t.Fatalf("production registry has duplicate eligible id %q", d.ID)
		}
		eligible[d.ID] = true
	}
	ineligible := map[string]bool{}
	for i := range supportMetricRegistry {
		if !supportMetricRegistry[i].TelemetryEligible {
			ineligible[supportMetricRegistry[i].ID] = true
		}
	}

	for id := range eligible {
		if _, ok := w.Metrics[id]; !ok {
			t.Errorf("fixture is missing eligible metric %q — an eligible metric was added without a coordinated fixture update", id)
		}
	}
	for id := range w.Metrics {
		if !eligible[id] {
			verb := "is not a telemetry-eligible production descriptor"
			if ineligible[id] {
				verb = "is an INELIGIBLE production descriptor and must never appear in the sample"
			}
			t.Errorf("fixture metric %q %s", id, verb)
		}
	}
	if len(w.Metrics) != len(eligible) {
		t.Errorf("fixture has %d metrics, eligible set has %d", len(w.Metrics), len(eligible))
	}

	// Structural exactly-once proof: count raw `"<id>":` occurrences in the
	// metrics object, which a decoded map would hide (a duplicate key decodes
	// to a single entry, last-write-wins).
	raw := readTelemetryGoldenFixture(t)
	for id := range eligible {
		if n := bytes.Count(raw, []byte(`"`+id+`":`)); n != 1 {
			t.Errorf("metric id %q appears %d times in the raw fixture bytes, want exactly 1", id, n)
		}
	}
}

// TestTelemetryGoldenFixtureMetricsAreFlatFiniteNumbers — every metric value is
// a JSON number (never a string, object, array, bool, or null), is finite, and
// the metrics object is flat: no nested metric objects, no arrays, no labels.
func TestTelemetryGoldenFixtureMetricsAreFlatFiniteNumbers(t *testing.T) {
	var top struct {
		Metrics map[string]json.RawMessage `json:"metrics"`
	}
	if err := json.Unmarshal(readTelemetryGoldenFixture(t), &top); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(top.Metrics) == 0 {
		t.Fatal("fixture metrics object is empty")
	}
	for id, rawVal := range top.Metrics {
		s := strings.TrimSpace(string(rawVal))
		if s == "" {
			t.Errorf("metric %q has an empty value", id)
			continue
		}
		switch s[0] {
		case '"':
			t.Errorf("metric %q is a STRING (%s) — telemetry metrics are label-free scalars", id, s)
			continue
		case '{':
			t.Errorf("metric %q is a nested OBJECT (%s) — no labels or nested metric objects are permitted", id, s)
			continue
		case '[':
			t.Errorf("metric %q is an ARRAY (%s) — no arrays are permitted in metrics", id, s)
			continue
		}
		if s == "true" || s == "false" || s == "null" {
			t.Errorf("metric %q is %s — every metric value must be a JSON number", id, s)
			continue
		}
		var n json.Number
		if err := json.Unmarshal(rawVal, &n); err != nil {
			t.Errorf("metric %q value %s is not a JSON number: %v", id, s, err)
			continue
		}
		f, err := n.Float64()
		if err != nil {
			t.Errorf("metric %q value %s does not parse as a float64: %v", id, s, err)
			continue
		}
		if math.IsNaN(f) || math.IsInf(f, 0) {
			t.Errorf("metric %q value %s is not finite", id, s)
		}
	}
}

// ─── 4. Identity-exclusion wall ─────────────────────────────────────────────

// telemetryGoldenFixtureForbiddenKeys are identity/credential-shaped JSON KEY
// names that must never appear at ANY nesting level of the inner plaintext.
//
// Matching is EXACT (case-insensitive) on the whole key, deliberately — not a
// substring scan. A substring rule would reject legitimate metric ids whose
// names merely happen to contain one of these tokens (a future
// support_health_ip_stack_ready is a perfectly legal label-free health gauge),
// which would make the wall unmaintainable and tempt a reviewer to weaken it.
// The exact-key rule is the one that actually encodes the contract: the §3.3
// plaintext carries no identity FIELD.
var telemetryGoldenFixtureForbiddenKeys = []string{
	// The set the M7 privacy contract names explicitly.
	"tenant", "tenant_id", "appliance", "appliance_id", "node_id",
	"hostname", "host_name", "ip", "ip_address", "serial", "mac",
	"credential", "authorization", "token", "key_id",
	// Defense in depth: because matching is exact-whole-key, the wall's
	// strength IS this enumeration, so it covers the other plausible
	// identity/credential spellings too.
	"install_id", "machine_id", "device_id", "instance_id", "cluster_id",
	"site_id", "account_id", "customer", "customer_id", "org", "org_id",
	"license", "license_key", "fqdn", "domain", "email", "user", "username",
	"secret", "password", "bearer", "api_key", "signature", "fingerprint",
	"uuid", "mac_address", "node", "host",
}

// telemetryGoldenFixtureAllJSONKeys collects every object KEY at every nesting
// level of the fixture, lowercased.
func telemetryGoldenFixtureAllJSONKeys(t *testing.T) map[string]bool {
	t.Helper()
	var doc any
	if err := json.Unmarshal(readTelemetryGoldenFixture(t), &doc); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	keys := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch n := v.(type) {
		case map[string]any:
			for k, child := range n {
				keys[strings.ToLower(k)] = true
				walk(child)
			}
		case []any:
			for _, child := range n {
				walk(child)
			}
		}
	}
	walk(doc)
	return keys
}

// TestTelemetryGoldenFixtureHasNoIdentityShapedKeys proves the fixture
// introduces no stable appliance identity at any nesting level.
func TestTelemetryGoldenFixtureHasNoIdentityShapedKeys(t *testing.T) {
	keys := telemetryGoldenFixtureAllJSONKeys(t)
	for _, banned := range telemetryGoldenFixtureForbiddenKeys {
		if keys[banned] {
			t.Errorf("fixture contains identity-shaped JSON key %q — the §3.3 inner plaintext carries no stable appliance identity", banned)
		}
	}
	// The positive half of the wall: every surviving key must be either one of
	// the six §3.3 wire fields or a metric id that is ACTUALLY in the current
	// telemetry-eligible production set. A `support_*` glob here would be a
	// no-op — every metric id already starts with `support_`, so the negative
	// list could never fire inside `metrics` and an identity-shaped id we
	// simply forgot to enumerate (say a stable numeric `support_install_id`)
	// would sail through. Binding to the eligible set instead means a new
	// metric can only reach this fixture by way of a deliberate registry edit
	// that a human reviewed for identity content.
	allowed := map[string]bool{
		"schema_version": true, "registry_hash": true, "generated_at": true,
		"sample_epoch": true, "sequence": true, "metrics": true,
	}
	for _, d := range supportMetricRegistry.Eligible() {
		allowed[strings.ToLower(d.ID)] = true
	}
	for k := range keys {
		if allowed[k] {
			continue
		}
		t.Errorf("fixture key %q is neither a §3.3 wire field nor a telemetry-eligible production metric id", k)
	}
}

// ─── 5. Delivery-identity semantics (§5) ────────────────────────────────────

// TestTelemetryGoldenFixtureDeliveryIdentity — sample_epoch is exactly 32
// lowercase hex characters, sequence is exactly 42, generated_at decodes to the
// fixed UTC instant AND is encoded exactly as Go's time.Time marshaller
// produces it (precision-drift wall).
func TestTelemetryGoldenFixtureDeliveryIdentity(t *testing.T) {
	w := decodeTelemetryGoldenFixture(t)

	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(w.SampleEpoch) {
		t.Errorf("sample_epoch %q is not exactly 32 lowercase hex characters", w.SampleEpoch)
	}
	if w.SampleEpoch != telemetryGoldenFixtureEpoch {
		t.Errorf("sample_epoch = %q, fixed fixture input = %q", w.SampleEpoch, telemetryGoldenFixtureEpoch)
	}
	if w.Sequence != telemetryGoldenFixtureSequence {
		t.Errorf("sequence = %d, want %d", w.Sequence, telemetryGoldenFixtureSequence)
	}

	if !w.GeneratedAt.Equal(telemetryGoldenFixtureInstant()) {
		t.Errorf("generated_at = %v, want %v", w.GeneratedAt, telemetryGoldenFixtureInstant())
	}
	if _, off := w.GeneratedAt.Zone(); off != 0 {
		t.Errorf("generated_at decoded with a non-UTC zone offset %d", off)
	}

	// RAW encoding — catches a precision/format drift that still decodes to
	// the same instant.
	var rawTop struct {
		GeneratedAt json.RawMessage `json:"generated_at"`
	}
	if err := json.Unmarshal(readTelemetryGoldenFixture(t), &rawTop); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	wantRaw := `"` + telemetryGoldenFixtureGeneratedAtRaw + `"`
	if string(rawTop.GeneratedAt) != wantRaw {
		t.Errorf("generated_at raw encoding = %s, want %s — Go's time.Time JSON representation drifted", rawTop.GeneratedAt, wantRaw)
	}
	// And prove that IS what Go produces for the fixed instant, rather than a
	// literal we merely agreed with.
	goRaw, err := json.Marshal(telemetryGoldenFixtureInstant())
	if err != nil {
		t.Fatalf("marshal fixed instant: %v", err)
	}
	if string(goRaw) != wantRaw {
		t.Errorf("Go marshals the fixed instant as %s, fixture records %s", goRaw, wantRaw)
	}
}

// ─── 6. Recorded SHA-256 (the cross-repository copy contract) ───────────────

// TestTelemetryGoldenFixtureSHA256MatchesRecordedMetadata proves the recorded
// digest describes the bytes actually on disk. The tac-platform copy verifies
// this same digest, so a drift here means the two repositories have silently
// diverged.
func TestTelemetryGoldenFixtureSHA256MatchesRecordedMetadata(t *testing.T) {
	sum := sha256.Sum256(readTelemetryGoldenFixture(t))
	got := hex.EncodeToString(sum[:])
	if got != telemetryGoldenFixtureSHA256 {
		t.Fatalf("fixture SHA-256 = %s, recorded contract metadata = %s.\n"+
			"Regenerate with %s=1 go test -run TestTelemetryGoldenFixtureRegenerate . and update BOTH the constant here and the %s copy.",
			got, telemetryGoldenFixtureSHA256, telemetryGoldenFixtureRegenerateEnv, telemetryGoldenFixtureProducerRepo)
	}
	// The producer bytes must hash to the same value (byte-equality is proven
	// separately; this makes the digest a property of the PRODUCER, not just
	// of a file that happens to sit in the tree).
	prod := sha256.Sum256(telemetryGoldenFixtureBytes(t))
	if hex.EncodeToString(prod[:]) != telemetryGoldenFixtureSHA256 {
		t.Fatalf("producer output SHA-256 = %s, recorded = %s", hex.EncodeToString(prod[:]), telemetryGoldenFixtureSHA256)
	}
}

// TestTelemetryGoldenFixtureContractMetadataIsWellFormed sanity-checks the
// recorded cross-repository metadata itself (no placeholder left behind, digest
// shapes correct, baseline SHA present).
func TestTelemetryGoldenFixtureContractMetadataIsWellFormed(t *testing.T) {
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex40 := regexp.MustCompile(`^[0-9a-f]{40}$`)
	if !hex64.MatchString(telemetryGoldenFixtureSHA256) {
		t.Errorf("telemetryGoldenFixtureSHA256 = %q is not 64 lowercase hex characters", telemetryGoldenFixtureSHA256)
	}
	if !hex64.MatchString(telemetryGoldenFixtureRegistryHash) {
		t.Errorf("telemetryGoldenFixtureRegistryHash = %q is not 64 lowercase hex characters", telemetryGoldenFixtureRegistryHash)
	}
	if !hex40.MatchString(telemetryGoldenFixtureProducerBaseline) {
		t.Errorf("telemetryGoldenFixtureProducerBaseline = %q is not a 40-character git SHA", telemetryGoldenFixtureProducerBaseline)
	}
	if !regexp.MustCompile(`^v\d+$`).MatchString(telemetryGoldenFixtureVersion) {
		t.Errorf("fixture version %q is not a v<N> identifier", telemetryGoldenFixtureVersion)
	}
	if telemetryGoldenFixtureProducerRepo != "KidCarmi/Culvert" {
		t.Errorf("producer repo = %q — Culvert owns the inner plaintext fixture", telemetryGoldenFixtureProducerRepo)
	}
	// The fixture must live under its versioned path so a v2 variant cannot
	// silently overwrite v1's bytes.
	if want := "testdata/telemetry/" + telemetryGoldenFixtureVersion + "/inner_sample.json"; telemetryGoldenFixtureRelPath != want {
		t.Errorf("fixture path %q is not the versioned path %q", telemetryGoldenFixtureRelPath, want)
	}
}

// TestTelemetryGoldenFixtureNoOrphanedVersionDirectory proves the on-disk set
// of fixture versions equals the ONE version this file governs.
//
// The versioned path exists so a future v2 cannot silently overwrite v1's
// bytes — but there is a single constant set here, so introducing v2 means
// MOVING the pointer, not adding a second fixture. Without this wall, v1 would
// then rot in-tree: no Culvert test would read it, nothing would flag it, and a
// TAC engineer could keep copying the orphaned v1 bytes from a README that
// still says Culvert owns them. Failing here forces a v2 author to either
// delete v1 or promote these constants to a per-version table.
func TestTelemetryGoldenFixtureNoOrphanedVersionDirectory(t *testing.T) {
	root := filepath.Join(pkgSourceDir(), "testdata", "telemetry")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	var found []string
	for _, e := range entries {
		// Skip dot-prefixed entries so a developer's dirty tree (editor state,
		// tool caches) fails the build for the right reasons, not this one.
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			found = append(found, e.Name())
		}
	}
	sort.Strings(found)
	want := []string{telemetryGoldenFixtureVersion}
	if !reflect.DeepEqual(found, want) {
		t.Errorf("testdata/telemetry contains version directories %v, but this file governs exactly %v — an orphaned fixture version is one nothing verifies and the consuming repository may still be copying",
			found, want)
	}
}

// telemetryGoldenFixtureREADMEPath is the consumer-facing copy of the contract
// metadata — the document a tac-platform reviewer reads to learn which digest
// to verify.
var telemetryGoldenFixtureREADMEPath = "testdata/telemetry/" + telemetryGoldenFixtureVersion + "/README.md"

// TestTelemetryGoldenFixtureREADMEMatchesRecordedMetadata is the single-source-
// of-truth wall between the Go constants and the fixture's README (same shape
// as TestReleaseIdentitySSOT / TestInstallScriptPinsSameReleaseIdentity).
//
// Without it the README is a THIRD, unasserted copy of the contract: a
// regeneration could update both constants, go fully green, and leave the
// consumer-facing document pointing the other repository at a stale digest —
// exactly the silent cross-repository divergence this slice exists to prevent.
func TestTelemetryGoldenFixtureREADMEMatchesRecordedMetadata(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(pkgSourceDir(), filepath.FromSlash(telemetryGoldenFixtureREADMEPath)))
	if err != nil {
		t.Fatalf("read %s: %v", telemetryGoldenFixtureREADMEPath, err)
	}
	readme := string(b)
	for _, want := range []struct{ what, value string }{
		{"fixture SHA-256", telemetryGoldenFixtureSHA256},
		{"registry hash", telemetryGoldenFixtureRegistryHash},
		{"producer baseline SHA", telemetryGoldenFixtureProducerBaseline},
		{"producer repository", telemetryGoldenFixtureProducerRepo},
		{"sample_epoch", telemetryGoldenFixtureEpoch},
		{"generated_at", telemetryGoldenFixtureGeneratedAtRaw},
		{"byte size", fmt.Sprintf("%d bytes", len(readTelemetryGoldenFixture(t)))},
		// Whole table ROWS, not bare numbers: `strings.Contains(readme, "`3`")`
		// would match almost any Markdown and make the assertion a no-op.
		{"schema_version row", fmt.Sprintf("| `schema_version` | `%d` |", telemetryGoldenFixtureSchemaVersion)},
		{"sequence row", fmt.Sprintf("| `sequence` | `%d` |", telemetryGoldenFixtureSequence)},
		{"fixture version row", fmt.Sprintf("| Fixture version | `%s` |", telemetryGoldenFixtureVersion)},
	} {
		if !strings.Contains(readme, want.value) {
			t.Errorf("%s does not record the current %s (%q) — regenerate updated the constants but not the consumer-facing document",
				telemetryGoldenFixtureREADMEPath, want.what, want.value)
		}
	}
}

// ─── 7. Determinism + immutability ──────────────────────────────────────────

// TestTelemetryGoldenFixtureGenerationIsDeterministic — repeated generation
// with the same fixed inputs yields byte-identical output. Covers Go map-key
// ordering (encoding/json sorts map keys) and any hidden per-run state.
func TestTelemetryGoldenFixtureGenerationIsDeterministic(t *testing.T) {
	first := telemetryGoldenFixtureBytes(t)
	for i := 0; i < 32; i++ {
		if got := telemetryGoldenFixtureBytes(t); !bytes.Equal(first, got) {
			t.Fatalf("fixture generation is non-deterministic on iteration %d:\nfirst: %s\ngot:   %s", i, first, got)
		}
	}
	// Explicit map-order proof: the metric keys appear in sorted order in the
	// raw bytes, which is what makes repeated marshals stable.
	var top struct {
		Metrics map[string]json.RawMessage `json:"metrics"`
	}
	if err := json.Unmarshal(first, &top); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ids := make([]string, 0, len(top.Metrics))
	for id := range top.Metrics {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	pos := -1
	for _, id := range ids {
		at := bytes.Index(first, []byte(`"`+id+`":`))
		if at <= pos {
			t.Errorf("metric ids are not in sorted order in the encoded bytes (%q at %d, previous at %d)", id, at, pos)
		}
		pos = at
	}
}

// TestTelemetryGoldenFixtureMetricsCopyCannotAffectBytes proves a caller
// mutating the defensive copy returned by Sample.Metrics() cannot change what
// the sample serializes — so no test (or future sender) can corrupt the fixture
// through that accessor.
func TestTelemetryGoldenFixtureMetricsCopyCannotAffectBytes(t *testing.T) {
	sample := telemetryGoldenFixtureSample(t)
	before, err := json.Marshal(sample)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	m := sample.Metrics()
	for k := range m {
		m[k] = -12345
		delete(m, k)
	}
	m["support_health_injected"] = 999

	after, err := json.Marshal(sample)
	if err != nil {
		t.Fatalf("marshal after mutation: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("mutating a Metrics() copy changed the serialized sample:\nbefore: %s\nafter:  %s", before, after)
	}
	if !bytes.Equal(after, readTelemetryGoldenFixture(t)) {
		t.Fatal("sample no longer matches the fixture after a Metrics() copy was mutated")
	}
}

// ─── 8. Regeneration is explicit opt-in and never runs in CI ────────────────

// writeTelemetryGoldenFixture writes the REAL repository fixture. It is a thin
// wrapper so that the negative test (which must prove the guards refuse) can
// aim writeTelemetryGoldenFixtureTo at a throwaway path instead: every guard
// lives inside the function under test, so a refactor that broke one would
// otherwise have destroyed the checked-in fixture as its first symptom — and
// under -shuffle=on the resulting cascade of failures would be order-dependent.
func writeTelemetryGoldenFixture(b []byte) error {
	return writeTelemetryGoldenFixtureTo(telemetryGoldenFixtureAbsPath(), b)
}

// writeTelemetryGoldenFixtureTo is the ONE writer on the A1 surface. It
// hard-refuses unless the developer explicitly opted in AND the run is not
// automated — so even a direct call from a stray test cannot rewrite a
// repository file during an ordinary run.
func writeTelemetryGoldenFixtureTo(path string, b []byte) error {
	if !telemetryGoldenFixtureOptedIn() {
		return fmt.Errorf("refusing to write %s: regeneration is explicit opt-in only (set %s=1)",
			path, telemetryGoldenFixtureRegenerateEnv)
	}
	for _, env := range telemetryGoldenFixtureCIEnvs {
		if os.Getenv(env) != "" {
			return fmt.Errorf("refusing to write %s: %s is set, so this is an automated run — golden fixtures are regenerated deliberately by a developer, never by CI",
				path, env)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create fixture directory: %w", err)
	}
	// 0600 on CREATE only (os.WriteFile leaves an existing file's mode
	// alone, and git does not track non-exec bits) — the fixture is public,
	// non-secret data, so the restrictive mode costs nothing.
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write fixture: %w", err)
	}
	return nil
}

// TestTelemetryGoldenFixtureRegenerate is the explicit developer command:
//
//	CULVERT_TELEMETRY_FIXTURE_REGENERATE=1 go test -run TestTelemetryGoldenFixtureRegenerate .
//
// It writes the deterministic producer bytes and prints the new contract
// metadata. It SKIPS (never writes) without the opt-in, so ordinary `go test`
// runs — including `./...`, `-count=2`, `-shuffle=on`, and `-race` — can never
// rewrite a repository file.
func TestTelemetryGoldenFixtureRegenerate(t *testing.T) {
	if !telemetryGoldenFixtureOptedIn() {
		t.Skipf("golden-fixture regeneration is opt-in: %s=1 go test -run %s .",
			telemetryGoldenFixtureRegenerateEnv, t.Name())
	}
	for _, env := range telemetryGoldenFixtureCIEnvs {
		if os.Getenv(env) != "" {
			t.Fatalf("%s is set — golden fixtures must never be regenerated by an automated run", env)
		}
	}

	b := telemetryGoldenFixtureBytes(t)
	// Determinism guard BEFORE writing: never persist bytes we cannot
	// reproduce.
	if again := telemetryGoldenFixtureBytes(t); !bytes.Equal(b, again) {
		t.Fatalf("refusing to write a non-deterministic fixture:\n%s\nvs\n%s", b, again)
	}
	if err := writeTelemetryGoldenFixture(b); err != nil {
		t.Fatalf("%v", err)
	}

	sum := sha256.Sum256(b)
	t.Logf(`
golden fixture regenerated: %s (%d bytes)

  fixture version   : %s
  producer repo     : %s
  schema_version    : %d
  registry_hash     : %s
  fixture sha256    : %s

UPDATE, IN THIS SAME COMMIT:
  1. telemetryGoldenFixtureSHA256           in %s
  2. telemetryGoldenFixtureRegistryHash     in %s
  3. telemetryGoldenFixtureSchemaVersion    (only if SchemaVersion was bumped)
  4. telemetryGoldenFixtureProducerBaseline (the main SHA whose registry schema
                                             produced these bytes)
  5. %s                                     (recorded metadata table)

THEN RE-RUN THE VERIFICATION TESTS — this command runs the WRITER ONLY:
  go test -run TestTelemetryGoldenFixture .

THEN, AS A COORDINATED CROSS-REPOSITORY CHANGE:
  the copied fixture bytes AND the recorded SHA-256 in the consuming
  tac-platform telemetry-gateway contract MUST be updated in the same change.
  A wire-shape/registry-schema change is a CONTRACT change, not a local edit.
`,
		telemetryGoldenFixtureRelPath, len(b),
		telemetryGoldenFixtureVersion, telemetryGoldenFixtureProducerRepo,
		supportmetrics.SchemaVersion, supportMetricRegistry.Hash(), hex.EncodeToString(sum[:]),
		telemetryGoldenFixtureTestFile, telemetryGoldenFixtureTestFile, telemetryGoldenFixtureREADMEPath)
}

// TestTelemetryGoldenFixtureWriteRefusesWithoutOptIn proves the writer refuses
// (and writes nothing) without the opt-in, and refuses even WITH the opt-in
// when a CI marker is present.
// MUST NOT call t.Parallel(): t.Setenv would panic, and more importantly this
// test briefly makes the opt-in env var true PROCESS-WIDE. Go only guarantees
// that serial top-level tests finish before parallel ones resume, so a parallel
// sibling could otherwise observe the opt-in and write for real.
func TestTelemetryGoldenFixtureWriteRefusesWithoutOptIn(t *testing.T) {
	before := readTelemetryGoldenFixture(t)
	// Deliberately NOT the real fixture path: a broken guard must fail this
	// test, not destroy the repository artifact every other test reads.
	target := filepath.Join(t.TempDir(), "inner_sample.json")

	for _, env := range telemetryGoldenFixtureCIEnvs {
		t.Setenv(env, "")
	}
	// Unset, DISABLED, and unrecognized values must all refuse. A bare
	// presence check would read "0"/"false" as consent and rewrite the
	// repository fixture during an ordinary `go test ./...`.
	for _, v := range []string{"", "0", "false", "no", "off", "FALSE", " 0 ", "maybe", "2"} {
		t.Setenv(telemetryGoldenFixtureRegenerateEnv, v)
		if telemetryGoldenFixtureOptedIn() {
			t.Errorf("%s=%q must NOT count as an opt-in", telemetryGoldenFixtureRegenerateEnv, v)
		}
		if err := writeTelemetryGoldenFixtureTo(target, []byte("corrupted")); err == nil {
			t.Errorf("the writer must refuse when %s=%q", telemetryGoldenFixtureRegenerateEnv, v)
		}
	}
	// The documented affirmative spellings DO opt in.
	for _, v := range []string{"1", "true", "yes", "on", "TRUE", " 1 "} {
		t.Setenv(telemetryGoldenFixtureRegenerateEnv, v)
		if !telemetryGoldenFixtureOptedIn() {
			t.Errorf("%s=%q must count as an opt-in", telemetryGoldenFixtureRegenerateEnv, v)
		}
	}

	t.Setenv(telemetryGoldenFixtureRegenerateEnv, "1")
	for _, env := range telemetryGoldenFixtureCIEnvs {
		t.Setenv(env, "true")
		if err := writeTelemetryGoldenFixtureTo(target, []byte("corrupted")); err == nil {
			t.Errorf("the writer must refuse when %s is set, even with the opt-in", env)
		}
		t.Setenv(env, "")
	}

	if _, err := os.Stat(target); err == nil {
		t.Error("a refused write still created the target file")
	}
	if after := readTelemetryGoldenFixture(t); !bytes.Equal(before, after) {
		t.Fatal("a refused write still modified the fixture file")
	}
}

// TestTelemetryGoldenFixtureNormalRunDoesNotModifyIt exercises every read-path
// helper in this file between two stat/read samples and proves NONE of them
// writes. It is the behavioral half of the claim only — the file-wide guarantee
// that no OTHER function can write either is
// TestTelemetryGoldenFixtureOnlyTheOptInHelperWrites (static, order-independent).
func TestTelemetryGoldenFixtureNormalRunDoesNotModifyIt(t *testing.T) {
	if telemetryGoldenFixtureOptedIn() {
		t.Skipf("%s is set — this run is an explicit regeneration", telemetryGoldenFixtureRegenerateEnv)
	}
	path := telemetryGoldenFixtureAbsPath()
	statBefore, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	before := readTelemetryGoldenFixture(t)

	// Exercise every non-regeneration code path in this file.
	_ = telemetryGoldenFixtureBytes(t)
	_ = decodeTelemetryGoldenFixture(t)
	_ = telemetryGoldenFixtureAllJSONKeys(t)
	_ = telemetryGoldenFixtureRegistry(t).Hash()
	_ = telemetryGoldenFixtureSample(t).Metrics()

	statAfter, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat fixture after: %v", err)
	}
	if !statAfter.ModTime().Equal(statBefore.ModTime()) {
		t.Errorf("fixture modification time changed during an ordinary test run: %v → %v", statBefore.ModTime(), statAfter.ModTime())
	}
	if statAfter.Size() != statBefore.Size() {
		t.Errorf("fixture size changed during an ordinary test run: %d → %d", statBefore.Size(), statAfter.Size())
	}
	if !bytes.Equal(before, readTelemetryGoldenFixture(t)) {
		t.Error("fixture bytes changed during an ordinary test run")
	}
}

// TestTelemetryGoldenFixtureOnlyTheOptInHelperWrites is the static counterpart:
// an AST walk proving no filesystem-mutating os.* call exists anywhere in this
// file outside writeTelemetryGoldenFixture. Without this, a future helper could
// add a "convenience" write that silently rewrites the fixture during a normal
// run.
func TestTelemetryGoldenFixtureOnlyTheOptInHelperWrites(t *testing.T) {
	mutators := map[string]bool{
		"WriteFile": true, "Create": true, "CreateTemp": true, "OpenFile": true,
		"Remove": true, "RemoveAll": true, "Rename": true, "Truncate": true,
		"Mkdir": true, "MkdirAll": true, "Chmod": true, "Chown": true,
		"Symlink": true, "Link": true, "OpenRoot": true,
	}
	seenWriter := false
	for _, path := range a1SourceFiles(t) {
		name := filepath.Base(path)
		f := parseA1Source(t, path)
		// Inspect the WHOLE file, not only function bodies — a package-level
		// `var _ = os.WriteFile(…)` would otherwise be invisible. enclosingFunc
		// returns "" for such a declaration, which is never the writer, so it
		// is reported.
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "os" || !mutators[sel.Sel.Name] {
				return true
			}
			in := enclosingFunc(f, call.Pos())
			if in != telemetryGoldenFixtureWriterFunc {
				where := in
				if where == "" {
					where = "a package-level declaration"
				}
				t.Errorf("%s: os.%s in %s — only %s may touch the filesystem, so an ordinary test run can never rewrite the fixture",
					name, sel.Sel.Name, where, telemetryGoldenFixtureWriterFunc)
			}
			return true
		})
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == telemetryGoldenFixtureWriterFunc {
				seenWriter = true
			}
		}
	}
	if !seenWriter {
		t.Fatalf("%s not found on the A1 surface — the writer wall is not actually guarding anything", telemetryGoldenFixtureWriterFunc)
	}
}

// parseA1Source parses one A1 source file with comments discarded.
func parseA1Source(t *testing.T, path string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return f
}

// enclosingFunc names the top-level function containing pos, or "" when pos is
// in a package-level declaration.
func enclosingFunc(f *ast.File, pos token.Pos) string {
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Pos() <= pos && pos <= fn.End() {
			return fn.Name.Name
		}
	}
	return ""
}

// ─── 9. A1 no-egress wall ───────────────────────────────────────────────────

// a1ForbiddenIdents are the outer-envelope / sealing / delivery-machinery
// identifiers that must not appear as CODE on the A1 surface.
//
// They are written verbatim — not concatenated — because the scan runs over
// blankA1Literals'd source, where every string literal and comment (including
// this table and this comment) is already erased. Concatenation was the earlier
// workaround for the self-match problem; blanking solves it properly, and it
// solves it in the fail-CLOSED direction: if blanking ever broke, the wall
// would match its own table and fail loudly rather than silently stop
// detecting anything.
func a1ForbiddenIdents() []string {
	return []string{
		"sealTelemetry", "telemetrySpool", "telemetryPending",
		"telemetrySender", "telemetryWorker", "deliveryStatus",
		"EnvelopeVersion", "ciphertextSha256", "ciphertextSHA256",
		"backoffFor(", "retryAfter(",
	}
}

// TestTelemetryGoldenFixtureA1HasNoEgress extends the M7 no-egress architecture
// wall to the A1 fixture surface WITHOUT weakening the existing Slice 1/2 walls
// (support_telemetry_noegress_test.go, whose marker table this reuses by
// reference rather than duplicating). A1 is a fixture + tests: no HTTP client,
// no dialer, no sender/worker loop, no retry/backoff, no outbound DNS, no spool
// file, no delivery status, no envelope sealing.
func TestTelemetryGoldenFixtureA1HasNoEgress(t *testing.T) {
	for _, path := range a1SourceFiles(t) {
		name := filepath.Base(path)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := blankA1Literals(t, name, b)
		for _, hit := range scanForIdents(src, telemetrySlice2OutboundIdents) {
			t.Errorf("%s contains outbound/background-worker/delivery marker %q — M7 Slice 2.5-A1 is a producer-owned fixture only, zero egress", name, hit)
		}
		// A1-specific: no outer-envelope/sealing/spool/delivery identifiers may
		// be introduced here either (those belong to Slice 3 / TAC 2.5-C).
		for _, hit := range scanForIdents(src, a1ForbiddenIdents()) {
			t.Errorf("%s references %q — outer envelope / sealing / delivery machinery is deferred (Slice 3, TAC 2.5-C)", name, hit)
		}
	}

	// And the fixture DATA itself must stay a pure inner plaintext. Note this
	// checks for a URL SCHEME, not the bare substring "http": a future eligible
	// metric named e.g. support_health_http_listener_ready is legal under
	// supportmetrics.idPattern, and failing it with "URL-shaped value" would be
	// simply false.
	fixture := string(readTelemetryGoldenFixture(t))
	for _, banned := range telemetryGoldenFixtureOuterEnvelopeFields {
		if strings.Contains(fixture, banned) {
			t.Errorf("fixture bytes mention outer-envelope field %q", banned)
		}
	}
	if strings.Contains(fixture, "://") {
		t.Error("fixture bytes contain a URL-shaped value — the inner plaintext is scalars only")
	}
}

// blankA1Literals returns src with every COMMENT and string/char LITERAL
// replaced by spaces (newlines preserved, so offsets and line numbers stay
// aligned). The A1 no-egress wall scans its own file, so without this a marker
// table — or a doc comment that merely NAMES a marker — makes the wall match
// itself. The earlier workaround (assembling markers by concatenation) hid that
// hazard rather than removing it, and it silently deleted coverage the moment a
// marker had to be spelled out elsewhere. Blanking removes the hazard at the
// source: only real CODE is scanned.
func blankA1Literals(t *testing.T, name string, src []byte) string {
	t.Helper()
	out := make([]byte, len(src))
	copy(out, src)

	fset := token.NewFileSet()
	file := fset.AddFile(name, fset.Base(), len(src))
	var sc scanner.Scanner
	sc.Init(file, src, func(pos token.Position, msg string) {
		t.Fatalf("scan %s: %s: %s", name, pos, msg)
	}, scanner.ScanComments)

	for {
		pos, tok, lit := sc.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.COMMENT && tok != token.STRING && tok != token.CHAR {
			continue
		}
		off := file.Offset(pos)
		for i := off; i < off+len(lit) && i < len(out); i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	return string(out)
}

// TestTelemetryGoldenFixtureA1ScannerSeesCodeNotLiterals is the positive
// control for blankA1Literals — the wall's correctness rests entirely on it
// doing BOTH halves of its job, and a blanker that erased everything would make
// every scan pass vacuously.
func TestTelemetryGoldenFixtureA1ScannerSeesCodeNotLiterals(t *testing.T) {
	const synthetic = `package p

// leaked in a comment: telemetrySender
var table = []string{"telemetrySpool", "EnvelopeVersion"}

func f() { telemetrySender() }
`
	got := blankA1Literals(t, "synthetic.go", []byte(synthetic))

	// Real code IS seen.
	if hits := scanForIdents(got, []string{"telemetrySender"}); len(hits) != 1 {
		t.Errorf("blankA1Literals hid a real code reference — the wall would detect nothing (blanked source: %q)", got)
	}
	// String literals and comments are NOT seen.
	for _, hidden := range []string{"telemetrySpool", "EnvelopeVersion"} {
		if hits := scanForIdents(got, []string{hidden}); len(hits) != 0 {
			t.Errorf("blankA1Literals left %q visible — the wall would match its own marker table and fail always", hidden)
		}
	}
	// Line count is preserved so failure messages stay locatable.
	if a, b := strings.Count(synthetic, "\n"), strings.Count(got, "\n"); a != b {
		t.Errorf("blankA1Literals changed the line count: %d → %d", a, b)
	}
}

// scanForIdents returns every ident that occurs in src, in table order.
func scanForIdents(src string, idents []string) []string {
	var hits []string
	for _, id := range idents {
		if strings.Contains(src, id) {
			hits = append(hits, id)
		}
	}
	return hits
}

// TestTelemetryGoldenFixtureA1MarkerTableIsEffective is the positive control
// for the wall above. A marker table is invisible when it is wrong: a typo, an
// empty entry, or a duplicate silently removes coverage while every test stays
// green. This proves the scanner actually FIRES on a synthetic source
// containing each marker — a scan that finds nothing in the positive control is
// a broken wall, not a clean one.
func TestTelemetryGoldenFixtureA1MarkerTableIsEffective(t *testing.T) {
	idents := a1ForbiddenIdents()
	if len(idents) == 0 {
		t.Fatal("a1ForbiddenIdents is empty — the A1-specific wall would silently pass anything")
	}
	seen := map[string]bool{}
	var synthetic strings.Builder
	for _, id := range idents {
		if strings.TrimSpace(id) == "" {
			t.Error("a1ForbiddenIdents contains an empty marker — it would match every file")
			continue
		}
		if seen[id] {
			t.Errorf("marker %q is duplicated in a1ForbiddenIdents", id)
		}
		seen[id] = true
		synthetic.WriteString("leaked marker: " + id + "\n")
	}
	if got := scanForIdents(synthetic.String(), idents); len(got) != len(idents) {
		t.Fatalf("the scanner found %d of %d markers in the positive control — the wall cannot detect what it claims to (found %v)", len(got), len(idents), got)
	}
	// Same proof for the reused Slice-1/2 table.
	var slice2 strings.Builder
	for _, id := range telemetrySlice2OutboundIdents {
		slice2.WriteString("leaked marker: " + id + "\n")
	}
	if got := scanForIdents(slice2.String(), telemetrySlice2OutboundIdents); len(got) != len(telemetrySlice2OutboundIdents) {
		t.Fatalf("the scanner found %d of %d Slice-1/2 outbound markers in the positive control", len(got), len(telemetrySlice2OutboundIdents))
	}
}

// a1ForbiddenDeclNames are the outer-envelope (§3.2) field names that must not
// appear as a Go struct field anywhere on the A1 surface.
var a1ForbiddenDeclNames = map[string]bool{
	"KeyID": true, "KeyId": true, "Ciphertext": true, "CiphertextSHA256": true,
	"CiphertextSha256": true, "Algorithm": true, "EnvelopeVersion": true,
	"SampleID": true, "SampleId": true, "Sealed": true, "Nonce": true,
	"RecipientKey": true, "BearerCredential": true,
}

// a1ForbiddenFuncPrefixes are verb prefixes that would mean this surface grew
// delivery or sealing behavior.
var a1ForbiddenFuncPrefixes = regexp.MustCompile(`(?i)^(seal|unseal|send|upload|dispatch|spool|flush|post|dial|transmit|deliver|enqueue|encrypt)`)

// TestTelemetryGoldenFixtureA1HasNoEnvelopeOrSenderShape closes the gap a pure
// text scan leaves open: an outer-envelope TYPE or an in-memory seal helper
// contains no http/net/dial/sleep marker at all, so the string-based wall would
// not see it, and the data-side walls only inspect the fixture JSON. Slice-3 /
// TAC 2.5-C envelope MODELING could therefore land here silently.
//
// This works on the AST, so it sees declarations rather than text — catching
// the shapes a text scan cannot express (a field named Ciphertext, a func named
// sealX) regardless of how they are spelled.
func TestTelemetryGoldenFixtureA1HasNoEnvelopeOrSenderShape(t *testing.T) {
	for _, path := range a1SourceFiles(t) {
		name := filepath.Base(path)
		f := parseA1Source(t, path)
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.FuncDecl:
				if a1ForbiddenFuncPrefixes.MatchString(v.Name.Name) {
					t.Errorf("%s declares %s() — sealing/delivery behavior is deferred to Slice 3 / TAC 2.5-C, not A1", name, v.Name.Name)
				}
			case *ast.StructType:
				for _, fld := range v.Fields.List {
					for _, id := range fld.Names {
						if a1ForbiddenDeclNames[id.Name] {
							t.Errorf("%s declares a struct field %q — that is an outer transport-envelope (§3.2) field; A1 is the inner plaintext only", name, id.Name)
						}
					}
				}
			}
			return true
		})
	}
}
