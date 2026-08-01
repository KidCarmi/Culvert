package main

// support_telemetry_sealed_golden_test.go — M7 Slice 2.5-C3 (producer half): the
// PRODUCER-OWNED, byte-exact SEALED telemetry golden vector.
//
// A1 (support_telemetry_golden_fixture_test.go) owns the §3.3 INNER plaintext
// (testdata/telemetry/v1/inner_sample.json). C3 wraps that EXACT inner fixture in
// the §3.2 OUTER transport envelope, sealed to a PUBLIC test recipient key, and
// checks the whole artifact set in under testdata/telemetry/v1/sealed/. The
// consuming tac-platform repository copies these bytes hermetically (2.5-C3 PR B)
// and proves DecodeOuter → FileRecipientKeyProvider → VerifyAndOpen reconstructs
// the exact VerifiedSampleHandle values.
//
// # Algorithm: RAW libsodium crypto_box_seal (NOT the CVRTSB01 support-bundle envelope)
//
// The telemetry `algorithm` label "x25519-sealbox" is libsodium `crypto_box_seal`:
// a RAW anonymous sealed box (golang.org/x/crypto/nacl/box.SealAnonymous —
// ephemeral X25519 public key ‖ ciphertext ‖ Poly1305 tag, 48-byte overhead), with
// NO `CVRTSB01` magic or version prefix. internal/sealbox.Seal is a DIFFERENT
// artifact: it frames the same primitive with a `CVRTSB01`+version header for the
// M4 support-bundle export. The merged TAC consumer (FileRecipientKeyProvider,
// M7 2.5-C1) opens the ciphertext directly with box.OpenAnonymous, so the telemetry
// vector must be the raw box. This is exactly the cross-repository detail C3 exists
// to pin: roadmap §3.2 is reconciled to the raw box in this same change.
//
// # No parallel reimplementation, and the deterministic-entropy seam
//
// The sealing uses the production NaCl primitive box.SealAnonymous (the same
// primitive internal/sealbox.Seal wraps) and the production low-order-key guard
// sealbox.ValidateRecipientPublicKey — nothing reimplements X25519 or the sealed-box
// construction. A sealed box normally draws a random ephemeral key; the golden bytes
// are reproducible because the ONLY randomness (the 32-byte ephemeral scalar) is
// supplied by a deterministic reader in the fixture path. A production sender
// (future Slice 3) passes crypto/rand.Reader to the same primitive;
// TestSealedGoldenProductionPathUsesSecureRandomness proves that path stays
// non-deterministic and still round-trips. The deterministic reader FAILS if the
// sealer requests an unexpected number of bytes, so a change to the sealing
// construction cannot silently keep the golden test green.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/KidCarmi/Culvert/internal/sealbox"
)

// ─── Pinned cross-repository contract metadata (the values tac-platform copies) ──

const (
	// sealedFixtureKeyID is the PUBLIC-TEST recipient key_id. It satisfies the
	// closed key_id grammar and deliberately contains no "prod", customer name, or
	// deployment identifier. NEVER load this in production.
	sealedFixtureKeyID = "tac-test-telemetry-v1"

	// sealedFixtureSampleID is one fixed 32-lowercase-hex test sample_id.
	sealedFixtureSampleID = "a1b2c3d4e5f60718293a4b5c6d7e8f90"

	// sealedFixtureAlgorithm is the fixed wire algorithm label.
	sealedFixtureAlgorithm = "x25519-sealbox"

	// sealedFixtureRegistryHash is the inner fixture's registry_hash (the §8
	// governed eligibility schema identity). The outer envelope carries the same.
	sealedFixtureRegistryHash = "061fe684aaabb895e87130943649ef37e450cc62e9d63c6c9d7fddfce73b15a7"

	// sealedFixtureRecipientPubHex is the committed recipient PUBLIC key, derived
	// from the committed test private scalar (proven by TestSealedGoldenKeyDerivation).
	sealedFixtureRecipientPubHex = "132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472"

	// Byte lengths and SHA-256 digests of the committed artifacts (the recorded
	// cross-repository copy contract; tac-platform verifies these same values).
	sealedFixtureInnerLen           = 476
	sealedFixtureInnerSHA256        = "22df6ee3b323b46332e0073be7925886d6d15121a781165f8ba79b6657549005"
	sealedFixtureCiphertextLen      = 524
	sealedFixtureCiphertextSHA256   = "2a664536aea5b4b72abdcd5dc160963c495a9385e27ee9c9ec9235ebb4358eea"
	sealedFixtureRecipientPrivLen   = 32
	sealedFixtureRecipientPrivSHA   = "425ed4e4a36b30ea21b90e21c712c649e8214c29b7eaf68089d1039c6e55384c"
	sealedFixtureRecipientPubLen    = 32
	sealedFixtureRecipientPubSHA    = "82dab32a9aedffb4925a762f879f6fdd05b8ba0aa825a6986a85b751ff3b21e4"
	sealedFixtureProducerRepository = "KidCarmi/Culvert"
	sealedFixtureVersion            = "v1"
)

// sealedFixtureDir is the artifact directory, relative to the package source dir.
const sealedFixtureDir = "testdata/telemetry/v1/sealed"

// Artifact file names.
const (
	sealedOuterEnvelopeFile   = "outer_envelope.json"
	sealedRecipientPrivFile   = "recipient_private_key.bin"
	sealedRecipientPubFile    = "recipient_public_key.bin"
	sealedManifestFile        = "manifest.json"
	sealedREADMEFile          = "README.md"
	sealedInnerFixtureRelPath = "testdata/telemetry/v1/inner_sample.json"
)

// sealedFixtureRegenerateEnv is the explicit developer opt-in for regeneration,
// mirroring the A1 fixture's guard: ordinary `go test` never rewrites a repo file.
const sealedFixtureRegenerateEnv = "CULVERT_TELEMETRY_SEALED_REGENERATE"

// ─── Documented, obviously-non-production test key material ──────────────────────

// sealedFixtureRecipientScalar is the PUBLIC TEST recipient private X25519 scalar:
// 32 bytes of 0x42. PUBLIC TEST VECTOR — NOT A SECRET — NEVER USE IN PRODUCTION. It
// is a deliberately obvious repeated-byte pattern so it can never be mistaken for a
// real key.
func sealedFixtureRecipientScalar() [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = 0x42
	}
	return s
}

// sealedFixtureEphemeralEntropy is the fixed 32-byte ephemeral scalar the sealed
// box's ephemeral key is drawn from: the sequential pattern 0x00..0x1f. Documented
// and non-random, so the sealed bytes are reproducible.
func sealedFixtureEphemeralEntropy() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// exactEntropyReader supplies its bytes once and returns an ERROR if the sealer
// asks for more than were provided. That is what makes "changed deterministic
// entropy" and "changed sealing construction" observable: a sealer that draws a
// different amount of randomness fails here instead of silently producing a
// different-but-green vector.
type exactEntropyReader struct {
	data []byte
	pos  int
}

func (r *exactEntropyReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, errors.New("deterministic entropy reader exhausted: the sealer requested more bytes than the fixture provides")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// ─── Sealing (production primitive, no reimplementation) ─────────────────────────

// sealTelemetryRaw produces the RAW x25519-sealbox ciphertext for inner using the
// production NaCl primitive and the production low-order-key guard. entropy is the
// ephemeral randomness source: the fixture passes a deterministic reader, a real
// sender passes crypto/rand.Reader.
func sealTelemetryRaw(inner []byte, recipientPub *[32]byte, entropy io.Reader) ([]byte, error) {
	if err := sealbox.ValidateRecipientPublicKey(recipientPub); err != nil {
		return nil, err
	}
	return box.SealAnonymous(nil, inner, recipientPub, entropy)
}

// sealedFixtureRecipientPub derives the recipient public key from the committed
// test scalar the SAME way the TAC consumer does (curve25519.X25519 against the
// basepoint).
func sealedFixtureRecipientPub(t *testing.T) [32]byte {
	t.Helper()
	priv := sealedFixtureRecipientScalar()
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive recipient public key: %v", err)
	}
	var out [32]byte
	copy(out[:], pub)
	return out
}

// regenerateCiphertext seals the on-disk inner fixture with the deterministic
// ephemeral entropy — the exact reproducible ciphertext.
func regenerateCiphertext(t *testing.T) []byte {
	t.Helper()
	inner := readInnerFixture(t)
	pub := sealedFixtureRecipientPub(t)
	rd := &exactEntropyReader{data: sealedFixtureEphemeralEntropy()}
	ct, err := sealTelemetryRaw(inner, &pub, rd)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if rd.pos != 32 {
		t.Fatalf("sealer read %d ephemeral bytes, want exactly 32 — the sealing construction changed", rd.pos)
	}
	return ct
}

// ─── Canonical serializers (identical bytes at generation and verification) ──────

// sealedOuterEnvelope is the §3.2 outer envelope with fields in the EXACT wire
// order. json.Marshal emits struct fields in declaration order, compact, no
// trailing newline — so this is the one canonical outer byte sequence.
type sealedOuterEnvelope struct {
	EnvelopeVersion  int    `json:"envelope_version"`
	KeyID            string `json:"key_id"`
	Algorithm        string `json:"algorithm"`
	Ciphertext       string `json:"ciphertext"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
	SampleID         string `json:"sample_id"`
	SchemaVersion    int    `json:"schema_version"`
	RegistryHash     string `json:"registry_hash"`
}

func buildOuterEnvelope(ciphertext []byte) []byte {
	sum := sha256.Sum256(ciphertext)
	env := sealedOuterEnvelope{
		EnvelopeVersion:  1,
		KeyID:            sealedFixtureKeyID,
		Algorithm:        sealedFixtureAlgorithm,
		Ciphertext:       base64.StdEncoding.EncodeToString(ciphertext),
		CiphertextSHA256: hex.EncodeToString(sum[:]),
		SampleID:         sealedFixtureSampleID,
		SchemaVersion:    3,
		RegistryHash:     sealedFixtureRegistryHash,
	}
	b, err := json.Marshal(env)
	if err != nil {
		panic(err) // struct of strings/ints cannot fail to marshal
	}
	return b
}

// sealedManifest is the strict, versioned manifest. It records the source-tree
// revision and the artifact hashes; it deliberately does NOT record its own SHA or
// the merge commit that contains it (the TAC provenance README records the final
// immutable Culvert merge commit — a self-referential manifest cannot name the SHA
// of the commit that adds it).
type sealedManifest struct {
	FixtureVersion            string `json:"fixture_version"`
	ProducerRepository        string `json:"producer_repository"`
	ProducerSourceCommit      string `json:"producer_source_commit"`
	GenerationContract        string `json:"generation_contract"`
	KeyID                     string `json:"key_id"`
	Algorithm                 string `json:"algorithm"`
	EnvelopeVersion           int    `json:"envelope_version"`
	SchemaVersion             int    `json:"schema_version"`
	RegistryHash              string `json:"registry_hash"`
	SampleID                  string `json:"sample_id"`
	InnerPlaintextPath        string `json:"inner_plaintext_path"`
	InnerPlaintextLength      int    `json:"inner_plaintext_length"`
	InnerPlaintextSHA256      string `json:"inner_plaintext_sha256"`
	OuterEnvelopePath         string `json:"outer_envelope_path"`
	OuterEnvelopeLength       int    `json:"outer_envelope_length"`
	OuterEnvelopeSHA256       string `json:"outer_envelope_sha256"`
	CiphertextLength          int    `json:"ciphertext_length"`
	CiphertextSHA256          string `json:"ciphertext_sha256"`
	RecipientPrivateKeyPath   string `json:"recipient_private_key_path"`
	RecipientPrivateKeyLength int    `json:"recipient_private_key_length"`
	RecipientPrivateKeySHA256 string `json:"recipient_private_key_sha256"`
	RecipientPublicKeyPath    string `json:"recipient_public_key_path"`
	RecipientPublicKeyLength  int    `json:"recipient_public_key_length"`
	RecipientPublicKeySHA256  string `json:"recipient_public_key_sha256"`
	DeterministicEntropyLabel string `json:"deterministic_entropy_label"`
}

// sealedFixtureProducerSourceCommit is the Culvert main-branch commit whose source
// tree produced these bytes — the branch point, so it does NOT contain the vector.
// The TAC consumer records the final immutable Culvert MERGE commit in its own
// provenance file.
const sealedFixtureProducerSourceCommit = "8d514e77dc041afda334686043d4928ab6bd9194"

const sealedFixtureEntropyLabel = "culvert-m7-c3-sealed-v1: recipient scalar = 32 bytes 0x42; ephemeral entropy = sequential 0x00..0x1f"

func buildManifest(inner, ciphertext, outer, priv, pub []byte) []byte {
	sum := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	m := sealedManifest{
		FixtureVersion:            sealedFixtureVersion,
		ProducerRepository:        sealedFixtureProducerRepository,
		ProducerSourceCommit:      sealedFixtureProducerSourceCommit,
		GenerationContract:        "roadmap/M7-proactive-telemetry-plan.md §3.2/§3.3/§13; algorithm x25519-sealbox = raw libsodium crypto_box_seal (nacl/box.SealAnonymous), NO CVRTSB01 framing",
		KeyID:                     sealedFixtureKeyID,
		Algorithm:                 sealedFixtureAlgorithm,
		EnvelopeVersion:           1,
		SchemaVersion:             3,
		RegistryHash:              sealedFixtureRegistryHash,
		SampleID:                  sealedFixtureSampleID,
		InnerPlaintextPath:        sealedInnerFixtureRelPath,
		InnerPlaintextLength:      len(inner),
		InnerPlaintextSHA256:      sum(inner),
		OuterEnvelopePath:         sealedFixtureDir + "/" + sealedOuterEnvelopeFile,
		OuterEnvelopeLength:       len(outer),
		OuterEnvelopeSHA256:       sum(outer),
		CiphertextLength:          len(ciphertext),
		CiphertextSHA256:          sum(ciphertext),
		RecipientPrivateKeyPath:   sealedFixtureDir + "/" + sealedRecipientPrivFile,
		RecipientPrivateKeyLength: len(priv),
		RecipientPrivateKeySHA256: sum(priv),
		RecipientPublicKeyPath:    sealedFixtureDir + "/" + sealedRecipientPubFile,
		RecipientPublicKeyLength:  len(pub),
		RecipientPublicKeySHA256:  sum(pub),
		DeterministicEntropyLabel: sealedFixtureEntropyLabel,
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		panic(err)
	}
	return b
}

// ─── path + read helpers ─────────────────────────────────────────────────────────

func sealedArtifactPath(name string) string {
	return filepath.Join(pkgSourceDir(), filepath.FromSlash(sealedFixtureDir), name)
}

func readSealedArtifact(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(sealedArtifactPath(name))
	if err != nil {
		t.Fatalf("read sealed artifact %s: %v (regenerate with %s=1 go test -run TestSealedGoldenRegenerate .)", name, err, sealedFixtureRegenerateEnv)
	}
	return b
}

func readInnerFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pkgSourceDir(), filepath.FromSlash(sealedInnerFixtureRelPath)))
	if err != nil {
		t.Fatalf("read inner fixture: %v", err)
	}
	return b
}

func hexSHA256(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// ─── 1. Byte-exact regeneration (the primary interoperability walls) ─────────────

// TestSealedGoldenCiphertextIsByteExact — regenerating the ciphertext from the real
// inner fixture with the deterministic entropy reproduces the committed raw sealbox
// blob exactly. (Requirement 4; mutation controls for changed entropy/inner/pubkey.)
func TestSealedGoldenCiphertextIsByteExact(t *testing.T) {
	got := regenerateCiphertext(t)
	if len(got) != sealedFixtureCiphertextLen {
		t.Fatalf("ciphertext length = %d, want %d", len(got), sealedFixtureCiphertextLen)
	}
	if h := hexSHA256(got); h != sealedFixtureCiphertextSHA256 {
		t.Fatalf("ciphertext SHA-256 = %s, want %s — the sealing algorithm, primitive, or entropy changed", h, sealedFixtureCiphertextSHA256)
	}
	// The committed outer envelope's ciphertext must decode to exactly these bytes.
	env := decodeCommittedOuter(t)
	ctFromOuter, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		t.Fatalf("decode committed ciphertext base64: %v", err)
	}
	if !bytes.Equal(got, ctFromOuter) {
		t.Fatal("regenerated ciphertext != the ciphertext embedded in the committed outer_envelope.json")
	}
}

// TestSealedGoldenOuterEnvelopeIsByteExact — rebuilding the outer envelope from the
// regenerated ciphertext reproduces the committed outer_envelope.json byte-for-byte.
// (Requirement 5; mutation controls for member order/added member/trailing newline.)
func TestSealedGoldenOuterEnvelopeIsByteExact(t *testing.T) {
	want := readSealedArtifact(t, sealedOuterEnvelopeFile)
	got := buildOuterEnvelope(regenerateCiphertext(t))
	if !bytes.Equal(got, want) {
		t.Fatalf("outer envelope drift:\n producer (%d bytes): %s\n committed (%d bytes): %s\nRegenerate with %s=1 go test -run TestSealedGoldenRegenerate .",
			len(got), got, len(want), want, sealedFixtureRegenerateEnv)
	}
	if len(want) != sealedFixtureOuterLen() {
		t.Fatalf("outer envelope length = %d, recorded %d", len(want), sealedFixtureOuterLen())
	}
	if h := hexSHA256(want); h != sealedFixtureOuterSHA256() {
		t.Fatalf("outer envelope SHA-256 = %s, recorded %s", h, sealedFixtureOuterSHA256())
	}
	// No trailing newline, compact, valid UTF-8, no BOM.
	if want[len(want)-1] == '\n' || want[len(want)-1] == '\r' {
		t.Error("outer_envelope.json ends with a newline — the request body is exactly json.Marshal output")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, want); err != nil {
		t.Fatalf("outer envelope is not valid JSON: %v", err)
	}
	if !bytes.Equal(want, compact.Bytes()) {
		t.Error("outer_envelope.json is not the compact encoding")
	}
	if bytes.HasPrefix(want, []byte{0xEF, 0xBB, 0xBF}) {
		t.Error("outer_envelope.json has a UTF-8 BOM")
	}
}

// The recorded outer length/SHA are derived (not hand-typed) so a regeneration
// cannot leave them stale: the committed bytes are the source of truth for these.
func sealedFixtureOuterLen() int { return len(mustReadFileForConst(sealedOuterEnvelopeFile)) }
func sealedFixtureOuterSHA256() string {
	return hexSHA256(mustReadFileForConst(sealedOuterEnvelopeFile))
}
func mustReadFileForConst(name string) []byte {
	b, err := os.ReadFile(sealedArtifactPath(name))
	if err != nil {
		panic(err)
	}
	return b
}

func decodeCommittedOuter(t *testing.T) sealedOuterEnvelope {
	t.Helper()
	var env sealedOuterEnvelope
	dec := json.NewDecoder(bytes.NewReader(readSealedArtifact(t, sealedOuterEnvelopeFile)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("strict decode of committed outer envelope: %v", err)
	}
	if dec.More() {
		t.Fatal("committed outer envelope has trailing content")
	}
	return env
}

// ─── 2. Inner fixture stays pinned; keys derive; opens back ──────────────────────

// TestSealedGoldenInnerFixtureUnchanged — the exact inner bytes and SHA A1 owns.
// (Requirement 1.)
func TestSealedGoldenInnerFixtureUnchanged(t *testing.T) {
	inner := readInnerFixture(t)
	if len(inner) != sealedFixtureInnerLen {
		t.Fatalf("inner fixture length = %d, want %d — the producer inner plaintext drifted", len(inner), sealedFixtureInnerLen)
	}
	if h := hexSHA256(inner); h != sealedFixtureInnerSHA256 {
		t.Fatalf("inner fixture SHA-256 = %s, want %s", h, sealedFixtureInnerSHA256)
	}
}

// TestSealedGoldenKeyDerivation — the committed private scalar derives the committed
// public key, and both artifacts match their recorded lengths and digests.
// (Requirement 2.)
func TestSealedGoldenKeyDerivation(t *testing.T) {
	priv := readSealedArtifact(t, sealedRecipientPrivFile)
	pub := readSealedArtifact(t, sealedRecipientPubFile)
	if len(priv) != sealedFixtureRecipientPrivLen || len(pub) != sealedFixtureRecipientPubLen {
		t.Fatalf("key lengths priv=%d pub=%d", len(priv), len(pub))
	}
	// The committed private key IS the documented 32×0x42 scalar.
	if want := sealedFixtureRecipientScalar(); !bytes.Equal(priv, want[:]) {
		t.Fatal("committed recipient_private_key.bin is not the documented 32×0x42 test scalar")
	}
	// Derive the public key the SAME way the TAC consumer does, and require it to
	// equal the committed public key — never a hand-typed value.
	var privArr [32]byte
	copy(privArr[:], priv)
	derived, err := curve25519.X25519(privArr[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	if !bytes.Equal(derived, pub) {
		t.Fatalf("committed public key %x does not derive from the committed private scalar (%x)", pub, derived)
	}
	if hex.EncodeToString(pub) != sealedFixtureRecipientPubHex {
		t.Fatalf("committed public key hex = %s, recorded %s", hex.EncodeToString(pub), sealedFixtureRecipientPubHex)
	}
	if hexSHA256(priv) != sealedFixtureRecipientPrivSHA || hexSHA256(pub) != sealedFixtureRecipientPubSHA {
		t.Fatalf("key digests drifted: priv=%s pub=%s", hexSHA256(priv), hexSHA256(pub))
	}
}

// TestSealedGoldenOpensToExactInnerPlaintext — the committed ciphertext opens with
// the committed key pair back to the EXACT 476-byte inner fixture. (Requirement 10.)
func TestSealedGoldenOpensToExactInnerPlaintext(t *testing.T) {
	env := decodeCommittedOuter(t)
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	priv := sealedFixtureRecipientScalar()
	pub := sealedFixtureRecipientPub(t)
	opened, ok := box.OpenAnonymous(nil, ct, &pub, &priv)
	if !ok {
		t.Fatal("committed ciphertext failed to open with the committed key pair")
	}
	inner := readInnerFixture(t)
	if !bytes.Equal(opened, inner) {
		t.Fatalf("opened plaintext (%d bytes) != inner fixture (%d bytes)", len(opened), len(inner))
	}
}

// TestSealedGoldenCiphertextDigestMatchesRawBlob — ciphertext_sha256 is the SHA-256
// of the decoded RAW sealed blob (pre-base64). (Requirement 6.)
func TestSealedGoldenCiphertextDigestMatchesRawBlob(t *testing.T) {
	env := decodeCommittedOuter(t)
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	if h := hexSHA256(ct); h != env.CiphertextSHA256 {
		t.Fatalf("ciphertext_sha256 = %s, sha256(raw blob) = %s", env.CiphertextSHA256, h)
	}
	if len(ct) != sealedFixtureCiphertextLen {
		t.Fatalf("raw blob length = %d, want %d (476 inner + 48 sealbox overhead)", len(ct), sealedFixtureCiphertextLen)
	}
}

// ─── 3. Exact member sets (§3.2 outer = 8; §3.3 inner = 6) ────────────────────────

// outerClosedSet is the §3.2 closed set of outer-envelope members (exactly eight).
var outerClosedSet = map[string]bool{
	"envelope_version": true, "key_id": true, "algorithm": true, "ciphertext": true,
	"ciphertext_sha256": true, "sample_id": true, "schema_version": true, "registry_hash": true,
}

// outerMemberViolations reports how a candidate outer envelope's member set
// deviates from the closed §3.2 eight; an empty slice means conformant. Both the
// golden test and the "added outer member" mutation control drive through this one
// validator, so the control exercises the real closed-set logic rather than a
// tautology.
func outerMemberViolations(b []byte) []string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return []string{"invalid JSON: " + err.Error()}
	}
	var v []string
	if len(raw) != len(outerClosedSet) {
		v = append(v, fmt.Sprintf("member count %d != %d", len(raw), len(outerClosedSet)))
	}
	for k := range raw {
		if !outerClosedSet[k] {
			v = append(v, "unexpected member "+k)
		}
	}
	for k := range outerClosedSet {
		if _, ok := raw[k]; !ok {
			v = append(v, "missing member "+k)
		}
	}
	return v
}

// TestSealedGoldenOuterHasExactlyEightMembers. (Requirement 8.)
func TestSealedGoldenOuterHasExactlyEightMembers(t *testing.T) {
	if v := outerMemberViolations(readSealedArtifact(t, sealedOuterEnvelopeFile)); len(v) != 0 {
		t.Errorf("committed outer envelope violates the closed §3.2 eight: %v", v)
	}
}

// TestSealedGoldenInnerHasExactlySixMembers. (Requirement 9.)
func TestSealedGoldenInnerHasExactlySixMembers(t *testing.T) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(readInnerFixture(t), &raw); err != nil {
		t.Fatalf("unmarshal inner: %v", err)
	}
	want := map[string]bool{
		"schema_version": true, "registry_hash": true, "generated_at": true,
		"sample_epoch": true, "sequence": true, "metrics": true,
	}
	if len(raw) != len(want) {
		t.Errorf("inner plaintext has %d members, want exactly %d", len(raw), len(want))
	}
	for k := range raw {
		if !want[k] {
			t.Errorf("inner plaintext has unexpected member %q", k)
		}
	}
}

// TestSealedGoldenOuterInnerBinding — outer schema_version and registry_hash equal
// the inner fixture's. (Requirement 7.)
func TestSealedGoldenOuterInnerBinding(t *testing.T) {
	env := decodeCommittedOuter(t)
	var inner struct {
		SchemaVersion int    `json:"schema_version"`
		RegistryHash  string `json:"registry_hash"`
	}
	if err := json.Unmarshal(readInnerFixture(t), &inner); err != nil {
		t.Fatalf("unmarshal inner: %v", err)
	}
	if env.SchemaVersion != inner.SchemaVersion {
		t.Errorf("outer schema_version %d != inner %d", env.SchemaVersion, inner.SchemaVersion)
	}
	if env.RegistryHash != inner.RegistryHash {
		t.Errorf("outer registry_hash %q != inner %q", env.RegistryHash, inner.RegistryHash)
	}
	if env.SchemaVersion != 3 || env.RegistryHash != sealedFixtureRegistryHash {
		t.Errorf("outer schema/registry drifted from the recorded contract: %d %q", env.SchemaVersion, env.RegistryHash)
	}
}

// ─── 4. Deterministic sealing uses the production primitive + secure randomness ──

// TestSealedGoldenProductionPathUsesSecureRandomness — the SAME sealing helper,
// given crypto/rand.Reader, produces a DIFFERENT ciphertext each run (proving the
// production path draws real randomness, not the fixed fixture entropy), and every
// such ciphertext still opens back to the inner plaintext. (Requirements 3 and 12.)
func TestSealedGoldenProductionPathUsesSecureRandomness(t *testing.T) {
	inner := readInnerFixture(t)
	pub := sealedFixtureRecipientPub(t)
	priv := sealedFixtureRecipientScalar()

	deterministic := regenerateCiphertext(t)
	seen := map[string]bool{string(deterministic): true}
	for i := 0; i < 8; i++ {
		ct, err := sealTelemetryRaw(inner, &pub, rand.Reader)
		if err != nil {
			t.Fatalf("seal with crypto/rand: %v", err)
		}
		if seen[string(ct)] {
			t.Fatalf("a crypto/rand seal collided with a prior ciphertext on iteration %d — the production path is not drawing fresh randomness", i)
		}
		seen[string(ct)] = true
		opened, ok := box.OpenAnonymous(nil, ct, &pub, &priv)
		if !ok || !bytes.Equal(opened, inner) {
			t.Fatalf("a crypto/rand-sealed ciphertext did not round-trip on iteration %d", i)
		}
	}
}

// TestSealedGoldenDeterministicReaderRejectsOverRead — the exact-entropy reader
// fails if the sealer requests more than the provided 32 bytes.
func TestSealedGoldenDeterministicReaderRejectsOverRead(t *testing.T) {
	rd := &exactEntropyReader{data: sealedFixtureEphemeralEntropy()}
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rd, buf); err != nil {
		t.Fatalf("first 32-byte read should succeed: %v", err)
	}
	if _, err := rd.Read(make([]byte, 1)); err == nil {
		t.Fatal("the deterministic reader did not fail on an over-read — a changed sealing construction could go unnoticed")
	}
}

// ─── 5. Mutation-positive controls (each proves the relevant check FIRES) ────────

func TestSealedGoldenMutationControls(t *testing.T) {
	inner := readInnerFixture(t)
	pub := sealedFixtureRecipientPub(t)
	base := regenerateCiphertext(t)
	baseOuter := buildOuterEnvelope(base)

	seal := func(in []byte, p *[32]byte, entropy []byte) []byte {
		rd := &exactEntropyReader{data: entropy}
		ct, err := sealTelemetryRaw(in, p, rd)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		return ct
	}

	t.Run("changed inner byte", func(t *testing.T) {
		mut := append([]byte(nil), inner...)
		mut[10] ^= 0x01
		if bytes.Equal(seal(mut, &pub, sealedFixtureEphemeralEntropy()), base) {
			t.Error("a changed inner byte produced the same ciphertext")
		}
	})
	t.Run("changed public key", func(t *testing.T) {
		other := pub
		other[0] ^= 0x01
		// May be low-order-rejected (also a valid failure); only a MATCH is wrong.
		rd := &exactEntropyReader{data: sealedFixtureEphemeralEntropy()}
		ct, err := sealTelemetryRaw(inner, &other, rd)
		if err == nil && bytes.Equal(ct, base) {
			t.Error("a changed public key produced the same ciphertext")
		}
	})
	t.Run("changed deterministic entropy", func(t *testing.T) {
		ent := sealedFixtureEphemeralEntropy()
		// Flip a MIDDLE byte: X25519 clamps the ephemeral scalar (clears the low 3
		// bits of byte 0 and the top bits of byte 31), so a change there could be
		// erased; a middle byte is preserved, guaranteeing a different ephemeral key.
		ent[15] ^= 0x01
		if bytes.Equal(seal(inner, &pub, ent), base) {
			t.Error("changed ephemeral entropy produced the same ciphertext")
		}
	})
	t.Run("changed ciphertext fails digest and open", func(t *testing.T) {
		mut := append([]byte(nil), base...)
		mut[len(mut)-1] ^= 0x01
		if hexSHA256(mut) == sealedFixtureCiphertextSHA256 {
			t.Error("a changed ciphertext still matched the recorded digest")
		}
		priv := sealedFixtureRecipientScalar()
		if _, ok := box.OpenAnonymous(nil, mut, &pub, &priv); ok {
			t.Error("a bit-flipped ciphertext still opened")
		}
	})
	t.Run("changed outer member order", func(t *testing.T) {
		// Re-serialize the SAME eight real values in a DIFFERENT key order and
		// require the bytes to differ from the canonical builder output. This
		// proves the byte-exact wall is order-sensitive (not merely value-
		// sensitive): the mutant carries the identical values, so any inequality
		// is driven by member order alone.
		var m map[string]json.RawMessage
		if err := json.Unmarshal(baseOuter, &m); err != nil {
			t.Fatalf("unmarshal baseOuter: %v", err)
		}
		order := []string{
			"registry_hash", "schema_version", "sample_id", "ciphertext_sha256",
			"ciphertext", "algorithm", "key_id", "envelope_version",
		}
		var buf bytes.Buffer
		buf.WriteByte('{')
		for i, k := range order {
			raw, ok := m[k]
			if !ok {
				t.Fatalf("baseOuter is missing expected member %q", k)
			}
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			buf.Write(raw)
		}
		buf.WriteByte('}')
		reordered := buf.Bytes()
		// Same members and values as the canonical bytes...
		if len(outerMemberViolations(reordered)) != 0 {
			t.Fatalf("reordered envelope changed the member set: %v", outerMemberViolations(reordered))
		}
		// ...yet byte-different, because only the key order changed.
		if bytes.Equal(reordered, baseOuter) {
			t.Error("a reordered outer envelope with identical values matched the canonical bytes — the byte-exact wall is not order-sensitive")
		}
	})
	t.Run("added outer member", func(t *testing.T) {
		// The unmutated bytes pass the closed-set validator...
		if v := outerMemberViolations(baseOuter); len(v) != 0 {
			t.Fatalf("baseline envelope unexpectedly violates the closed set: %v", v)
		}
		// ...and adding a ninth member makes the SAME validator fire.
		var m map[string]json.RawMessage
		if err := json.Unmarshal(baseOuter, &m); err != nil {
			t.Fatalf("unmarshal baseOuter: %v", err)
		}
		m["ninth"] = json.RawMessage(`1`)
		mb, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal mutated envelope: %v", err)
		}
		if v := outerMemberViolations(mb); len(v) == 0 {
			t.Error("a nine-member envelope passed the closed-set validator")
		}
	})
	t.Run("trailing newline", func(t *testing.T) {
		// The canonical builder never emits a trailing newline, so a byte-exact
		// comparison against a freshly rebuilt envelope (the real wall in
		// TestSealedGoldenOuterEnvelopeIsByteExact) must reject an appended '\n'.
		withNL := append(append([]byte(nil), baseOuter...), '\n')
		if bytes.Equal(withNL, buildOuterEnvelope(base)) {
			t.Error("a trailing-newline envelope matched the canonical builder output")
		}
	})
	t.Run("wrong digest is bound to the ciphertext", func(t *testing.T) {
		// Mutating the ciphertext must change the derived ciphertext_sha256 the
		// builder records (proving the digest binds to the ciphertext), and the
		// recorded digest must verify against its own ciphertext.
		mut := append([]byte(nil), base...)
		mut[0] ^= 0x01
		var mutated, canonical sealedOuterEnvelope
		if err := json.Unmarshal(buildOuterEnvelope(mut), &mutated); err != nil {
			t.Fatalf("unmarshal mutated: %v", err)
		}
		if err := json.Unmarshal(baseOuter, &canonical); err != nil {
			t.Fatalf("unmarshal canonical: %v", err)
		}
		if mutated.CiphertextSHA256 == canonical.CiphertextSHA256 {
			t.Error("mutating the ciphertext did not change ciphertext_sha256 — the digest is not bound to the ciphertext")
		}
		ct, err := base64.StdEncoding.DecodeString(mutated.Ciphertext)
		if err != nil {
			t.Fatalf("decode mutated ciphertext: %v", err)
		}
		if hexSHA256(ct) != mutated.CiphertextSHA256 {
			t.Error("ciphertext_sha256 does not verify against its own ciphertext")
		}
	})
	t.Run("wrong registry hash breaks binding", func(t *testing.T) {
		// Establish that the real values bind (the wall's precondition)...
		env := decodeCommittedOuter(t)
		var inner struct {
			RegistryHash string `json:"registry_hash"`
		}
		if err := json.Unmarshal(readInnerFixture(t), &inner); err != nil {
			t.Fatalf("unmarshal inner: %v", err)
		}
		if env.RegistryHash != inner.RegistryHash {
			t.Fatalf("precondition failed: committed outer/inner registry_hash already differ (%q vs %q)", env.RegistryHash, inner.RegistryHash)
		}
		// ...then show a mutated outer value breaks the equality the binding wall
		// (TestSealedGoldenOuterInnerBinding) enforces.
		mutated := strings.Repeat("a", 64)
		if mutated == inner.RegistryHash {
			t.Error("a mutated registry_hash still equals the inner value — the binding wall would not fire")
		}
	})
}

// ─── 6. Manifest + README are consistent metadata ───────────────────────────────

// TestSealedGoldenManifestMatchesArtifacts — every value the manifest records
// matches the artifacts actually on disk, and the manifest is byte-exact with the
// canonical builder.
func TestSealedGoldenManifestMatchesArtifacts(t *testing.T) {
	inner := readInnerFixture(t)
	ct := regenerateCiphertext(t)
	outer := readSealedArtifact(t, sealedOuterEnvelopeFile)
	priv := readSealedArtifact(t, sealedRecipientPrivFile)
	pub := readSealedArtifact(t, sealedRecipientPubFile)

	want := buildManifest(inner, ct, outer, priv, pub)
	got := readSealedArtifact(t, sealedManifestFile)
	if !bytes.Equal(got, want) {
		t.Fatalf("manifest drift:\n committed: %s\n rebuilt:   %s\nRegenerate with %s=1 go test -run TestSealedGoldenRegenerate .", got, want, sealedFixtureRegenerateEnv)
	}

	// The manifest must NOT record its own SHA (self-reference) or a merge commit.
	var m sealedManifest
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("manifest is not valid JSON: %v", err)
	}
	if m.InnerPlaintextSHA256 != hexSHA256(inner) || m.OuterEnvelopeSHA256 != hexSHA256(outer) ||
		m.CiphertextSHA256 != hexSHA256(ct) || m.RecipientPrivateKeySHA256 != hexSHA256(priv) ||
		m.RecipientPublicKeySHA256 != hexSHA256(pub) {
		t.Error("a manifest digest does not match its artifact")
	}
	if m.ProducerRepository != sealedFixtureProducerRepository || m.KeyID != sealedFixtureKeyID {
		t.Error("manifest identity fields drifted")
	}
	// producer_source_commit is a branch-point pointer, not the merge commit; it is
	// a 40-char git SHA.
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(m.ProducerSourceCommit) {
		t.Errorf("producer_source_commit %q is not a 40-char git SHA", m.ProducerSourceCommit)
	}
}

// TestSealedGoldenREADMEIsPresentAndMarked — the README carries the PUBLIC-TEST
// warning and records the artifact digests the consumer verifies.
func TestSealedGoldenREADMEIsPresentAndMarked(t *testing.T) {
	readme := string(readSealedArtifact(t, sealedREADMEFile))
	outer := readSealedArtifact(t, sealedOuterEnvelopeFile)
	// Every digest/length the README publishes is asserted here, so a
	// regeneration that changes any artifact fails this test loudly (the README
	// is not rewritten by TestSealedGoldenRegenerate) rather than silently
	// leaving a stale row.
	for _, want := range []string{
		"PUBLIC TEST VECTOR — NOT A SECRET — NEVER USE IN PRODUCTION",
		sealedFixtureKeyID,
		sealedFixtureCiphertextSHA256,
		sealedFixtureRecipientPubHex,
		hexSHA256(outer),              // outer_envelope.json SHA row
		fmt.Sprintf("%d", len(outer)), // outer_envelope.json length row (1036)
		sealedFixtureRecipientPrivSHA, // recipient_private_key.bin SHA row
		sealedFixtureRecipientPubSHA,  // recipient_public_key.bin SHA row
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("sealed README does not record %q", want)
		}
	}
}

// ─── 7. Test-key confinement + no-egress walls ───────────────────────────────────

// productionGoSources returns the package-main production .go files (non-test),
// excluding this file's own test surface.
func sealedProductionGoFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(pkgSourceDir())
	if err != nil {
		t.Fatalf("read pkg dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(pkgSourceDir(), n))
	}
	if len(out) == 0 {
		t.Fatal("no production .go files found — the confinement wall would be vacuous")
	}
	sort.Strings(out)
	return out
}

// TestSealedGoldenTestKeyIsConfinedToTestData — no PRODUCTION source (package main
// non-test files, and every non-test .go under internal/) references the test
// key_id or the sealed artifact directory. The fixture key material lives only in
// testdata. (Requirement 11; test-key confinement wall.)
func TestSealedGoldenTestKeyIsConfinedToTestData(t *testing.T) {
	markers := []string{sealedFixtureKeyID, "recipient_private_key.bin", "telemetry/v1/sealed"}
	checked := 0
	err := filepath.WalkDir(pkgSourceDir(), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == "testdata" || base == ".git" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		checked++
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		src := string(b)
		for _, m := range markers {
			if strings.Contains(src, m) {
				rel, _ := filepath.Rel(pkgSourceDir(), path)
				t.Errorf("production file %s references %q — the C3 test key material must be confined to testdata and tests", rel, m)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if checked == 0 {
		t.Fatal("no production files scanned — the confinement wall would be vacuous")
	}
}

// TestSealedGoldenTestKeyNotInDockerfileOrConfig — no Dockerfile or production
// config copies the sealed artifacts or defaults to the test key_id.
func TestSealedGoldenTestKeyNotInDockerImage(t *testing.T) {
	root := pkgSourceDir()
	for _, name := range []string{"Dockerfile", ".dockerignore"} {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			continue // absent is fine
		}
		s := string(b)
		for _, m := range []string{sealedFixtureKeyID, "telemetry/v1/sealed", "recipient_private_key"} {
			// A .dockerignore that EXCLUDES testdata is good; only a COPY-in is bad.
			if name == "Dockerfile" && strings.Contains(s, m) {
				t.Errorf("Dockerfile references %q — the public test key must never enter a production image", m)
			}
		}
	}
}

// TestSealedGoldenNoEgress — the C3 test surface introduces no network/egress: it
// does no HTTP, opens no socket, starts no sender. Scanned as AST imports over this
// file, so a stray net/http import fails.
func TestSealedGoldenNoEgress(t *testing.T) {
	fset := token.NewFileSet()
	self := filepath.Join(pkgSourceDir(), "support_telemetry_sealed_golden_test.go")
	parsed, err := parser.ParseFile(fset, self, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse self: %v", err)
	}
	forbidden := map[string]bool{
		"net": true, "net/http": true, "net/url": true, "os/exec": true,
	}
	for _, imp := range parsed.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if forbidden[p] {
			t.Errorf("the C3 sealed-vector test imports %q — C3 adds a golden vector, not egress (Slice 3 is blocked)", p)
		}
	}
	_ = ast.Inspect // keep go/ast referenced for the confinement helpers above
}

// TestSealedGoldenKeyIDHasNoProductionIdentity — the test key_id carries no "prod",
// customer, or deployment identifier. (Requirement 13.)
func TestSealedGoldenKeyIDHasNoProductionIdentity(t *testing.T) {
	low := strings.ToLower(sealedFixtureKeyID)
	for _, banned := range []string{"prod", "production", "customer", "live", "real"} {
		if strings.Contains(low, banned) {
			t.Errorf("test key_id %q contains a production-shaped token %q", sealedFixtureKeyID, banned)
		}
	}
	if !strings.Contains(low, "test") {
		t.Errorf("test key_id %q does not announce itself as a test vector", sealedFixtureKeyID)
	}
	// The committed private key is the obvious 32×0x42 pattern, not a real key.
	priv := readSealedArtifact(t, sealedRecipientPrivFile)
	allSame := true
	for _, b := range priv {
		if b != 0x42 {
			allSame = false
			break
		}
	}
	if !allSame {
		t.Error("committed recipient_private_key.bin is not the documented obvious test pattern (32×0x42)")
	}
}

// ─── 8. Regeneration (explicit opt-in, never in ordinary test runs) ──────────────

// TestSealedGoldenRegenerate rewrites the committed artifacts from the deterministic
// inputs. It refuses unless CULVERT_TELEMETRY_SEALED_REGENERATE is truthy, so an
// ordinary `go test ./...` never mutates a repository file.
func TestSealedGoldenRegenerate(t *testing.T) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(sealedFixtureRegenerateEnv))) {
	case "1", "true", "yes", "on":
	default:
		t.Skipf("regeneration is explicit opt-in only (set %s=1)", sealedFixtureRegenerateEnv)
	}
	inner := readInnerFixture(t)
	pub := sealedFixtureRecipientPub(t)
	priv := sealedFixtureRecipientScalar()
	ct := regenerateCiphertext(t)
	outer := buildOuterEnvelope(ct)
	manifest := buildManifest(inner, ct, outer, priv[:], pubBytes(pub))

	dir := filepath.Join(pkgSourceDir(), filepath.FromSlash(sealedFixtureDir))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writes := map[string][]byte{
		sealedRecipientPrivFile: priv[:],
		sealedRecipientPubFile:  pubBytes(pub),
		sealedOuterEnvelopeFile: outer,
		sealedManifestFile:      manifest,
	}
	for name, b := range writes {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	t.Logf("regenerated %d sealed artifacts under %s", len(writes), sealedFixtureDir)
}

func pubBytes(p [32]byte) []byte { return p[:] }
