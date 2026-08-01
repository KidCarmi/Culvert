package main

// saas_feed_floor.go — F3b-1: durable rollback-floor / commit-intent records +
// the selection & recovery state machine.
//
// Authority: roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md, Part B (§B.3 schema, §B.5
// commit ordering, §B.6 write quorum + floor selection, §B.7 recovery precedence,
// §B.8 crash matrix, §B.9 idempotent completion, §B.12 invariants).
//
// SCOPE (F3b-1 only). This file provides the reusable, node-local durable floor
// subsystem: the canonical floor record + codec, strict validation, CRC-32C
// corruption detection, the two redundant records (floor.a / floor.b), the
// two-record write quorum, monotonic floor selection, equivocation detection, and
// a deterministic recovery classification. It performs NO network I/O, NO Sigstore
// verification, NO manifest/artifact fetch, NO immutable-generation write, NO
// activation-record commit, NO live cutover, and NO GC. It is UNWIRED until F3b-3
// composes it with the downloader (F3b-2) and activation-state.
//
// Separation of concerns (§B.1). A floor NUMBER never selects served content. The
// floor record BINDS a concrete generation identity + digests; recovery classifies
// a "floor-ahead" binding as a resumable candidate that a LATER slice (F3b-2/F3b-3)
// must FULLY re-verify from signed bytes before it may serve. This file only
// classifies and returns that candidate identity — it never verifies or activates.
//
// Clock independence (§B.11). Floor selection is version-ordered, so recovery takes
// NO clock: it is a pure function of the on-disk bytes (no now(), no mtime, no
// directory enumeration). Freshness (which IS clock-bound) lands with F3b-2.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// ─── constants ──────────────────────────────────────────────────────────────────

const (
	// floorSchemaVersion is the only supported floor-record schema (§B.3).
	floorSchemaVersion = 1

	// floorFileA / floorFileB are the FIXED record filenames (§B.4). Recovery reads
	// ONLY these two paths — never a directory scan, never mtime (§B.12 #6).
	floorFileA = "floor.a.json"
	floorFileB = "floor.b.json"

	// maxFloorRecordBytes bounds decoder input. A floor record is ~350 bytes; 4 KiB
	// is generous headroom while capping a corrupt/hostile file (obligation: bounded
	// input).
	maxFloorRecordBytes = 4096

	floorFilePerm os.FileMode = 0o600 // records are 0600 (§B.3 writeFloorRecord).
	floorDirPerm  os.FileMode = 0o700 // the saas_feed/ dir is 0700.
)

// compiledMinFeedVersionPlaceholder is a DOCUMENTED PLACEHOLDER, not the production
// compiled checkpoint. Per the F3b-1 slice note the production COMPILED_MIN_FEED_VERSION
// is DEFERRED to the compiled-constant slice; this subsystem therefore takes the
// checkpoint as an EXPLICIT, VALIDATED constructor input (newFloorStore) rather than
// baking a final value here. The placeholder is the schema minimum (feed_version ≥ 1),
// suitable as a caller default until the real constant is linked in.
//
// COMPILED_MAX_VALIDITY (§B.3 / F3b-1 slice) is urlcatfeed.MaxValidity (30d); it gates
// a FETCHED manifest's validity window, which is an F3b-2 (downloader/freshness)
// concern — F3b-1 stores no expires_at and enforces no freshness, so it is referenced
// there rather than re-aliased here as dead state.
const compiledMinFeedVersionPlaceholder int64 = 1

// defaultFloorCheckpoint returns the placeholder checkpoint. Callers (and F3b-3) pass
// the real compiled minimum explicitly to newFloorStore; this is only a default.
func defaultFloorCheckpoint() int64 { return compiledMinFeedVersionPlaceholder }

// ─── structured errors (classification for later F3b observability) ──────────────

var (
	errFloorEmpty        = errors.New("saas feed floor: empty record")
	errFloorOversize     = errors.New("saas feed floor: record exceeds max size")
	errFloorTrailing     = errors.New("saas feed floor: trailing data after record")
	errFloorNoncanonical = errors.New("saas feed floor: record is not in canonical form")
	errFloorSchema       = errors.New("saas feed floor: unsupported schema_version")
	errFloorProtocol     = errors.New("saas feed floor: protocol mismatch")
	errFloorFeed         = errors.New("saas feed floor: feed mismatch")
	errFloorVersion      = errors.New("saas feed floor: invalid feed_version")
	errFloorTime         = errors.New("saas feed floor: non-canonical generated_at (want whole-second UTC RFC3339)")
	errFloorGenerationID = errors.New("saas feed floor: unsafe generation_id")
	errFloorDigest       = errors.New("saas feed floor: invalid sha-256 digest (want 64 lowercase hex)")
	errFloorCRC          = errors.New("saas feed floor: crc32c corruption")

	errFloorCheckpoint   = errors.New("saas feed floor: invalid compiled checkpoint")
	errFloorNoDir        = errors.New("saas feed floor: empty data directory")
	errFloorRollback     = errors.New("saas feed floor: candidate below current floor (rollback rejected)")
	errFloorReplay       = errors.New("saas feed floor: same-version older generated_at (replay rejected)")
	errFloorEquivocation = errors.New("saas feed floor: same-version identity equivocation")
	errFloorQuorumWrite  = errors.New("saas feed floor: quorum write failed")
	errFloorQuorumVerify = errors.New("saas feed floor: quorum read-back verification failed")
)

// ─── the record + codec (§B.3) ───────────────────────────────────────────────────

// floorRecord is the canonical floor / commit-intent record (§B.3). It is BOTH the
// rollback floor (concern 1) and the resumable-candidate binding (concern 3). The
// JSON field order below is FIXED and load-bearing: the canonical bytes must be
// byte-stable across writers/platforms.
type floorRecord struct {
	SchemaVersion  int    `json:"schema_version"`
	Protocol       string `json:"protocol"`        // must equal urlcatfeed.Protocol
	Feed           string `json:"feed"`            // must equal urlcatfeed.FeedID
	FeedVersion    int64  `json:"feed_version"`    // the floor watermark (≥ 1)
	GeneratedAt    string `json:"generated_at"`    // canonical whole-second UTC RFC3339
	GenerationID   string `json:"generation_id"`   // immutable generation dir name (safe path segment)
	ManifestSHA256 string `json:"manifest_sha256"` // 64 lowercase hex
	ArtifactSHA256 string `json:"artifact_sha256"` // 64 lowercase hex
	CRC32C         string `json:"crc32c"`          // EXACTLY 8 lowercase hex (fmt %08x)
}

// floorRecordSansCRC is the CRC-omitted canonical VIEW (§B.3 "checksum input"): the
// identical field order to floorRecord with crc32c ABSENT (not empty, not zero). The
// CRC is computed over THIS view's canonical bytes, never over the full record.
type floorRecordSansCRC struct {
	SchemaVersion  int    `json:"schema_version"`
	Protocol       string `json:"protocol"`
	Feed           string `json:"feed"`
	FeedVersion    int64  `json:"feed_version"`
	GeneratedAt    string `json:"generated_at"`
	GenerationID   string `json:"generation_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	ArtifactSHA256 string `json:"artifact_sha256"`
}

// floorCRCTable is CRC-32/Castagnoli (§B.3). A checksum is CORRUPTION DETECTION, NOT
// authenticity — any local writer can recompute a valid crc32c. Content authenticity
// comes solely from the Sigstore signatures a later slice re-verifies (§B.9).
var floorCRCTable = crc32.MakeTable(crc32.Castagnoli)

// floorCanonicalBytes encodes v with the shared canonical scheme (§B.3 / F1): compact,
// HTML-escaping DISABLED, fixed struct field order, no trailing newline.
func floorCanonicalBytes(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("saas feed floor: canonical encode: %w", err)
	}
	b := buf.Bytes()
	if n := len(b); n > 0 && b[n-1] == '\n' { // Encoder appends exactly one '\n'.
		b = b[:n-1]
	}
	return append([]byte(nil), b...), nil
}

// floorComputeCRC derives the crc32c string (8 lowercase hex) over the crc-omitted
// canonical bytes.
func floorComputeCRC(rec floorRecord) (string, error) {
	sans := floorRecordSansCRC{
		SchemaVersion:  rec.SchemaVersion,
		Protocol:       rec.Protocol,
		Feed:           rec.Feed,
		FeedVersion:    rec.FeedVersion,
		GeneratedAt:    rec.GeneratedAt,
		GenerationID:   rec.GenerationID,
		ManifestSHA256: rec.ManifestSHA256,
		ArtifactSHA256: rec.ArtifactSHA256,
	}
	b, err := floorCanonicalBytes(sans)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08x", crc32.Checksum(b, floorCRCTable)), nil
}

// encodeFloorRecord (re)computes crc32c and returns the full canonical bytes.
func encodeFloorRecord(rec floorRecord) ([]byte, error) {
	crc, err := floorComputeCRC(rec)
	if err != nil {
		return nil, err
	}
	rec.CRC32C = crc
	return floorCanonicalBytes(rec)
}

// decodeFloorRecord strictly decodes and fully validates one canonical record.
// Rejections (each ⇒ the record is EXCLUDED from selection, never a silent reset):
// oversized/empty, unknown fields, trailing data, non-canonical bytes (reordering,
// whitespace, HTML escaping, duplicate keys, alternate scalar encodings), bad
// schema/protocol/feed/version/time/generation_id/digests, and crc mismatch.
func decodeFloorRecord(data []byte) (floorRecord, error) {
	if len(data) == 0 {
		return floorRecord{}, errFloorEmpty
	}
	if len(data) > maxFloorRecordBytes {
		return floorRecord{}, fmt.Errorf("%w: %d > %d", errFloorOversize, len(data), maxFloorRecordBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rec floorRecord
	if err := dec.Decode(&rec); err != nil {
		return floorRecord{}, fmt.Errorf("saas feed floor: decode: %w", err)
	}
	if dec.More() {
		return floorRecord{}, errFloorTrailing
	}
	// Canonical byte-equality is the belt that rejects reordering, whitespace, HTML
	// escaping, duplicate keys (a dup makes the input longer than canonical), and
	// alternate scalar encodings — it re-encodes the decoded struct and requires an
	// exact match with the input.
	canon, err := floorCanonicalBytes(rec)
	if err != nil {
		return floorRecord{}, err
	}
	if !bytes.Equal(canon, data) {
		return floorRecord{}, errFloorNoncanonical
	}
	if err := validateFloorRecord(rec); err != nil {
		return floorRecord{}, err
	}
	return rec, nil
}

// validateFloorFields checks every semantic field EXCEPT the crc32c value (which the
// write path computes). Identity is pinned to the signed SaaS feed contract.
func validateFloorFields(rec floorRecord) error {
	if rec.SchemaVersion != floorSchemaVersion {
		return fmt.Errorf("%w: %d", errFloorSchema, rec.SchemaVersion)
	}
	if rec.Protocol != urlcatfeed.Protocol {
		return errFloorProtocol
	}
	if rec.Feed != urlcatfeed.FeedID {
		return errFloorFeed
	}
	if rec.FeedVersion < 1 {
		return fmt.Errorf("%w: %d", errFloorVersion, rec.FeedVersion)
	}
	if _, ok := canonicalUTCSecond(rec.GeneratedAt); !ok {
		return fmt.Errorf("%w: %q", errFloorTime, rec.GeneratedAt)
	}
	if !validGenerationID(rec.GenerationID) {
		return fmt.Errorf("%w: %q", errFloorGenerationID, rec.GenerationID)
	}
	if !validSHA256Hex(rec.ManifestSHA256) {
		return fmt.Errorf("%w: manifest", errFloorDigest)
	}
	if !validSHA256Hex(rec.ArtifactSHA256) {
		return fmt.Errorf("%w: artifact", errFloorDigest)
	}
	return nil
}

// validateFloorRecord is the read-path check: all semantic fields PLUS the crc32c
// format and recomputed value.
func validateFloorRecord(rec floorRecord) error {
	if err := validateFloorFields(rec); err != nil {
		return err
	}
	if !validCRC32Hex(rec.CRC32C) {
		return fmt.Errorf("%w: format %q", errFloorCRC, rec.CRC32C)
	}
	want, err := floorComputeCRC(rec)
	if err != nil {
		return err
	}
	if rec.CRC32C != want {
		return fmt.Errorf("%w: stored %s recomputed %s", errFloorCRC, rec.CRC32C, want)
	}
	return nil
}

// ─── field validators ────────────────────────────────────────────────────────────

// canonicalUTCSecond parses s and requires it to be a whole-second UTC RFC3339
// timestamp whose canonical re-format is byte-identical (rejects sub-seconds, a
// numeric offset instead of 'Z', and any non-canonical form).
func canonicalUTCSecond(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	if t.UTC().Format(time.RFC3339) != s {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// validGenerationID requires a safe, non-empty single path segment (no separators, no
// '.'/'..', no control chars, bounded). By convention generation_id == the feed_version
// string, but it is an INDEPENDENT identity field (two records may share a version yet
// bind different generation_ids — that is equivocation, §B.3), so it is NOT tied to
// feed_version here.
func validGenerationID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	if id == "." || id == ".." {
		return false
	}
	if id != filepath.Clean(id) {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c == '/' || c == '\\' || c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func validSHA256Hex(s string) bool { return isLowerHex(s, 64) }
func validCRC32Hex(s string) bool  { return isLowerHex(s, 8) }

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ─── filesystem seam (injectable durability) ─────────────────────────────────────

// floorFS is the narrow durability seam. Production delegates to fileutil.AtomicWrite
// (temp → fsync → rename → parent-dir fsync — the file+parent-dir durability §B.2.1
// requires; verified sufficient, no new primitive added) and os.ReadFile/os.MkdirAll.
// Tests inject failures at the write/read boundary. From the state machine's view any
// AtomicWrite failure is uniform: the target is old-or-new, never torn — so failure
// classification is cause-agnostic (an fsync, rename, or dir-sync failure all surface
// as "the write did not complete").
type floorFS struct {
	atomicWrite func(path string, data []byte, perm os.FileMode) error
	readFile    func(path string) ([]byte, error)
	mkdirAll    func(path string, perm os.FileMode) error
}

func osFloorFS() floorFS {
	return floorFS{
		atomicWrite: fileutil.AtomicWrite,
		readFile:    os.ReadFile, // #nosec G304 -- fixed constructed paths, not attacker-controlled
		mkdirAll:    os.MkdirAll,
	}
}

// ─── record read/write ───────────────────────────────────────────────────────────

type floorReadStatus int

const (
	floorAbsent     floorReadStatus = iota // file not present — legitimate; zero contribution
	floorValid                             // decoded + validated + crc ok
	floorCorrupt                           // present but failed decode/validate/crc → excluded
	floorUnreadable                        // I/O error other than NotExist → excluded
)

func (s floorReadStatus) String() string {
	switch s {
	case floorAbsent:
		return "absent"
	case floorValid:
		return "valid"
	case floorCorrupt:
		return "corrupt"
	case floorUnreadable:
		return "unreadable"
	default:
		return "unknown"
	}
}

// readFloorRecord is fail-closed (§B.3): missing ⇒ absent (zero contribution — a
// single file's absence is legitimate, the pair is anchored by the checkpoint);
// unreadable / structurally-invalid / crc-mismatch ⇒ excluded (never a silent zero
// that could lower the max). The err is returned for classification/logging only.
func readFloorRecord(fs floorFS, path string) (floorRecord, floorReadStatus, error) {
	b, err := fs.readFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return floorRecord{}, floorAbsent, nil
		}
		return floorRecord{}, floorUnreadable, err
	}
	rec, err := decodeFloorRecord(b)
	if err != nil {
		return floorRecord{}, floorCorrupt, err
	}
	return rec, floorValid, nil
}

// writeFloorRecord validates the semantic fields, (re)computes the crc, and writes the
// canonical bytes via the atomic seam. It NEVER writes in place.
func writeFloorRecord(fs floorFS, path string, rec floorRecord) error {
	if err := validateFloorFields(rec); err != nil {
		return err
	}
	b, err := encodeFloorRecord(rec)
	if err != nil {
		return err
	}
	return fs.atomicWrite(path, b, floorFilePerm)
}

func readBothFloorRecords(fs floorFS, paths floorPaths) (recs [2]floorRecord, sts [2]floorReadStatus) {
	recs[0], sts[0], _ = readFloorRecord(fs, paths.a)
	recs[1], sts[1], _ = readFloorRecord(fs, paths.b)
	return recs, sts
}

func validFrom(recs [2]floorRecord, sts [2]floorReadStatus) []floorRecord {
	var v []floorRecord
	for i := 0; i < 2; i++ {
		if sts[i] == floorValid {
			v = append(v, recs[i])
		}
	}
	return v
}

// ─── monotonic watermark + selection (§B.6) ──────────────────────────────────────

// floorWatermark is the (feed_version, generated_at) ordering key (§B.3): higher
// version wins; at equal version, newer generated_at wins (the SEC-F4 ordering).
type floorWatermark struct {
	Version     int64
	GeneratedAt time.Time
}

func (w floorWatermark) less(o floorWatermark) bool {
	if w.Version != o.Version {
		return w.Version < o.Version
	}
	return w.GeneratedAt.Before(o.GeneratedAt)
}

func (w floorWatermark) equal(o floorWatermark) bool {
	return w.Version == o.Version && w.GeneratedAt.Equal(o.GeneratedAt)
}

func recordWatermark(rec floorRecord) floorWatermark {
	t, _ := canonicalUTCSecond(rec.GeneratedAt) // valid records only reach here
	return floorWatermark{Version: rec.FeedVersion, GeneratedAt: t}
}

// selectFloor returns the max PROVEN floor over the checkpoint ∪ all valid records,
// plus any same-version identity equivocation. Numeric max is a FLOOR operation over
// valid, compatible records — never content selection. Equivocation is detected but
// does NOT lower the returned floor (§B.6.2 / invariant #9): two intact records that
// disagree at version V still both prove the floor is ≥ V.
func selectFloor(checkpoint int64, recs []floorRecord) (floorWatermark, *floorEquivocation) {
	floor := floorWatermark{Version: checkpoint}
	for i := range recs {
		if w := recordWatermark(recs[i]); floor.less(w) {
			floor = w
		}
	}
	return floor, detectEquivocation(recs)
}

// floorEquivocation records two-or-more valid records that share a feed_version but
// disagree on a bound identity field (§B.3).
type floorEquivocation struct {
	Version int64
	Records []floorRecord
}

func detectEquivocation(recs []floorRecord) *floorEquivocation {
	byVer := map[int64][]floorRecord{}
	for i := range recs {
		byVer[recs[i].FeedVersion] = append(byVer[recs[i].FeedVersion], recs[i])
	}
	var worst *floorEquivocation
	for ver, group := range byVer {
		if len(group) < 2 {
			continue
		}
		conflict := false
		for j := 1; j < len(group); j++ {
			if !sameFloorContent(group[0], group[j]) {
				conflict = true
				break
			}
		}
		// Deterministic despite map iteration: keep the HIGHEST conflicting version
		// (the one that could block the top candidate).
		if conflict && (worst == nil || ver > worst.Version) {
			worst = &floorEquivocation{Version: ver, Records: group}
		}
	}
	return worst
}

// sameFloorContent compares the CONTENT-identity fields that define equivocation:
// generation_id, manifest/artifact digests, plus protocol/feed (always equal for valid
// records — pinned to the constants — but compared as defense-in-depth). generated_at
// is DELIBERATELY EXCLUDED here: it is the ORDERING axis (maxPair tiebreak, §B.6.2), not
// a content-conflict axis. Two records at the same version binding the SAME content but
// a different generated_at is an interrupted re-sign (newer wins; the stale replica is
// repaired) — NOT equivocation. Two records at the same version binding DIFFERENT
// content (which generation is authentic?) IS equivocation (§B.8 crash matrix "same
// version but different digests"). See the F3b-1 report's design-tension note: §B.3's
// prose also lists generated_at, but including it would make the user-required
// same-version-newer-generated_at re-sign ADVANCE (replay guard) impossible, so the
// coherent, crash-matrix-aligned reading excludes it from the equivocation set.
func sameFloorContent(a, b floorRecord) bool {
	return a.GenerationID == b.GenerationID &&
		a.ManifestSHA256 == b.ManifestSHA256 &&
		a.ArtifactSHA256 == b.ArtifactSHA256 &&
		a.Protocol == b.Protocol &&
		a.Feed == b.Feed
}

// sameFloorIdentity is the FULL identity (content + generated_at). Used for read-back
// exactness (the record written must read back byte-for-byte) and exact-retry
// idempotency — NOT for equivocation (that is content-only, see sameFloorContent).
func sameFloorIdentity(a, b floorRecord) bool {
	return sameFloorContent(a, b) && a.GeneratedAt == b.GeneratedAt
}

// floorAheadCandidate returns the digest-bound record whose feed_version equals the
// selected floor and is strictly AHEAD of activeGenVersion — the resumable candidate a
// LATER slice must fully re-verify before serving (§B.7/§B.9). It returns nil if the
// top version is not ahead of the active generation, or if that version equivocates
// (content resume refused). Content selection is SEPARATE from floor selection: a
// floor number never activates (§B.12 #7).
func floorAheadCandidate(recs []floorRecord, activeGenVersion int64, floor floorWatermark, equiv *floorEquivocation) *floorRecord {
	if equiv != nil && equiv.Version == floor.Version {
		return nil // disputed top version — refuse either candidate
	}
	if floor.Version <= activeGenVersion {
		return nil // not ahead of what is already active
	}
	for i := range recs {
		if recs[i].FeedVersion == floor.Version {
			r := recs[i] // records at the floor version agree (no equivocation here)
			return &r
		}
	}
	return nil
}

// ─── recovery classification (§B.7 / §B.8) ───────────────────────────────────────

type floorHealth int

const (
	floorHealthFresh        floorHealth = iota // no records at all — true fresh install (benign)
	floorHealthy                               // ≥1 valid record, no corruption/equivocation, quorum intact
	floorHealthDegraded                        // valid max survives, but a replica is missing/corrupt/stale (repair)
	floorHealthEquivocation                    // two valid same-version records disagree on identity (critical)
	floorHealthCorruptAll                      // zero valid records but corruption was detected (critical)
)

func (h floorHealth) String() string {
	switch h {
	case floorHealthFresh:
		return "fresh"
	case floorHealthy:
		return "healthy"
	case floorHealthDegraded:
		return "degraded"
	case floorHealthEquivocation:
		return "equivocation"
	case floorHealthCorruptAll:
		return "corrupt_all"
	default:
		return "unknown"
	}
}

// floorRecovery is the deterministic recovery result. It separates the FIVE concepts
// the recovery contract requires: the max trusted numeric floor, the exact resumable
// candidate identity (if unambiguous), record health, whether repair/resume is
// required, and whether activation must remain fail-closed.
type floorRecovery struct {
	Floor               floorWatermark // max proven rollback floor (≥ checkpoint), never lowered
	Checkpoint          int64          // the compiled checkpoint used
	FloorFromCheckpoint bool           // true iff no valid record set the floor
	Candidate           *floorRecord   // resumable floor-ahead candidate (unambiguous), else nil
	Health              floorHealth    // record health classification
	RepairRequired      bool           // a replica must be rewritten to restore the two-record quorum
	ResumeRequired      bool           // candidate binds content ahead of active gen → full signed re-verify (F3b-2/3)
	FailClosed          bool           // activation must remain fail-closed (equivocation / corrupt-all)
	Equivocation        *floorEquivocation
	Statuses            [2]floorReadStatus // per fixed source, path order (a, b)
}

// recoverFloor reads the two FIXED floor records (no dir scan / mtime) and classifies
// recovery state deterministically. activeGenVersion is the currently-active
// generation version (0 when none/unknown; F3b-3 supplies it from activation-state).
// checkpoint is the compiled minimum floor. This function is a PURE function of the
// on-disk bytes + its two int inputs.
func recoverFloor(fs floorFS, paths floorPaths, checkpoint, activeGenVersion int64) floorRecovery {
	recs, sts := readBothFloorRecords(fs, paths)
	valid := validFrom(recs, sts)
	floor, equiv := selectFloor(checkpoint, valid)

	out := floorRecovery{Checkpoint: checkpoint, Statuses: sts, Equivocation: equiv, Floor: floor}

	if len(valid) == 0 {
		return classifyNoValidRecords(out, sts, checkpoint)
	}
	if equiv != nil && equiv.Version == floor.Version {
		// Top version disputed: floor RETAINED at the shared version (already in
		// out.Floor), content resume REFUSED, fail closed. Never an arbitrary pick,
		// never a floor regression (§B.6.2 / invariant #9).
		out.Health = floorHealthEquivocation
		out.FailClosed = true
		return out
	}
	// floorFromRecord: did a valid record REACH the floor, or does the compiled
	// checkpoint dominate all on-disk records (e.g. after a binary upgrade that raised
	// the checkpoint above the persisted records)? Repair-to-a-record only applies when
	// a record set the floor.
	floorFromRecord := false
	for i := range valid {
		if recordWatermark(valid[i]).equal(floor) {
			floorFromRecord = true
			break
		}
	}
	out.FloorFromCheckpoint = !floorFromRecord
	out.Candidate = floorAheadCandidate(valid, activeGenVersion, floor, equiv)
	out.ResumeRequired = out.Candidate != nil
	out.RepairRequired = repairNeeded(valid, sts, floor, floorFromRecord)
	if out.RepairRequired || equiv != nil {
		out.Health = floorHealthDegraded
	} else {
		out.Health = floorHealthy
	}
	return out
}

// classifyNoValidRecords distinguishes a TRUE fresh install (both files absent →
// benign checkpoint) from post-corruption loss (≥1 file present-but-corrupt →
// CRITICAL checkpoint + fail-closed). The numeric floor is the checkpoint in both.
func classifyNoValidRecords(out floorRecovery, sts [2]floorReadStatus, checkpoint int64) floorRecovery {
	out.Floor = floorWatermark{Version: checkpoint}
	out.FloorFromCheckpoint = true
	corrupt := func(s floorReadStatus) bool { return s == floorCorrupt || s == floorUnreadable }
	if corrupt(sts[0]) || corrupt(sts[1]) {
		out.Health = floorHealthCorruptAll
		out.FailClosed = true
	} else {
		out.Health = floorHealthFresh
	}
	return out
}

// repairNeeded reports whether the two-record quorum must be restored: any non-valid
// replica always needs a rewrite; and when a RECORD set the floor, a valid replica
// that is stale (below the floor version) needs rewriting to the floor. When the
// compiled checkpoint dominates all records (floorFromRecord=false), there is no
// record-driven rewrite target, so only a missing/corrupt replica counts. (A
// same-version identity disagreement is equivocation, handled before this is reached.)
func repairNeeded(valid []floorRecord, sts [2]floorReadStatus, floor floorWatermark, floorFromRecord bool) bool {
	for _, s := range sts {
		if s != floorValid {
			return true
		}
	}
	if floorFromRecord {
		for i := range valid {
			if !recordWatermark(valid[i]).equal(floor) {
				return true // a replica below the floor watermark (stale version OR stale re-sign)
			}
		}
	}
	return false
}

// ─── on-disk paths ───────────────────────────────────────────────────────────────

// floorPaths names the two FIXED record locations. Recovery/selection read ONLY these
// (no directory enumeration — §B.12 #6).
type floorPaths struct {
	a string
	b string
}

func floorPathsIn(dir string) floorPaths {
	return floorPaths{a: filepath.Join(dir, floorFileA), b: filepath.Join(dir, floorFileB)}
}

// ─── the store + two-record write quorum (§B.5 S3 / §B.6.1) ──────────────────────

// floorStore owns the two fixed record paths, the durability seam, the compiled
// checkpoint, and a writer mutex that SERIALIZES advances (so two concurrent advances
// can never interleave into mixed identities). It performs S3 only — the two floor
// records — and NEVER the activation-state (S4) or live cutover (S5), which are F3b-3.
type floorStore struct {
	fs         floorFS
	paths      floorPaths
	dir        string
	checkpoint int64
	mu         sync.Mutex
}

func newFloorStore(dir string, checkpoint int64) (*floorStore, error) {
	return newFloorStoreFS(osFloorFS(), dir, checkpoint)
}

func newFloorStoreFS(fs floorFS, dir string, checkpoint int64) (*floorStore, error) {
	if dir == "" {
		return nil, errFloorNoDir
	}
	if checkpoint < 1 {
		return nil, fmt.Errorf("%w: %d", errFloorCheckpoint, checkpoint)
	}
	return &floorStore{fs: fs, paths: floorPathsIn(dir), dir: dir, checkpoint: checkpoint}, nil
}

// Recover reads the two fixed records under the writer lock (a consistent snapshot vs.
// a concurrent Advance) and returns the deterministic classification.
func (s *floorStore) Recover(activeGenVersion int64) floorRecovery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return recoverFloor(s.fs, s.paths, s.checkpoint, activeGenVersion)
}

type floorAdvanceOutcome int

const (
	floorAdvanceCommitted  floorAdvanceOutcome = iota // both records durable + verified for a NEW (higher) floor
	floorAdvanceIdempotent                            // exact-record retry — the floor was already at this identity
)

func (o floorAdvanceOutcome) String() string {
	if o == floorAdvanceIdempotent {
		return "idempotent"
	}
	return "committed"
}

// floorQuorumResult is returned ONLY on quorum success (both records durable +
// read-back verified).
type floorQuorumResult struct {
	Outcome floorAdvanceOutcome
	Floor   floorWatermark
}

// Advance is the two-record write quorum (§B.6.1) for a validated candidate. Ordering
// (§B.5 S3): (1) validate the candidate; (2) reject rollback / equivocation / replay
// against the current recoverable state; (3) atomically write + durably sync floor.a;
// (4) atomically write + durably sync floor.b; (5) read BOTH back and verify; (6)
// return quorum success. On ANY write/verify failure it returns an error, NEVER
// reports quorum success, performs NO live cutover, and PRESERVES whatever record was
// written (a floor-ahead partial an EXACT-record idempotent retry can complete). No
// path lowers the durable or recovered floor.
func (s *floorStore) Advance(ctx context.Context, cand floorRecord) (floorQuorumResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. validate candidate structure/identity (crc is (re)computed on write).
	if err := validateFloorFields(cand); err != nil {
		return floorQuorumResult{}, fmt.Errorf("saas feed floor: invalid candidate: %w", err)
	}
	crc, err := floorComputeCRC(cand)
	if err != nil {
		return floorQuorumResult{}, err
	}
	cand.CRC32C = crc
	candW := recordWatermark(cand)

	// 2. reject rollback / equivocation / replay against the current recoverable state.
	if err := ctx.Err(); err != nil {
		return floorQuorumResult{}, err
	}
	recs, sts := readBothFloorRecords(s.fs, s.paths)
	cur, _ := selectFloor(s.checkpoint, validFrom(recs, sts))
	idempotent, err := s.checkAdvanceAllowed(cand, candW, cur, validFrom(recs, sts))
	if err != nil {
		return floorQuorumResult{}, err
	}

	// 3+4. write BOTH records durably. AtomicWrite = temp → fsync → rename → dir fsync.
	b, err := encodeFloorRecord(cand)
	if err != nil {
		return floorQuorumResult{}, err
	}
	if err := s.fs.mkdirAll(s.dir, floorDirPerm); err != nil {
		return floorQuorumResult{}, fmt.Errorf("saas feed floor: mkdir: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return floorQuorumResult{}, err
	}
	if err := s.fs.atomicWrite(s.paths.a, b, floorFilePerm); err != nil {
		return floorQuorumResult{}, fmt.Errorf("%w: floor.a: %v", errFloorQuorumWrite, err)
	}
	// A is durable; B not yet. A crash/cancel HERE is a floor-ahead partial an exact
	// retry completes — NEVER a reported success.
	if err := ctx.Err(); err != nil {
		return floorQuorumResult{}, err
	}
	if err := s.fs.atomicWrite(s.paths.b, b, floorFilePerm); err != nil {
		return floorQuorumResult{}, fmt.Errorf("%w: floor.b: %v", errFloorQuorumWrite, err)
	}

	// 5. read BOTH back and verify identity before declaring quorum.
	if err := s.verifyReadBack(s.paths.a, cand); err != nil {
		return floorQuorumResult{}, fmt.Errorf("%w: floor.a: %v", errFloorQuorumVerify, err)
	}
	if err := s.verifyReadBack(s.paths.b, cand); err != nil {
		return floorQuorumResult{}, fmt.Errorf("%w: floor.b: %v", errFloorQuorumVerify, err)
	}

	// 6. quorum success.
	outcome := floorAdvanceCommitted
	if idempotent {
		outcome = floorAdvanceIdempotent
	}
	return floorQuorumResult{Outcome: outcome, Floor: candW}, nil
}

// checkAdvanceAllowed enforces the monotonic + equivocation + replay gate (step 2). It
// returns idempotent=true when the candidate is an exact retry of the current floor
// identity (same version + same generated_at). It rejects: a lower version (rollback),
// a same-version different-identity candidate (equivocation), and a same-version
// strictly-older generated_at (replay). A same-version newer generated_at (re-sign) and
// a strictly-higher version both advance.
func (s *floorStore) checkAdvanceAllowed(cand floorRecord, candW, cur floorWatermark, curValid []floorRecord) (bool, error) {
	if candW.Version < cur.Version {
		return false, fmt.Errorf("%w: candidate v%d < floor v%d", errFloorRollback, candW.Version, cur.Version)
	}
	if candW.Version > cur.Version {
		return false, nil // strictly higher — advance
	}
	// Same version as the current floor. Any valid record at this version binding
	// DIFFERENT CONTENT is equivocation — refuse (never overwrite committed content at a
	// version with different content). A same-content different-generated_at candidate is
	// the re-sign/replay axis, handled by the generated_at comparison below.
	for i := range curValid {
		if curValid[i].FeedVersion == candW.Version && !sameFloorContent(curValid[i], cand) {
			return false, fmt.Errorf("%w: v%d", errFloorEquivocation, candW.Version)
		}
	}
	if candW.GeneratedAt.Before(cur.GeneratedAt) {
		return false, fmt.Errorf("%w: v%d", errFloorReplay, candW.Version)
	}
	// Exact retry iff same (version, generated_at); a newer generated_at is a re-sign
	// advance, still permitted, but not "idempotent".
	return candW.GeneratedAt.Equal(cur.GeneratedAt), nil
}

// verifyReadBack re-reads a written record and asserts it decodes valid and binds the
// exact candidate identity + crc.
func (s *floorStore) verifyReadBack(path string, want floorRecord) error {
	got, st, err := readFloorRecord(s.fs, path)
	if st != floorValid {
		if err != nil {
			return err
		}
		return fmt.Errorf("read-back status %s", st)
	}
	if got.FeedVersion != want.FeedVersion || got.CRC32C != want.CRC32C || !sameFloorIdentity(got, want) {
		return errors.New("read-back identity mismatch")
	}
	return nil
}
