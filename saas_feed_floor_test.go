package main

// saas_feed_floor_test.go — F3b-1 floor/commit-intent record + selection & recovery
// state-machine tests. These prove the STATE TRANSITIONS and returned
// CLASSIFICATIONS (not merely code paths): the canonical/golden bytes, CRC
// representation, strict decoding + every non-canonical form, the full recovery
// crash matrix (§B.8), monotonic/equivocation invariants (§B.12 4/5/6/7/9), the
// two-record write quorum with failure injection at every durability point, exact
// idempotent retry, deterministic concurrency, and fuzz/property coverage.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

const (
	floorHexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	floorHexB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	floorHexC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	floorHexD = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	floorTS0  = "2026-07-31T00:00:00Z"
	floorTS1  = "2026-08-01T00:00:00Z"
)

// mkFloor builds a fully-valid record with a correctly-computed crc.
func mkFloor(t *testing.T, ver int64, genAt, genID, man, art string) floorRecord {
	t.Helper()
	rec := floorRecord{
		SchemaVersion:  floorSchemaVersion,
		Protocol:       urlcatfeed.Protocol,
		Feed:           urlcatfeed.FeedID,
		FeedVersion:    ver,
		GeneratedAt:    genAt,
		GenerationID:   genID,
		ManifestSHA256: man,
		ArtifactSHA256: art,
	}
	crc, err := floorComputeCRC(rec)
	if err != nil {
		t.Fatalf("floorComputeCRC: %v", err)
	}
	rec.CRC32C = crc
	return rec
}

// ─── fake FS seam (deterministic failure injection) ──────────────────────────────

type fakeFloorFS struct {
	mu        sync.Mutex
	files     map[string][]byte
	writes    int
	writeHook func(path string, n int) error                                    // non-nil ⇒ fail before storing
	readHook  func(path string, data []byte, exists bool) ([]byte, error, bool) // handled=true ⇒ use return
	mkdirErr  error
}

func newFakeFS() *fakeFloorFS { return &fakeFloorFS{files: map[string][]byte{}} }

func (f *fakeFloorFS) seam() floorFS {
	return floorFS{atomicWrite: f.write, readFile: f.read, mkdirAll: f.mkdir}
}

func (f *fakeFloorFS) write(path string, data []byte, _ os.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	if f.writeHook != nil {
		if err := f.writeHook(path, f.writes); err != nil {
			return err
		}
	}
	f.files[path] = append([]byte(nil), data...) // atomic replace: old-or-new, never torn
	return nil
}

func (f *fakeFloorFS) read(path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.files[path]
	if f.readHook != nil {
		if out, err, handled := f.readHook(path, data, ok); handled {
			return out, err
		}
	}
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), data...), nil
}

func (f *fakeFloorFS) mkdir(_ string, _ os.FileMode) error { return f.mkdirErr }

// putRaw injects arbitrary bytes at a path (corruption / hand-built records).
func (f *fakeFloorFS) putRaw(path string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = append([]byte(nil), data...)
}

func (f *fakeFloorFS) has(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.files[path]
	return ok
}

// newFakeStore wires a store over the fake FS with a fixed dir + checkpoint.
func newFakeStore(t *testing.T, fs *fakeFloorFS, checkpoint int64) *floorStore {
	t.Helper()
	s, err := newFloorStoreFS(fs.seam(), "/data/saas_feed", checkpoint)
	if err != nil {
		t.Fatalf("newFloorStoreFS: %v", err)
	}
	return s
}

// ─── 1. canonical / golden record bytes ──────────────────────────────────────────

func TestFloor_GoldenBytes(t *testing.T) {
	rec := mkFloor(t, 42, floorTS0, "42", floorHexA, floorHexB)
	if rec.CRC32C != "43d5a692" {
		t.Fatalf("golden crc drift: got %q want 43d5a692", rec.CRC32C)
	}
	got, err := encodeFloorRecord(rec)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	want := `{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/saas",` +
		`"feed_version":42,"generated_at":"2026-07-31T00:00:00Z","generation_id":"42",` +
		`"manifest_sha256":"` + floorHexA + `","artifact_sha256":"` + floorHexB + `",` +
		`"crc32c":"43d5a692"}`
	if string(got) != want {
		t.Fatalf("golden bytes drift:\n got=%s\nwant=%s", got, want)
	}
	if strings.HasSuffix(string(got), "\n") {
		t.Fatal("canonical bytes must have no trailing newline")
	}
	// round-trip: decode → equal.
	back, err := decodeFloorRecord(got)
	if err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	if back != rec {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", back, rec)
	}
}

// ─── 2. CRC calculation + representation ──────────────────────────────────────────

func TestFloor_CRC(t *testing.T) {
	rec := mkFloor(t, 42, floorTS0, "42", floorHexA, floorHexB)
	if !validCRC32Hex(rec.CRC32C) {
		t.Fatalf("crc %q is not 8 lowercase hex", rec.CRC32C)
	}
	// The stored crc32c value is NOT part of the checksum input: mutating it does not
	// change the recomputed crc.
	tampered := rec
	tampered.CRC32C = "00000000"
	c1, _ := floorComputeCRC(rec)
	c2, _ := floorComputeCRC(tampered)
	if c1 != c2 {
		t.Fatalf("crc must be independent of the stored crc32c field: %s vs %s", c1, c2)
	}
	// Any bound-field change changes the crc.
	for _, mut := range []func(r *floorRecord){
		func(r *floorRecord) { r.FeedVersion = 43 },
		func(r *floorRecord) { r.GeneratedAt = floorTS1 },
		func(r *floorRecord) { r.GenerationID = "43" },
		func(r *floorRecord) { r.ManifestSHA256 = floorHexC },
		func(r *floorRecord) { r.ArtifactSHA256 = floorHexD },
	} {
		m := rec
		mut(&m)
		if got, _ := floorComputeCRC(m); got == rec.CRC32C {
			t.Errorf("crc collision after field mutation: %+v", m)
		}
	}
}

// ─── 3 + 4. strict decoding: every non-canonical / malformed form ─────────────────

func TestFloor_StrictDecode_Rejections(t *testing.T) {
	base := string(mustEncode(t, mkFloor(t, 42, floorTS0, "42", floorHexA, floorHexB)))
	reordered := `{"protocol":"signed_manifest_v1","schema_version":1,"feed":"url-categories/saas",` +
		`"feed_version":42,"generated_at":"2026-07-31T00:00:00Z","generation_id":"42",` +
		`"manifest_sha256":"` + floorHexA + `","artifact_sha256":"` + floorHexB + `","crc32c":"43d5a692"}`
	dupKey := strings.Replace(base, `"schema_version":1,`, `"schema_version":1,"schema_version":1,`, 1)

	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", errFloorEmpty},
		{"oversize", "{" + strings.Repeat(" ", maxFloorRecordBytes) + "}", errFloorOversize},
		{"trailing_data", base + " " + base, errFloorTrailing},
		{"trailing_newline", base + "\n", errFloorNoncanonical},
		{"leading_space", " " + base, errFloorNoncanonical},
		{"internal_whitespace", strings.Replace(base, `"feed_version":42`, `"feed_version": 42`, 1), errFloorNoncanonical},
		{"reordered_fields", reordered, errFloorNoncanonical},
		{"duplicate_key", dupKey, errFloorNoncanonical},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := decodeFloorRecord([]byte(c.in))
			if !errors.Is(err, c.want) {
				t.Fatalf("decode %q: got %v, want %v", c.name, err, c.want)
			}
		})
	}

	// Unknown field is caught by DisallowUnknownFields (before the canonical check).
	unknown := strings.Replace(base, `"crc32c":"43d5a692"}`, `"crc32c":"43d5a692","evil":true}`, 1)
	if _, err := decodeFloorRecord([]byte(unknown)); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}

// ─── 5. invalid schema / protocol / feed / version / time / gen-id / digests ──────

func TestFloor_FieldValidation(t *testing.T) {
	// Each mutation is re-CRC'd so the ONLY failure is the semantic field.
	crcOf := func(r floorRecord) floorRecord {
		c, _ := floorComputeCRC(r)
		r.CRC32C = c
		return r
	}
	good := mkFloor(t, 42, floorTS0, "42", floorHexA, floorHexB)
	cases := []struct {
		name string
		mut  func(r *floorRecord)
		want error
	}{
		{"schema", func(r *floorRecord) { r.SchemaVersion = 2 }, errFloorSchema},
		{"protocol", func(r *floorRecord) { r.Protocol = "legacy_raw_json_v0" }, errFloorProtocol},
		{"feed", func(r *floorRecord) { r.Feed = "url-categories/other" }, errFloorFeed},
		{"version_zero", func(r *floorRecord) { r.FeedVersion = 0 }, errFloorVersion},
		{"version_negative", func(r *floorRecord) { r.FeedVersion = -1 }, errFloorVersion},
		{"time_subsecond", func(r *floorRecord) { r.GeneratedAt = "2026-07-31T00:00:00.5Z" }, errFloorTime},
		{"time_offset", func(r *floorRecord) { r.GeneratedAt = "2026-07-31T05:00:00+05:00" }, errFloorTime},
		{"time_garbage", func(r *floorRecord) { r.GeneratedAt = "not-a-time" }, errFloorTime},
		{"genid_traversal", func(r *floorRecord) { r.GenerationID = "../42" }, errFloorGenerationID},
		{"genid_slash", func(r *floorRecord) { r.GenerationID = "a/b" }, errFloorGenerationID},
		{"genid_empty", func(r *floorRecord) { r.GenerationID = "" }, errFloorGenerationID},
		{"genid_dotdot", func(r *floorRecord) { r.GenerationID = ".." }, errFloorGenerationID},
		{"manifest_short", func(r *floorRecord) { r.ManifestSHA256 = "abc" }, errFloorDigest},
		{"manifest_upper", func(r *floorRecord) { r.ManifestSHA256 = strings.ToUpper(floorHexA) }, errFloorDigest},
		{"artifact_nonhex", func(r *floorRecord) { r.ArtifactSHA256 = strings.Repeat("g", 64) }, errFloorDigest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := good
			c.mut(&r)
			r = crcOf(r)
			b, err := floorCanonicalBytes(r)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			_, derr := decodeFloorRecord(b)
			if !errors.Is(derr, c.want) {
				t.Fatalf("got %v, want %v", derr, c.want)
			}
		})
	}
}

// crc corruption: flip a bound field WITHOUT re-CRC ⇒ crc mismatch.
func TestFloor_CRCMismatch(t *testing.T) {
	rec := mkFloor(t, 42, floorTS0, "42", floorHexA, floorHexB)
	rec.FeedVersion = 99 // crc now stale
	b, err := floorCanonicalBytes(rec)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := decodeFloorRecord(b); !errors.Is(err, errFloorCRC) {
		t.Fatalf("got %v, want errFloorCRC", err)
	}
}

// ─── read-status classification ──────────────────────────────────────────────────

func TestFloor_ReadStatus(t *testing.T) {
	fs := newFakeFS()
	paths := floorPathsIn("/d")
	// absent
	if _, st, _ := readFloorRecord(fs.seam(), paths.a); st != floorAbsent {
		t.Fatalf("missing ⇒ want absent, got %s", st)
	}
	// valid
	fs.putRaw(paths.a, mustEncode(t, mkFloor(t, 1, floorTS0, "1", floorHexA, floorHexB)))
	if _, st, _ := readFloorRecord(fs.seam(), paths.a); st != floorValid {
		t.Fatalf("want valid, got %s", st)
	}
	// corrupt
	fs.putRaw(paths.b, []byte("{garbage"))
	if _, st, _ := readFloorRecord(fs.seam(), paths.b); st != floorCorrupt {
		t.Fatalf("want corrupt, got %s", st)
	}
	// unreadable (I/O error other than NotExist)
	fs.readHook = func(path string, _ []byte, _ bool) ([]byte, error, bool) {
		if path == paths.a {
			return nil, errors.New("EIO"), true
		}
		return nil, nil, false
	}
	if _, st, _ := readFloorRecord(fs.seam(), paths.a); st != floorUnreadable {
		t.Fatalf("want unreadable, got %s", st)
	}
}

// ─── 6. clean fresh install ───────────────────────────────────────────────────────

func TestFloor_Recovery_FreshInstall(t *testing.T) {
	fs := newFakeFS()
	rec := recoverFloor(fs.seam(), floorPathsIn("/d"), 7, 0)
	if rec.Health != floorHealthFresh {
		t.Fatalf("health=%s, want fresh", rec.Health)
	}
	if rec.Floor.Version != 7 || !rec.FloorFromCheckpoint {
		t.Fatalf("floor=%d fromCheckpoint=%v, want 7/true", rec.Floor.Version, rec.FloorFromCheckpoint)
	}
	if rec.FailClosed || rec.Candidate != nil || rec.RepairRequired {
		t.Fatalf("fresh install must be benign: %+v", rec)
	}
}

// ─── 7. both records healthy ─────────────────────────────────────────────────────

func TestFloor_Recovery_BothHealthy(t *testing.T) {
	fs := newFakeFS()
	paths := floorPathsIn("/d")
	r := mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB)
	fs.putRaw(paths.a, mustEncode(t, r))
	fs.putRaw(paths.b, mustEncode(t, r))

	// activeGen already at 5 ⇒ no floor-ahead candidate.
	rec := recoverFloor(fs.seam(), paths, 1, 5)
	if rec.Health != floorHealthy || rec.RepairRequired || rec.FailClosed || rec.Candidate != nil {
		t.Fatalf("healthy same-gen: %+v", rec)
	}
	if rec.Floor.Version != 5 {
		t.Fatalf("floor=%d want 5", rec.Floor.Version)
	}
	// activeGen behind (0) ⇒ floor-ahead candidate = record, resume required.
	rec = recoverFloor(fs.seam(), paths, 1, 0)
	if rec.Health != floorHealthy || rec.Candidate == nil || !rec.ResumeRequired {
		t.Fatalf("healthy ahead-of-active: %+v", rec)
	}
	if rec.Candidate.FeedVersion != 5 || rec.Candidate.GenerationID != "5" {
		t.Fatalf("candidate identity wrong: %+v", rec.Candidate)
	}
}

// ─── 8. A valid / B missing (and inverse) ────────────────────────────────────────

func TestFloor_Recovery_OneMissing(t *testing.T) {
	r := mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB)
	for _, present := range []string{"a", "b"} {
		t.Run(present, func(t *testing.T) {
			fs := newFakeFS()
			paths := floorPathsIn("/d")
			if present == "a" {
				fs.putRaw(paths.a, mustEncode(t, r))
			} else {
				fs.putRaw(paths.b, mustEncode(t, r))
			}
			rec := recoverFloor(fs.seam(), paths, 1, 0)
			if rec.Floor.Version != 5 {
				t.Fatalf("floor=%d want 5 (valid max preserved)", rec.Floor.Version)
			}
			if rec.Health != floorHealthDegraded || !rec.RepairRequired {
				t.Fatalf("one-missing ⇒ degraded+repair: %+v", rec)
			}
			if rec.FailClosed {
				t.Fatal("one-missing must NOT fail closed (valid max survives)")
			}
		})
	}
}

// ─── 9. A valid / B corrupt (and inverse) ────────────────────────────────────────

func TestFloor_Recovery_OneCorrupt(t *testing.T) {
	r := mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB)
	for _, good := range []string{"a", "b"} {
		t.Run(good, func(t *testing.T) {
			fs := newFakeFS()
			paths := floorPathsIn("/d")
			if good == "a" {
				fs.putRaw(paths.a, mustEncode(t, r))
				fs.putRaw(paths.b, []byte("{corrupt"))
			} else {
				fs.putRaw(paths.a, []byte("{corrupt"))
				fs.putRaw(paths.b, mustEncode(t, r))
			}
			rec := recoverFloor(fs.seam(), paths, 1, 0)
			if rec.Floor.Version != 5 || rec.Health != floorHealthDegraded || !rec.RepairRequired {
				t.Fatalf("one-corrupt ⇒ floor preserved + degraded + repair: %+v", rec)
			}
			if rec.FailClosed {
				t.Fatal("one-corrupt must NOT fail closed")
			}
		})
	}
}

// ─── 10. versions old/new in both permutations (partial / floor-ahead) ───────────

func TestFloor_Recovery_DifferentVersions(t *testing.T) {
	older := mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB)
	newer := mkFloor(t, 6, floorTS1, "6", floorHexC, floorHexD)
	for _, order := range []string{"a_newer", "b_newer"} {
		t.Run(order, func(t *testing.T) {
			fs := newFakeFS()
			paths := floorPathsIn("/d")
			if order == "a_newer" {
				fs.putRaw(paths.a, mustEncode(t, newer))
				fs.putRaw(paths.b, mustEncode(t, older))
			} else {
				fs.putRaw(paths.a, mustEncode(t, older))
				fs.putRaw(paths.b, mustEncode(t, newer))
			}
			rec := recoverFloor(fs.seam(), paths, 1, 0)
			if rec.Floor.Version != 6 {
				t.Fatalf("floor=%d want 6 (max)", rec.Floor.Version)
			}
			if rec.Health != floorHealthDegraded || !rec.RepairRequired {
				t.Fatalf("different-versions ⇒ degraded+repair (stale replica): %+v", rec)
			}
			if rec.FailClosed {
				t.Fatal("different versions is NOT equivocation")
			}
			if rec.Candidate == nil || rec.Candidate.FeedVersion != 6 {
				t.Fatalf("candidate must be the F' record: %+v", rec.Candidate)
			}
		})
	}
}

// ─── same-version, SAME content, different generated_at (interrupted re-sign) ─────
//
// Design-tension resolution (see sameFloorContent): generated_at is the ORDERING
// axis, not an equivocation axis. Two records at v5 binding identical content but a
// different generated_at is a benign interrupted re-sign — newer wins, the stale
// replica is repaired — NOT critical equivocation.
func TestFloor_Recovery_ReSignPartialIsNotEquivocation(t *testing.T) {
	newer := mkFloor(t, 5, floorTS1, "5", floorHexA, floorHexB)
	older := mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB) // same content, older gen
	fs := newFakeFS()
	paths := floorPathsIn("/d")
	fs.putRaw(paths.a, mustEncode(t, newer))
	fs.putRaw(paths.b, mustEncode(t, older))

	rec := recoverFloor(fs.seam(), paths, 1, 0)
	if rec.Health == floorHealthEquivocation || rec.FailClosed {
		t.Fatalf("same-content re-sign partial must NOT be equivocation: %+v", rec)
	}
	if rec.Health != floorHealthDegraded || !rec.RepairRequired {
		t.Fatalf("re-sign partial ⇒ degraded + repair (rewrite stale replica): %+v", rec)
	}
	if !rec.Floor.GeneratedAt.Equal(recordWatermark(newer).GeneratedAt) {
		t.Fatalf("floor must take the NEWER generated_at, got %v", rec.Floor.GeneratedAt)
	}
}

// ─── 11 + 12. same-version identity equivocation ⇒ floor RETAINED ────────────────

func TestFloor_Recovery_Equivocation(t *testing.T) {
	a := mkFloor(t, 7, floorTS0, "7a", floorHexA, floorHexB)
	b := mkFloor(t, 7, floorTS0, "7b", floorHexC, floorHexD) // same version, different identity
	fs := newFakeFS()
	paths := floorPathsIn("/d")
	fs.putRaw(paths.a, mustEncode(t, a))
	fs.putRaw(paths.b, mustEncode(t, b))

	rec := recoverFloor(fs.seam(), paths, 3, 0)
	if rec.Health != floorHealthEquivocation {
		t.Fatalf("health=%s want equivocation", rec.Health)
	}
	if !rec.FailClosed {
		t.Fatal("equivocation must fail closed for content")
	}
	if rec.Candidate != nil {
		t.Fatal("equivocation must NOT pick a candidate arbitrarily")
	}
	// The CRITICAL invariant (§B.12 #9): the floor is NOT lowered to the checkpoint.
	if rec.Floor.Version != 7 {
		t.Fatalf("equivocation lowered the floor to %d — must be RETAINED at 7", rec.Floor.Version)
	}
	if rec.Equivocation == nil || rec.Equivocation.Version != 7 {
		t.Fatalf("equivocation detail missing: %+v", rec.Equivocation)
	}
}

// ─── 13. both corrupt ⇒ checkpoint + CRITICAL (distinct from fresh) ───────────────

func TestFloor_Recovery_BothCorrupt(t *testing.T) {
	fs := newFakeFS()
	paths := floorPathsIn("/d")
	fs.putRaw(paths.a, []byte("{corrupt-a"))
	fs.putRaw(paths.b, []byte("not json at all"))

	rec := recoverFloor(fs.seam(), paths, 9, 0)
	if rec.Health != floorHealthCorruptAll {
		t.Fatalf("health=%s want corrupt_all (critical)", rec.Health)
	}
	if !rec.FailClosed || rec.Floor.Version != 9 || !rec.FloorFromCheckpoint {
		t.Fatalf("both-corrupt ⇒ checkpoint + fail-closed: %+v", rec)
	}
	// Contrast: absent (not corrupt) is benign fresh, same floor but not critical.
	fresh := recoverFloor(newFakeFS().seam(), paths, 9, 0)
	if fresh.Health != floorHealthFresh || fresh.FailClosed {
		t.Fatalf("absent must be benign fresh, not critical: %+v", fresh)
	}
}

// ─── 14. checkpoint greater than disk records ─────────────────────────────────────

func TestFloor_Recovery_CheckpointDominates(t *testing.T) {
	r := mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB)
	fs := newFakeFS()
	paths := floorPathsIn("/d")
	fs.putRaw(paths.a, mustEncode(t, r))
	fs.putRaw(paths.b, mustEncode(t, r))

	rec := recoverFloor(fs.seam(), paths, 100, 0) // compiled checkpoint 100 >> records at 5
	if rec.Floor.Version != 100 {
		t.Fatalf("floor=%d want 100 (checkpoint dominates)", rec.Floor.Version)
	}
	if !rec.FloorFromCheckpoint {
		t.Fatal("floor came from the checkpoint, not a record")
	}
	if rec.Candidate != nil {
		t.Fatal("no record reaches the checkpoint floor ⇒ no candidate")
	}
	// Both replicas intact ⇒ no missing/corrupt repair; the below-checkpoint records
	// are simply superseded (a fetch below 100 would still be rejected — the point).
	if rec.Health != floorHealthy || rec.RepairRequired || rec.FailClosed {
		t.Fatalf("checkpoint-dominates should be benign healthy: %+v", rec)
	}
}

// ─── 15. lower-floor write rejection ──────────────────────────────────────────────

func TestFloor_Advance_RollbackRejected(t *testing.T) {
	fs := newFakeFS()
	s := newFakeStore(t, fs, 1)
	if _, err := s.Advance(context.Background(), mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB)); err != nil {
		t.Fatalf("seed v5: %v", err)
	}
	before, _ := fs.read(s.paths.a)
	_, err := s.Advance(context.Background(), mkFloor(t, 3, floorTS0, "3", floorHexC, floorHexD))
	if !errors.Is(err, errFloorRollback) {
		t.Fatalf("got %v want errFloorRollback", err)
	}
	after, _ := fs.read(s.paths.a)
	if !bytes.Equal(before, after) {
		t.Fatal("a rejected rollback must NOT mutate the durable record")
	}
	if got := s.Recover(0).Floor.Version; got != 5 {
		t.Fatalf("floor decreased to %d after a rejected rollback", got)
	}
}

// ─── 16. exact idempotent retry ──────────────────────────────────────────────────

func TestFloor_Advance_IdempotentRetry(t *testing.T) {
	fs := newFakeFS()
	s := newFakeStore(t, fs, 1)
	cand := mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB)
	r1, err := s.Advance(context.Background(), cand)
	if err != nil || r1.Outcome != floorAdvanceCommitted {
		t.Fatalf("first advance: outcome=%s err=%v", r1.Outcome, err)
	}
	a1, _ := fs.read(s.paths.a)
	b1, _ := fs.read(s.paths.b)

	r2, err := s.Advance(context.Background(), cand) // exact retry
	if err != nil {
		t.Fatalf("idempotent retry err: %v", err)
	}
	if r2.Outcome != floorAdvanceIdempotent {
		t.Fatalf("retry outcome=%s want idempotent", r2.Outcome)
	}
	a2, _ := fs.read(s.paths.a)
	b2, _ := fs.read(s.paths.b)
	if !bytes.Equal(a1, a2) || !bytes.Equal(b1, b2) {
		t.Fatal("idempotent retry must produce byte-identical records")
	}
}

// ─── 17. same-version / different-identity retry rejection ────────────────────────

func TestFloor_Advance_SameVersionEquivocationRejected(t *testing.T) {
	fs := newFakeFS()
	s := newFakeStore(t, fs, 1)
	if _, err := s.Advance(context.Background(), mkFloor(t, 5, floorTS0, "5a", floorHexA, floorHexB)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before, _ := fs.read(s.paths.a)
	_, err := s.Advance(context.Background(), mkFloor(t, 5, floorTS0, "5b", floorHexC, floorHexD))
	if !errors.Is(err, errFloorEquivocation) {
		t.Fatalf("got %v want errFloorEquivocation", err)
	}
	after, _ := fs.read(s.paths.a)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected equivocating write must not mutate the durable record")
	}
}

// same-version OLDER generated_at ⇒ replay rejected; NEWER ⇒ re-sign advance accepted.
func TestFloor_Advance_ReplayAndResign(t *testing.T) {
	fs := newFakeFS()
	s := newFakeStore(t, fs, 1)
	if _, err := s.Advance(context.Background(), mkFloor(t, 5, floorTS1, "5", floorHexA, floorHexB)); err != nil {
		t.Fatalf("seed at TS1: %v", err)
	}
	// same version, OLDER generated_at ⇒ replay.
	_, err := s.Advance(context.Background(), mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB))
	if !errors.Is(err, errFloorReplay) {
		t.Fatalf("older gen_at: got %v want errFloorReplay", err)
	}
	// same version, NEWER generated_at ⇒ re-sign advance (accepted).
	newerGen := mkFloor(t, 5, "2026-08-02T00:00:00Z", "5", floorHexA, floorHexB)
	if _, err := s.Advance(context.Background(), newerGen); err != nil {
		t.Fatalf("newer gen_at (re-sign) must be accepted: %v", err)
	}
}

// ─── 18 + 19 + 20. failure injection at every durability point ────────────────────
//
// Split into focused top-level tests (one durability point each) so the cognitive
// complexity stays low; together they cover mkdir, first write, second write, and
// read-back.

func TestFloor_Advance_FailInject_Mkdir(t *testing.T) {
	fs := newFakeFS()
	fs.mkdirErr = errors.New("EACCES")
	s := newFakeStore(t, fs, 1)
	cand := mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB)
	if _, err := s.Advance(context.Background(), cand); err == nil {
		t.Fatal("mkdir failure must abort the advance")
	}
	if fs.has(s.paths.a) || fs.has(s.paths.b) {
		t.Fatal("no record should be written after mkdir failure")
	}
}

// The floor state machine treats any AtomicWrite failure uniformly (an fsync, rename,
// or dir-sync failure all surface as "the write did not complete"), so cause-labeled
// errors at the first write prove cause-agnostic handling AND that a failed first write
// leaves nothing durable.
func TestFloor_Advance_FailInject_WriteA(t *testing.T) {
	cand := mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB)
	for _, cause := range []string{"fsync", "rename", "dir_sync", "generic"} {
		t.Run(cause, func(t *testing.T) {
			fs := newFakeFS()
			fs.writeHook = func(_ string, n int) error {
				if n == 1 {
					return fmt.Errorf("simulated %s failure", cause)
				}
				return nil
			}
			s := newFakeStore(t, fs, 1)
			_, err := s.Advance(context.Background(), cand)
			if !errors.Is(err, errFloorQuorumWrite) {
				t.Fatalf("got %v want errFloorQuorumWrite", err)
			}
			if fs.has(s.paths.a) || fs.has(s.paths.b) {
				t.Fatal("failed first write must leave nothing durable")
			}
		})
	}
}

// 19. first replica durable, second fails ⇒ partial preserved, NO success, and an
// exact retry completes the quorum.
func TestFloor_Advance_FailInject_WriteBThenRetry(t *testing.T) {
	fs := newFakeFS()
	fs.writeHook = func(_ string, n int) error {
		if n == 2 {
			return errors.New("simulated floor.b failure")
		}
		return nil
	}
	s := newFakeStore(t, fs, 1)
	cand := mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB)
	if _, err := s.Advance(context.Background(), cand); !errors.Is(err, errFloorQuorumWrite) {
		t.Fatalf("got %v want errFloorQuorumWrite", err)
	}
	if !fs.has(s.paths.a) || fs.has(s.paths.b) {
		t.Fatal("floor.a must be durable (partial) and floor.b absent")
	}
	// Recovery classifies the partial as degraded, floor preserved at the candidate.
	rec := s.Recover(0)
	if rec.Floor.Version != 5 || rec.Health != floorHealthDegraded || !rec.RepairRequired {
		t.Fatalf("partial must be degraded + floor preserved: %+v", rec)
	}
	// Exact-record retry with a healthy FS completes the quorum idempotently.
	fs.writeHook = nil
	r2, err := s.Advance(context.Background(), cand)
	if err != nil {
		t.Fatalf("retry err: %v", err)
	}
	if r2.Outcome != floorAdvanceIdempotent {
		t.Fatalf("retry outcome=%s want idempotent", r2.Outcome)
	}
	if !fs.has(s.paths.a) || !fs.has(s.paths.b) {
		t.Fatal("retry must complete both records")
	}
	if s.Recover(0).Health != floorHealthy {
		t.Fatal("after retry the quorum must be healthy")
	}
}

// 20. both durable, read-back verification fails ⇒ NO success.
func TestFloor_Advance_FailInject_ReadBack(t *testing.T) {
	fs := newFakeFS()
	s := newFakeStore(t, fs, 1)
	cand := mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB)
	// Corrupt every read of floor.a ONCE both writes have happened (read-back phase).
	fs.readHook = func(path string, _ []byte, exists bool) ([]byte, error, bool) {
		if path == s.paths.a && fs.writes >= 2 && exists {
			return []byte("{tampered-readback"), nil, true
		}
		return nil, nil, false
	}
	if _, err := s.Advance(context.Background(), cand); !errors.Is(err, errFloorQuorumVerify) {
		t.Fatalf("got %v want errFloorQuorumVerify", err)
	}
}

// ─── cancellation cannot convert a partial quorum into success ───────────────────

func TestFloor_Advance_CancellationNoSuccess(t *testing.T) {
	cand := mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB)

	// Pre-cancelled context ⇒ abort before any write.
	fs := newFakeFS()
	s := newFakeStore(t, fs, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Advance(ctx, cand); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled: got %v want context.Canceled", err)
	}
	if fs.has(s.paths.a) || fs.has(s.paths.b) {
		t.Fatal("pre-cancelled advance must write nothing")
	}

	// Cancel AFTER the first write lands (via the write hook) ⇒ partial preserved, no
	// success, and a fresh-context exact retry completes.
	fs2 := newFakeFS()
	s2 := newFakeStore(t, fs2, 1)
	ctx2, cancel2 := context.WithCancel(context.Background())
	fs2.writeHook = func(path string, _ int) error {
		if path == s2.paths.a {
			cancel2() // A is about to be stored; cancel so the post-A ctx check aborts
		}
		return nil
	}
	if _, err := s2.Advance(ctx2, cand); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-quorum cancel: got %v want context.Canceled", err)
	}
	if !fs2.has(s2.paths.a) || fs2.has(s2.paths.b) {
		t.Fatal("mid-quorum cancel: A durable (partial), B absent")
	}
	fs2.writeHook = nil
	if _, err := s2.Advance(context.Background(), cand); err != nil {
		t.Fatalf("retry after cancel: %v", err)
	}
	if s2.Recover(0).Health != floorHealthy {
		t.Fatal("retry must complete the quorum")
	}
}

// ─── 21. deterministic concurrent writers ────────────────────────────────────────

func TestFloor_Advance_ConcurrentWriters(t *testing.T) {
	fs := newFakeFS()
	s := newFakeStore(t, fs, 1)
	const n = 12
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			<-start
			gen := fmt.Sprintf("%d", v)
			_, _ = s.Advance(context.Background(), mkFloor(t, int64(v), floorTS0, gen, floorHexA, floorHexB))
		}(i)
	}
	close(start)
	wg.Wait()

	// Serialized advances ⇒ a single consistent final state at the max version, both
	// replicas byte-identical, no mixed identity, never a lower version winning.
	rec := s.Recover(0)
	if rec.Floor.Version != n {
		t.Fatalf("final floor=%d want %d (max)", rec.Floor.Version, n)
	}
	a, _ := fs.read(s.paths.a)
	b, _ := fs.read(s.paths.b)
	if !bytes.Equal(a, b) {
		t.Fatal("replicas diverged under concurrency (mixed identity)")
	}
	if rec.Health != floorHealthy {
		t.Fatalf("final health=%s want healthy", rec.Health)
	}
}

// same version, different identity, concurrent ⇒ exactly one wins, other equivocates.
func TestFloor_Advance_ConcurrentSameVersionConflict(t *testing.T) {
	fs := newFakeFS()
	s := newFakeStore(t, fs, 1)
	cands := []floorRecord{
		mkFloor(t, 5, floorTS0, "5a", floorHexA, floorHexB),
		mkFloor(t, 5, floorTS0, "5b", floorHexC, floorHexD),
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var okCount, equivCount int
	start := make(chan struct{})
	for _, c := range cands {
		wg.Add(1)
		go func(cand floorRecord) {
			defer wg.Done()
			<-start
			_, err := s.Advance(context.Background(), cand)
			mu.Lock()
			switch {
			case err == nil:
				okCount++
			case errors.Is(err, errFloorEquivocation):
				equivCount++
			}
			mu.Unlock()
		}(c)
	}
	close(start)
	wg.Wait()

	if okCount != 1 || equivCount != 1 {
		t.Fatalf("want exactly one winner + one equivocation, got ok=%d equiv=%d", okCount, equivCount)
	}
	a, _ := fs.read(s.paths.a)
	b, _ := fs.read(s.paths.b)
	if !bytes.Equal(a, b) {
		t.Fatal("final replicas must be the single winner's identity")
	}
	if s.Recover(0).Health != floorHealthy {
		t.Fatal("final state must be healthy (one consistent winner)")
	}
}

// ─── 22. no mtime / directory-order dependence ───────────────────────────────────

func TestFloor_Recovery_NoDirScanOrMtime(t *testing.T) {
	dir := t.TempDir()
	s, err := newFloorStore(dir, 1) // REAL os fs
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, err := s.Advance(context.Background(), mkFloor(t, 4, floorTS0, "4", floorHexA, floorHexB)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	baseline := s.Recover(0)

	// Add decoy files (higher "versions", tempish names, alphabetically later) + shuffle
	// mtimes. A directory scan or mtime read would change the result; fixed-path reads
	// must not.
	for _, decoy := range []string{"floor.c.json", "floor.z.json", "floor.a.json.tmp.999", "zzz.json"} {
		hi := mkFloor(t, 9999, floorTS1, "9999", floorHexC, floorHexD)
		if err := os.WriteFile(filepath.Join(dir, decoy), mustEncode(t, hi), 0o600); err != nil {
			t.Fatalf("decoy: %v", err)
		}
	}
	after := s.Recover(0)
	if after.Floor.Version != baseline.Floor.Version || after.Floor.Version != 4 {
		t.Fatalf("recovery changed with decoys: %d → %d (must ignore non-fixed paths)", baseline.Floor.Version, after.Floor.Version)
	}
	if after.Health != floorHealthy {
		t.Fatalf("decoys must not perturb health: %s", after.Health)
	}
}

// ─── 23. fixed filenames + safe permissions ──────────────────────────────────────

func TestFloor_FixedFilenamesAndPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "saas_feed")
	s, err := newFloorStore(dir, 1)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, err := s.Advance(context.Background(), mkFloor(t, 4, floorTS0, "4", floorHexA, floorHexB)); err != nil {
		t.Fatalf("advance: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = true
		info, _ := e.Info()
		if !e.IsDir() && info.Mode().Perm() != floorFilePerm {
			t.Errorf("%s perm=%o want %o", e.Name(), info.Mode().Perm(), floorFilePerm)
		}
	}
	if !got[floorFileA] || !got[floorFileB] || len(entries) != 2 {
		t.Fatalf("dir must hold exactly floor.a.json + floor.b.json, got %v", got)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Mode().Perm() != floorDirPerm {
		t.Errorf("dir perm=%o want %o", di.Mode().Perm(), floorDirPerm)
	}
}

// ─── 24. no temp-file leakage under a real failure path ──────────────────────────

func TestFloor_NoTempLeakOnFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := newFloorStore(dir, 1) // REAL os fs ⇒ exercises AtomicWrite's temp cleanup
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	// Force floor.b's rename to fail by occupying its path with a DIRECTORY.
	if err := os.Mkdir(s.paths.b, 0o700); err != nil {
		t.Fatalf("occupy floor.b: %v", err)
	}
	if _, err := s.Advance(context.Background(), mkFloor(t, 4, floorTS0, "4", floorHexA, floorHexB)); err == nil {
		t.Fatal("advance must fail when floor.b path is a directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Fatalf("temp file leaked after failure: %s", e.Name())
		}
	}
}

// ─── 25. fuzz + property (decoder never panics; monotonic floor invariant) ────────

func FuzzFloor_Decode(f *testing.F) {
	f.Add(mustEncode(&testing.T{}, floorRecord{
		SchemaVersion: 1, Protocol: urlcatfeed.Protocol, Feed: urlcatfeed.FeedID,
		FeedVersion: 1, GeneratedAt: floorTS0, GenerationID: "1",
		ManifestSHA256: floorHexA, ArtifactSHA256: floorHexB, CRC32C: "00000000",
	}))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"schema_version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		rec, err := decodeFloorRecord(data) // must never panic
		if err != nil {
			return
		}
		// Any ACCEPTED record must round-trip byte-identically and re-decode equal.
		out, eerr := encodeFloorRecord(rec)
		if eerr != nil {
			t.Fatalf("accepted record failed to re-encode: %v", eerr)
		}
		if !bytes.Equal(out, data) {
			t.Fatalf("accepted record is non-canonical (round-trip differs):\n in=%q\nout=%q", data, out)
		}
		again, aerr := decodeFloorRecord(out)
		if aerr != nil || again != rec {
			t.Fatalf("re-decode mismatch: %v", aerr)
		}
	})
}

// Property: adding any valid record to the candidate set NEVER lowers the floor, and
// max is order-independent (§B.12 #4/#5).
func TestFloor_Property_MonotonicSelection(t *testing.T) {
	recs := []floorRecord{
		mkFloor(t, 3, floorTS0, "3", floorHexA, floorHexB),
		mkFloor(t, 7, floorTS0, "7", floorHexC, floorHexD),
		mkFloor(t, 7, floorTS1, "7", floorHexC, floorHexD), // same ver, newer gen
		mkFloor(t, 5, floorTS0, "5", floorHexA, floorHexB),
	}
	prev := floorWatermark{Version: 1}
	acc := []floorRecord{}
	for i := range recs {
		acc = append(acc, recs[i])
		floor, _ := selectFloor(1, acc)
		if floor.less(prev) {
			t.Fatalf("floor decreased from %+v to %+v after adding a record", prev, floor)
		}
		prev = floor
	}
	// Order independence: reverse the set, same floor.
	rev := make([]floorRecord, len(recs))
	for i := range recs {
		rev[len(recs)-1-i] = recs[i]
	}
	fwd, _ := selectFloor(1, recs)
	back, _ := selectFloor(1, rev)
	if !fwd.equal(back) {
		t.Fatalf("selectFloor is order-dependent: %+v vs %+v", fwd, back)
	}
	// The winner is v7 at the NEWER generated_at.
	if fwd.Version != 7 {
		t.Fatalf("max version=%d want 7", fwd.Version)
	}
}

// ─── constructor validation ──────────────────────────────────────────────────────

func TestFloor_StoreConstructorValidation(t *testing.T) {
	if _, err := newFloorStore("", 1); !errors.Is(err, errFloorNoDir) {
		t.Fatalf("empty dir: got %v", err)
	}
	if _, err := newFloorStore("/d", 0); !errors.Is(err, errFloorCheckpoint) {
		t.Fatalf("zero checkpoint: got %v", err)
	}
	if _, err := newFloorStore("/d", -5); !errors.Is(err, errFloorCheckpoint) {
		t.Fatalf("negative checkpoint: got %v", err)
	}
	if defaultFloorCheckpoint() != 1 {
		t.Fatalf("default checkpoint placeholder = %d want 1", defaultFloorCheckpoint())
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────────

func mustEncode(t *testing.T, rec floorRecord) []byte {
	t.Helper()
	b, err := encodeFloorRecord(rec)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}
