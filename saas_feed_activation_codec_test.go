package main

// F3b-3 activation-record codec tests: deterministic/golden canonical bytes, CRC
// behavior, strict bounded decode (unknown/duplicate/trailing/non-canonical rejected),
// and store commit + read-back.

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const (
	actHexA = "1111111111111111111111111111111111111111111111111111111111111111"
	actHexB = "2222222222222222222222222222222222222222222222222222222222222222"
	actHexC = "3333333333333333333333333333333333333333333333333333333333333333"
)

func mkActivation() activationRecord {
	return activationRecord{
		SchemaVersion:    activationSchemaVersion,
		Protocol:         "signed_manifest_v1",
		Feed:             "url-categories/saas",
		ActiveVersion:    42,
		GenerationID:     "42",
		ManifestSHA256:   actHexA,
		ArtifactSHA256:   actHexB,
		SnapshotSHA256:   actHexC,
		GeneratedAt:      "2026-07-31T00:00:00Z",
		ExpiresAt:        "2026-08-14T00:00:00Z",
		ETag:             `"v42"`,
		FloorVersion:     42,
		FloorGeneratedAt: "2026-07-31T00:00:00Z",
		ConfigRevision:   "rev-1",
		Provenance:       activationProvenanceDownloaded,
	}
}

// ── deterministic / golden bytes ─────────────────────────────────────────────────

func TestF3b3_Activation_GoldenBytes(t *testing.T) {
	rec := mkActivation()
	got, err := encodeActivationRecord(rec)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	want := `{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/saas",` +
		`"active_feed_version":42,"generation_id":"42",` +
		`"manifest_sha256":"` + actHexA + `","artifact_sha256":"` + actHexB + `","snapshot_sha256":"` + actHexC + `",` +
		`"generated_at":"2026-07-31T00:00:00Z","expires_at":"2026-08-14T00:00:00Z","etag":"\"v42\"",` +
		`"floor_version":42,"floor_generated_at":"2026-07-31T00:00:00Z",` +
		`"config_revision":"rev-1","provenance":"downloaded","crc32c":"`
	if !strings.HasPrefix(string(got), want) {
		t.Fatalf("golden prefix drift:\n got=%s", got)
	}
	if strings.HasSuffix(string(got), "\n") {
		t.Fatal("canonical bytes must have no trailing newline")
	}
	// Round-trips exactly.
	back, err := decodeActivationRecord(got)
	if err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	if !sameActivationIdentity(back, rec) {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", back, rec)
	}
	// Deterministic: re-encode is byte-identical.
	got2, _ := encodeActivationRecord(rec)
	if !bytes.Equal(got, got2) {
		t.Fatal("encode is not deterministic")
	}
}

func TestF3b3_Activation_CRCIndependentOfStoredField(t *testing.T) {
	rec := mkActivation()
	c1, _ := activationComputeCRC(rec)
	tampered := rec
	tampered.CRC32C = "deadbeef"
	c2, _ := activationComputeCRC(tampered)
	if c1 != c2 {
		t.Fatalf("crc must be independent of the stored crc32c field: %s vs %s", c1, c2)
	}
	// Any bound-field change changes the crc.
	for name, mut := range map[string]func(r *activationRecord){
		"version":  func(r *activationRecord) { r.ActiveVersion = 43; r.GenerationID = "43" },
		"manifest": func(r *activationRecord) { r.ManifestSHA256 = actHexC },
		"snapshot": func(r *activationRecord) { r.SnapshotSHA256 = actHexA },
		"floor":    func(r *activationRecord) { r.FloorVersion = 41 },
		"config":   func(r *activationRecord) { r.ConfigRevision = "rev-2" },
		"prov":     func(r *activationRecord) { r.Provenance = activationProvenanceCached },
	} {
		m := rec
		mut(&m)
		cm, _ := activationComputeCRC(m)
		if cm == c1 {
			t.Fatalf("%s change did not alter crc", name)
		}
	}
}

// ── strict / bounded decode ──────────────────────────────────────────────────────

func TestF3b3_Activation_DecodeRejections(t *testing.T) {
	good, _ := encodeActivationRecord(mkActivation())
	cases := map[string][]byte{
		"empty":         nil,
		"oversize":      make([]byte, maxActivationRecordBytes+1),
		"unknown field": []byte(strings.Replace(string(good), `"crc32c":"`, `"x":1,"crc32c":"`, 1)),
		"trailing":      append(append([]byte(nil), good...), []byte(" {}")...),
		"reordered": []byte(`{"protocol":"signed_manifest_v1","schema_version":1,"feed":"url-categories/saas",` +
			`"active_feed_version":42,"generation_id":"42","manifest_sha256":"` + actHexA + `","artifact_sha256":"` + actHexB +
			`","snapshot_sha256":"` + actHexC + `","generated_at":"2026-07-31T00:00:00Z","expires_at":"2026-08-14T00:00:00Z",` +
			`"floor_version":42,"floor_generated_at":"2026-07-31T00:00:00Z","config_revision":"rev-1","provenance":"downloaded","crc32c":"00000000"}`),
		"crc mismatch": []byte(strings.Replace(string(good), string(good[len(good)-9:len(good)-1]), "00000000", 1)),
	}
	for name, data := range cases {
		if _, err := decodeActivationRecord(data); err == nil {
			t.Errorf("%s: expected rejection, got nil", name)
		}
	}
}

func TestF3b3_Activation_FieldValidation(t *testing.T) {
	base := mkActivation()
	for name, mut := range map[string]func(r *activationRecord){
		"schema":      func(r *activationRecord) { r.SchemaVersion = 2 },
		"protocol":    func(r *activationRecord) { r.Protocol = "x" },
		"feed":        func(r *activationRecord) { r.Feed = "x" },
		"version<1":   func(r *activationRecord) { r.ActiveVersion = 0 },
		"id mismatch": func(r *activationRecord) { r.GenerationID = "99" },
		"bad digest":  func(r *activationRecord) { r.ManifestSHA256 = "xyz" },
		"bad time":    func(r *activationRecord) { r.GeneratedAt = "2026-07-31" },
		"exp<=gen":    func(r *activationRecord) { r.ExpiresAt = r.GeneratedAt },
		"floor>ver":   func(r *activationRecord) { r.FloorVersion = 99 },
		"bad prov":    func(r *activationRecord) { r.Provenance = "wat" },
		"empty rev":   func(r *activationRecord) { r.ConfigRevision = "" },
		"ctrl etag":   func(r *activationRecord) { r.ETag = "a\x00b" },
	} {
		m := base
		mut(&m)
		if err := validateActivationFields(m); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

// ── store commit + read-back ─────────────────────────────────────────────────────

func TestF3b3_Activation_StoreCommitReadBack(t *testing.T) {
	dir := t.TempDir()
	st, err := newActivationStore(dir)
	if err != nil {
		t.Fatalf("newActivationStore: %v", err)
	}
	if _, s, _ := st.Read(); s != activationAbsent {
		t.Fatalf("fresh read status = %s; want absent", s)
	}
	rec := mkActivation()
	if err := st.Commit(rec); err != nil {
		t.Fatalf("commit: %v", err)
	}
	got, s, err := st.Read()
	if s != activationValid || err != nil {
		t.Fatalf("read after commit: status=%s err=%v", s, err)
	}
	if !sameActivationIdentity(got, rec) {
		t.Fatal("read-back identity mismatch")
	}
}

func TestF3b3_Activation_CommitWriteFailure(t *testing.T) {
	fs := newFakeFS()
	fs.writeHook = func(string, int) error { return errors.New("disk full") }
	st, _ := newActivationStoreFS(fs.seam(), "/data/saas_feed")
	if err := st.Commit(mkActivation()); err == nil {
		t.Fatal("expected commit write failure")
	}
	// Nothing durable → a subsequent read is absent (no partial record).
	if _, s, _ := st.Read(); s != activationAbsent {
		t.Fatalf("status after failed commit = %s; want absent", s)
	}
}
