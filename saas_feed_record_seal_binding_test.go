package main

import (
	"bytes"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed/noderecord"
)

// IM-020 (ADR-0053): the floor, activation and authority records bind their
// canonical bytes and CRC-32C seal to internal/urlcatfeed/noderecord. The byte
// strings below were captured from main BEFORE the bind (origin/main 0fe4578),
// when each record computed its own checksum with the floor file's Castagnoli
// table. A record already on disk must still decode, so these must not move.
// TestFloor_GoldenBytes pins the floor record the same way (crc 43d5a692).
func TestIM020_RecordSealsUnchangedByBinding(t *testing.T) {
	const wantActivation = `{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/saas",` +
		`"active_feed_version":42,"generation_id":"42",` +
		`"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111",` +
		`"artifact_sha256":"2222222222222222222222222222222222222222222222222222222222222222",` +
		`"snapshot_sha256":"3333333333333333333333333333333333333333333333333333333333333333",` +
		`"generated_at":"2026-07-31T00:00:00Z","expires_at":"2026-08-14T00:00:00Z","etag":"\"v42\"",` +
		`"floor_version":42,"floor_generated_at":"2026-07-31T00:00:00Z",` +
		`"config_revision":"rev-1","provenance":"downloaded","crc32c":"def7bec8"}`
	const wantAuthority = `{"schema_version":1,"protocol":"signed_manifest_v1",` +
		`"url":"https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json",` +
		`"managed":true,"enabled":true,"refresh_seconds":3600,"overrides_fingerprint":"none",` +
		`"epoch":7,"config_version":42,"cp_fingerprint":"ab12cd34","crc32c":"4b2fd64f"}`

	act, err := encodeActivationRecord(mkActivation())
	if err != nil || string(act) != wantActivation {
		t.Fatalf("activation record bytes moved (%v):\n got=%s\nwant=%s", err, act, wantActivation)
	}
	if _, err := decodeActivationRecord([]byte(wantActivation)); err != nil {
		t.Fatalf("a pre-bind activation record no longer decodes: %v", err)
	}
	auth, err := encodeSaaSFeedAuthorityRecord(validAuthorityRecord())
	if err != nil || string(auth) != wantAuthority {
		t.Fatalf("authority record bytes moved (%v):\n got=%s\nwant=%s", err, auth, wantAuthority)
	}
	if _, err := decodeSaaSFeedAuthorityRecord([]byte(wantAuthority)); err != nil {
		t.Fatalf("a pre-bind authority record no longer decodes: %v", err)
	}

	// Negative control: a record sealed with the IEEE polynomial instead of
	// Castagnoli is refused, so the pins above are not satisfied by any CRC.
	sans, err := floorCanonicalBytes(mkActivation().sansCRC())
	if err != nil {
		t.Fatal(err)
	}
	ieee := strings.Replace(wantActivation, `"crc32c":"def7bec8"`, `"crc32c":"`+hex8(crc32.ChecksumIEEE(sans))+`"`, 1)
	if ieee == wantActivation {
		t.Fatal("negative control did not change the record")
	}
	if _, err := decodeActivationRecord([]byte(ieee)); err == nil {
		t.Fatal("an IEEE-sealed activation record was accepted")
	}
}

// The root names are bindings, not second copies: they agree with the owner
// on canonical bytes, on the failure text and on the checksum form.
func TestIM020_RootCodecNamesBindNodeRecord(t *testing.T) {
	rec := mkActivation()
	got, err := floorCanonicalBytes(rec)
	want, werr := noderecord.Canonical(rec)
	if err != nil || werr != nil || !bytes.Equal(got, want) {
		t.Fatalf("floorCanonicalBytes=%s (%v), noderecord.Canonical=%s (%v)", got, err, want, werr)
	}
	if _, err := floorCanonicalBytes(make(chan int)); err == nil ||
		err.Error() != "saas feed floor: canonical encode: json: unsupported type: chan int" {
		t.Fatalf("encode failure text moved: %v", err)
	}
	for _, s := range []string{"def7bec8", "DEF7BEC8", "def7bec", "def7bec80", "", "def7becg"} {
		if validCRC32Hex(s) != noderecord.ValidChecksum(s) {
			t.Fatalf("validCRC32Hex(%q) disagrees with noderecord.ValidChecksum", s)
		}
	}
	crc, err := activationComputeCRC(rec)
	seal, serr := noderecord.Seal(rec.sansCRC())
	if err != nil || serr != nil || crc != seal || crc != "def7bec8" {
		t.Fatalf("activationComputeCRC=%s (%v), noderecord.Seal=%s (%v)", crc, err, seal, serr)
	}
}

func hex8(v uint32) string {
	const digits = "0123456789abcdef"
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = digits[v&0xf]
		v >>= 4
	}
	return string(b)
}
