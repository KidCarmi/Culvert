package main

// saas_feed_authority_test.go — F3b-4: managed-DP durable authority mirror + the
// effective-configuration authority resolver.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catoverride"
)

func validAuthorityRecord() saasFeedAuthorityRecord {
	return saasFeedAuthorityRecord{
		SchemaVersion:        saasFeedAuthoritySchemaVersion,
		Protocol:             saasFeedProtocolV1,
		URL:                  builtinSaaSFeedURL,
		Managed:              true,
		Enabled:              true,
		RefreshSeconds:       3600,
		OverridesFingerprint: saasFeedNoOverridesSentinel,
		Epoch:                7,
		ConfigVersion:        42,
		CPFingerprint:        "ab12cd34",
	}
}

// ─── codec: round-trip, canonical, crc, strict decode ────────────────────────────

func TestF3b4_Authority_RoundTrip(t *testing.T) {
	r := validAuthorityRecord()
	b, err := encodeSaaSFeedAuthorityRecord(r)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := decodeSaaSFeedAuthorityRecord(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.sansCRC() != r.sansCRC() {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, r)
	}
}

func TestF3b4_Authority_CanonicalByteStable(t *testing.T) {
	r := validAuthorityRecord()
	b1, err := encodeSaaSFeedAuthorityRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := encodeSaaSFeedAuthorityRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Errorf("non-deterministic encoding:\n%s\n%s", b1, b2)
	}
	// Field order is load-bearing: schema_version must be first, crc32c last.
	if !strings.HasPrefix(string(b1), `{"schema_version":`) {
		t.Errorf("schema_version not first: %s", b1)
	}
	if !strings.Contains(string(b1), `"crc32c":`) {
		t.Errorf("crc32c missing: %s", b1)
	}
}

func TestF3b4_Authority_CRCCorruptionDetected(t *testing.T) {
	r := validAuthorityRecord()
	b, err := encodeSaaSFeedAuthorityRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the "url" value → CRC mismatch on decode.
	corrupt := strings.Replace(string(b), "feeds.culvertlabs.com", "feeds.culvertlxbs.com", 1)
	if corrupt == string(b) {
		t.Fatal("test setup: no substitution made")
	}
	if _, err := decodeSaaSFeedAuthorityRecord([]byte(corrupt)); err == nil {
		t.Error("corrupt record accepted (crc or url validation should reject)")
	}
}

func TestF3b4_Authority_StrictDecode(t *testing.T) {
	good, _ := encodeSaaSFeedAuthorityRecord(validAuthorityRecord())
	cases := map[string][]byte{
		"empty":         {},
		"unknown field": []byte(`{"schema_version":1,"bogus":1}`),
		"trailing":      append(append([]byte{}, good...), []byte(" {}")...),
		"oversize":      []byte(`{"x":"` + strings.Repeat("a", maxSaaSFeedAuthorityRecordBytes) + `"}`),
		"non-canonical": []byte(`{ "schema_version": 1 }`),
	}
	for name, data := range cases {
		if _, err := decodeSaaSFeedAuthorityRecord(data); err == nil {
			t.Errorf("%s: accepted invalid record", name)
		}
	}
}

func TestF3b4_Authority_FieldValidation(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*saasFeedAuthorityRecord)
	}{
		{"bad schema", func(r *saasFeedAuthorityRecord) { r.SchemaVersion = 2 }},
		{"bad protocol", func(r *saasFeedAuthorityRecord) { r.Protocol = "raw_v1" }},
		{"non-official url", func(r *saasFeedAuthorityRecord) { r.URL = "https://evil.example.com/x" }},
		{"empty url", func(r *saasFeedAuthorityRecord) { r.URL = "" }},
		{"negative refresh", func(r *saasFeedAuthorityRecord) { r.RefreshSeconds = -1 }},
		{"bad fingerprint", func(r *saasFeedAuthorityRecord) { r.OverridesFingerprint = "xyz" }},
		{"negative epoch", func(r *saasFeedAuthorityRecord) { r.Epoch = -1 }},
		{"negative config version", func(r *saasFeedAuthorityRecord) { r.ConfigVersion = -1 }},
		{"control-char cp fingerprint", func(r *saasFeedAuthorityRecord) { r.CPFingerprint = "a\x00b" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validAuthorityRecord()
			tc.mut(&r)
			if err := validateSaaSFeedAuthorityFields(r); err == nil {
				t.Errorf("%s: accepted invalid field", tc.name)
			}
		})
	}
}

// ─── store: commit + read-back + absent ──────────────────────────────────────────

func TestF3b4_Authority_StoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := newSaaSFeedAuthorityStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Absent before any commit.
	if _, st, _ := store.Read(); st != saasFeedAuthorityAbsent {
		t.Fatalf("pre-commit status = %s, want absent", st)
	}
	r := validAuthorityRecord()
	if err := store.Commit(r); err != nil {
		t.Fatalf("commit: %v", err)
	}
	got, st, err := store.Read()
	if err != nil || st != saasFeedAuthorityValid {
		t.Fatalf("read-back status=%s err=%v", st, err)
	}
	if got.sansCRC() != r.sansCRC() {
		t.Errorf("read-back mismatch:\n got %+v\nwant %+v", got, r)
	}
	// Commit into a not-yet-existing nested dir must mkdir.
	nested, err := newSaaSFeedAuthorityStore(filepath.Join(dir, "saas_feed"))
	if err != nil {
		t.Fatal(err)
	}
	if err := nested.Commit(r); err != nil {
		t.Fatalf("commit into nested dir: %v", err)
	}
}

func TestF3b4_Authority_CorruptFileRead(t *testing.T) {
	dir := t.TempDir()
	store, _ := newSaaSFeedAuthorityStore(dir)
	if err := store.fs.atomicWrite(store.path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, st, _ := store.Read(); st != saasFeedAuthorityCorrupt {
		t.Errorf("corrupt file status = %s, want corrupt", st)
	}
}

// ─── overrides fingerprint determinism ───────────────────────────────────────────

func TestF3b4_Authority_OverridesFingerprint(t *testing.T) {
	if fp := saasFeedOverridesFingerprint(catoverride.Overrides{}); fp != saasFeedNoOverridesSentinel {
		t.Errorf("empty fingerprint = %q, want %q", fp, saasFeedNoOverridesSentinel)
	}
	a := catoverride.Overrides{Added: map[string]string{"a.example.com": "social"}, Tombstones: []string{"bad.example.com"}}
	b := catoverride.Overrides{Added: map[string]string{"a.example.com": "social"}, Tombstones: []string{"bad.example.com"}}
	fpA, fpB := saasFeedOverridesFingerprint(a), saasFeedOverridesFingerprint(b)
	if fpA != fpB {
		t.Errorf("equal override sets produced different fingerprints: %q vs %q", fpA, fpB)
	}
	if !validSHA256Hex(fpA) {
		t.Errorf("non-empty fingerprint not 64-hex: %q", fpA)
	}
	c := catoverride.Overrides{Added: map[string]string{"a.example.com": "news"}}
	if saasFeedOverridesFingerprint(c) == fpA {
		t.Error("different override sets collided")
	}
}

// ─── resolver matrix ─────────────────────────────────────────────────────────────

func TestF3b4_ResolveAuthority_Standalone(t *testing.T) {
	res := resolveFeedAuthority(resolveFeedAuthorityInput{
		Authority: authorityStandalone,
		Durable:   saasFeedDurable{Managed: true, Enabled: true, Protocol: saasFeedProtocolV1},
	})
	if !res.Ready || res.WaitingForAuthority {
		t.Fatalf("standalone should be ready: %+v", res)
	}
	if !res.Config.Enabled {
		t.Errorf("expected enabled config, got %+v", res.Config)
	}
}

func TestF3b4_ResolveAuthority_StandaloneInvalidConfig(t *testing.T) {
	res := resolveFeedAuthority(resolveFeedAuthorityInput{
		Authority: authorityStandalone,
		Durable:   saasFeedDurable{Managed: true, Enabled: true, Protocol: "raw_bogus"},
	})
	if !res.Ready {
		t.Fatalf("invalid local config is still node-authoritative (ready): %+v", res)
	}
	if res.Config.Enabled {
		t.Errorf("invalid config must resolve to a disabled feed: %+v", res.Config)
	}
}

func TestF3b4_ResolveAuthority_ManagedDP_Matrix(t *testing.T) {
	mirror := validAuthorityRecord()
	mirror.OverridesFingerprint = saasFeedNoOverridesSentinel

	t.Run("mirror absent ⇒ waiting", func(t *testing.T) {
		res := resolveFeedAuthority(resolveFeedAuthorityInput{
			Authority: authorityManagedDP, MirrorStatus: saasFeedAuthorityAbsent,
		})
		if !res.WaitingForAuthority || res.Ready || res.Config.Enabled {
			t.Errorf("absent mirror must wait, no fetch: %+v", res)
		}
	})
	t.Run("mirror corrupt ⇒ waiting", func(t *testing.T) {
		res := resolveFeedAuthority(resolveFeedAuthorityInput{
			Authority: authorityManagedDP, MirrorStatus: saasFeedAuthorityCorrupt,
		})
		if !res.WaitingForAuthority || res.Config.Enabled {
			t.Errorf("corrupt mirror must wait: %+v", res)
		}
	})
	t.Run("valid + overrides consistent ⇒ ready", func(t *testing.T) {
		res := resolveFeedAuthority(resolveFeedAuthorityInput{
			Authority: authorityManagedDP, MirrorStatus: saasFeedAuthorityValid,
			MirrorRecord: mirror, Overrides: catoverride.Overrides{}, EpochFloor: mirror.Epoch,
		})
		if !res.Ready || res.WaitingForAuthority {
			t.Fatalf("valid mirror must be ready: %+v", res)
		}
		if !res.Config.Enabled || res.OverrideRevision != saasFeedNoOverridesSentinel {
			t.Errorf("config/override revision wrong: %+v", res)
		}
	})
	t.Run("valid but overrides inconsistent ⇒ waiting (ambiguous)", func(t *testing.T) {
		res := resolveFeedAuthority(resolveFeedAuthorityInput{
			Authority: authorityManagedDP, MirrorStatus: saasFeedAuthorityValid,
			MirrorRecord: mirror,
			Overrides:    catoverride.Overrides{Tombstones: []string{"x.example.com"}}, // fp != "none"
			EpochFloor:   mirror.Epoch,
		})
		if !res.WaitingForAuthority {
			t.Errorf("inconsistent overrides must wait (never silently drop): %+v", res)
		}
	})
	t.Run("valid but epoch below fencing floor ⇒ waiting (conflict)", func(t *testing.T) {
		res := resolveFeedAuthority(resolveFeedAuthorityInput{
			Authority: authorityManagedDP, MirrorStatus: saasFeedAuthorityValid,
			MirrorRecord: mirror, Overrides: catoverride.Overrides{},
			EpochFloor: mirror.Epoch + 5, // DP has since observed a higher fencing epoch
		})
		if !res.WaitingForAuthority {
			t.Errorf("stale-epoch mirror must wait (CP identity/epoch conflict): %+v", res)
		}
	})
}

// ─── write-point: applySnapshotSaaSFeed persists the mirror on a managed DP ───────

func swapAuthorityStore(t *testing.T, dir string) *saasFeedAuthorityStore {
	t.Helper()
	store, err := newSaaSFeedAuthorityStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	prev := globalSaaSFeedAuthorityStore
	globalSaaSFeedAuthorityStore = store
	t.Cleanup(func() { globalSaaSFeedAuthorityStore = prev })
	return store
}

func swapClusterRole(t *testing.T, role string) {
	t.Helper()
	clusterRoleMu.Lock()
	prev := clusterRole.role
	clusterRole.role = role
	clusterRoleMu.Unlock()
	t.Cleanup(func() {
		clusterRoleMu.Lock()
		clusterRole.role = prev
		clusterRoleMu.Unlock()
	})
}

func TestF3b4_Authority_WritePointManagedDP(t *testing.T) {
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)
	store := swapAuthorityStore(t, t.TempDir())
	swapClusterRole(t, "data-plane")

	// Seed the fencing floor so the snapshot's epoch is accepted, then apply.
	origEpoch := dpLastSeenEpoch.Load()
	t.Cleanup(func() { dpLastSeenEpoch.Store(origEpoch) })
	dpLastSeenEpoch.Store(0)

	applySnapshotSaaSFeed(ConfigSnapshot{
		Version: 12, Epoch: 4, CAFingerprint: "cafp-abc",
		SaaSFeedManaged:  boolPtr(true),
		SaaSFeedEnabled:  boolPtr(true),
		SaaSFeedProtocol: saasFeedProtocolV1,
		SaaSFeedURL:      builtinSaaSFeedURL,
		CategoryOverrides: &CategoryOverrides{
			Tombstones: []string{"ads.example.com"},
		},
	})

	rec, st, err := store.Read()
	if err != nil || st != saasFeedAuthorityValid {
		t.Fatalf("mirror not written: status=%s err=%v", st, err)
	}
	if !rec.Managed || !rec.Enabled || rec.URL != builtinSaaSFeedURL || rec.Epoch != 4 || rec.ConfigVersion != 12 || rec.CPFingerprint != "cafp-abc" {
		t.Errorf("mirror record wrong: %+v", rec)
	}
	if rec.OverridesFingerprint == saasFeedNoOverridesSentinel {
		t.Error("mirror should bind the non-empty override fingerprint")
	}

	// Restart simulation: resolve authority from the durable mirror + durable overrides.
	res := resolveFeedAuthority(resolveFeedAuthorityInput{
		Authority: authorityManagedDP, MirrorStatus: st, MirrorRecord: rec,
		Overrides: globalCategoryOverrides.Get(), EpochFloor: 4,
	})
	if !res.Ready || res.WaitingForAuthority {
		t.Fatalf("managed DP should resolve Ready from the mirror: %+v", res)
	}
	if !res.Config.Enabled {
		t.Errorf("resolved config should be enabled: %+v", res.Config)
	}
}

func TestF3b4_Authority_WritePointStandaloneNoop(t *testing.T) {
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)
	store := swapAuthorityStore(t, t.TempDir())
	swapClusterRole(t, "standalone")

	applySnapshotSaaSFeed(ConfigSnapshot{
		Version: 3, Epoch: 1, SaaSFeedManaged: boolPtr(true), SaaSFeedEnabled: boolPtr(true),
		SaaSFeedProtocol: saasFeedProtocolV1,
	})
	if _, st, _ := store.Read(); st != saasFeedAuthorityAbsent {
		t.Errorf("standalone node must NOT write the managed-DP authority mirror: status=%s", st)
	}
}

func TestF3b4_BuildAuthorityRecord_ResolvesURL(t *testing.T) {
	// Empty URL ⇒ resolves to the built-in official endpoint (never stored empty).
	rec, err := buildSaaSFeedAuthorityRecord(saasFeedDurable{Enabled: true}, catoverride.Overrides{}, 3, 9, "cafp")
	if err != nil {
		t.Fatal(err)
	}
	if rec.URL != builtinSaaSFeedURL || rec.Protocol != saasFeedProtocolV1 {
		t.Errorf("unresolved record: %+v", rec)
	}
	if err := validateSaaSFeedAuthorityFields(rec); err != nil {
		t.Errorf("built record fails validation: %v", err)
	}
}
