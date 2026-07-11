package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

// ─── checkCatalogFreshness ───────────────────────────────────────────────────

func TestFreshness_MissingExpiryRejected(t *testing.T) {
	cat := &Catalog{generatedAt: mustTime(t, "2026-01-01T00:00:00Z")} // expiresAt zero
	err := checkCatalogFreshness(cat, mustTime(t, "2026-01-02T00:00:00Z"), catalogClockSkew)
	if !errors.Is(err, errCatalogExpiryMissing) {
		t.Fatalf("err = %v; want errCatalogExpiryMissing", err)
	}
}

func TestFreshness_ExpiredRejected(t *testing.T) {
	cat := &Catalog{
		generatedAt: mustTime(t, "2026-01-01T00:00:00Z"),
		expiresAt:   mustTime(t, "2026-01-10T00:00:00Z"),
	}
	// now is past expires_at + skew.
	err := checkCatalogFreshness(cat, mustTime(t, "2026-01-10T00:10:00Z"), catalogClockSkew)
	if !errors.Is(err, errCatalogExpired) {
		t.Fatalf("err = %v; want errCatalogExpired", err)
	}
}

func TestFreshness_WithinSkewAccepted(t *testing.T) {
	cat := &Catalog{
		generatedAt: mustTime(t, "2026-01-01T00:00:00Z"),
		expiresAt:   mustTime(t, "2026-01-10T00:00:00Z"),
	}
	// 2 minutes past expiry but inside the 5-minute skew tolerance.
	if err := checkCatalogFreshness(cat, mustTime(t, "2026-01-10T00:02:00Z"), catalogClockSkew); err != nil {
		t.Fatalf("within-skew catalog rejected: %v", err)
	}
}

func TestFreshness_FutureGeneratedRejected(t *testing.T) {
	cat := &Catalog{
		generatedAt: mustTime(t, "2026-06-01T00:00:00Z"), // far ahead of now
		expiresAt:   mustTime(t, "2099-01-01T00:00:00Z"),
	}
	err := checkCatalogFreshness(cat, mustTime(t, "2026-01-01T00:00:00Z"), catalogClockSkew)
	if !errors.Is(err, errCatalogFutureDated) {
		t.Fatalf("err = %v; want errCatalogFutureDated", err)
	}
}

// ─── checkCatalogRollback ────────────────────────────────────────────────────

func TestRollback_MissingVersionRejected(t *testing.T) {
	cat := &Catalog{version: 0}
	if err := checkCatalogRollback(cat, 0); !errors.Is(err, errCatalogVersionMissing) {
		t.Fatalf("err = %v; want errCatalogVersionMissing", err)
	}
}

func TestRollback_BelowFloorRejected(t *testing.T) {
	cat := &Catalog{version: 4}
	if err := checkCatalogRollback(cat, 5); !errors.Is(err, errCatalogRollback) {
		t.Fatalf("err = %v; want errCatalogRollback", err)
	}
}

func TestRollback_AtOrAboveFloorAccepted(t *testing.T) {
	for _, v := range []int{5, 6} {
		if err := checkCatalogRollback(&Catalog{version: v}, 5); err != nil {
			t.Errorf("version %d at floor 5 rejected: %v", v, err)
		}
	}
}

// ─── applyFreshnessAndRollback (persistence) ─────────────────────────────────

func TestApply_PersistsAndRefusesDowngrade(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	now := mustTime(t, "2026-01-01T00:00:00Z")
	p := freshnessPolicy{enabled: true, now: func() time.Time { return now }, skew: catalogClockSkew, statePath: statePath}

	exp := mustTime(t, "2099-01-01T00:00:00Z")
	mk := func(v int) *Catalog { return &Catalog{generatedAt: now, expiresAt: exp, version: v} }

	// First accept v5 → floor becomes 5.
	if err := p.applyFreshnessAndRollback(mk(5)); err != nil {
		t.Fatalf("accept v5: %v", err)
	}
	if st, _ := p.readFloorState(); st.HighestVersion != 5 {
		t.Fatalf("floor = %d; want 5", st.HighestVersion)
	}
	// A replay of v4 (a captured older signed catalog) is refused.
	if err := p.applyFreshnessAndRollback(mk(4)); !errors.Is(err, errCatalogRollback) {
		t.Fatalf("downgrade to v4: err = %v; want errCatalogRollback", err)
	}
	// Floor unchanged by the refused downgrade.
	if st, _ := p.readFloorState(); st.HighestVersion != 5 {
		t.Fatalf("floor after refused downgrade = %d; want 5", st.HighestVersion)
	}
	// Forward to v6 accepted and floor raised.
	if err := p.applyFreshnessAndRollback(mk(6)); err != nil {
		t.Fatalf("accept v6: %v", err)
	}
	if st, _ := p.readFloorState(); st.HighestVersion != 6 {
		t.Fatalf("floor = %d; want 6", st.HighestVersion)
	}
}

// SEC-F4 (M1-4, §10): the ratchet is a (catalog_version, generated_at) PAIR —
// weekly re-signs never bump the version, so an equal-version catalog with an
// OLDER generated_at (a captured earlier re-sign) must be REFUSED, while the
// identical pair (a restart reloading the very catalog that set the floor)
// stays idempotent and a NEWER re-sign advances the floor.
func TestApply_SameVersionResignReplayRefused(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	now := mustTime(t, "2026-07-10T00:00:00Z") // advanced below as the weeks pass
	p := freshnessPolicy{enabled: true, now: func() time.Time { return now }, skew: catalogClockSkew, statePath: statePath}
	exp := mustTime(t, "2099-01-01T00:00:00Z")
	mk := func(gen string) *Catalog {
		return &Catalog{generatedAt: mustTime(t, gen), expiresAt: exp, version: 7}
	}

	// Install the week-2 re-sign → floor (7, week2).
	if err := p.applyFreshnessAndRollback(mk("2026-07-06T03:00:00Z")); err != nil {
		t.Fatalf("accept week-2 re-sign: %v", err)
	}
	st, _ := p.readFloorState()
	if st.HighestVersion != 7 || st.HighestGeneratedAt != "2026-07-06T03:00:00Z" {
		t.Fatalf("floor pair not persisted: %+v", st)
	}
	// The captured week-1 re-sign (same version, older generated_at) is refused.
	if err := p.applyFreshnessAndRollback(mk("2026-06-29T03:00:00Z")); !errors.Is(err, errCatalogRollback) {
		t.Fatalf("SEC-F4 violated: equal-version/older-generated_at accepted (err=%v)", err)
	}
	// Floor untouched by the refusal.
	if st, _ := p.readFloorState(); st.HighestGeneratedAt != "2026-07-06T03:00:00Z" {
		t.Fatalf("floor moved on a refused replay: %+v", st)
	}
	// Restart idempotency: the identical pair reloads fine.
	if err := p.applyFreshnessAndRollback(mk("2026-07-06T03:00:00Z")); err != nil {
		t.Fatalf("reload of the floor catalog must stay idempotent: %v", err)
	}
	// The week-3 re-sign advances the generated_at half (clock moves with it,
	// else the future-dating guard would trip — correct but not under test here).
	now = mustTime(t, "2026-07-13T04:00:00Z")
	if err := p.applyFreshnessAndRollback(mk("2026-07-13T03:00:00Z")); err != nil {
		t.Fatalf("accept week-3 re-sign: %v", err)
	}
	if st, _ := p.readFloorState(); st.HighestGeneratedAt != "2026-07-13T03:00:00Z" {
		t.Fatalf("generated_at floor not advanced: %+v", st)
	}
	// Legacy migration: a version-only state file (no generated_at half) checks
	// nothing until the next install writes the pair — never bricks an upgrade.
	legacy := freshnessPolicy{enabled: true, now: func() time.Time { return now }, skew: catalogClockSkew,
		statePath: filepath.Join(t.TempDir(), "legacy.json")}
	if err := legacy.writeVersionFloor(7); err != nil {
		t.Fatal(err)
	}
	if err := legacy.applyFreshnessAndRollback(mk("2026-06-29T03:00:00Z")); err != nil {
		t.Fatalf("legacy version-only floor must not refuse a same-version catalog: %v", err)
	}
	if st, _ := legacy.readFloorState(); st.HighestGeneratedAt == "" {
		t.Fatalf("first post-migration install must write the generated_at half: %+v", st)
	}
}

func TestApply_DisabledIsNoop(t *testing.T) {
	// A disabled policy ignores even a missing expiry / version.
	if err := (freshnessPolicy{}).applyFreshnessAndRollback(&Catalog{}); err != nil {
		t.Fatalf("disabled policy must be a no-op; got %v", err)
	}
}

// ─── isExpiredNow (use-time) ─────────────────────────────────────────────────

func TestIsExpiredNow(t *testing.T) {
	exp := mustTime(t, "2026-01-10T00:00:00Z")
	cat := &Catalog{expiresAt: exp}
	cases := []struct {
		name    string
		enabled bool
		now     string
		want    bool
	}{
		{"disabled never expires", false, "2030-01-01T00:00:00Z", false},
		{"before expiry", true, "2026-01-09T00:00:00Z", false},
		{"within skew", true, "2026-01-10T00:02:00Z", false},
		{"past expiry+skew", true, "2026-01-10T00:10:00Z", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := mustTime(t, tc.now)
			p := freshnessPolicy{enabled: tc.enabled, now: func() time.Time { return now }, skew: catalogClockSkew}
			if got := p.isExpiredNow(cat); got != tc.want {
				t.Errorf("isExpiredNow = %v; want %v", got, tc.want)
			}
		})
	}
}

// A catalog accepted while fresh is HIDDEN from readers once the live clock
// passes expires_at + skew — without unpublishing it or touching the floor.
func TestHolder_UseTimeExpiryHidesCatalog(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	writeSignedCatalogDir(t, dir, priv, freshValidSource("2026-05-10T00:00:00Z", 1))

	clock := mustTime(t, "2026-05-01T00:00:00Z") // after generated_at, before expiry
	now := func() time.Time { return clock }
	ts, err := NewTrustStore([]TrustKey{{KeyID: holderTestKeyID, Alg: catalogSigAlg, PublicKey: pub}}, VerifyEnforce)
	if err != nil {
		t.Fatal(err)
	}
	h := NewCatalogHolder(dir, ts, WithFreshnessEnforcement(now, catalogClockSkew, filepath.Join(t.TempDir(), "s.json")))

	if err := h.Reload(); err != nil {
		t.Fatalf("fresh catalog must load: %v", err)
	}
	if h.GetCatalog() == nil || !h.HasCatalog() {
		t.Fatal("catalog must be visible while fresh")
	}
	// Advance the clock past expiry + skew: the same published pointer is now
	// hidden from readers.
	clock = mustTime(t, "2026-05-10T00:10:00Z")
	if h.GetCatalog() != nil {
		t.Fatal("expired catalog must be hidden from GetCatalog (use-time expiry)")
	}
	if h.HasCatalog() {
		t.Fatal("HasCatalog must reflect use-time expiry")
	}
}

func TestReadVersionFloor_CorruptFailsClosed(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(statePath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := freshnessPolicy{enabled: true, statePath: statePath}
	if _, err := p.readFloorState(); err == nil {
		t.Fatal("a corrupt version-floor file must fail closed, not reset the floor to 0")
	}
}
