// Release Catalog Freshness & Rollback Protection — Phase 1.
//
// Authenticity (release_catalog_verify.go) proves a catalog is GENUINE; it does
// NOT prove it is the LATEST. This file adds the two missing trust dimensions a
// signed update channel needs (TUF "timestamp"/"snapshot" roles, in spirit):
//
//   - Freshness: a signed catalog declares expires_at; a CP past that instant
//     (plus a small clock-skew tolerance) refuses it, so a captured-and-replayed
//     stale-but-validly-signed catalog cannot silently pin users to an old,
//     vulnerable release forever.
//   - Rollback / freeze protection: each catalog carries a monotonic
//     catalog_version; the CP persists the highest version it has ever accepted
//     and refuses anything below it, so an attacker who can serve an OLD signed
//     catalog cannot downgrade the deployment.
//
// Both checks are ENFORCE-mode only and are composed ON TOP of signature
// verification — they never widen trust, only narrow it. They are deliberately
// kept out of the structural loader (release_catalog.go) and the signature gate
// (release_catalog_verify.go) so those layers stay pure/offline; freshness needs
// a clock and rollback needs persisted state, which only the holder owns.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// catalogClockSkew is the tolerance applied to expires_at so a CP whose clock is
// slightly ahead of the signer does not spuriously reject a still-valid catalog.
const catalogClockSkew = 5 * time.Minute

// Distinct freshness/rollback error kinds (mirrors the §8 authenticity kinds) so
// callers/CI/alerting can tell a stale/replayed catalog apart from a forged one.
var (
	errCatalogExpiryMissing  = errors.New("release catalog: expires_at is required in enforce mode")
	errCatalogExpired        = errors.New("release catalog: expired")
	errCatalogFutureDated    = errors.New("release catalog: generated_at is in the future beyond skew tolerance")
	errCatalogVersionMissing = errors.New("release catalog: catalog_version is required in enforce mode")
	errCatalogRollback       = errors.New("release catalog: catalog_version is below the highest accepted version (rollback refused)")
)

// freshnessPolicy is the holder-owned configuration for the enforce-mode
// freshness + rollback gate. The zero value is DISABLED (no clock, no state),
// which is exactly what the structural/authenticity unit tests want — they
// exercise the signature boundary, not the trust-channel freshness layer.
type freshnessPolicy struct {
	enabled   bool
	now       func() time.Time
	skew      time.Duration
	statePath string // JSON file holding the persisted version floor ("" ⇒ no rollback persistence)
}

// catalogStateFile is the on-disk rollback floor. It lives OUTSIDE the catalog
// directory so replacing the catalog (a refresh) never clears the floor.
type catalogStateFile struct {
	HighestVersion int `json:"highest_accepted_version"`
}

// checkCatalogFreshness applies the freshness (expires_at) check against now.
// It is pure given (cat, now, skew). In enforce mode a missing expires_at is a
// hard failure: a signed catalog with no expiry is indistinguishable from a
// replayable forever-token, which defeats the whole freshness role.
func checkCatalogFreshness(cat *Catalog, now time.Time, skew time.Duration) error {
	if cat.ExpiresAt().IsZero() {
		return errCatalogExpiryMissing
	}
	if now.After(cat.ExpiresAt().Add(skew)) {
		return fmt.Errorf("%w: expires_at=%s now=%s", errCatalogExpired,
			cat.ExpiresAt().UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	// A catalog generated far in the FUTURE is a clock-attack / mis-signed-bundle
	// smell; reject beyond the same skew tolerance so a future expires_at cannot
	// be paired with a future generated_at to extend a stale catalog's life.
	if cat.GeneratedAt().After(now.Add(skew)) {
		return fmt.Errorf("%w: generated_at=%s now=%s", errCatalogFutureDated,
			cat.GeneratedAt().UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// isExpiredNow reports whether cat has passed its freshness window as of now.
// It is the USE-TIME counterpart to checkCatalogFreshness and is consulted on the
// holder read path (GetCatalog). It is a no-op unless the policy is enabled
// (enforce mode); a published catalog in enforce mode always carries a non-zero
// expires_at (the load-time gate rejects a missing one), so the zero-expiry guard
// here is purely defensive and never hides a legitimately-published catalog.
func (p freshnessPolicy) isExpiredNow(cat *Catalog) bool {
	if !p.enabled || cat.ExpiresAt().IsZero() {
		return false
	}
	now := time.Now
	if p.now != nil {
		now = p.now
	}
	return now().After(cat.ExpiresAt().Add(p.skew))
}

// checkCatalogRollback verifies the catalog version is present and not below the
// supplied floor. Pure given (cat, floor); persistence is the caller's job.
func checkCatalogRollback(cat *Catalog, floor int) error {
	if cat.Version() < 1 {
		return errCatalogVersionMissing
	}
	if cat.Version() < floor {
		return fmt.Errorf("%w: catalog_version=%d floor=%d", errCatalogRollback, cat.Version(), floor)
	}
	return nil
}

// applyFreshnessAndRollback runs both enforce-mode gates and, on success, raises
// the persisted version floor. It is a no-op when the policy is disabled. The
// floor is raised only AFTER both checks pass, so a rejected catalog never moves
// the floor (and a freshness failure never blocks a later in-window catalog).
func (p freshnessPolicy) applyFreshnessAndRollback(cat *Catalog) error {
	if !p.enabled {
		return nil
	}
	now := time.Now
	if p.now != nil {
		now = p.now
	}
	if err := checkCatalogFreshness(cat, now(), p.skew); err != nil {
		return err
	}
	floor, err := p.readVersionFloor()
	if err != nil {
		return err
	}
	if err := checkCatalogRollback(cat, floor); err != nil {
		return err
	}
	if cat.Version() > floor {
		if err := p.writeVersionFloor(cat.Version()); err != nil {
			return fmt.Errorf("release catalog: persist version floor: %w", err)
		}
	}
	return nil
}

// readVersionFloor reads the persisted highest-accepted version. A missing file
// is the genuine "first catalog ever" state and yields floor 0 (no rollback
// possible yet). A present-but-unreadable/corrupt file FAILS CLOSED rather than
// silently resetting the floor to 0, which would re-open the rollback window.
func (p freshnessPolicy) readVersionFloor() (int, error) {
	if p.statePath == "" {
		return 0, nil
	}
	b, err := os.ReadFile(p.statePath) // #nosec G304 -- fixed operator-configured state path, not attacker-controlled
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("release catalog: read version floor: %w", err)
	}
	var st catalogStateFile
	if err := json.Unmarshal(b, &st); err != nil {
		return 0, fmt.Errorf("release catalog: parse version floor: %w", err)
	}
	if st.HighestVersion < 0 {
		return 0, fmt.Errorf("release catalog: persisted version floor %d is negative", st.HighestVersion)
	}
	return st.HighestVersion, nil
}

// writeVersionFloor atomically persists the new highest-accepted version.
func (p freshnessPolicy) writeVersionFloor(v int) error {
	if p.statePath == "" {
		return nil
	}
	b, err := json.Marshal(catalogStateFile{HighestVersion: v})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.statePath), 0o750); err != nil {
		return err
	}
	tmp := p.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.statePath)
}
