// Release Catalog Verified Auto-Seed — P1.7.
//
// At Control-Plane startup, if CULVERT_RELEASE_CATALOG_URL is set AND signature
// verification is in enforce mode, fetch the official signed catalog from that
// URL, verify it (signature + freshness + rollback), and atomically install it
// into <dataDir>/release_catalog/ so a clean install reaches available:true
// without manual file placement. Anything wrong ⇒ leave the existing on-disk
// catalog untouched and continue (fail closed). NO unsigned auto-download.
//
// Verification lives HERE, in the Go binary (it holds the trust roots) — never in
// the installer/shell. The installer only forwards the env var.
//
// Scope (roadmap/D1.6d-P1.7-catalog-autoseed-plan.md): boot-time seed only. NO
// background ticker/polling, NO GUI, NO mirror/air-gap, NO agent changes. The
// provider + this function are reusable by a later refresh slice.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

// catalogStager is the transport seam the auto-seed depends on: it stages a
// VERIFIED catalog candidate (index + signature + manifests) into a fresh dir and
// returns its path, or errCatalogUnchanged on a 304. HTTPCatalogProvider is the
// production implementation; tests inject a fake.
type catalogStager interface {
	Stage(ctx context.Context) (string, error)
}

// autoSeedConfig carries the (already-validated) inputs for one seed attempt.
type autoSeedConfig struct {
	catalogDir string // destination: <dataDir>/release_catalog
	statePath  string // rollback version floor (read-only here)
	trust      TrustStore
	now        func() time.Time // injectable clock (tests); nil ⇒ time.Now
	skew       time.Duration
}

// autoSeedCatalog runs one stage → READ-ONLY validate → atomic swap cycle. It is
// best-effort: every failure returns a non-nil error for the caller to LOG, but
// always leaves the existing on-disk catalog untouched (fail closed). It never
// writes the rollback floor — the authoritative floor raise is the real
// holder.Reload() that runs AFTER the swap, so a failed swap can never leave the
// floor ahead of the installed catalog.
func autoSeedCatalog(ctx context.Context, stager catalogStager, cfg autoSeedConfig) error {
	stage, err := stager.Stage(ctx)
	if err != nil {
		if errors.Is(err, errCatalogUnchanged) {
			return nil // 304 — the on-disk catalog is already current
		}
		return fmt.Errorf("release catalog: auto-seed stage: %w", err)
	}
	// Own the staged dir: remove it unless it is successfully swapped into place.
	swapped := false
	defer func() {
		if !swapped {
			_ = os.RemoveAll(stage)
		}
	}()

	// READ-ONLY validation on the staged candidate. LoadVerifiedCatalog re-checks
	// the signature (defense-in-depth on top of the provider's two-phase verify);
	// the freshness + rollback checks are the pure, side-effect-free variants — no
	// floor is written here.
	cat, err := LoadVerifiedCatalog(&dirCatalogSource{dir: stage}, cfg.trust)
	if err != nil {
		return fmt.Errorf("release catalog: auto-seed verify: %w", err)
	}
	now := time.Now
	if cfg.now != nil {
		now = cfg.now
	}
	if err := checkCatalogFreshness(cat, now(), cfg.skew); err != nil {
		return fmt.Errorf("release catalog: auto-seed freshness: %w", err)
	}
	st, err := (freshnessPolicy{enabled: true, statePath: cfg.statePath}).readFloorState()
	if err != nil {
		return fmt.Errorf("release catalog: auto-seed read floor: %w", err)
	}
	if err := checkCatalogRollback(cat, st.HighestVersion); err != nil {
		return fmt.Errorf("release catalog: auto-seed rollback: %w", err)
	}
	// SEC-F4: an origin serving an OLDER re-sign of the already-accepted version
	// (same catalog_version, older generated_at) is a freshness rollback and is
	// refused here, before the swap — the holder's post-swap gate rechecks too.
	floorGen, err := parseFloorGen(st.HighestGeneratedAt)
	if err != nil {
		return fmt.Errorf("release catalog: auto-seed read floor: %w", err)
	}
	if err := checkCatalogReplay(cat, st.HighestVersion, floorGen); err != nil {
		return fmt.Errorf("release catalog: auto-seed rollback: %w", err)
	}

	if err := swapCatalogDir(stage, cfg.catalogDir); err != nil {
		return fmt.Errorf("release catalog: auto-seed swap: %w", err)
	}
	swapped = true
	return nil
}

// swapCatalogDir atomically replaces dst with stage. The previous dst is moved
// aside to dst+".bak" (atomic) BEFORE the install rename, and restored if the
// install rename fails — so a good on-disk catalog is never lost to a failed
// seed. stage and dst MUST be on the same filesystem (the caller stages under the
// data dir) or os.Rename fails with EXDEV.
func swapCatalogDir(stage, dst string) error {
	bak := dst + ".bak"
	_ = os.RemoveAll(bak) // clear any stale backup from a prior crash

	dstExists := false
	if _, err := os.Lstat(dst); err == nil {
		dstExists = true
		if err := os.Rename(dst, bak); err != nil {
			return fmt.Errorf("move current catalog aside: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := os.Rename(stage, dst); err != nil {
		if dstExists {
			_ = os.Rename(bak, dst) // restore the previous catalog
		}
		return fmt.Errorf("install staged catalog: %w", err)
	}
	_ = os.RemoveAll(bak)
	return nil
}
