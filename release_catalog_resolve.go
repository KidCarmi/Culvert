// Release Catalog Runtime — Slice 1: query surface (Resolve / Lookup / Current
// / List). All methods are pure and I/O-free after LoadCatalog.
package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Resolve maps a channel forward to its release's agent-facing PinnedRef
// (repo@sha256:<64hex>). Errors if the channel is unknown or unset.
func (c *Catalog) Resolve(ch Channel) (ResolvedRelease, error) {
	relID, ok := c.channels[ch]
	if !ok {
		return ResolvedRelease{}, fmt.Errorf("release catalog: channel %q is unknown or unset", ch)
	}
	rel := c.byReleaseID[relID]
	return ResolvedRelease{
		ReleaseID: rel.ReleaseID,
		VersionID: rel.VersionID,
		Severity:  rel.Severity,
		PinnedRef: rel.PinnedRef,
	}, nil
}

// Lookup maps a repo-bound pinned ref (repo@sha256:…) back to its release by
// EXACT match. ok is false for any ref not in the catalog.
func (c *Catalog) Lookup(pinnedRef string) (Release, bool) {
	relID, ok := c.byPinnedRef[pinnedRef]
	if !ok {
		return Release{}, false
	}
	return c.byReleaseID[relID], true
}

// Current derives the running release from an authoritative running digest (a
// P1.1 /v1/status.running_image.repo_digests entry, repo@sha256:…). It is Known
// ONLY when runningRef exactly equals a catalog PinnedRef; any other digest —
// per-arch, tag-resolved, legacy/pre-catalog, or simply absent — yields
// {Known:false} (unknown/custom), which is a normal state, NOT an error.
func (c *Catalog) Current(runningRef string) CurrentView {
	if rel, ok := c.Lookup(runningRef); ok {
		return CurrentView{Known: true, ReleaseID: rel.ReleaseID, VersionID: rel.VersionID}
	}
	return CurrentView{Known: false}
}

// List enumerates the catalog, digest-free, with each release's channel badges.
// Order is semver-safe: by parsed semantic version descending (newest first),
// with ReleaseID as a stable tiebreaker.
func (c *Catalog) List() []ReleaseView {
	out := make([]ReleaseView, 0, len(c.byReleaseID))
	// Index-based access (not range-value) to avoid copying the Release struct.
	for id := range c.byReleaseID {
		rel := c.byReleaseID[id]
		out = append(out, ReleaseView{
			ReleaseID: rel.ReleaseID,
			VersionID: rel.VersionID,
			Severity:  rel.Severity,
			Channels:  c.channelsFor(rel.ReleaseID),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if cmp := catalogCompareSemver(out[i].VersionID, out[j].VersionID); cmp != 0 {
			return cmp > 0 // descending: newest version first
		}
		return out[i].ReleaseID < out[j].ReleaseID
	})
	return out
}

// GeneratedAt returns the index's generated_at, for staleness display later.
func (c *Catalog) GeneratedAt() time.Time { return c.generatedAt }

// ExpiresAt returns the index's expires_at (the freshness floor). A zero value
// means the catalog declared no expiry — tolerated by the structural loader but
// rejected by the enforce-mode freshness gate.
func (c *Catalog) ExpiresAt() time.Time { return c.expiresAt }

// Version returns the index's catalog_version (the monotonic rollback counter).
// 0 means unset; the enforce-mode gate requires ≥ 1 and refuses any value below
// the persisted floor.
func (c *Catalog) Version() int { return c.version }

func (c *Catalog) channelsFor(relID string) []Channel {
	var chs []Channel
	for ch, id := range c.channels {
		if id == relID {
			chs = append(chs, ch)
		}
	}
	sort.Slice(chs, func(i, j int) bool { return chs[i] < chs[j] })
	return chs
}

// ─── semver-safe comparison (no external dependency) ─────────────────────────

// catalogCompareSemver returns -1/0/+1 by SemVer precedence (build metadata
// ignored). Inputs are pre-validated as semver at load, so parse is safe.
func catalogCompareSemver(a, b string) int {
	amaj, amin, apat, apre := catalogSplitSemver(a)
	bmaj, bmin, bpat, bpre := catalogSplitSemver(b)
	if amaj != bmaj {
		return catalogCmpInt(amaj, bmaj)
	}
	if amin != bmin {
		return catalogCmpInt(amin, bmin)
	}
	if apat != bpat {
		return catalogCmpInt(apat, bpat)
	}
	// A version with NO prerelease has higher precedence than one with a
	// prerelease (1.0.0 > 1.0.0-rc.1).
	switch {
	case apre == "" && bpre == "":
		return 0
	case apre == "":
		return 1
	case bpre == "":
		return -1
	default:
		return catalogComparePrerelease(apre, bpre)
	}
}

func catalogSplitSemver(v string) (maj, mnr, pat int, pre string) {
	if i := strings.IndexByte(v, '+'); i >= 0 { // strip build metadata
		v = v[:i]
	}
	core := v
	if i := strings.IndexByte(v, '-'); i >= 0 { // split prerelease
		core, pre = v[:i], v[i+1:]
	}
	parts := strings.SplitN(core, ".", 3)
	if len(parts) == 3 {
		maj, _ = strconv.Atoi(parts[0])
		mnr, _ = strconv.Atoi(parts[1])
		pat, _ = strconv.Atoi(parts[2])
	}
	return maj, mnr, pat, pre
}

func catalogComparePrerelease(a, b string) int {
	ai := strings.Split(a, ".")
	bi := strings.Split(b, ".")
	for i := 0; i < len(ai) && i < len(bi); i++ {
		x, y := ai[i], bi[i]
		xn, xErr := strconv.Atoi(x)
		yn, yErr := strconv.Atoi(y)
		switch {
		case xErr == nil && yErr == nil: // both numeric → numeric compare
			if xn != yn {
				return catalogCmpInt(xn, yn)
			}
		case xErr == nil: // numeric identifiers have lower precedence than alphanumeric
			return -1
		case yErr == nil:
			return 1
		default:
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
		}
	}
	// All shared identifiers equal: fewer identifiers has lower precedence.
	return catalogCmpInt(len(ai), len(bi))
}

func catalogCmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
