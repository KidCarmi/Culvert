// Release catalog lineage — every supported upgrade SOURCE stays in the signed
// catalog.
//
// The maintenance agent authorizes an upgrade only when BOTH the target and
// the release it observes running are proven by signed catalog evidence
// (docs/appliance/signed-update-agent-boundary.md); with an empty ledger the
// proxy must send prior_release_proof, and it can only build one for a
// running digest the catalog lists. A catalog that carried only the newest
// release therefore refused every real Release Management upgrade (403 from
// the agent) — the very appliances it existed to update.
//
// The fix keeps the trust model intact: the generator carries predecessor
// releases into the new catalog, and every carried release is taken VERBATIM
// from a catalog that verified against the production trust store (signature
// + structure through LoadVerifiedCatalog, expiry-tolerant like the re-sign
// gate: an old release's catalog may legitimately have lapsed). Nothing is
// reconstructed from unsigned input, so a carried manifest is byte-identical
// to the one its own release was published with, and the new index signs over
// its sha256 again. The set carried is exactly the SUPPORTED sources:
// releases at or above the transition floor (releaseMinUpgradeFrom), older
// than the target, from the target's repository — including releases a node
// skipped — and the caller names which published releases must be present, so
// a missing source fails the publication instead of silently stranding the
// nodes that run it.
package main

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// carriedRelease is one predecessor release carried verbatim from a verified
// catalog: its identity and its EXACT manifest bytes.
type carriedRelease struct {
	ReleaseID  string
	VersionID  string
	Repo       string
	ListDigest string
	Manifest   []byte
}

// lineageSource is one predecessor catalog bundle on disk (a directory with
// index.json, manifests/ and its signature sidecar(s)).
type lineageSource struct {
	Dir string
}

// collectVerifiedPredecessors verifies each source against trust and returns
// the supported predecessors of target (repo, version), deduplicated and in
// release_id order. require lists versions (bare X.Y.Z) that MUST be among the
// result — the published supported releases — so an absent or unverifiable
// source is a hard error, never a smaller catalog.
func collectVerifiedPredecessors(sources []lineageSource, trust TrustStore, repo, floor, target string, require []string) ([]carriedRelease, error) {
	// Only ENFORCE-mode verification counts: permissive/disabled break-glass
	// modes accept unsigned catalogs, and nothing unsigned is ever carried.
	if trust.mode != VerifyEnforce {
		return nil, fmt.Errorf("release lineage: trust store is not in enforce mode (a predecessor is carried only from a verified catalog)")
	}
	if err := catalogValidateRepo(repo); err != nil {
		return nil, fmt.Errorf("release lineage: %w", err)
	}
	if !catalogSemverRE.MatchString(target) {
		return nil, fmt.Errorf("release lineage: target version %q is not semver", target)
	}
	if floor != "" && !catalogSemverRE.MatchString(floor) {
		return nil, fmt.Errorf("release lineage: floor %q is not semver", floor)
	}
	byID := map[string]carriedRelease{}
	for _, src := range sources {
		if err := collectFromSource(byID, src, trust, repo, floor, target); err != nil {
			return nil, err
		}
	}
	out := make([]carriedRelease, 0, len(byID))
	seenVersion := map[string]string{}
	for _, c := range byID {
		if other, dup := seenVersion[c.VersionID]; dup {
			return nil, fmt.Errorf("release lineage: version %s is claimed by both %q and %q (fail closed)", c.VersionID, other, c.ReleaseID)
		}
		seenVersion[c.VersionID] = c.ReleaseID
		out = append(out, c)
	}
	var missing []string
	for _, v := range require {
		v = strings.TrimPrefix(strings.TrimSpace(v), "v")
		if v == "" {
			continue
		}
		if _, ok := seenVersion[v]; !ok {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("release lineage: supported predecessor(s) %s have no verified catalog entry; publishing without them would leave those appliances unable to upgrade", strings.Join(missing, ", "))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReleaseID < out[j].ReleaseID })
	return out, nil
}

// collectFromSource verifies one source catalog and adds its supported
// releases to byID, refusing a release two verified sources disagree about.
func collectFromSource(byID map[string]carriedRelease, src lineageSource, trust TrustStore, repo, floor, target string) error {
	cat, err := LoadVerifiedCatalog(&dirCatalogSource{dir: src.Dir}, trust)
	if err != nil {
		return fmt.Errorf("release lineage: source %s failed verification (nothing is carried from it): %w", src.Dir, err)
	}
	if cat.proof == nil {
		return fmt.Errorf("release lineage: source %s carries no signature evidence", src.Dir)
	}
	for id := range cat.byReleaseID {
		rel := cat.byReleaseID[id]
		if !lineageSupported(&rel, repo, floor, target) {
			continue
		}
		raw := cat.proof.manifests[id]
		if len(raw) == 0 {
			return fmt.Errorf("release lineage: source %s: no verified manifest bytes for %q", src.Dir, id)
		}
		if prev, dup := byID[id]; dup {
			// Two verified catalogs disagreeing about one release is a
			// publication inconsistency; refuse rather than pick one.
			if !bytes.Equal(prev.Manifest, raw) {
				return fmt.Errorf("release lineage: release %q has different verified manifests in two sources (fail closed)", id)
			}
			continue
		}
		byID[id] = carriedRelease{ReleaseID: id, VersionID: rel.VersionID, Repo: rel.Repo, ListDigest: rel.ListDigest, Manifest: bytes.Clone(raw)}
	}
	return nil
}

// lineageSupported reports whether rel is a supported upgrade source for the
// target: same repository, version >= floor (when set) and strictly older
// than the target. The target itself is never carried — it is generated.
func lineageSupported(rel *Release, repo, floor, target string) bool {
	if rel.Repo != repo || !catalogSemverRE.MatchString(rel.VersionID) {
		return false
	}
	if catalogCompareSemver(rel.VersionID, target) >= 0 {
		return false
	}
	return floor == "" || catalogCompareSemver(rel.VersionID, floor) >= 0
}
