package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestE2ESeedSignedCatalog is the seed step of the real-binary / real-image
// catalog E2E (.github/workflows/catalog-e2e.yml). It is NOT a unit assertion —
// it is a CI helper that generates a deterministic catalog, ed25519-signs
// index.json, writes the full bundle (index.json + index.json.sig + manifests/)
// into the seed dir, and writes the matching trust-keys JSON, so the workflow can
// start a real Control Plane in enforce mode and assert the catalog loads +
// verifies + serves. Skipped unless CULVERT_E2E_SEED_OUT (+ _KEYS) are set.
//
// Env knobs (all optional except OUT/KEYS) — these let one helper drive a whole
// upgrade + anti-rollback sequence by re-seeding with the SAME key:
//
//	CULVERT_E2E_SEED_OUT        catalog dir to populate (required)
//	CULVERT_E2E_SEED_KEYS       file to write the trust-keys JSON (pubkey) to (required)
//	CULVERT_E2E_SEED_PRIV       file to persist/REUSE the ed25519 private seed; if it
//	                            exists it is reused so successive seeds share ONE key
//	                            (the CP is started once with that key as its root)
//	CULVERT_E2E_SEED_VERSION    catalog_version (default 1) — raise it to test upgrade,
//	                            lower it (below the persisted floor) to test rollback
//	CULVERT_E2E_SEED_VERSION_ID release version_id (default 9.9.9)
//	CULVERT_E2E_SEED_EXPIRES    expires_at RFC3339 (default 2099-01-01T00:00:00Z)
//	CULVERT_E2E_SEED_IMAGE_REPO   image.repo baked into the manifest (default
//	                              ghcr.io/kidcarmi/culvert). Set it to a LOCAL
//	                              registry repo so a real dispatch → maint-agent
//	                              pull resolves against the seeded digest.
//	CULVERT_E2E_SEED_IMAGE_DIGEST image.list_digest baked into the manifest
//	                              ("sha256:<64hex>", default a synthetic aaaa…
//	                              digest). Set it to the REAL pushed manifest-list
//	                              digest so dispatch's verify-by-digest matches the
//	                              running container after the flip.
//	CULVERT_E2E_SEED_CARRY        colon-separated catalog dirs published EARLIER
//	                              with the same key: every release in them older
//	                              than this one is carried byte-identical
//	                              (release_lineage.go — the production carry,
//	                              enforce-mode verification first). Unset ⇒ a
//	                              single-entry (pre-lineage) catalog.
//	CULVERT_E2E_SEED_AGENT_KEYRING  file to write the maintenance agent's
//	                              release_trust_keys keyring ({"key_id":"<b64>"}),
//	                              the same PUBLIC key in the agent's format.
func TestE2ESeedSignedCatalog(t *testing.T) {
	outDir := strings.TrimSpace(os.Getenv("CULVERT_E2E_SEED_OUT"))
	keysFile := strings.TrimSpace(os.Getenv("CULVERT_E2E_SEED_KEYS"))
	if outDir == "" || keysFile == "" {
		t.Skip("set CULVERT_E2E_SEED_OUT and CULVERT_E2E_SEED_KEYS to seed a real E2E catalog")
	}

	version := envIntOr(t, "CULVERT_E2E_SEED_VERSION", 1)
	versionID := envOr("CULVERT_E2E_SEED_VERSION_ID", "9.9.9")
	expires := envOr("CULVERT_E2E_SEED_EXPIRES", "2099-01-01T00:00:00Z")
	// Image binding — defaults keep the historical (read-only catalog-e2e.yml)
	// behaviour; the appliance-catalog-update E2E overrides both so the catalog
	// points at a real, pullable registry digest.
	imageRepo := envOr("CULVERT_E2E_SEED_IMAGE_REPO", "ghcr.io/kidcarmi/culvert")
	imageDigest := envOr("CULVERT_E2E_SEED_IMAGE_DIGEST", "sha256:"+strings.Repeat("a", 64))

	spec := releaseCatalogSpec{
		GeneratedAt:    "2026-01-01T00:00:00Z",
		ExpiresAt:      expires,
		CatalogVersion: version,
		Entries: []releaseEntrySpec{{
			ReleaseID:  "culvert-" + versionID,
			VersionID:  versionID,
			Severity:   "normal",
			Repo:       imageRepo,
			ListDigest: imageDigest,
			Platforms:  []string{"linux/amd64", "linux/arm64"},
			CreatedAt:  "2026-01-01T00:00:00Z",
			Channels:   []Channel{ChannelRecommended},
		}},
	}
	// Stable key across re-seeds: the CP is started ONCE with this key's pubkey as
	// its trust root, so an upgrade (v2) signed by a different key would be
	// rejected. Persist the private seed and reuse it on later seeds.
	priv := e2eLoadOrCreateKey(t, strings.TrimSpace(os.Getenv("CULVERT_E2E_SEED_PRIV")))
	pub := priv.Public().(ed25519.PublicKey)

	const keyID = "e2e-catalog"
	if carry := strings.TrimSpace(os.Getenv("CULVERT_E2E_SEED_CARRY")); carry != "" {
		trust, err := NewTrustStore([]TrustKey{{KeyID: keyID, Alg: catalogSigAlg, PublicKey: pub}}, VerifyEnforce)
		if err != nil {
			t.Fatal(err)
		}
		var srcs []lineageSource
		for _, d := range strings.Split(carry, ":") {
			if d = strings.TrimSpace(d); d != "" {
				srcs = append(srcs, lineageSource{Dir: d})
			}
		}
		carried, err := collectVerifiedPredecessors(srcs, trust, imageRepo, "", versionID, nil)
		if err != nil {
			t.Fatalf("release lineage: %v", err)
		}
		spec.Carried = carried
		t.Logf("carrying %d predecessor(s): %s", len(carried), carriedVersions(carried))
	}
	bundle, err := generateReleaseCatalog(spec)
	if err != nil {
		t.Fatalf("generateReleaseCatalog: %v", err)
	}
	sigEnv := sigEnvelopeBytes(t, catalogSigAlg, keyID, ed25519.Sign(priv, bundle.Index))
	if err := writeReleaseBundle(outDir, bundle, sigEnv); err != nil {
		t.Fatalf("writeReleaseBundle: %v", err)
	}

	keysJSON := fmt.Sprintf(`[{"key_id":%q,"alg":%q,"public_key":%q}]`,
		keyID, catalogSigAlg, base64.StdEncoding.EncodeToString(pub))
	if err := os.WriteFile(keysFile, []byte(keysJSON), 0o600); err != nil {
		t.Fatalf("write keys file: %v", err)
	}
	if ring := strings.TrimSpace(os.Getenv("CULVERT_E2E_SEED_AGENT_KEYRING")); ring != "" {
		b, err := json.Marshal(map[string][]byte{keyID: pub})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ring, b, 0o600); err != nil {
			t.Fatalf("write agent keyring: %v", err)
		}
	}
	t.Logf("seeded signed catalog into %s (catalog_version=%d, version_id=%s, expires=%s)",
		outDir, version, versionID, expires)
}

// e2eLoadOrCreateKey reuses a persisted ed25519 seed (so a re-seed keeps the same
// key the CP already trusts) or mints + persists a fresh one. With no path it
// just mints an ephemeral key (single-seed callers).
func e2eLoadOrCreateKey(t *testing.T, privPath string) ed25519.PrivateKey {
	t.Helper()
	if privPath != "" {
		if seed, err := os.ReadFile(privPath); err == nil && len(seed) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(seed)
		}
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_ = pub
	if privPath != "" {
		if err := os.WriteFile(privPath, priv.Seed(), 0o600); err != nil {
			t.Fatalf("persist priv seed: %v", err)
		}
	}
	return priv
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envIntOr(t *testing.T, key string, def int) int {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("%s must be an int: %v", key, err)
	}
	return n
}

// TestE2EEmitAgentRequest is the companion CI helper for the direct-agent
// checks of the appliance-catalog-update E2E. It loads a seeded catalog through
// the REAL verifier (enforce, the seed key), runs the REAL dispatch planner for
// the running image, and writes an agent request body derived from it:
//
//	CULVERT_E2E_REQ_CATALOG  seeded catalog dir (required)
//	CULVERT_E2E_REQ_KEYS     the seed's trust-keys JSON (required)
//	CULVERT_E2E_REQ_REPO     proxy repo (required)
//	CULVERT_E2E_REQ_RUNNING  the running pinned ref (required)
//	CULVERT_E2E_REQ_OUT      output file (required)
//	CULVERT_E2E_REQ_MODE     planned      the apply body the planner builds
//	                         no-prior     the same body without prior_release_proof
//	                         prior=<id>   the body with ANOTHER release's proof as
//	                                      the baseline (a mismatched baseline)
//	                         rollback=<id> a standalone image-rollback body to
//	                                      release <id>, with the running release's
//	                                      proof as the baseline
//
// It never signs anything: every proof is the catalog's own signed bytes.
func TestE2EEmitAgentRequest(t *testing.T) {
	dir := strings.TrimSpace(os.Getenv("CULVERT_E2E_REQ_CATALOG"))
	if dir == "" {
		t.Skip("set CULVERT_E2E_REQ_CATALOG (+_KEYS/_REPO/_RUNNING/_OUT/_MODE) to emit an agent request")
	}
	keysRaw, err := os.ReadFile(os.Getenv("CULVERT_E2E_REQ_KEYS")) // #nosec G304 -- CI helper input
	if err != nil {
		t.Fatal(err)
	}
	keys, err := parseReleaseCatalogTrustKeys(string(keysRaw))
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(keys, VerifyEnforce)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := LoadVerifiedCatalog(&dirCatalogSource{dir: dir}, trust)
	if err != nil {
		t.Fatalf("catalog failed verification: %v", err)
	}
	repo, running := os.Getenv("CULVERT_E2E_REQ_REPO"), os.Getenv("CULVERT_E2E_REQ_RUNNING")
	mode := envOr("CULVERT_E2E_REQ_MODE", "planned")
	var body any
	if id, ok := strings.CutPrefix(mode, "rollback="); ok {
		rel, found := cat.byReleaseID[id]
		cur, known := cat.Lookup(running)
		if !found || !known {
			t.Fatalf("rollback: target %q found=%v, running %q listed=%v", id, found, running, known)
		}
		body = map[string]any{"mode": "image", "image_ref": rel.PinnedRef,
			"release_proof": cat.releaseProof(id), "prior_release_proof": cat.releaseProof(cur.ReleaseID)}
	} else {
		d, err := NewDispatcher(e2eCatalogProvider{cat: cat}, DispatchConfig{ProxyRepo: repo})
		if err != nil {
			t.Fatal(err)
		}
		plan := d.Plan(DispatchTarget{Channel: ChannelRecommended}, []string{running}, DispatchOptions{})
		if plan.Outcome != OutcomePlan {
			t.Fatalf("planner did not plan an apply: outcome=%v kind=%v reason=%v", plan.Outcome, plan.Kind, plan.Reason)
		}
		req := plan.Apply
		switch {
		case mode == "planned":
		case mode == "no-prior":
			req.PriorReleaseProof = nil
		case strings.HasPrefix(mode, "prior="):
			other := strings.TrimPrefix(mode, "prior=")
			if req.PriorReleaseProof = cat.releaseProof(other); req.PriorReleaseProof == nil {
				t.Fatalf("no proof for %q in the catalog", other)
			}
		default:
			t.Fatalf("unknown CULVERT_E2E_REQ_MODE %q", mode)
		}
		body = req
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("CULVERT_E2E_REQ_OUT"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s request (%d bytes)", mode, len(b))
}
