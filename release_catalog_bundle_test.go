package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// ─── bundle builders ─────────────────────────────────────────────────────────

type bundleEntry struct {
	name     string
	body     []byte
	typeflag byte   // 0 ⇒ tar.TypeReg
	linkname string // for symlink/hardlink entries
}

// tarBundle builds a tar archive from entries (deterministic order as given).
func tarBundle(t *testing.T, entries []bundleEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0o600,
			Size:     int64(len(e.body)),
			Typeflag: tf,
			Linkname: e.linkname,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if tf == tar.TypeReg {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// catalogBundleEntries builds the standard signed-catalog entry set from a
// memSource (signed with priv under holderTestKeyID), in deterministic order.
func catalogBundleEntries(t *testing.T, priv ed25519.PrivateKey, ms *memSource) []bundleEntry {
	t.Helper()
	sig := ed25519.Sign(priv, ms.index)
	entries := []bundleEntry{
		{name: "index.json", body: ms.index},
		{name: "index.json.sig", body: sigEnvelopeBytes(t, catalogSigAlg, holderTestKeyID, sig)},
	}
	refs := make([]string, 0, len(ms.manifests))
	for ref := range ms.manifests {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		entries = append(entries, bundleEntry{name: "manifests/" + ref, body: ms.manifests[ref]})
	}
	return entries
}

// writeBundle writes archive bytes to a temp file and returns a provider over it
// (staging under a fresh base dir for cleanup assertions).
func writeBundle(t *testing.T, archive []byte) (p *BundleCatalogProvider, stageBase string) {
	t.Helper()
	bundlePath := filepath.Join(t.TempDir(), "release-bundle.tar")
	if err := os.WriteFile(bundlePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	p = NewBundleCatalogProvider(bundlePath)
	stageBase = t.TempDir()
	p.stageBase = stageBase
	return p, stageBase
}

func mustStageFail(t *testing.T, p *BundleCatalogProvider, stageBase, what string) {
	t.Helper()
	if dir, err := p.Stage(context.Background()); err == nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("Stage must reject %s", what)
	}
	if !stageEmpty(t, stageBase) {
		t.Fatalf("staging dir must be cleaned up after rejecting %s", what)
	}
}

// ─── tests ───────────────────────────────────────────────────────────────────

// A signed bundle (plain tar AND tar.gz) stages and verifies end-to-end through
// the unchanged trust boundary — verification is identical to online (plan §8).
func TestBundle_HappyImport(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	entries := catalogBundleEntries(t, priv, validSource())
	// Include a non-catalog entry (a future image blob) — skipped unread.
	entries = append(entries, bundleEntry{name: "images/proxy.oci", body: bytes.Repeat([]byte{0xab}, 2048)})
	plain := tarBundle(t, entries)

	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	for name, archive := range map[string][]byte{"tar": plain, "tar.gz": gzBuf.Bytes()} {
		p, _ := writeBundle(t, archive)
		dir, err := p.Stage(context.Background())
		if err != nil {
			t.Fatalf("%s: Stage: %v", name, err)
		}
		c, err := LoadVerifiedCatalog(&dirCatalogSource{dir: dir}, holderTrust(t, pub))
		_ = os.RemoveAll(dir)
		if err != nil {
			t.Fatalf("%s: LoadVerifiedCatalog over staged bundle: %v", name, err)
		}
		if len(c.byReleaseID) != 2 {
			t.Fatalf("%s: staged catalog has %d releases; want 2", name, len(c.byReleaseID))
		}
	}
}

// A traversal entry name rejects the WHOLE bundle (never silently skipped).
func TestBundle_TraversalRejected(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, evil := range []string{"../evil.json", "manifests/../../evil.json", "/etc/passwd"} {
		entries := append(catalogBundleEntries(t, priv, validSource()),
			bundleEntry{name: evil, body: []byte("x")})
		p, stageBase := writeBundle(t, tarBundle(t, entries))
		mustStageFail(t, p, stageBase, "traversal entry "+evil)
	}
}

// Any symlink (or hardlink) entry rejects the whole bundle.
func TestBundle_SymlinkRejected(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, tf := range map[string]byte{"symlink": tar.TypeSymlink, "hardlink": tar.TypeLink} {
		entries := append(catalogBundleEntries(t, priv, validSource()),
			bundleEntry{name: "manifests/evil.json", typeflag: tf, linkname: "/etc/passwd"})
		p, stageBase := writeBundle(t, tarBundle(t, entries))
		mustStageFail(t, p, stageBase, name+" entry")
	}
}

// A bundle without index.json.sig stages (transport-only), but enforce-mode
// verification rejects it at the trust boundary.
func TestBundle_MissingSignatureRejectedInEnforce(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	entries := catalogBundleEntries(t, priv, validSource())[0:1] // index.json only
	for ref, b := range validSource().manifests {
		entries = append(entries, bundleEntry{name: "manifests/" + ref, body: b})
	}
	p, _ := writeBundle(t, tarBundle(t, entries))
	dir, err := p.Stage(context.Background())
	if err != nil {
		t.Fatalf("Stage (transport) should succeed without a signature: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if _, err := LoadVerifiedCatalog(&dirCatalogSource{dir: dir}, holderTrust(t, pub)); !errors.Is(err, errSigMissing) {
		t.Fatalf("enforce verify of an unsigned bundle: err = %v; want errSigMissing", err)
	}
}

// A bundle signed by an untrusted key stages but fails verification.
func TestBundle_BadSignatureRejected(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil) // trusted key
	if err != nil {
		t.Fatal(err)
	}
	_, attackerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := writeBundle(t, tarBundle(t, catalogBundleEntries(t, attackerPriv, validSource())))
	dir, err := p.Stage(context.Background())
	if err != nil {
		t.Fatalf("Stage (transport) should succeed: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if _, err := LoadVerifiedCatalog(&dirCatalogSource{dir: dir}, holderTrust(t, pub)); err == nil {
		t.Fatal("verification must reject a bundle signed by an untrusted key")
	}
}

// A catalog entry over the per-file bound rejects the bundle.
func TestBundle_OversizeEntryRejected(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte{'x'}, catalogMaxReadBytes+1)
	entries := append(catalogBundleEntries(t, priv, validSource()),
		bundleEntry{name: "manifests/huge.json", body: big})
	p, stageBase := writeBundle(t, tarBundle(t, entries))
	mustStageFail(t, p, stageBase, "an oversize catalog entry")
}

// A manifest tampered inside the bundle stages (index is intact) but is caught
// by LoadVerifiedCatalog's manifest_sha256 hash binding.
func TestBundle_TamperedManifestRejectedByVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ms := validSource()
	entries := catalogBundleEntries(t, priv, ms)
	for i := range entries {
		if entries[i].name == "manifests/a.json" {
			entries[i].body = append(append([]byte(nil), entries[i].body...), ' ') // tamper
		}
	}
	p, _ := writeBundle(t, tarBundle(t, entries))
	dir, err := p.Stage(context.Background())
	if err != nil {
		t.Fatalf("Stage (transport) should succeed: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if _, err := LoadVerifiedCatalog(&dirCatalogSource{dir: dir}, holderTrust(t, pub)); err == nil {
		t.Fatal("verification must reject the tampered manifest (hash mismatch)")
	}
}

// Failure cleanup: a corrupt archive and a bundle with no index.json both leave
// the staging base empty.
func TestBundle_CleanupOnFailure(t *testing.T) {
	// Corrupt archive bytes (not tar, not gzip).
	p, stageBase := writeBundle(t, []byte("this is not a tar archive at all, padded to get past Peek"))
	mustStageFail(t, p, stageBase, "a corrupt archive")

	// Valid tar, but no index.json.
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	entries := catalogBundleEntries(t, priv, validSource())[1:] // drop index.json
	p2, stageBase2 := writeBundle(t, tarBundle(t, entries))
	mustStageFail(t, p2, stageBase2, "a bundle without index.json")
}
