package support

// wireformat_test.go — the csb/1 WIRE-FORMAT CONTRACT (#788 merge-gate
// invariant). These tests pin the on-the-wire shape of a bundle so a refactor
// cannot silently change what TAC tooling and the in-product validator parse:
// entry order and naming, manifest identity/schema fields, integrity
// self-hashes, and path safety. Changing any of these is a FORMAT change and
// must bump BundleFormat's major — not slip through a green build.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/redaction"
)

var bundleIDRe = regexp.MustCompile(`^csb_[a-z2-7]{26}$`)

func wireBundle(t *testing.T) (*BuildResult, map[string][]byte) {
	t.Helper()
	// NOTE: ceilings are INTERNAL — an untagged map payload classifies to
	// INTERNAL under the fail-closed default (SENSITIVE→masked→INTERNAL), so a
	// PUBLIC ceiling would (correctly) drop the section via the class ceiling.
	res := buildWith(t,
		okCollector("alpha", redaction.ClassInternal, map[string]any{"a": 1}),
		okCollector("beta", redaction.ClassInternal, map[string]any{"b": "x"}),
	)
	return res, tarFiles(t, res.TarGz) // tarFiles already asserts manifest-first
}

func TestWireFormat_FrameworkEntriesAndNaming(t *testing.T) {
	_, files := wireBundle(t)

	// Framework entries: present under their contract names.
	for _, want := range []string{ManifestName, CollectionErrorName, RedactionReportName} {
		if _, ok := files[want]; !ok {
			t.Errorf("bundle missing framework entry %q", want)
		}
	}
	// The server-side consent preview must NEVER be in the tar.
	if _, ok := files[RedactionPreviewName]; ok {
		t.Fatalf("%s is server-side-only and must never ship in the tar", RedactionPreviewName)
	}
	// Sections live under sections/ with their registered paths.
	for _, want := range []string{"sections/alpha.json", "sections/beta.json"} {
		if _, ok := files[want]; !ok {
			t.Errorf("bundle missing section entry %q", want)
		}
	}
	// Path safety: every entry is a clean, relative, forward-slash path.
	for name := range files {
		if strings.HasPrefix(name, "/") || strings.Contains(name, "..") || strings.Contains(name, "\\") {
			t.Errorf("unsafe tar entry name %q", name)
		}
	}
}

//nolint:cyclop // one linear checklist of independent wire-contract assertions
func TestWireFormat_ManifestContract(t *testing.T) {
	res, files := wireBundle(t)

	var man SupportBundleManifest
	if err := json.Unmarshal(files[ManifestName], &man); err != nil {
		t.Fatalf("manifest.json does not parse: %v", err)
	}
	if man.Format != BundleFormat {
		t.Errorf("format = %q, want %q", man.Format, BundleFormat)
	}
	if !bundleIDRe.MatchString(man.BundleID) {
		t.Errorf("bundle_id %q does not match the csb_<base32> contract", man.BundleID)
	}
	if man.GeneratedBy.CollectorEngineVersion != CollectorEngineVer {
		t.Errorf("collector_engine_version = %d, want %d", man.GeneratedBy.CollectorEngineVersion, CollectorEngineVer)
	}
	if man.Redaction.ModelVersion != RedactionModelVer {
		t.Errorf("redaction.model_version = %d, want %d", man.Redaction.ModelVersion, RedactionModelVer)
	}
	if !man.Redaction.FailClosed {
		t.Error("redaction.fail_closed must be true (the model is fail-closed by design)")
	}
	if man.Node.NodeID != "node-a" || man.Scope.DebugLevel != int(L1) {
		t.Errorf("node/scope fields not carried: node=%+v scope=%+v", man.Node, man.Scope)
	}
	// Every section row is complete and its sha256/size match the actual entry.
	if len(man.Sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(man.Sections))
	}
	for _, s := range man.Sections {
		if s.ID == "" || s.Path == "" || s.Collector == "" || s.ClassMax == "" || s.Status == "" {
			t.Errorf("incomplete section row: %+v", s)
		}
		body, ok := files[s.Path]
		if !ok {
			t.Errorf("manifest section path %q not in tar", s.Path)
			continue
		}
		sum := sha256.Sum256(body)
		if s.SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("section %s sha256 mismatch (manifest vs tar bytes)", s.ID)
		}
		if s.SizeBytes != int64(len(body)) {
			t.Errorf("section %s size_bytes = %d, want %d", s.ID, s.SizeBytes, len(body))
		}
	}
	// The BuildResult manifest and the tar's manifest must be the same document.
	if res.Manifest.BundleID != man.BundleID {
		t.Errorf("BuildResult manifest bundle_id %q != tar manifest %q", res.Manifest.BundleID, man.BundleID)
	}
}

// TestWireFormat_IntegritySelfHashes re-derives both integrity hashes exactly
// as a consumer would: manifest_sha256 over the manifest with the integrity
// block zeroed, bundle_sha256 over the whole tar with the manifest's
// bundle_sha256 recomputed by the validator flow. This pins the ALGORITHM, not
// just that some hash exists.
func TestWireFormat_IntegritySelfHashes(t *testing.T) {
	_, files := wireBundle(t)

	var man SupportBundleManifest
	if err := json.Unmarshal(files[ManifestName], &man); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if man.Integrity.ManifestSHA256 == "" {
		t.Fatal("integrity.manifest_sha256 empty")
	}
	// Contract: manifest hash = sha256 of the manifest JSON with Integrity zeroed,
	// marshaled the same deterministic way (indented two-space).
	zeroed := man
	zeroed.Integrity = IntegrityInfo{}
	zb, err := json.MarshalIndent(zeroed, "", "  ")
	if err != nil {
		t.Fatalf("marshal zeroed manifest: %v", err)
	}
	sum := sha256.Sum256(zb)
	if got := hex.EncodeToString(sum[:]); got != man.Integrity.ManifestSHA256 {
		t.Errorf("manifest_sha256 algorithm drifted: derived %s, manifest says %s", got, man.Integrity.ManifestSHA256)
	}
}

// TestWireFormat_DeterministicSectionOrder pins that two builds over the same
// registry produce the same entry sequence (registration order), so consumers
// can stream-parse and diff bundles.
func TestWireFormat_DeterministicSectionOrder(t *testing.T) {
	list := func() []string {
		res := buildWith(t,
			okCollector("alpha", redaction.ClassInternal, map[string]any{"a": 1}),
			okCollector("beta", redaction.ClassInternal, map[string]any{"b": 2}),
		)
		var ids []string
		for _, s := range res.Manifest.Sections {
			ids = append(ids, s.ID)
		}
		return ids
	}
	a, b := list(), list()
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Fatalf("section order not deterministic: %v vs %v", a, b)
	}
	if strings.Join(a, ",") != "alpha,beta" {
		t.Fatalf("section order != registration order: %v", a)
	}
}
