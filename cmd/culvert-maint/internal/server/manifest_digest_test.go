package server

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const (
	digAMD  = "1111111111111111111111111111111111111111111111111111111111111111"
	digARM  = "2222222222222222222222222222222222222222222222222222222222222222"
	digLayr = "3333333333333333333333333333333333333333333333333333333333333333"
	digCfg  = "4444444444444444444444444444444444444444444444444444444444444444"
)

// hostEntry renders a verbose entry whose descriptor platform matches this
// host, so the host-match path is exercised regardless of CI architecture.
func hostEntry(digest string) string {
	return fmt.Sprintf(`{"Descriptor":{"digest":"sha256:%s","platform":{"os":%q,"architecture":%q}}}`,
		digest, runtime.GOOS, runtime.GOARCH)
}

func TestResolveTargetManifestDigest_SingleArchObject(t *testing.T) {
	// Single-arch: a bare object with one descriptor; platform irrelevant.
	out := []byte(`{"Descriptor":{"digest":"sha256:` + digAMD + `"}}`)
	got, err := resolveTargetManifestDigest(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "sha256:"+digAMD {
		t.Errorf("got %q, want sha256:%s", got, digAMD)
	}
}

func TestResolveTargetManifestDigest_MultiArchSelectsHost(t *testing.T) {
	// Two descriptors — one for this host, one for a foreign arch. The
	// host one must be selected deterministically.
	foreignArch := "arm64"
	if runtime.GOARCH == "arm64" {
		foreignArch = "amd64"
	}
	out := []byte(`[` +
		hostEntry(digAMD) + `,` +
		fmt.Sprintf(`{"Descriptor":{"digest":"sha256:%s","platform":{"os":%q,"architecture":%q}}}`, digARM, runtime.GOOS, foreignArch) +
		`]`)
	got, err := resolveTargetManifestDigest(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "sha256:"+digAMD {
		t.Errorf("got %q, want the host descriptor sha256:%s", got, digAMD)
	}
}

// TestResolveTargetManifestDigest_IgnoresLayerAndConfigDigests is the
// regression this fix exists for: verbose output embeds the per-platform
// manifest body, whose config/layer digests are lexicographically smaller
// than the real descriptor digest. The old targetDigests[0] path would have
// pinned a layer/config blob; the structural parser must ignore them.
func TestResolveTargetManifestDigest_IgnoresLayerAndConfigDigests(t *testing.T) {
	// digLayr/digCfg (3.../4...) sort AFTER digAMD here, but the danger is
	// real when a layer digest sorts first; include one that sorts BEFORE
	// the descriptor to prove structure — not ordering — is what matters.
	lowLayer := "0000000000000000000000000000000000000000000000000000000000000000"
	out := []byte(fmt.Sprintf(
		`{"Descriptor":{"digest":"sha256:%s","platform":{"os":%q,"architecture":%q}},`+
			`"SchemaV2Manifest":{"config":{"digest":"sha256:%s"},"layers":[{"digest":"sha256:%s"}]}}`,
		digAMD, runtime.GOOS, runtime.GOARCH, digCfg, lowLayer))
	got, err := resolveTargetManifestDigest(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "sha256:"+digAMD {
		t.Errorf("got %q, want the descriptor digest sha256:%s (must not pin config/layer)", got, digAMD)
	}
}

func TestResolveTargetManifestDigest_NoHostMatchFailsClosed(t *testing.T) {
	// Two foreign platforms, none matching the host → fail closed.
	out := []byte(`[` +
		`{"Descriptor":{"digest":"sha256:` + digAMD + `","platform":{"os":"plan9","architecture":"mips"}}},` +
		`{"Descriptor":{"digest":"sha256:` + digARM + `","platform":{"os":"plan9","architecture":"sparc"}}}` +
		`]`)
	if _, err := resolveTargetManifestDigest(out); err == nil {
		t.Fatal("expected fail-closed error when no descriptor matches host platform")
	}
}

func TestResolveTargetManifestDigest_AmbiguousHostMatchFailsClosed(t *testing.T) {
	// Two descriptors both claiming the host platform → ambiguous → fail.
	out := []byte(`[` + hostEntry(digAMD) + `,` + hostEntry(digARM) + `]`)
	_, err := resolveTargetManifestDigest(out)
	if err == nil {
		t.Fatal("expected fail-closed error on ambiguous host-platform match")
	}
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("error should mention ambiguity, got %v", err)
	}
}

func TestResolveTargetManifestDigest_EmptyAndGarbage(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"not-json", "not json at all"},
		{"no-descriptor", `{"Ref":"x"}`},
		{"malformed-digest", `{"Descriptor":{"digest":"sha256:deadbeef"}}`},
		{"empty-array", `[]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolveTargetManifestDigest([]byte(tc.in)); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}
