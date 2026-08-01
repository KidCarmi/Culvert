package main

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// parseFeedIdentityEnv reads the KEY=VALUE lines of feeds_identity.env (ignoring
// blanks/comments). Values are taken verbatim (no quote stripping) so the SAN
// regex compares byte-for-byte with the Go constant.
func parseFeedIdentityEnv(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open("feeds_identity.env")
	if err != nil {
		t.Fatalf("open feeds_identity.env: %v", err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = v
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan feeds_identity.env: %v", err)
	}
	return out
}

// TestFeedIdentitySSOT pins the feed single-source-of-truth invariant (F2): the
// issuer + SAN regex CI feeds to cosign MUST be byte-identical to the in-binary
// feed verifier's pinned identity (urlcatfeed.Official* constants). Drift would
// let a feed sign under one identity while the binary pins another.
func TestFeedIdentitySSOT(t *testing.T) {
	env := parseFeedIdentityEnv(t)
	if got := env["CULVERT_FEED_SIGSTORE_ISSUER"]; got != urlcatfeed.OfficialIssuer {
		t.Errorf("issuer drift: feeds_identity.env=%q urlcatfeed.OfficialIssuer=%q", got, urlcatfeed.OfficialIssuer)
	}
	if got := env["CULVERT_FEED_SIGSTORE_SAN_REGEX"]; got != urlcatfeed.OfficialSANRegex {
		t.Errorf("SAN regex drift:\n  feeds_identity.env=%q\n  urlcatfeed.OfficialSANRegex=%q", got, urlcatfeed.OfficialSANRegex)
	}
}

// TestFeedIdentityDistinctFromCatalog proves the feed identity is a SEPARATE pin,
// not a copy of the release-catalog identity (F0 §5: distinct signing workflow +
// tag namespace, distinct blast radius). The issuer is shared (the GitHub OIDC
// issuer), but the SAN regex — the workflow+tag anchor — must differ.
func TestFeedIdentityDistinctFromCatalog(t *testing.T) {
	if urlcatfeed.OfficialSANRegex == officialSigstoreSANRegex {
		t.Fatal("feed SAN regex must NOT equal the release-catalog SAN regex (separate identity)")
	}
	if !strings.Contains(urlcatfeed.OfficialSANRegex, `publish-feeds\.yml`) {
		t.Errorf("feed SAN regex must pin the feed signing workflow; got %q", urlcatfeed.OfficialSANRegex)
	}
	if !strings.Contains(urlcatfeed.OfficialSANRegex, "feeds-v") {
		t.Errorf("feed SAN regex must pin the feeds-v* tag namespace; got %q", urlcatfeed.OfficialSANRegex)
	}
}

// TestFeedReusesSharedTrustedRoot proves the feed trust kernel REUSES the shared
// Sigstore public-good trusted root BY VALUE — the exact bytes the release
// catalog bakes (bakedSigstoreTrustedRootJSON) construct a working feed verifier.
// No separate cryptographic root is provisioned (F0 §5); only the identity is
// distinct. This does NOT touch the catalog trust path.
func TestFeedReusesSharedTrustedRoot(t *testing.T) {
	v, err := urlcatfeed.NewVerifierFromJSON(bakedSigstoreTrustedRootJSON, urlcatfeed.OfficialIdentity())
	if err != nil {
		t.Fatalf("feed verifier from shared baked root: %v", err)
	}
	if v == nil {
		t.Fatal("nil verifier from shared baked root")
	}
}
