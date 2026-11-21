package main

// install_script_extract_toml_string_basic_escape_test.go — extract_toml_string
// in packaging/culvert-maint/install.sh must read a TOML BASIC ("...") string
// the way the agent's TOML decoder does: `\\` is one backslash and `\"` is a
// quote that does not end the string.
//
// image_allowlist is a regex, so it carries backslashes (`ghcr\.io`). The
// shipped config writes it as a literal ('...') string, but the same value as
// a basic string, `"^ghcr\\.io/..."`, is equally valid TOML and is what the
// agent (toml.DecodeFile in cmd/culvert-maint/internal/config) accepts. The
// installer copied the escaped bytes verbatim, so its own cross-check tested
// the pinned ref against `ghcr\\.io` (a literal backslash, then any character)
// and aborted the install with "proxy_repo ... is not matched by
// image_allowlist" for a config the agent itself runs with.

import (
	"strings"
	"testing"
)

func TestCulvertMaintInstall_ExtractTomlString_BasicStringEscapes(t *testing.T) {
	const want = `^ghcr\.io/kidcarmi/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$`
	// The same regex as the shipped default, written as a basic string.
	cfg := `image_allowlist = "^ghcr\\.io/kidcarmi/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$"  # mirror` + "\n"

	got := runExtractTomlString(t, cfg, "image_allowlist")
	if got != want {
		t.Fatalf("basic-string image_allowlist:\n got  %q\n want %q (TOML `\\\\` is one backslash)", got, want)
	}

	// End to end: the value the installer extracted must pass the installer's
	// own proxy_repo/image_allowlist cross-check for the default repo.
	if died, out := runCheckProxyRepoMatchesAllowlist(t, "ghcr.io/kidcarmi/culvert", got); died {
		t.Fatalf("install aborts on a valid basic-string image_allowlist: %s", out)
	}
}

func TestCulvertMaintInstall_ExtractTomlString_BasicStringEscapedQuote(t *testing.T) {
	// An escaped quote is part of the value, not its end; the string ends at
	// the first UNESCAPED quote and the trailing comment stays out.
	got := runExtractTomlString(t, `compose_file = "a\"b.yml" # "c"`+"\n", "compose_file")
	if want := `a"b.yml`; got != want {
		t.Fatalf("escaped quote: got %q, want %q", got, want)
	}
	// A backslash-free basic string is unchanged.
	got = runExtractTomlString(t, `proxy_repo = "ghcr.io/kidcarmi/culvert" # x`+"\n", "proxy_repo")
	if want := "ghcr.io/kidcarmi/culvert"; got != want || strings.Contains(got, `"`) {
		t.Fatalf("plain basic string: got %q, want %q", got, want)
	}
}
