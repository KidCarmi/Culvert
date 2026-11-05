package main

import "testing"

// A TOML multi-line literal string written on one line (”'value”') is valid
// TOML and is accepted by the maint agent's own config parser and by
// maint_toml_string() in scripts/install.sh. packaging/culvert-maint/install.sh
// extract_toml_string() must read the same value; otherwise the agent installer
// reports "compose_project_dir not found" (or silently falls back to a default
// proxy_repo/compose_file) for a config the agent itself would load.
func TestExtractTomlString_TripleQuotedLiteral(t *testing.T) {
	cases := map[string]string{
		"compose_project_dir = '''/srv/culvert'''\n":            "/srv/culvert",
		"proxy_repo = '''ghcr.io/example/custom'''  # mirror\n": "ghcr.io/example/custom",
		"compose_file = '''docker-compose.ha.yml'''\n":          "docker-compose.ha.yml",
	}
	for toml, want := range cases {
		key := toml[:indexByte(toml, ' ')]
		if got := runExtractTomlString(t, toml, key); got != want {
			t.Errorf("extract_toml_string(%q) = %q, want %q", toml, got, want)
		}
	}
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
