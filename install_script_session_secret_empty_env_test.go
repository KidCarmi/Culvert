package main

// install_script_session_secret_empty_env_test.go — persist_host_env_session_
// secret() must treat a CULVERT_SESSION_SECRET line that docker compose
// resolves to an EMPTY value (CRLF-only, an empty quote pair, or a blank
// followed by an inline comment) as unset, exactly as secret_already_set()
// does for the passphrases. Otherwise the operator's host-env secret is never
// persisted and every node silently falls back to its own random signing key.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScript_PersistHostEnvSessionSecret_EmptyComposeValueCountsAsUnset(t *testing.T) {
	cases := map[string]string{
		"crlf-empty":        "CULVERT_SESSION_SECRET=\r\n",
		"double-quote-pair": "CULVERT_SESSION_SECRET=\"\"\n",
		"single-quote-pair": "CULVERT_SESSION_SECRET=''\n",
		"inline-comment":    "CULVERT_SESSION_SECRET= # set me\n",
	}
	secret := strings.Repeat("ab", 32)
	for name, seed := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(seed), 0o600); err != nil {
				t.Fatalf("seed .env: %v", err)
			}
			out, exitCode, envContent := runPersistHostEnvSessionSecret(t, dir,
				`export CULVERT_SESSION_SECRET="`+secret+`"`)
			if exitCode != 0 {
				t.Fatalf("exit %d; output:\n%s", exitCode, out)
			}
			if !strings.Contains(envContent, "CULVERT_SESSION_SECRET="+secret) {
				t.Fatalf("host-env secret not persisted over an empty-valued .env line %q; .env:\n%s", seed, envContent)
			}
		})
	}
}
