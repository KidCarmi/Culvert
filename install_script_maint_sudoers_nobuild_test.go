package main

// Workstream C: packaging/culvert-maint/install.sh renders exactly ONE
// compose.up family into /etc/sudoers.d/culvert-maint. A compose_no_build
// (appliance) host keeps only the `--no-build` forms, so a compromised
// culvert-maint user cannot run an `up` that could build the sidecar from
// source; every other host keeps only the historical plain forms. The render
// block and the compose_no_build parse are extracted VERBATIM from the
// script, so this test cannot drift from what the installer runs.

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func renderMaintSudoersNoBuild(t *testing.T, noBuild, override string) string {
	t.Helper()
	const sh = "packaging/culvert-maint/install.sh"
	script := extractShellFunction(t, sh, "sed_escape_replacement") + "\n" +
		extractShellFunction(t, sh, "sudoers_escape_colon") + "\n" +
		"PROJECT_DIR='/srv/culvert'\nCOMPOSE_FILE='docker-compose.yml'\n" +
		"PROXY_REPO='ghcr.io/kidcarmi/culvert'\n" +
		"COMPOSE_OVERRIDE_FILE='" + override + "'\n" +
		"COMPOSE_NO_BUILD='" + noBuild + "'\n" +
		"SUDOERS_TEMPLATE='packaging/sudoers/culvert-maint'\n" +
		extractShellLineRange(t, sh, `COMPOSE_PATH="$PROJECT_DIR/$COMPOSE_FILE"`, `mv "$RENDERED_SUDOERS_TMP" "$RENDERED_SUDOERS"`) + "\n" +
		`cat "$RENDERED_SUDOERS"; rm -f "$RENDERED_SUDOERS"` + "\n"
	out, err := exec.CommandContext(t.Context(), "bash", "-c", script).CombinedOutput() // #nosec G204 -- fixed test script content
	if err != nil {
		t.Fatalf("render failed: %v\n%s", err, out)
	}
	return string(out)
}

func composeUpLines(rendered string) []string {
	var ups []string
	for _, l := range strings.Split(rendered, "\n") {
		if strings.HasPrefix(l, "culvert-maint ") && strings.Contains(l, " compose -f ") && strings.Contains(l, " up -d") {
			ups = append(ups, l)
		}
	}
	return ups
}

func TestCulvertMaintInstall_SudoersRender_ComposeUpFamily(t *testing.T) {
	for _, tc := range []struct {
		noBuild, override string
		wantUps           int
	}{
		{"false", "", 1},
		{"false", "docker-compose.maint-agent.yml", 2},
		{"true", "", 1},
		{"true", "docker-compose.maint-agent.yml", 2},
	} {
		t.Run("no_build="+tc.noBuild+",override="+tc.override, func(t *testing.T) {
			rendered := renderMaintSudoersNoBuild(t, tc.noBuild, tc.override)
			ups := composeUpLines(rendered)
			if len(ups) != tc.wantUps {
				t.Fatalf("want %d compose.up lines, got %d:\n%s", tc.wantUps, len(ups), strings.Join(ups, "\n"))
			}
			for _, l := range ups {
				hasNoBuild := strings.HasSuffix(l, " up -d --no-build")
				if tc.noBuild == "true" && !hasNoBuild {
					t.Errorf("a no-build host must not be allowed a build-capable `up`: %q", l)
				}
				if tc.noBuild == "false" && (hasNoBuild || !strings.HasSuffix(l, " up -d")) {
					t.Errorf("a default host must keep exactly the historical `up -d`: %q", l)
				}
			}
			if _, err := exec.LookPath("visudo"); err == nil {
				f := t.TempDir() + "/sudoers"
				if err := os.WriteFile(f, []byte(rendered), 0o600); err != nil {
					t.Fatal(err)
				}
				// #nosec G204 -- fixed argv; f is a temp path this test wrote
				if out, err := exec.CommandContext(t.Context(), "visudo", "-c", "-f", f).CombinedOutput(); err != nil {
					t.Fatalf("visudo rejected the render: %v\n%s", err, out)
				}
			}
		})
	}
}

// The compose_no_build value is parsed by the real extract_toml_string and
// accepted ONLY as absent/false/true; anything else stops the install rather
// than silently selecting a sudoers family.
func TestCulvertMaintInstall_ComposeNoBuildParse(t *testing.T) {
	const sh = "packaging/culvert-maint/install.sh"
	parse := extractShellLineRange(t, sh, `COMPOSE_NO_BUILD=$(extract_toml_string compose_no_build)`, `esac`)
	for body, want := range map[string]string{
		"":                           "false",
		"compose_no_build = false\n": "false",
		"compose_no_build = true\n":  "true",
		"compose_no_build = yes\n":   "DIE",
		"compose_no_build = 1\n":     "DIE",
	} {
		cfg := t.TempDir() + "/config.toml"
		if err := os.WriteFile(cfg, []byte("compose_project_dir = \"/srv/culvert\"\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		script := "CONFIG_DEST='" + cfg + "'\ndie() { echo DIE; exit 0; }\n" +
			extractShellFunctionBraceAware(t, sh, "extract_toml_string") + "\n" + parse + "\necho \"$COMPOSE_NO_BUILD\"\n"
		out, err := exec.CommandContext(t.Context(), "bash", "-c", script).CombinedOutput() // #nosec G204 -- fixed test script content
		if err != nil {
			t.Fatalf("%q: %v\n%s", body, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("%q: got %q want %q", body, got, want)
		}
	}
}
