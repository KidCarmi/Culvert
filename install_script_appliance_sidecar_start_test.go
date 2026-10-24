package main

// Workstream C (ASTRA 5978949299, C blocker 2 "before adoption/start"): before
// the first `compose up` an appliance restores its baked sidecar, then requires
// that the compose file about to start names exactly that sidecar and that it
// resolves to the recorded image ID. A damaged manifest keeps --no-build. The
// functions are extracted from scripts/install.sh, not copied.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runApplianceStart(t *testing.T, manifest, composeTag, localID string, dirs bool) (string, error) {
	t.Helper()
	root := t.TempDir()
	install := filepath.Join(root, "srv")
	state := filepath.Join(root, "appliance-state")
	if err := os.MkdirAll(install, 0o750); err != nil {
		t.Fatal(err)
	}
	if dirs {
		if err := os.MkdirAll(state, 0o750); err != nil {
			t.Fatal(err)
		}
		if manifest != "" {
			if err := os.WriteFile(filepath.Join(state, "manifest.env"), []byte(manifest), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	compose := "services:\n  clamav:\n    image: " + composeTag + "\n"
	if err := os.WriteFile(filepath.Join(install, "docker-compose.yml"), []byte(compose), 0o600); err != nil {
		t.Fatal(err)
	}
	var fns []string
	for _, n := range []string{"sidecar_image_of", "is_appliance", "appliance_manifest_value", "appliance_sidecar_check", "ensure_appliance_sidecar"} {
		fns = append(fns, extractShellFunction(t, "scripts/install.sh", n))
	}
	noBuildInit := extractShellLineRange(t, "scripts/install.sh", "COMPOSE_NO_BUILD=()", "fi")
	script := `set -uo pipefail
info() { :; }
error() { echo "ERROR $*"; exit 1; }
sudo() { "$@"; }
docker() { [[ "$1 $2" == "image inspect" && -n "$LOCAL_ID" ]] && { echo "$LOCAL_ID"; return 0; }; return 1; }
helper_stub() { echo "helper $*"; }
CLAMAV_IMAGE_TOOL=helper_stub
APPLIANCE_STATE_DIR="$ROOT/appliance-state"
APPLIANCE_OPT_DIR="$ROOT/appliance-opt"
APPLIANCE_ETC_DIR="$ROOT/appliance-etc"
` + strings.Join(fns, "\n") + "\n" + noBuildInit + `
echo "NO_BUILD=${COMPOSE_NO_BUILD[*]:-}"
ensure_appliance_sidecar
echo STARTED
`
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script built from the repo's install.sh
	cmd.Env = append(os.Environ(), "ROOT="+root, "INSTALL_DIR="+install, "LOCAL_ID="+localID)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestInstallScript_ApplianceStart_BindsComposeSidecarToBakedRecord(t *testing.T) {
	const ref = "culvert/clamav:1.5.4-culvert.2"
	manifest := bakedManifest(ref)
	for _, tc := range []struct {
		name, tag, id, want string
		ok                  bool
	}{
		{"approved", ref, applianceBakedID, "STARTED", true},
		{"compose names another tag", "culvert/clamav:other", applianceBakedID, "this appliance was built with", false},
		{"baked tag names other bytes", ref, applianceOtherID, "but this appliance recorded", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runApplianceStart(t, manifest, tc.tag, tc.id, true)
			if tc.ok != (err == nil) || !strings.Contains(out, tc.want) {
				t.Fatalf("err=%v, want %q:\n%s", err, tc.want, out)
			}
			if !strings.Contains(out, "NO_BUILD=--no-build") || !strings.Contains(out, "helper ensure") {
				t.Fatalf("an appliance start must be --no-build and restore via the helper first:\n%s", out)
			}
		})
	}
}

// A damaged manifest is still an appliance: --no-build stays on and the start
// is refused rather than treated as quick-start.
func TestInstallScript_ApplianceStart_DamagedManifestKeepsNoBuildAndRefuses(t *testing.T) {
	out, err := runApplianceStart(t, "CLAMAV_SIDECAR_ID=latest\n", "culvert/clamav:1.5.4-culvert.2", applianceBakedID, true)
	if err == nil || !strings.Contains(out, "NO_BUILD=--no-build") || strings.Contains(out, "STARTED") {
		t.Fatalf("a damaged manifest must keep --no-build and refuse:\n%s", out)
	}
}

// CONTROL: a quick-start host (no appliance directories) does nothing extra.
func TestInstallScript_ApplianceStart_QuickStartUnchanged(t *testing.T) {
	out, err := runApplianceStart(t, "", "culvert/clamav:1.5.4-culvert.2", "", false)
	if err != nil || !strings.Contains(out, "NO_BUILD=\n") || strings.Contains(out, "helper") || !strings.Contains(out, "STARTED") {
		t.Fatalf("quick-start must keep plain up and skip the helper:\n%s", out)
	}
}
