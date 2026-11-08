package main

// install_script_detect_distro_debian_like_test.go — detect_distro's ID_LIKE
// fallback must pair the Docker apt repo distro with its own codename.
//
// scripts/install.sh builds the Docker apt source as
// https://download.docker.com/linux/${DISTRO_ID} ${DISTRO_CODENAME}. For a
// Debian-derived distro that is not named in the explicit case arm (e.g.
// Raspberry Pi OS, ID=raspbian, ID_LIKE=debian, VERSION_CODENAME=bookworm) the
// fallback used to force DISTRO_ID=ubuntu while keeping the DEBIAN codename,
// yielding linux/ubuntu + "bookworm" — a repo that does not exist, so
// `apt-get update` fails and the install aborts.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runDetectDistro(t *testing.T, osRelease string) (id, codename string) {
	t.Helper()
	script, err := os.ReadFile("scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(script)
	start := strings.Index(src, "\ndetect_distro() {")
	if start < 0 {
		t.Fatal("detect_distro not found")
	}
	end := strings.Index(src[start:], "\n}\n")
	fn := src[start : start+end+3]
	dir := t.TempDir()
	rel := filepath.Join(dir, "os-release")
	if err := os.WriteFile(rel, []byte(osRelease), 0o600); err != nil {
		t.Fatal(err)
	}
	fn = strings.ReplaceAll(fn, "/etc/os-release", rel)
	harness := "set -euo pipefail\ninfo(){ :; }\nerror(){ echo \"ERR $*\" >&2; exit 1; }\n" +
		fn + "\ndetect_distro\nprintf '%s|%s\\n' \"$DISTRO_ID\" \"$DISTRO_CODENAME\"\n"
	out, err := exec.CommandContext(t.Context(), "bash", "-c", harness).CombinedOutput() //nolint:gosec // fixed harness built from repo script
	if err != nil {
		t.Fatalf("detect_distro: %v: %s", err, out)
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	return parts[0], parts[1]
}

func TestDetectDistro_DebianLikeUsesDebianRepo(t *testing.T) {
	id, cn := runDetectDistro(t, "ID=raspbian\nID_LIKE=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n")
	if id != "debian" || cn != "bookworm" {
		t.Fatalf("got docker repo linux/%s %s; want linux/debian bookworm", id, cn)
	}
}

func TestDetectDistro_UbuntuLikeKeepsUbuntuRepo(t *testing.T) {
	id, cn := runDetectDistro(t, "ID=zorin\nID_LIKE=\"ubuntu debian\"\nVERSION_CODENAME=faye\nUBUNTU_CODENAME=jammy\n")
	if id != "ubuntu" || cn != "jammy" {
		t.Fatalf("got linux/%s %s; want linux/ubuntu jammy", id, cn)
	}
}

func TestDetectDistro_DirectDistrosUnchanged(t *testing.T) {
	if id, cn := runDetectDistro(t, "ID=debian\nVERSION_CODENAME=bookworm\n"); id != "debian" || cn != "bookworm" {
		t.Fatalf("debian: %s %s", id, cn)
	}
	if id, cn := runDetectDistro(t, "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_CODENAME=wilma\nUBUNTU_CODENAME=noble\n"); id != "ubuntu" || cn != "noble" {
		t.Fatalf("mint: %s %s", id, cn)
	}
}
