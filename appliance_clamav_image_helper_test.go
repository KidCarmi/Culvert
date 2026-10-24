package main

// Workstream C: appliance/provision/culvert-clamav-image is the ONLY way the
// baked ClamAV sidecar tag comes back on an appliance (every `compose up`
// there runs with --no-build). These tests run the real script against a fake
// docker whose image store is a file, and pin each outcome: present, reloaded
// from a hash-verified archive, and every refusal — none of which builds,
// pulls, or changes the store.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	helperRef = "culvert/clamav:1.5.4-culvert.2"
	helperID  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	otherID   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

type clamHelperRig struct {
	t                 *testing.T
	state, store, log string
}

// newClamHelperRig builds an appliance state dir whose archive "contains"
// archiveID (the fake `docker load` installs it) and whose build-info records
// the archive's real SHA-256 unless recordSHA overrides it.
func newClamHelperRig(t *testing.T, archiveID, recordSHA string) *clamHelperRig {
	t.Helper()
	root := t.TempDir()
	r := &clamHelperRig{t: t, state: filepath.Join(root, "state"), store: filepath.Join(root, "store"), log: filepath.Join(root, "docker.log")}
	if err := os.MkdirAll(filepath.Join(r.state, "images"), 0o750); err != nil {
		t.Fatal(err)
	}
	archive := []byte(archiveID + "\n")
	sum := sha256.Sum256(archive)
	if recordSHA == "" {
		recordSHA = hex.EncodeToString(sum[:])
	}
	r.write(filepath.Join(r.state, "images", "clamav.tar.gz"), string(archive))
	r.write(filepath.Join(r.state, "manifest.env"), "CLAMAV_SIDECAR_REF="+helperRef+"\nCLAMAV_SIDECAR_ID="+helperID+"\n")
	r.write(filepath.Join(r.state, "build-info.json"), `{"application":{"clamav_baked_tar_sha256":"`+recordSHA+`"}}`)
	bin := filepath.Join(root, "docker")
	r.write(bin, `#!/bin/bash
echo "$*" >> "$LOG"
case "$1 $2" in
  "image inspect") [[ -s "$STORE" ]] || { echo "Error: No such image: $3" >&2; exit 1; }; cat "$STORE" ;;
  "load -q") cp "$4" "$STORE" ;;
  "image rm") rm -f "$STORE" ;;
  *) echo "unexpected docker $*" >&2; exit 99 ;;
esac
`)
	if err := os.Chmod(bin, 0o700); err != nil { //nolint:gosec // test stub must be executable
		t.Fatal(err)
	}
	return r
}

func (r *clamHelperRig) write(p, body string) {
	r.t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *clamHelperRig) storeHolds(id string) {
	r.t.Helper()
	r.write(r.store, id+"\n")
}

func (r *clamHelperRig) run() (out string, code int) {
	r.t.Helper()
	cmd := exec.CommandContext(r.t.Context(), "bash", "appliance/provision/culvert-clamav-image", "ensure") // #nosec G204 -- repo script, fixed args
	cmd.Env = append(os.Environ(), "CULVERT_APPLIANCE_STATE_DIR="+r.state, "CULVERT_DOCKER="+filepath.Join(filepath.Dir(r.store), "docker"),
		"STORE="+r.store, "LOG="+r.log)
	b, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok { //nolint:errorlint // exit status of a direct child
		code = ee.ExitCode()
	} else if err != nil {
		r.t.Fatalf("run: %v\n%s", err, b)
	}
	return string(b), code
}

func (r *clamHelperRig) stateFile() map[string]string {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.state, "clamav-image.state"))
	if err != nil {
		r.t.Fatalf("no state file: %v", err)
	}
	m := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = v
		}
	}
	return m
}

func (r *clamHelperRig) dockerLog() string {
	b, _ := os.ReadFile(r.log)
	return string(b)
}

func (r *clamHelperRig) assertNeverBuiltOrPulled() {
	r.t.Helper()
	for _, verb := range []string{"build", "pull", "compose"} {
		for _, l := range strings.Split(r.dockerLog(), "\n") {
			if strings.HasPrefix(l, verb+" ") {
				r.t.Fatalf("the helper must never %s:\n%s", verb, r.dockerLog())
			}
		}
	}
}

func TestClamAVImageHelper_PresentDoesNothing(t *testing.T) {
	r := newClamHelperRig(t, helperID, "")
	r.storeHolds(helperID)
	if out, code := r.run(); code != 0 {
		t.Fatalf("present: code %d\n%s", code, out)
	}
	if s := r.stateFile(); s["status"] != "present" {
		t.Fatalf("state: %v", s)
	}
	if strings.Contains(r.dockerLog(), "load") {
		t.Fatalf("a present image must not be reloaded:\n%s", r.dockerLog())
	}
}

func TestClamAVImageHelper_AbsentIsReloadedFromVerifiedArchive(t *testing.T) {
	for name, held := range map[string]string{"absent": "", "wrong image under the tag": otherID} {
		t.Run(name, func(t *testing.T) {
			r := newClamHelperRig(t, helperID, "")
			if held != "" {
				r.storeHolds(held)
			}
			if out, code := r.run(); code != 0 {
				t.Fatalf("reload: code %d\n%s", code, out)
			}
			if s := r.stateFile(); s["status"] != "reloaded" || s["expected_id"] != helperID {
				t.Fatalf("state: %v", s)
			}
			r.assertNeverBuiltOrPulled()
		})
	}
}

func TestClamAVImageHelper_Refusals(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		setup        func(r *clamHelperRig)
		archiveID    string
		recordSHA    string
	}{
		{name: "archive missing", reason: "archive_missing", archiveID: helperID,
			setup: func(r *clamHelperRig) { _ = os.Remove(filepath.Join(r.state, "images", "clamav.tar.gz")) }},
		{name: "archive tampered", reason: "archive_hash_mismatch", archiveID: helperID, recordSHA: strings.Repeat("0", 64)},
		{name: "archive hash unrecorded", reason: "archive_hash_unrecorded", archiveID: helperID,
			setup: func(r *clamHelperRig) { r.write(filepath.Join(r.state, "build-info.json"), `{"images":{}}`) }},
		{name: "archive holds another image", reason: "loaded_id_mismatch", archiveID: otherID},
		{name: "manifest incomplete", reason: "manifest_incomplete", archiveID: helperID,
			setup: func(r *clamHelperRig) {
				r.write(filepath.Join(r.state, "manifest.env"), "CLAMAV_SIDECAR_REF="+helperRef+"\nCLAMAV_SIDECAR_ID=latest\n")
			}},
		{name: "manifest missing", reason: "manifest_missing", archiveID: helperID,
			setup: func(r *clamHelperRig) { _ = os.Remove(filepath.Join(r.state, "manifest.env")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newClamHelperRig(t, tc.archiveID, tc.recordSHA)
			if tc.setup != nil {
				tc.setup(r)
			}
			out, code := r.run()
			if code != 2 {
				t.Fatalf("a refusal must exit 2, got %d\n%s", code, out)
			}
			if s := r.stateFile(); s["status"] != "refused" || s["reason"] != tc.reason {
				t.Fatalf("state: %v want reason %s", s, tc.reason)
			}
			if !strings.Contains(out, "NOT rebuilt or pulled") {
				t.Fatalf("the refusal must say nothing was rebuilt:\n%s", out)
			}
			r.assertNeverBuiltOrPulled()
		})
	}
}

// A refusal never leaves the tag naming unverified bytes (ASTRA 5978949299 C7:
// "nothing changed" was too broad — a refused load had already retagged). With
// a valid recorded ID proving the tag names other bytes, the tag is removed so
// `compose up --no-build` cannot start them.
func TestClamAVImageHelper_RefusalRemovesATagNamingUnverifiedBytes(t *testing.T) {
	for name, setup := range map[string]func(r *clamHelperRig){
		"archive loaded other bytes": func(*clamHelperRig) {},
		"wrong image already under the tag, archive missing": func(r *clamHelperRig) {
			r.storeHolds(otherID)
			_ = os.Remove(filepath.Join(r.state, "images", "clamav.tar.gz"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newClamHelperRig(t, otherID, "")
			setup(r)
			out, code := r.run()
			if code != 2 {
				t.Fatalf("must refuse, got %d\n%s", code, out)
			}
			if b, err := os.ReadFile(r.store); err == nil && len(b) > 0 {
				t.Fatalf("the tag still names unverified bytes %q:\n%s", b, out)
			}
			if !strings.Contains(out, "the tag was removed") {
				t.Fatalf("the removal must be stated:\n%s", out)
			}
		})
	}
}

// CONTROL: with damaged metadata nothing proves the tag wrong, so it is kept.
func TestClamAVImageHelper_DamagedManifestLeavesTheTagAlone(t *testing.T) {
	r := newClamHelperRig(t, helperID, "")
	r.storeHolds(helperID)
	r.write(filepath.Join(r.state, "manifest.env"), "CLAMAV_SIDECAR_REF="+helperRef+"\nCLAMAV_SIDECAR_ID=latest\n")
	if _, code := r.run(); code != 2 {
		t.Fatal("a damaged manifest must refuse")
	}
	if b, _ := os.ReadFile(r.store); strings.TrimSpace(string(b)) != helperID {
		t.Fatalf("the tag must be left alone without a valid recorded ID, store=%q", b)
	}
}
