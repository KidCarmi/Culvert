package main

// Workstream C: on an appliance (its manifest records the baked sidecar's
// image ID) the installer never builds the ClamAV sidecar. A re-run whose new
// bundle names a sidecar tag this host does not have leaves every host
// component as installed (nothing built, nothing replaced) instead of building
// new, unscanned bytes from Docker Hub and the Alpine CDN. A quick-start host
// (no manifest) keeps building it — TestInstallScript_HostRefresh_AdoptsANewSidecar.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func (h *hostRefreshHarness) makeAppliance() {
	h.t.Helper()
	dir := filepath.Join(h.root, "appliance-state")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		h.t.Fatal(err)
	}
	body := "CLAMAV_SIDECAR_REF=culvert/clamav:1.4.6-old\nCLAMAV_SIDECAR_ID=sha256:" + strings.Repeat("ab", 32) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "manifest.env"), []byte(body), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func TestInstallScript_HostRefresh_ApplianceNeverBuildsTheSidecar(t *testing.T) {
	h := newHostRefreshHarness(t)
	h.makeAppliance()
	h.newRelease()
	before := h.snapshot()

	out, rc := h.run()
	if rc != 3 {
		t.Fatalf("an appliance must refuse a bundle whose sidecar it does not have (rc %d):\n%s", rc, out)
	}
	if h.built() {
		t.Fatalf("an appliance must never build the sidecar:\n%s", out)
	}
	if calls, _ := os.ReadFile(h.calls); strings.Contains(string(calls), "docker build") {
		t.Fatalf("no docker build may be attempted on an appliance:\n%s", calls)
	}
	if after := h.snapshot(); !mapsEqual(before, after) {
		t.Fatalf("nothing may be replaced:\n%v\n%v", before, after)
	}
	if !strings.Contains(out, "never builds one") {
		t.Fatalf("the operator must be told why:\n%s", out)
	}
}

// An appliance bundle whose sidecar IS present (the image the appliance was
// built with) is adopted normally, without a build.
func TestInstallScript_HostRefresh_ApplianceAdoptsBundleWithPresentSidecar(t *testing.T) {
	h := newHostRefreshHarness(t)
	h.makeAppliance()
	h.newRelease()
	h.present("culvert/clamav:1.4.6-new")

	out, rc := h.run()
	if rc != 0 || h.built() {
		t.Fatalf("a present sidecar must be adopted without a build (rc %d, built %v):\n%s", rc, h.built(), out)
	}
	if !strings.Contains(h.read("docker-compose.yml"), "1.4.6-new") {
		t.Fatalf("the refreshed compose must be installed:\n%s", h.read("docker-compose.yml"))
	}
}

// A manifest without a valid recorded ID is not an appliance: a quick-start
// host that happens to carry a stray file keeps the build path.
func TestInstallScript_HostRefresh_MalformedManifestIsNotAnAppliance(t *testing.T) {
	h := newHostRefreshHarness(t)
	dir := filepath.Join(h.root, "appliance-state")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.env"), []byte("CLAMAV_SIDECAR_ID=latest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.newRelease()
	if out, rc := h.run(); rc != 0 || !h.built() {
		t.Fatalf("without a recorded ID the host is quick-start and builds (rc %d):\n%s", rc, out)
	}
}
