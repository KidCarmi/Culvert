package main

// Workstream C: on an appliance the installer never builds the ClamAV sidecar,
// and it adopts or starts only the sidecar the appliance was built with.
//
// ASTRA 5978949299 found two fail-open boundaries in the first version:
//   - appliance identity came from the manifest's ID being VALID, so an appliance
//     whose manifest was damaged ("CLAMAV_SIDECAR_ID=latest") was treated as a
//     quick-start host and BUILT the sidecar — the pinned test said so;
//   - any locally PRESENT new tag was adopted, though presence proves nothing
//     about which bytes the tag names.
// Identity now comes from the directories the OVA build installs; the compose
// sidecar must equal the manifest's ref and, when present, resolve to its ID.
// A quick-start host (none of those directories) keeps building —
// TestInstallScript_HostRefresh_AdoptsANewSidecar.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	applianceBakedID = "sha256:" + "abababababababababababababababababababababababababababababababab"
	applianceOtherID = "sha256:" + "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
)

// makeAppliance creates the appliance state directory with a manifest body
// (empty body ⇒ no manifest file at all).
func (h *hostRefreshHarness) makeAppliance(manifest string) {
	h.t.Helper()
	dir := filepath.Join(h.root, "appliance-state")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		h.t.Fatal(err)
	}
	if manifest == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.env"), []byte(manifest), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func bakedManifest(ref string) string {
	return "CLAMAV_SIDECAR_REF=" + ref + "\nCLAMAV_SIDECAR_ID=" + applianceBakedID + "\n"
}

// presentAs marks tag present locally and resolving to id.
func (h *hostRefreshHarness) presentAs(tag, id string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.root, "img-"+strings.NewReplacer("/", "_", ":", "_").Replace(tag)), []byte(id+"\n"), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// sameSidecarRelease changes host components but keeps the baked sidecar tag.
func (h *hostRefreshHarness) sameSidecarRelease() {
	h.writeTree(h.image, hostRefreshOldCompose, "FROM base\nRUN apk add zlib=1.3.2-r0\n", "agent installer v2\n")
}

func (h *hostRefreshHarness) assertRefusedUnchanged(before map[string]string, out string, rc int, why string) {
	h.t.Helper()
	if rc != 3 {
		h.t.Fatalf("an appliance must refuse (rc 3), got rc %d:\n%s", rc, out)
	}
	if h.built() {
		h.t.Fatalf("an appliance must never build the sidecar:\n%s", out)
	}
	if calls, _ := os.ReadFile(h.calls); strings.Contains(string(calls), "docker build") {
		h.t.Fatalf("no docker build may be attempted on an appliance:\n%s", calls)
	}
	if after := h.snapshot(); !mapsEqual(before, after) {
		h.t.Fatalf("nothing may be replaced:\n%v\n%v", before, after)
	}
	if !strings.Contains(out, "never builds one") || !strings.Contains(out, why) {
		h.t.Fatalf("the operator must be told why (%q):\n%s", why, out)
	}
}

func TestInstallScript_HostRefresh_ApplianceRefusesAnUnapprovedSidecar(t *testing.T) {
	for _, tc := range []struct {
		name, why string
		setup     func(h *hostRefreshHarness)
	}{
		{"different tag, absent", "this appliance was built with", func(h *hostRefreshHarness) {
			h.newRelease()
		}},
		// Presence of the new tag is not approval (ASTRA C blocker 2).
		{"different tag, present", "this appliance was built with", func(h *hostRefreshHarness) {
			h.newRelease()
			h.presentAs("culvert/clamav:1.4.6-new", applianceBakedID)
		}},
		// The baked tag names other bytes.
		{"baked tag, wrong image ID", "but this appliance recorded", func(h *hostRefreshHarness) {
			h.sameSidecarRelease()
			h.presentAs("culvert/clamav:1.4.6-old", applianceOtherID)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostRefreshHarness(t)
			h.makeAppliance(bakedManifest("culvert/clamav:1.4.6-old"))
			tc.setup(h)
			before := h.snapshot()
			out, rc := h.run()
			h.assertRefusedUnchanged(before, out, rc, tc.why)
		})
	}
}

// Damaged or missing metadata on an appliance is still an appliance: it refuses
// and never falls back to the quick-start build (ASTRA C blocker 1; this reverses
// the earlier test that pinned the fail-open case).
func TestInstallScript_HostRefresh_ApplianceWithUnusableManifestRefuses(t *testing.T) {
	for name, manifest := range map[string]string{
		"invalid recorded ID": "CLAMAV_SIDECAR_REF=culvert/clamav:1.4.6-old\nCLAMAV_SIDECAR_ID=latest\n",
		"no recorded ref":     "CLAMAV_SIDECAR_ID=" + applianceBakedID + "\n",
		"manifest missing":    "",
	} {
		t.Run(name, func(t *testing.T) {
			h := newHostRefreshHarness(t)
			h.makeAppliance(manifest)
			h.newRelease()
			before := h.snapshot()
			out, rc := h.run()
			h.assertRefusedUnchanged(before, out, rc, "does not record a usable sidecar ref and image ID")
		})
	}
}

// The program or config directory alone also identifies an appliance (a wiped
// state directory must not turn it into a quick-start host).
func TestInstallScript_HostRefresh_ApplianceIdentityWithoutStateDir(t *testing.T) {
	for _, d := range []string{"appliance-opt", "appliance-etc"} {
		t.Run(d, func(t *testing.T) {
			h := newHostRefreshHarness(t)
			if err := os.MkdirAll(filepath.Join(h.root, d), 0o750); err != nil {
				t.Fatal(err)
			}
			h.newRelease()
			before := h.snapshot()
			out, rc := h.run()
			h.assertRefusedUnchanged(before, out, rc, "does not record a usable sidecar ref and image ID")
		})
	}
}

// CONTROLS: the approved sidecar is adopted without a build, whether it is
// present with the recorded ID or absent (restored from the archive at start).
func TestInstallScript_HostRefresh_ApplianceAdoptsTheApprovedSidecar(t *testing.T) {
	for name, present := range map[string]bool{"present with recorded ID": true, "absent locally": false} {
		t.Run(name, func(t *testing.T) {
			h := newHostRefreshHarness(t)
			h.makeAppliance(bakedManifest("culvert/clamav:1.4.6-old"))
			h.sameSidecarRelease()
			if present {
				h.presentAs("culvert/clamav:1.4.6-old", applianceBakedID)
			} else {
				_ = os.Remove(filepath.Join(h.root, "img-culvert_clamav_1.4.6-old"))
			}
			out, rc := h.run()
			if rc != 0 || h.built() {
				t.Fatalf("the approved sidecar must be adopted without a build (rc %d, built %v):\n%s", rc, h.built(), out)
			}
			if !strings.Contains(h.read("packaging/culvert-maint/install.sh"), "agent installer v2") {
				t.Fatal("the refreshed host components must be installed")
			}
		})
	}
}
