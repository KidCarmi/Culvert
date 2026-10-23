package server

import (
	"strings"
	"testing"

	"culvert-maint/internal/config"
)

// Workstream C: a compose_no_build host runs `compose up --no-build`, so a
// local-only image (the baked ClamAV sidecar) that is missing can never be
// built back — the recreate would fail half-way through an apply or rollback.
// preflight_dependencies refuses BEFORE anything is pulled, tagged or
// restarted, names the image and the recovery command, and refuses only on
// the daemon's own "No such image" evidence.

const sidecarRef = "culvert/clamav:1.5.4-culvert.2"

func startNoBuildRig(t *testing.T) *applyRig {
	t.Helper()
	return startApplyRigCfg(t, t.TempDir(), allowReleaseTrustForTest{}, func(c *config.Config) {
		c.ComposeNoBuild = true
		c.LocalOnlyImages = []string{sidecarRef}
	})
}

func TestNoBuildHost_UpgradeRefusesWhenLocalOnlyImageAbsent(t *testing.T) {
	rig := startNoBuildRig(t)
	defer rig.stop()
	rig.absentRefs = map[string]bool{sidecarRef: true}

	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" || op["failure_reason"] != "validation" {
		t.Fatalf("a missing local-only image must refuse the upgrade: state=%v reason=%v", op["state"], op["failure_reason"])
	}
	if rig.sawCommand("pull") || rig.sawCommand("up") || rig.sawCommand("tag") {
		t.Fatalf("nothing may be pulled, tagged or restarted while refusing:\n%s", rig.opLog(t, opID))
	}
	log := rig.opLog(t, opID)
	if !strings.Contains(log, "required local image absent: "+sidecarRef) || !strings.Contains(log, "culvert-clamav-image ensure") {
		t.Errorf("the refusal must name the image and the recovery command:\n%s", log)
	}
	if res, _ := op["result"].(map[string]interface{}); res != nil && res["rollback_attempted"] == true {
		t.Fatalf("a pre-mutation refusal must not roll back: %v", res)
	}
}

func TestNoBuildHost_RollbackRefusesWhenLocalOnlyImageAbsent(t *testing.T) {
	rig := startNoBuildRig(t)
	defer rig.stop()
	rig.absentRefs = map[string]bool{sidecarRef: true}

	op, _ := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" || rig.sawCommand("up") || rig.sawCommand("pull") {
		t.Fatalf("a rollback must refuse before pull/up while the sidecar image is absent: %+v", op)
	}
}

// Present image ⇒ the op runs, and every `up` it issues carries --no-build.
func TestNoBuildHost_UpgradeProceedsAndUpCarriesNoBuild(t *testing.T) {
	rig := startNoBuildRig(t)
	defer rig.stop()

	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "succeeded" {
		t.Fatalf("state: got %v want succeeded:\n%s", op["state"], rig.opLog(t, opID))
	}
	assertEveryUpIsNoBuild(t, rig)
}

// An inspect that fails WITHOUT the "No such image" signature (daemon,
// permission, timeout) is not evidence of absence and does not refuse: with
// --no-build the worst case is an explicit `up` failure, never new bytes.
func TestNoBuildHost_InspectFailureWithoutSignatureDoesNotRefuse(t *testing.T) {
	rig := startNoBuildRig(t)
	defer rig.stop()
	rig.inspectErrRefs = map[string]bool{sidecarRef: true}

	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "succeeded" {
		t.Fatalf("an inconclusive inspect must not refuse: state=%v\n%s", op["state"], rig.opLog(t, opID))
	}
	assertEveryUpIsNoBuild(t, rig)
}

// A host WITHOUT compose_no_build never probes the list and keeps the
// historical plain `up -d` (quick-start hosts must be byte-identical).
func TestDefaultHost_NoLocalImageProbeAndPlainUp(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.absentRefs = map[string]bool{sidecarRef: true} // would refuse if probed

	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "succeeded" {
		t.Fatalf("state: got %v want succeeded:\n%s", op["state"], rig.opLog(t, opID))
	}
	for _, argv := range rig.snapshot() {
		if inspectedRef(argv) == sidecarRef {
			t.Fatalf("a default host must not probe local-only images: %q", argv)
		}
		if argvHas(argv, "up") && argvHas(argv, "--no-build") {
			t.Fatalf("a default host must keep plain `up -d`: %q", argv)
		}
	}
}

func assertEveryUpIsNoBuild(t *testing.T, rig *applyRig) {
	t.Helper()
	ups := 0
	for _, argv := range rig.snapshot() {
		if !argvHas(argv, "compose") || !argvHas(argv, "up") {
			continue
		}
		ups++
		if argv[len(argv)-1] != "--no-build" {
			t.Errorf("every `compose up` on a no-build host must end in --no-build: %q", argv)
		}
	}
	if ups == 0 {
		t.Fatal("no `compose up` was issued; the assertion would be vacuous")
	}
}
