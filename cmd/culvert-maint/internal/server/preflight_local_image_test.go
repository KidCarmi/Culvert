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
		c.LocalOnlyImages = []config.LocalImage{{Ref: sidecarRef}}
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

// A PRESENCE-ONLY entry (no recorded ID): an inspect that fails WITHOUT the
// "No such image" signature (daemon, permission, timeout) is not evidence of
// absence and does not refuse — with --no-build the worst case is an explicit
// `up` failure, never new bytes. An ID-bound entry refuses instead
// (TestNoBuildHost_IDBoundRefusesWhenInspectFails).
func TestNoBuildHost_InspectFailureWithoutSignatureDoesNotRefuse(t *testing.T) {
	rig := startNoBuildRig(t)
	defer rig.stop()
	rig.inspectErrRefs = map[string]string{sidecarRef: inspectErrPermission}

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

// An entry that records the image ID binds the tag to those bytes: presence is
// not approval (the same rule ASTRA 5978949299 applied to the installer).
func startNoBuildRigWithID(t *testing.T) *applyRig {
	t.Helper()
	return startApplyRigCfg(t, t.TempDir(), allowReleaseTrustForTest{}, func(c *config.Config) {
		c.ComposeNoBuild = true
		c.LocalOnlyImages = []config.LocalImage{{Ref: sidecarRef, ID: sidecarRecordedID}}
	})
}

const (
	sidecarRecordedID = "sha256:" + "abababababababababababababababababababababababababababababababab"
	sidecarOtherID    = "sha256:" + "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
)

func TestNoBuildHost_RefusesWhenTheTagNamesOtherBytes(t *testing.T) {
	for name, reported := range map[string]string{"different image": sidecarOtherID, "unreadable answer": "unreadable"} {
		t.Run(name+"/apply", func(t *testing.T) {
			rig := startNoBuildRigWithID(t)
			defer rig.stop()
			rig.localRefIDs = map[string]string{sidecarRef: reported}
			op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
			if op["state"] != "failed" || op["failure_reason"] != "validation" {
				t.Fatalf("a tag naming other bytes must refuse: state=%v reason=%v", op["state"], op["failure_reason"])
			}
			if rig.sawCommand("pull") || rig.sawCommand("up") || rig.sawCommand("tag") {
				t.Fatalf("nothing may move while refusing:\n%s", rig.opLog(t, opID))
			}
			if !strings.Contains(rig.opLog(t, opID), "does not name the recorded bytes: "+sidecarRef) {
				t.Fatalf("the refusal must name the image:\n%s", rig.opLog(t, opID))
			}
		})
		t.Run(name+"/rollback", func(t *testing.T) {
			rig := startNoBuildRigWithID(t)
			defer rig.stop()
			rig.localRefIDs = map[string]string{sidecarRef: reported}
			op, _ := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": repo + "@sha256:" + digNew})
			if op["state"] != "failed" || rig.sawCommand("up") || rig.sawCommand("pull") {
				t.Fatalf("a rollback must refuse before pull/up: %+v", op)
			}
		})
	}
}

// CONTROL: the recorded bytes under the tag let the op run, still --no-build.
func TestNoBuildHost_RecordedBytesProceed(t *testing.T) {
	rig := startNoBuildRigWithID(t)
	defer rig.stop()
	rig.localRefIDs = map[string]string{sidecarRef: sidecarRecordedID}
	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "succeeded" {
		t.Fatalf("state %v:\n%s", op["state"], rig.opLog(t, opID))
	}
	assertEveryUpIsNoBuild(t, rig)
}

// Failed inspects that carry no "No such image" signature. The text is what
// the docker CLI prints for each case.
const (
	inspectErrPermission = "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock"
	inspectErrDaemonDown = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"
	inspectErrDeadline   = "context deadline exceeded"
)

// An ID-bound entry demands that the tag resolve to the recorded bytes. When
// the inspect FAILS without the absence signature, that identity was not
// established, so apply and image rollback refuse before anything moves
// (ASTRA 5978949299, 08:15: the error branch used to `continue` past the ID
// check and the op went ahead on unverified bytes).
func TestNoBuildHost_IDBoundRefusesWhenInspectFails(t *testing.T) {
	for name, stderr := range map[string]string{
		"permission denied":  inspectErrPermission,
		"daemon unreachable": inspectErrDaemonDown,
		"deadline":           inspectErrDeadline,
		"no stderr":          "",
	} {
		t.Run(name+"/apply", func(t *testing.T) {
			rig := startNoBuildRigWithID(t)
			defer rig.stop()
			rig.inspectErrRefs = map[string]string{sidecarRef: stderr}
			op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
			if op["state"] != "failed" || op["failure_reason"] != "validation" {
				t.Fatalf("an unverifiable ID-bound image must refuse: state=%v reason=%v\n%s", op["state"], op["failure_reason"], rig.opLog(t, opID))
			}
			if rig.sawCommand("pull") || rig.sawCommand("up") || rig.sawCommand("tag") {
				t.Fatalf("nothing may move while refusing:\n%s", rig.opLog(t, opID))
			}
			log := rig.opLog(t, opID)
			if !strings.Contains(log, "could not verify which image the local tag names: "+sidecarRef) {
				t.Fatalf("the refusal must name the image and say it could not be verified:\n%s", log)
			}
			if strings.Contains(log, "does not name the recorded bytes") || strings.Contains(log, "required local image absent") {
				t.Fatalf("an unanswered inspect is neither proof of other bytes nor of absence:\n%s", log)
			}
		})
		t.Run(name+"/rollback", func(t *testing.T) {
			rig := startNoBuildRigWithID(t)
			defer rig.stop()
			rig.inspectErrRefs = map[string]string{sidecarRef: stderr}
			op, _ := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": repo + "@sha256:" + digNew})
			if op["state"] != "failed" || rig.sawCommand("up") || rig.sawCommand("pull") || rig.sawCommand("tag") {
				t.Fatalf("a rollback must refuse before pull/tag/up: %+v", op)
			}
		})
	}
}
