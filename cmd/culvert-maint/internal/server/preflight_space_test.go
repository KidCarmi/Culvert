package server

import (
	"strings"
	"testing"
)

func TestTargetCompressedBytes(t *testing.T) {
	d1 := "sha256:" + strings.Repeat("1", 64)
	d2 := "sha256:" + strings.Repeat("2", 64)
	single := `{"Descriptor":{"digest":"` + d1 + `"},"OCIManifest":{"config":{"size":10},"layers":[{"size":100},{"size":200}]}}`
	if got := targetCompressedBytes([]byte(single), d1); got != 310 {
		t.Errorf("single: got %d want 310", got)
	}
	multi := `[{"Descriptor":{"digest":"` + d1 + `","platform":{"os":"linux","architecture":"arm64"}},"OCIManifest":{"config":{"size":1},"layers":[{"size":9}]}},` +
		`{"Descriptor":{"digest":"` + d2 + `","platform":{"os":"linux","architecture":"amd64"}},"SchemaV2Manifest":{"config":{"size":5},"layers":[{"size":45}]}}]`
	if got := targetCompressedBytes([]byte(multi), d2); got != 50 {
		t.Errorf("multi, pinned entry: got %d want 50", got)
	}
	if got := targetCompressedBytes([]byte(`{"Descriptor":{"digest":"`+d1+`"}}`), d1); got != 0 {
		t.Errorf("no embedded manifest must be unknown (0), got %d", got)
	}
	if got := targetCompressedBytes([]byte("not json"), d1); got != 0 {
		t.Errorf("unparseable must be unknown (0), got %d", got)
	}
}

// A full root disk crashed the RUNNING proxy on the Deep gate runner and
// Docker could not restart it. The agent must not start a pull that cannot
// fit: refused before pull/tag/up, no rollback.
func TestUpgradeApply_RefusesWhenTheTargetCannotFit(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.targetSize = 100 << 20     // 100 MiB compressed ⇒ ~556 MiB needed
	rig.freeBytes.Store(200 << 20) // 200 MiB free

	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" || op["failure_reason"] != "validation" {
		t.Fatalf("a target that cannot fit must be refused: state=%v reason=%v", op["state"], op["failure_reason"])
	}
	if rig.sawCommand("pull") || rig.sawCommand("up") || rig.sawCommand("tag") {
		t.Fatalf("nothing may be pulled, tagged or restarted:\n%s", rig.opLog(t, opID))
	}
	if log := rig.opLog(t, opID); !strings.Contains(log, "preflight_space: REFUSED") || !strings.Contains(log, "200 MiB free") {
		t.Errorf("op-log must state free vs needed:\n%s", log)
	}
}

// CONTROLS: enough space proceeds; an unknown target size proceeds (the
// check never guesses a refusal).
func TestUpgradeApply_SpaceCheckPassesOrStepsAside(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()
	rig.targetSize = 100 << 20
	rig.freeBytes.Store(2 << 30)
	if op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew}); op["state"] != "succeeded" {
		t.Fatalf("enough space must proceed: %+v", op)
	}
	rig2 := startApplyRig(t)
	defer rig2.stop()
	rig2.freeBytes.Store(1 << 20) // 1 MiB free, but the size is unknown
	op, opID := rig2.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "succeeded" || !strings.Contains(rig2.opLog(t, opID), "target size unknown") {
		t.Fatalf("an unknown target size must proceed and say so: %+v", op)
	}
}
