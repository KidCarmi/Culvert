package server

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"culvert-maint/internal/runtimehealth"
)

func withRuntimeHealth(t *testing.T) func(*applyRig) {
	return func(r *applyRig) {
		st, err := runtimehealth.Open(r.stateDir)
		if err != nil {
			t.Fatal(err)
		}
		r.runtimeHealth = st
	}
}

// A verified upgrade records the image it installed and the image it replaced.
func TestProvenance_VerifiedUpgradeRecordsInstalled(t *testing.T) {
	rig := startApplyRig(t, withRuntimeHealth(t))
	defer rig.stop()
	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "succeeded" {
		t.Fatalf("upgrade = %v", op["state"])
	}
	in, err := rig.runtimeHealth.ReadInstalled()
	if err != nil || in == nil {
		t.Fatalf("installed = %+v, %v", in, err)
	}
	if in.Ref != repo+"@sha256:"+digNew || in.Digest != "sha256:"+digNew || in.Kind != "upgrades.apply" || in.ReplacedImageID == "" || in.ReplacedImageID == in.ImageID {
		t.Fatalf("installed = %+v", in)
	}
	if in.ReplacedRef != repo+"@sha256:"+digOld {
		t.Fatalf("replaced_ref = %q, want the validated prior reference", in.ReplacedRef)
	}
}

// Nothing is written without the store, for an upgrade that fails its gate, or
// for one that was already current.
func TestProvenance_OnlyAVerifiedUpgradeWithTheStoreOn(t *testing.T) {
	t.Run("store off", func(t *testing.T) {
		rig := startApplyRig(t)
		defer rig.stop()
		op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
		if op["state"] != "succeeded" {
			t.Fatalf("upgrade = %v", op["state"])
		}
		if _, err := os.Stat(filepath.Join(rig.stateDir, "health")); !os.IsNotExist(err) {
			t.Fatalf("a health directory was created with the store off: %v", err)
		}
	})
	t.Run("gate fails", func(t *testing.T) {
		rig := startApplyRig(t, withRuntimeHealth(t))
		defer rig.stop()
		rig.healthFail.Store(true)
		op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
		if op["state"] == "succeeded" {
			t.Fatal("the upgrade succeeded with a failing gate")
		}
		if in, _ := rig.runtimeHealth.ReadInstalled(); in != nil {
			t.Fatalf("a failed upgrade recorded provenance: %+v", in)
		}
	})
	t.Run("already current", func(t *testing.T) {
		rig := startApplyRig(t, withRuntimeHealth(t))
		defer rig.stop()
		rig.digBefore = digNew
		op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
		if op["state"] != "succeeded" {
			t.Fatalf("upgrade = %v", op["state"])
		}
		if in, _ := rig.runtimeHealth.ReadInstalled(); in != nil {
			t.Fatalf("an already-current upgrade recorded provenance: %+v", in)
		}
	})
}

// The observer keeps the last two distinct gated images, and a bad reading
// never touches the history.
func TestObserver_KeepsTheGatedHistory(t *testing.T) {
	r := newObsRig(t)
	ctx := context.Background()
	if out := r.srv.observeOnce(ctx); out != obsRecordedAndGood {
		t.Fatalf("first = %s", out)
	}
	r.docker.next = runningOn(obsImgOther, obsCtr2, obsRef)
	r.docker.tag = obsImgOther
	if out := r.srv.observeOnce(ctx); out != obsRecordedAndGood {
		t.Fatalf("second = %s", out)
	}
	h, err := r.store.ReadGated()
	if err != nil || h == nil || len(h.Entries) != 2 || h.Entries[0].ImageID != obsImgOther || h.Entries[1].ImageID != obsImgGood {
		t.Fatalf("history = %+v, %v", h, err)
	}
	before, _ := os.ReadFile(filepath.Join(r.store.Dir(), "gated.json"))
	r.ready.Store(http.StatusServiceUnavailable)
	r.srv.observeOnce(ctx)
	if after, _ := os.ReadFile(filepath.Join(r.store.Dir(), "gated.json")); !bytes.Equal(after, before) {
		t.Fatal("an unhealthy reading changed the gated history")
	}
}
