//go:build linux

package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/releaseproof"

	"culvert-maint/internal/releasetrust"
)

func releaseFixture(t *testing.T) (store *releasetrust.Store, target, prior *releaseproof.Evidence) {
	return versionedReleaseFixture(t, "new", "old", "")
}

func versionedReleaseFixture(t *testing.T, targetVersion, priorVersion, floor string) (store *releasetrust.Store, target, prior *releaseproof.Evidence) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := releasetrust.New(t.TempDir(), releaseproof.Policy{CatalogRepository: repo, ProxyRepository: repo, Ed25519Keys: map[string][]byte{"test": pub}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	proof := func(id, digest, versionID, minUpgrade string) *releaseproof.Evidence {
		m, _ := json.Marshal(map[string]any{"schema_version": 1, "release_id": id, "version_id": versionID, "min_upgrade_from": minUpgrade, "image": map[string]string{"repo": repo, "list_digest": "sha256:" + digest}})
		h := sha256.Sum256(m)
		idx, _ := json.Marshal(map[string]any{"schema_version": 1, "catalog_version": 1, "generated_at": now.Add(-time.Minute).UTC().Format(time.RFC3339), "expires_at": now.Add(time.Hour).UTC().Format(time.RFC3339), "releases": []map[string]string{{"release_id": id, "version_id": versionID, "manifest_ref": "releases/" + id + ".json", "manifest_sha256": hex.EncodeToString(h[:])}}})
		sig, _ := json.Marshal(map[string]any{"schema_version": 1, "alg": "ed25519", "key_id": "test", "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(key, idx))})
		return &releaseproof.Evidence{ReleaseID: id, Index: idx, Signature: sig, Manifest: m}
	}
	return s, proof("new", digNew, targetVersion, floor), proof("old", digOld, priorVersion, "")
}

func TestReleaseTrustSpaceRefusalThenRetryWithoutRestart(t *testing.T) {
	s, p, pp := releaseFixture(t)
	rig := startApplyRigWithTrustAt(t, t.TempDir(), s)
	defer rig.stop()
	rig.targetSize = 100 << 20
	rig.freeBytes.Store(200 << 20)
	body := map[string]any{"image_ref": targetRef, "release_proof": p, "prior_release_proof": pp}
	op, id := rig.acceptAndWait(t, body)
	if op["state"] != "failed" || !strings.Contains(rig.opLog(t, id), "preflight_space: REFUSED") {
		t.Fatalf("expected ordinary space refusal: %v", op)
	}
	if err := s.Known(targetRef); err == nil {
		t.Fatal("space refusal persisted authorization before checking capacity")
	}
	if rig.sawCommand("pull") || rig.sawCommand("tag") || rig.sawCommand("up") {
		t.Fatal("space refusal mutated images")
	}
	// Manager.Finish publishes the terminal state before journal/audit cleanup.
	// The host flock is released when that orchestrator goroutine exits, and
	// goOp decrements opWG only after the release. Wait for that actual barrier
	// rather than treating a terminal status response as admission readiness.
	drained := make(chan struct{})
	go func() {
		rig.srv.opWG.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("terminal operation did not finish host-lock cleanup")
	}
	rig.freeBytes.Store(2 << 30)
	op, _ = rig.acceptAndWait(t, body)
	if op["state"] != "succeeded" {
		t.Fatalf("retry on same agent/store failed after freeing capacity: %v", op)
	}
	if err := s.Known(priorRef); err != nil {
		t.Fatalf("retry did not durably authorize recovery baseline: %v", err)
	}
}

func TestReleaseTrustUnsupportedJumpCannotMutate(t *testing.T) {
	s, p, pp := versionedReleaseFixture(t, "1.0.260", "1.0.249", "1.0.250")
	rig := startApplyRigWithTrustAt(t, t.TempDir(), s)
	defer rig.stop()
	t.Setenv("CULVERT_BACKUP_PASSPHRASE", "test-only-passphrase")
	op, id := rig.acceptAndWait(t, map[string]any{"image_ref": targetRef, "release_proof": p, "prior_release_proof": pp, "pre_backup": true, "passphrase_ref": "env:CULVERT_BACKUP_PASSPHRASE"})
	if op["state"] != "failed" || !strings.Contains(rig.opLog(t, id), "min_upgrade_from") {
		t.Fatalf("unsupported transition not refused: %v", op)
	}
	for _, cmd := range []string{"backup", "pull", "tag", "up"} {
		if rig.sawCommand(cmd) {
			t.Fatalf("%s ran for unsupported signed transition", cmd)
		}
	}
	if err := s.Known(targetRef); err == nil {
		t.Fatal("unsupported target persisted")
	}
}

func TestReleaseTrustRollbackCannotBypassSignedMinimum(t *testing.T) {
	for _, tc := range []struct {
		name, baseline           string
		cached, missing, allowed bool
	}{
		{name: "below minimum", baseline: "1.0.249"},
		{name: "at minimum", baseline: "1.0.250", allowed: true},
		{name: "cached target below minimum", baseline: "1.0.249", cached: true},
		{name: "no observed baseline", baseline: "1.0.250", missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, p, pp := versionedReleaseFixture(t, "1.0.260", tc.baseline, "1.0.250")
			if tc.cached {
				if err := s.Prepare(targetRef, p, targetRef, p); err != nil {
					t.Fatal(err)
				}
			}
			rig := startApplyRigWithTrustAt(t, t.TempDir(), s)
			defer rig.stop()
			rig.noPriorDigest = tc.missing
			body := map[string]any{"mode": "image", "image_ref": targetRef, "prior_release_proof": pp}
			if !tc.cached {
				body["release_proof"] = p
			}
			op, _ := rig.rollbackAndWait(t, body)
			checkRollbackMinimumOutcome(t, rig, s, op, tc.allowed, tc.cached)
		})
	}
}

func checkRollbackMinimumOutcome(t *testing.T, rig *applyRig, s *releasetrust.Store, op map[string]interface{}, allowed, cached bool) {
	t.Helper()
	if allowed {
		if op["state"] != "succeeded" {
			t.Fatalf("supported standalone transition failed: %v", op)
		}
		return
	}
	if op["state"] != "failed" {
		t.Fatalf("unsupported standalone transition accepted: %v", op)
	}
	for _, cmd := range []string{"pull", "tag", "up"} {
		if rig.sawCommand(cmd) {
			t.Fatalf("%s ran for refused standalone transition", cmd)
		}
	}
	if !cached {
		if err := s.Known(targetRef); err == nil {
			t.Fatal("failed standalone transition primed target recovery membership")
		}
	}
}

func TestReleaseTrustAgentRejectsBeforeCommands(t *testing.T) {
	s, p, _ := releaseFixture(t)
	rig := startApplyRigWithTrustAt(t, t.TempDir(), s)
	defer rig.stop()
	for _, body := range []any{
		map[string]any{"image_ref": targetRef},
		map[string]any{"image_ref": priorRef, "release_proof": p},
	} {
		code, _ := rig.post(t, body)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d, want403", code)
		}
		if len(rig.snapshot()) != 0 {
			t.Fatal("runner command occurred before proof rejection")
		}
	}
}

//nolint:gocognit,nestif // paired integration scenarios assert outcomes and absence of every mutation
func TestReleaseTrustAgentRequiresObservedSignedBaseline(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "signed"}[valid], func(t *testing.T) {
			s, p, pp := releaseFixture(t)
			rig := startApplyRigWithTrustAt(t, t.TempDir(), s)
			defer rig.stop()
			body := map[string]any{"image_ref": targetRef, "release_proof": p}
			if valid {
				body["prior_release_proof"] = pp
			}
			code, b := rig.post(t, body)
			if code != http.StatusAccepted {
				t.Fatalf("status=%d body=%s", code, b)
			}
			var accepted map[string]any
			if err := json.Unmarshal(b, &accepted); err != nil {
				t.Fatal(err)
			}
			id, _ := accepted["op_id"].(string)
			if id == "" {
				t.Fatalf("missing operation ID: %s", b)
			}
			result := rig.waitOp(t, id)
			if valid {
				if result["state"] != "succeeded" {
					t.Fatalf("signed apply failed: %v", result)
				}
				if err := s.Known(priorRef); err != nil {
					t.Fatal(err)
				}
			} else {
				if result["state"] != "failed" {
					t.Fatalf("unsigned baseline state: %v", result)
				}
				for _, cmd := range []string{"pull", "tag", "up"} {
					if rig.sawCommand(cmd) {
						t.Fatalf("%s occurred without signed baseline", cmd)
					}
				}
			}
		})
	}
}
