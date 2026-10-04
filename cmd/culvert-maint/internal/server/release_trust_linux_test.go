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
	proof := func(id, digest string) *releaseproof.Evidence {
		m, _ := json.Marshal(map[string]any{"schema_version": 1, "release_id": id, "version_id": id, "image": map[string]string{"repo": repo, "list_digest": "sha256:" + digest}})
		h := sha256.Sum256(m)
		idx, _ := json.Marshal(map[string]any{"schema_version": 1, "catalog_version": 1, "generated_at": now.Add(-time.Minute).UTC().Format(time.RFC3339), "expires_at": now.Add(time.Hour).UTC().Format(time.RFC3339), "releases": []map[string]string{{"release_id": id, "version_id": id, "manifest_ref": "releases/" + id + ".json", "manifest_sha256": hex.EncodeToString(h[:])}}})
		sig, _ := json.Marshal(map[string]any{"schema_version": 1, "alg": "ed25519", "key_id": "test", "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(key, idx))})
		return &releaseproof.Evidence{ReleaseID: id, Index: idx, Signature: sig, Manifest: m}
	}
	return s, proof("new", digNew), proof("old", digOld)
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
	rig.freeBytes.Store(2 << 30)
	op, _ = rig.acceptAndWait(t, body)
	if op["state"] != "succeeded" {
		t.Fatalf("retry on same agent/store failed after freeing capacity: %v", op)
	}
	if err := s.Known(priorRef); err != nil {
		t.Fatalf("retry did not durably authorize recovery baseline: %v", err)
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
