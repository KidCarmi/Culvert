//go:build linux

package releasetrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/releaseproof"
)

type fixture struct {
	policy releaseproof.Policy
	key    ed25519.PrivateKey
	now    time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{policy: releaseproof.Policy{CatalogRepository: "test/repo", ProxyRepository: "test/repo", Ed25519Keys: map[string][]byte{"test": pub}}, key: key, now: time.Now().UTC().Truncate(time.Second)}
}

func (f fixture) proof(digit string, version int, generated time.Time) (string, *releaseproof.Evidence) {
	ref := "test/repo@sha256:" + strings.Repeat(digit, 64)
	m, _ := json.Marshal(map[string]any{"schema_version": 1, "release_id": "r" + digit, "version_id": "v1.0." + digit, "image": map[string]string{"repo": "test/repo", "list_digest": strings.Split(ref, "@")[1]}})
	h := sha256.Sum256(m)
	idx, _ := json.Marshal(map[string]any{"schema_version": 1, "catalog_version": version, "generated_at": generated.Format(time.RFC3339), "expires_at": generated.Add(time.Hour).Format(time.RFC3339), "releases": []map[string]string{{"release_id": "r" + digit, "version_id": "v1.0." + digit, "manifest_ref": "releases/r" + digit + ".json", "manifest_sha256": hex.EncodeToString(h[:])}}})
	sig, _ := json.Marshal(map[string]any{"schema_version": 1, "alg": "ed25519", "key_id": "test", "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(f.key, idx))})
	return ref, &releaseproof.Evidence{ReleaseID: "r" + digit, Index: idx, Manifest: m, Signature: sig}
}

func TestStoreSignedBaselineAndOfflineRecovery(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	s, err := New(dir, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return f.now }
	target, p := f.proof("b", 2, f.now)
	prior, pp := f.proof("a", 2, f.now)
	if err = s.Check(target, nil); err == nil {
		t.Fatal("proofless target accepted")
	}
	if err = s.Prepare(target, p, "", nil); err == nil {
		t.Fatal("missing observed baseline accepted")
	}
	if err = s.Prepare(target, p, prior, nil); err == nil {
		t.Fatal("unsigned prior accepted")
	}
	if err = s.Known(target); err == nil {
		t.Fatal("rejected operation cached target")
	}
	if err = s.Prepare(target, p, prior, pp); err != nil {
		t.Fatal(err)
	}
	s, err = New(dir, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return f.now.Add(24 * time.Hour) }
	if err = s.Known(prior); err != nil {
		t.Fatalf("durable expired offline recovery failed: %v", err)
	}
	if err = s.AdmitRollback(prior, nil); err != nil {
		t.Fatal(err)
	}
	other, op := f.proof("c", 2, f.now)
	if err = s.AdmitRollback(other, op); err == nil {
		t.Fatal("uncached expired evidence accepted")
	}
	if err = s.Check(target, p); err == nil {
		t.Fatal("cached evidence waived freshness for new apply")
	}
}

func TestStoreFloorAndTampering(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	s, err := New(dir, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return f.now }
	r, p := f.proof("a", 3, f.now)
	if err = s.AdmitRollback(r, p); err != nil {
		t.Fatal(err)
	}
	old, op := f.proof("b", 2, f.now)
	if err = s.Check(old, op); err == nil {
		t.Fatal("catalog rollback accepted")
	}
	old, op = f.proof("b", 3, f.now.Add(-time.Second))
	if err = s.Check(old, op); err == nil {
		t.Fatal("same-version older signature epoch accepted")
	}
	l, err := s.read()
	if err != nil {
		t.Fatal(err)
	}
	proof := l.Entries[r]
	proof.Manifest = append(proof.Manifest, ' ')
	l.Entries[r] = proof
	b, _ := json.Marshal(l)
	if err = os.WriteFile(s.path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = s.Known(r); err == nil {
		t.Fatal("tampered ledger accepted")
	}
	if _, err = New(dir, f.policy); err == nil {
		t.Fatal("corrupt startup silently reset trust floor")
	}
}

func TestStoreFailedDurabilityNeverAuthorizes(t *testing.T) {
	f := newFixture(t)
	s, err := New(t.TempDir(), f.policy)
	if err != nil {
		t.Fatal(err)
	}
	r, p := f.proof("a", 1, f.now)
	// Simulate rename succeeding but the parent-directory fsync failing.
	s.write = func(path string, b []byte) error {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return err
		}
		return errors.New("fsync failed")
	}
	if err = s.AdmitRollback(r, p); err == nil {
		t.Fatal("durability error ignored")
	}
	if err = s.Known(r); err == nil {
		t.Fatal("failed durability cached authorization")
	}
}

func TestPolicyFileRejectsCallerOwnedOrWritableAncestry(t *testing.T) {
	dir := t.TempDir()
	// Do not depend on TMPDIR being /tmp: root CI may use a private directory.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(p, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A writable ancestor must be rejected even when this test is root.
	if _, err := ReadPolicyFile(p); err == nil {
		t.Fatal("policy from mutable ancestor accepted")
	}
	if err := os.Symlink(p, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPolicyFile(filepath.Join(dir, "alias")); err == nil {
		t.Fatal("symlink policy accepted")
	}
}

func TestStateAncestryRejectsReplacementPaths(t *testing.T) {
	f := newFixture(t)
	t.Run("writable parent", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		state := filepath.Join(dir, "state")
		if err := os.Mkdir(state, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := New(state, f.policy); err == nil {
			t.Fatal("private final directory hid replaceable ancestor")
		}
	})
	t.Run("symlink parent", func(t *testing.T) {
		dir := t.TempDir()
		actual := filepath.Join(dir, "real")
		if err := os.Mkdir(actual, 0o700); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(dir, "alias")
		if err := os.Symlink(actual, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := New(alias, f.policy); err == nil {
			t.Fatal("symlink state ancestor accepted")
		}
	})
}
