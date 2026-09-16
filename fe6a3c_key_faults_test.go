package main

// FE-6A.2 round 3 (Blocker 2) — the non-sync faults of the candidate key's
// durable publication. These gates need the publication seam introduced
// WITH the primitive (fileutil.SetPublishIOHookForTest), so they could not
// be part of the RED commit on eb90ebc5 (whose mint was a bare
// os.WriteFile with no seam); each was verified failing by disabling the
// corresponding check in fileutil.PublishExclusive.
//
//	KF1  a write fault, a SHORT write, and a link fault during publication
//	     each leave the store DEGRADED — no intent can be recorded, no key
//	     of unknown content is ever published, no residue is left
//	KF2  a directory-fsync fault AFTER the link still fails closed for this
//	     boot while the complete key stays for the next one
//	KF3  a loser of the exclusive publication reads the winner's bytes and
//	     leaves no temp residue

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

func fe6a3cDirResidue(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestFE6A3C_KF1_PublicationIOFaultsFailClosed(t *testing.T) {
	for _, step := range []string{"write", "short_write", "link"} {
		t.Run(step, func(t *testing.T) {
			regPath, keyPath, dir := fe6a3cKeyPaths(t)
			injected := errors.New("injected " + step + " fault")
			restore := fileutil.SetPublishIOHookForTest(func(s string) error {
				if s == step {
					return injected
				}
				return nil
			})
			defer restore()
			store := newIdPOperationStore(regPath)
			if store.Degraded() == nil {
				t.Fatalf("a %s fault during key publication left the ledger HEALTHY", step)
			}
			if _, _, err := store.Begin(idpOperation{OperationID: testOperationID(), Action: "idp.create", SpecDigest: "d", CandidateCommitment: "c"}); !errors.Is(err, errIdPOperationLedgerDegraded) {
				t.Fatalf("Begin after a %s fault = %v, want %v", step, err, errIdPOperationLedgerDegraded)
			}
			if _, err := os.Stat(keyPath); err == nil {
				t.Fatalf("a key was published despite the %s fault", step)
			}
			if res := fe6a3cDirResidue(t, dir); len(res) != 0 {
				t.Fatalf("publication residue after a %s fault: %v", step, res)
			}
		})
	}
}

func TestFE6A3C_KF2_DirSyncFaultAfterLinkFailsClosedButKeepsTheKey(t *testing.T) {
	regPath, keyPath, dir := fe6a3cKeyPaths(t)
	restore := fileutil.SetSyncHookForTest(func(kind, path string) error {
		if kind == "dir" && path == dir {
			return errors.New("injected dir fsync fault")
		}
		return nil
	})
	store := newIdPOperationStore(regPath)
	restore()
	if store.Degraded() == nil {
		t.Fatal("a directory-fsync fault after the link left the ledger HEALTHY (the name's durability is unknown)")
	}
	// The complete key is left for the next boot to find (the link happened
	// before the fault); a restart with a working directory sync loads it.
	if b, err := os.ReadFile(keyPath); err != nil || len(b) != idpCandidateKeyLen {
		t.Fatalf("published key after the dir fault: %v (%d bytes)", err, len(b))
	}
	if d := newIdPOperationStore(regPath).Degraded(); d != nil {
		t.Fatalf("the next boot must load the published key: %+v", d)
	}
	if res := fe6a3cDirResidue(t, dir); len(res) != 0 {
		t.Fatalf("residue: %v", res)
	}
}

func TestFE6A3C_KF3_ExclusiveLoserReadsTheWinner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".idp_candidate_key")
	winner := []byte(strings.Repeat("w", idpCandidateKeyLen))
	if created, err := fileutil.PublishExclusive(path, winner, 0o600); err != nil || !created {
		t.Fatalf("first publication: created=%v err=%v", created, err)
	}
	loser := []byte(strings.Repeat("l", idpCandidateKeyLen))
	created, err := fileutil.PublishExclusive(path, loser, 0o600)
	if err != nil || created {
		t.Fatalf("second publication: created=%v err=%v, want created=false, nil", created, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(winner) {
		t.Fatalf("published bytes = %q (%v), want the winner's", got, err)
	}
	key, err := idpLoadOrMintCandidateKey(path)
	if err != nil || string(key) != string(winner) {
		t.Fatalf("loader = %q (%v), want the winner's key", key, err)
	}
	if res := fe6a3cDirResidue(t, dir); len(res) != 0 {
		t.Fatalf("residue: %v", res)
	}
}
