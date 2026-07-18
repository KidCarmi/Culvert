package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catgroup"
	"github.com/KidCarmi/Culvert/internal/decryptprofile"
	"github.com/KidCarmi/Culvert/internal/filetxn"
)

func TestConfigApplyJournalPathUsesStartupRecoveryDirectory(t *testing.T) {
	oldDataDir, oldTxnDir, oldPolicy := dataDir, crossStoreTxnDir, policyStore
	dataDir = t.TempDir()
	crossStoreTxnDir = dataDir
	policyStore = &PolicyStore{path: filepath.Join(t.TempDir(), "custom-policy.json")}
	t.Cleanup(func() {
		dataDir, crossStoreTxnDir, policyStore = oldDataDir, oldTxnDir, oldPolicy
	})
	got, err := configApplyJournalPath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dataDir, "config_apply.txn")
	if got != want {
		t.Fatalf("journal path = %q, want startup-recovered path %q", got, want)
	}
}

func TestConfigSnapshotJournalUsesStartupRecoveryDirectory(t *testing.T) {
	oldDataDir, oldTxnDir, oldPolicy := dataDir, crossStoreTxnDir, policyStore
	dataDir = t.TempDir()
	crossStoreTxnDir = dataDir
	policyStore = &PolicyStore{path: filepath.Join(t.TempDir(), "custom-policy.json")}
	t.Cleanup(func() {
		dataDir, crossStoreTxnDir, policyStore = oldDataDir, oldTxnDir, oldPolicy
	})
	oldBegin := beginCrossStoreTxn
	var got string
	beginCrossStoreTxn = func(journalPath, _ string, _ []filetxn.Write, _ ...filetxn.Option) (*filetxn.Txn, error) {
		got = journalPath
		return nil, errors.New("injected begin failure")
	}
	t.Cleanup(func() { beginCrossStoreTxn = oldBegin })
	if err := commitPreparedConfigSnapshot(ConfigSnapshot{PolicyRules: []PolicyRule{{Priority: 1, Name: "new", Action: ActionAllow}}}, nil, nil); err == nil {
		t.Fatal("snapshot transaction unexpectedly succeeded")
	}
	want := filepath.Join(dataDir, "config_apply.txn")
	if got != want {
		t.Fatalf("snapshot journal path = %q, want startup-recovered path %q", got, want)
	}
}

func TestPreparedConfigFailureRestoresPolicyAndTaxonomy(t *testing.T) {
	dir := t.TempDir()
	oldPolicy, oldCategories, oldGroups, oldProfiles := policyStore, catStore, globalCategoryGroups, globalDecryptionProfiles
	policyStore = &PolicyStore{path: filepath.Join(dir, "policy.json")}
	catStore = newCategoryStore(nil)
	catStore.SetPathForTest(filepath.Join(dir, "categories.json"))
	globalCategoryGroups = catgroup.New()
	globalCategoryGroups.SetPathForTest(filepath.Join(dir, "groups.json"))
	globalDecryptionProfiles = decryptprofile.New()
	globalDecryptionProfiles.SetPathForTest(filepath.Join(dir, "profiles.json"))
	t.Cleanup(func() {
		policyStore, catStore, globalCategoryGroups, globalDecryptionProfiles = oldPolicy, oldCategories, oldGroups, oldProfiles
	})
	oldCat := []CategoryEntry{{Name: "old-category", Hosts: []string{"old.example"}}}
	oldGroup := []CategoryGroup{{ID: "old-group", Name: "old-group", Categories: []string{"old-category"}}}
	oldProfile := []DecryptionProfile{{ID: "old-profile", Name: "old-profile", CertVerification: "strict"}}
	if err := policyStore.ReplaceAllAndSave([]PolicyRule{{Name: "old-policy", Action: ActionAllow}}); err != nil {
		t.Fatal(err)
	}
	catStore.ReplaceAll(oldCat)
	catStore.Save()
	globalCategoryGroups.ReplaceAll(oldGroup)
	globalCategoryGroups.Save()
	globalDecryptionProfiles.ReplaceAll(oldProfile)
	globalDecryptionProfiles.Save()

	prepared, err := preparePolicyTaxonomyApply(
		[]PolicyRule{{Name: "new-policy", Action: ActionDrop, DestCategoryGroup: "new-group", DestCategoryGroupID: "new-group"}},
		[]CategoryEntry{{Name: "new-category", Hosts: []string{"new.example"}}},
		[]CategoryGroup{{ID: "new-group", Name: "new-group", Categories: []string{"new-category"}}},
		[]DecryptionProfile{{ID: "new-profile", Name: "new-profile", CertVerification: "strict"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("injected category boundary failure")
	err = commitPreparedConfig(prepared, filepath.Join(dir, "config_apply.txn"), filetxn.WithBoundaryHook(func(point string) error {
		if point == "after-write-2" {
			return failure
		}
		return nil
	}))
	if !errors.Is(err, failure) {
		t.Fatalf("commit error = %v", err)
	}
	if got := policyStore.List()[0].Name; got != "old-policy" {
		t.Fatalf("live policy = %q", got)
	}
	if got := catStore.All()[0].Name; got != "old-category" {
		t.Fatalf("live category = %q", got)
	}
	freshPolicy := &PolicyStore{}
	if err := freshPolicy.Load(policyStore.path); err != nil {
		t.Fatal(err)
	}
	if got := freshPolicy.List()[0].Name; got != "old-policy" {
		t.Fatalf("disk policy = %q", got)
	}
	freshCategories := newCategoryStore(nil)
	if err := freshCategories.Load(catStore.Path()); err != nil {
		t.Fatal(err)
	}
	if got := freshCategories.All()[0].Name; got != "old-category" {
		t.Fatalf("disk category = %q", got)
	}
}

func TestPreparedConfigCrashBeforeCommitRecoversAllOldOnRestart(t *testing.T) {
	dir := t.TempDir()
	oldPolicy, oldCategories, oldGroups, oldProfiles := policyStore, catStore, globalCategoryGroups, globalDecryptionProfiles
	policyStore = &PolicyStore{path: filepath.Join(dir, "policy.json")}
	catStore = newCategoryStore(nil)
	catStore.SetPathForTest(filepath.Join(dir, "categories.json"))
	globalCategoryGroups = catgroup.New()
	globalCategoryGroups.SetPathForTest(filepath.Join(dir, "groups.json"))
	globalDecryptionProfiles = decryptprofile.New()
	globalDecryptionProfiles.SetPathForTest(filepath.Join(dir, "profiles.json"))
	t.Cleanup(func() {
		policyStore, catStore, globalCategoryGroups, globalDecryptionProfiles = oldPolicy, oldCategories, oldGroups, oldProfiles
	})
	if err := policyStore.ReplaceAllAndSave([]PolicyRule{{Name: "old-policy", Action: ActionAllow}}); err != nil {
		t.Fatal(err)
	}
	catStore.ReplaceAll([]CategoryEntry{{Name: "old-category", Hosts: []string{"old.example"}}})
	catStore.Save()
	globalCategoryGroups.ReplaceAll([]CategoryGroup{{ID: "old-group", Name: "old-group", Categories: []string{"old-category"}}})
	globalCategoryGroups.Save()
	globalDecryptionProfiles.ReplaceAll([]DecryptionProfile{{ID: "old-profile", Name: "old-profile", CertVerification: "strict"}})
	globalDecryptionProfiles.Save()

	prepared, err := preparePolicyTaxonomyApply(
		[]PolicyRule{{Name: "new-policy", Action: ActionDrop}},
		[]CategoryEntry{{Name: "new-category", Hosts: []string{"new.example"}}},
		[]CategoryGroup{{ID: "new-group", Name: "new-group", Categories: []string{"new-category"}}},
		[]DecryptionProfile{{ID: "new-profile", Name: "new-profile", CertVerification: "strict"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "config_apply.txn")
	err = commitPreparedConfig(prepared, journal, filetxn.WithBoundaryHook(func(point string) error {
		if point == "after-write-2" {
			return filetxn.ErrSimulatedCrash
		}
		return nil
	}))
	if !errors.Is(err, filetxn.ErrSimulatedCrash) {
		t.Fatalf("commit error = %v, want simulated crash", err)
	}
	if _, err := os.Stat(journal); err != nil {
		t.Fatalf("uncommitted crash journal missing: %v", err)
	}
	if err := filetxn.Recover(journal); err != nil {
		t.Fatal(err)
	}
	freshPolicy := &PolicyStore{}
	if err := freshPolicy.Load(policyStore.path); err != nil {
		t.Fatal(err)
	}
	if got := freshPolicy.List()[0].Name; got != "old-policy" {
		t.Fatalf("recovered policy = %q", got)
	}
	freshCategories := newCategoryStore(nil)
	if err := freshCategories.Load(catStore.Path()); err != nil {
		t.Fatal(err)
	}
	if got := freshCategories.All()[0].Name; got != "old-category" {
		t.Fatalf("recovered category = %q", got)
	}
	if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovered journal still exists: %v", err)
	}
}

func TestPreparedConfigCrashAfterCommitKeepsAllNewOnRestart(t *testing.T) {
	dir := t.TempDir()
	oldPolicy, oldCategories, oldGroups, oldProfiles := policyStore, catStore, globalCategoryGroups, globalDecryptionProfiles
	policyStore = &PolicyStore{path: filepath.Join(dir, "policy.json")}
	catStore = newCategoryStore(nil)
	catStore.SetPathForTest(filepath.Join(dir, "categories.json"))
	globalCategoryGroups = catgroup.New()
	globalCategoryGroups.SetPathForTest(filepath.Join(dir, "groups.json"))
	globalDecryptionProfiles = decryptprofile.New()
	globalDecryptionProfiles.SetPathForTest(filepath.Join(dir, "profiles.json"))
	t.Cleanup(func() {
		policyStore, catStore, globalCategoryGroups, globalDecryptionProfiles = oldPolicy, oldCategories, oldGroups, oldProfiles
	})
	if err := policyStore.ReplaceAllAndSave([]PolicyRule{{Name: "old-policy", Action: ActionAllow}}); err != nil {
		t.Fatal(err)
	}
	catStore.ReplaceAll([]CategoryEntry{{Name: "old-category", Hosts: []string{"old.example"}}})
	catStore.Save()

	prepared, err := preparePolicyTaxonomyApply(
		[]PolicyRule{{Name: "new-policy", Action: ActionDrop}},
		[]CategoryEntry{{Name: "new-category", Hosts: []string{"new.example"}}}, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "config_apply.txn")
	err = commitPreparedConfig(prepared, journal, filetxn.WithBoundaryHook(func(point string) error {
		if point == "after-commit" {
			return filetxn.ErrSimulatedCrash
		}
		return nil
	}))
	if !errors.Is(err, filetxn.ErrSimulatedCrash) {
		t.Fatalf("commit error = %v, want simulated crash", err)
	}
	if got := policyStore.List()[0].Name; got != "old-policy" {
		t.Fatalf("memory published despite simulated process crash: %q", got)
	}
	if err := filetxn.Recover(journal); err != nil {
		t.Fatal(err)
	}
	policyData, err := os.ReadFile(policyStore.path)
	if err != nil {
		t.Fatal(err)
	}
	var rules []PolicyRule
	if err := json.Unmarshal(policyData, &rules); err != nil {
		t.Fatal(err)
	}
	if got := rules[0].Name; got != "new-policy" {
		t.Fatalf("committed policy after recovery = %q", got)
	}
	freshCategories := newCategoryStore(nil)
	if err := freshCategories.Load(catStore.Path()); err != nil {
		t.Fatal(err)
	}
	if got := freshCategories.All()[0].Name; got != "new-category" {
		t.Fatalf("committed category after recovery = %q", got)
	}
}

func TestPreparedPolicyReplacementDefersDiskAndMemoryPublication(t *testing.T) {
	ps := &PolicyStore{path: filepath.Join(t.TempDir(), "policy.json")}
	if err := ps.ReplaceAllAndSave([]PolicyRule{{Name: "old", Action: ActionAllow}}); err != nil {
		t.Fatal(err)
	}
	prepared, err := ps.prepareReplacement([]PolicyRule{{Name: "new", Action: ActionDrop}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Abort()
	if got := ps.List()[0].Name; got != "old" {
		t.Fatalf("live policy changed during preparation: %q", got)
	}
	fresh := &PolicyStore{}
	if err := fresh.Load(ps.path); err != nil {
		t.Fatal(err)
	}
	if got := fresh.List()[0].Name; got != "old" {
		t.Fatalf("disk policy changed during preparation: %q", got)
	}

	tx, err := filetxn.Begin(filepath.Join(filepath.Dir(ps.path), "config_apply.txn"), "config", prepared.Writes())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := ps.List()[0].Name; got != "old" {
		t.Fatalf("live policy changed before publish: %q", got)
	}
	prepared.Publish()
	if err := tx.Finish(); err != nil {
		t.Fatal(err)
	}
	if got := ps.List()[0].Name; got != "new" {
		t.Fatalf("live policy after publish = %q", got)
	}
	fresh = &PolicyStore{}
	if err := fresh.Load(ps.path); err != nil {
		t.Fatal(err)
	}
	if got := fresh.List()[0].Name; got != "new" {
		t.Fatalf("disk policy after commit = %q", got)
	}
}
