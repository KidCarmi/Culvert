package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/KidCarmi/Culvert/internal/catgroup"
	"github.com/KidCarmi/Culvert/internal/decryptprofile"
	"github.com/KidCarmi/Culvert/internal/filetxn"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// configApplyMu orders policy-plus-dependency generations across rollback,
// import, DP, and HA apply paths.
var configApplyMu sync.Mutex

// crossStoreTxnDir is wired once by main before recovery or store loading.
// Direct unit tests that do not execute main leave it empty and use the first
// participating store directory as an isolated fallback.
var crossStoreTxnDir string

// beginCrossStoreTxn is a deterministic crash-boundary seam for transaction
// recovery tests. Production uses filetxn.Begin directly.
var beginCrossStoreTxn = filetxn.Begin

type preparedConfigApply struct {
	policy     *preparedPolicyReplacement
	categories []urlcat.Entry
	groups     []catgroup.Group
	profiles   []decryptprofile.Profile
	writes     []filetxn.Write
	done       bool
}

func preparePolicyTaxonomyApply(rules []PolicyRule, categories []urlcat.Entry, groups []catgroup.Group, profiles []decryptprofile.Profile) (*preparedConfigApply, error) {
	preparedPolicy, err := policyStore.prepareReplacement(rules, nil)
	if err != nil {
		return nil, err
	}
	prepared := &preparedConfigApply{policy: preparedPolicy, writes: preparedPolicy.Writes()}
	fail := func(err error) (*preparedConfigApply, error) {
		preparedPolicy.Abort()
		return nil, err
	}
	if categories != nil {
		candidate := urlcat.New(nil)
		candidate.ReplaceAll(categories)
		prepared.categories = candidate.All()
		if path := catStore.Path(); path != "" {
			data, err := json.MarshalIndent(prepared.categories, "", "  ")
			if err != nil {
				return fail(fmt.Errorf("marshal URL categories: %w", err))
			}
			prepared.writes = append(prepared.writes, filetxn.Write{Path: path, Data: data, Mode: 0o600})
		}
	}
	if groups != nil {
		candidate := catgroup.New()
		candidate.ReplaceAll(groups)
		prepared.groups = candidate.List()
		if path := globalCategoryGroups.Path(); path != "" {
			data, err := json.MarshalIndent(prepared.groups, "", "  ")
			if err != nil {
				return fail(fmt.Errorf("marshal category groups: %w", err))
			}
			prepared.writes = append(prepared.writes, filetxn.Write{Path: path, Data: data, Mode: 0o600})
		}
	}
	if profiles != nil {
		candidate := decryptprofile.New()
		candidate.ReplaceAll(profiles)
		prepared.profiles = candidate.List()
		if len(prepared.profiles) != len(profiles) {
			return fail(errors.New("invalid or duplicate decryption profile in config generation"))
		}
		if path := globalDecryptionProfiles.Path(); path != "" {
			data, err := json.MarshalIndent(prepared.profiles, "", "  ")
			if err != nil {
				return fail(fmt.Errorf("marshal decryption profiles: %w", err))
			}
			prepared.writes = append(prepared.writes, filetxn.Write{Path: path, Data: data, Mode: 0o600})
		}
	}
	return prepared, nil
}

func (p *preparedConfigApply) publishDependencies() {
	if p.done {
		return
	}
	if p.categories != nil {
		catStore.ReplaceAll(p.categories)
	}
	if p.groups != nil {
		globalCategoryGroups.ReplaceAll(p.groups)
	}
	if p.profiles != nil {
		globalDecryptionProfiles.ReplaceAll(p.profiles)
	}
}

func (p *preparedConfigApply) publishPolicy() {
	if p.done {
		return
	}
	p.policy.Publish()
	p.done = true
}

func (p *preparedConfigApply) publish() {
	p.publishDependencies()
	p.publishPolicy()
}

func (p *preparedConfigApply) abort() {
	if p == nil || p.done {
		return
	}
	p.policy.Abort()
	p.done = true
}

func commitPreparedConfig(p *preparedConfigApply, journalPath string, opts ...filetxn.Option) error {
	if len(p.writes) == 0 {
		p.publish()
		return nil
	}
	tx, err := beginCrossStoreTxn(journalPath, "config-apply", p.writes, opts...)
	if err != nil {
		p.abort()
		return err
	}
	if err := tx.Apply(); err != nil {
		p.abort()
		return err
	}
	if err := tx.Commit(); err != nil {
		p.abort()
		return err
	}
	p.publish()
	if err := tx.Finish(); err != nil && logger != nil {
		logger.Printf("Config apply: committed transaction cleanup deferred: %v", err)
	}
	return nil
}

func configApplyJournalPath() (string, error) {
	if crossStoreTxnDir != "" {
		return filepath.Join(crossStoreTxnDir, "config_apply.txn"), nil
	}
	for _, path := range []string{policyStore.path, catStore.Path(), globalCategoryGroups.Path(), globalDecryptionProfiles.Path()} {
		if path != "" {
			return filepath.Join(filepath.Dir(path), "config_apply.txn"), nil
		}
	}
	return "", errors.New("config apply has no persistence path")
}

// recoverCrossStoreTransactions runs before affected stores load or background
// replication starts. A malformed or unverifiable generation is fatal.
func recoverCrossStoreTransactions(dir string) error {
	for _, name := range []string{"ha_bundle.txn", "config_apply.txn", "dp_config_apply.txn"} {
		if err := filetxn.Recover(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("recover %s: %w", name, err)
		}
	}
	return nil
}
