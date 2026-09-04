package main

// upstream_v2.go — Upstream v2 wiring in package main (2F-C, contract
// C4/C10): the node-local credential key, the boot-time load of the v2
// document, the durable-or-nothing migration of the legacy credential-
// bearing key, and the bounded migration/degradation state surfaced on
// GET /api/upstream. All engine logic lives in internal/upstream.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/upstream"
)

// upstreamState is the bounded, node-local truth about the v2 store surfaced
// to operators: migration outcome, key availability, and a validation
// degradation (a reason enum and counts only — never a URL, username or
// credential).
type upstreamState struct {
	Migration upstreamMigrationState `json:"migration"`
	Key       upstreamKeyState       `json:"key"`
	Degraded  *upstreamDegraded      `json:"degraded,omitempty"`
}

type upstreamMigrationState struct {
	State    string `json:"state"` // none | ok | degraded
	Reason   string `json:"reason,omitempty"`
	At       string `json:"at,omitempty"`
	Migrated int    `json:"migrated,omitempty"`
	Sealed   int    `json:"sealed,omitempty"`
	// YAMLOwned counts legacy entries dropped because a YAML-owned entry
	// already carries the same canonical authority.
	YAMLOwned int `json:"yamlOwned,omitempty"`
}

type upstreamKeyState struct {
	State string `json:"state"` // present | missing | unreadable | unused
	KeyID string `json:"keyId,omitempty"`
}

type upstreamDegraded struct {
	Reason string `json:"reason"` // duplicate_authority | invalid_entry | key_unusable
	Count  int    `json:"count,omitempty"`
}

var (
	upstreamStateMu  sync.RWMutex
	upstreamStateCur = upstreamState{Migration: upstreamMigrationState{State: "none"}, Key: upstreamKeyState{State: "unused"}}
)

func setUpstreamState(mut func(st *upstreamState)) {
	upstreamStateMu.Lock()
	mut(&upstreamStateCur)
	upstreamStateMu.Unlock()
}

func getUpstreamState() upstreamState {
	upstreamStateMu.RLock()
	defer upstreamStateMu.RUnlock()
	return upstreamStateCur
}

// upstreamKeyDir is where .upstream_cred_key lives: beside the admin
// settings file (the data dir).
func upstreamKeyDir() string {
	if adminSettingsPath != "" {
		return filepath.Dir(adminSettingsPath)
	}
	return dataDir
}

// upstreamOpenKey loads the node-local key on the READ path (never mints).
// It records the bounded key state and installs the key (or its absence)
// on the pool.
func upstreamOpenKey() *upstream.Keyring {
	k, err := upstream.OpenKey(upstreamKeyDir(), false)
	switch {
	case err == nil:
		upstreamPool.SetKey(k, "")
		setUpstreamState(func(st *upstreamState) { st.Key = upstreamKeyState{State: "present", KeyID: k.KeyID()} })
		return k
	case errors.Is(err, upstream.ErrKeyMissing):
		upstreamPool.SetKey(nil, "key_missing")
		setUpstreamState(func(st *upstreamState) { st.Key = upstreamKeyState{State: "missing"} })
	default:
		upstreamPool.SetKey(nil, "key_unreadable")
		setUpstreamState(func(st *upstreamState) { st.Key = upstreamKeyState{State: "unreadable"} })
		logger.Printf("Upstream: credential key unreadable; sealed credentials are UNUSABLE until it is restored")
	}
	return nil
}

// upstreamEnsureKey returns the key, minting one ONLY when none exists AND
// the pool holds no ciphertext (first credential / migration).
func upstreamEnsureKey() (*upstream.Keyring, error) {
	if k, _ := upstreamPool.Key(); k != nil {
		return k, nil
	}
	eff := upstreamPool.EffectiveEntries()
	for i := range eff {
		if eff[i].Credential != nil {
			return nil, errors.New("key_unusable: sealed credentials exist but the credential key is unavailable; restore .upstream_cred_key before adding credentials")
		}
	}
	if _, err := upstream.OpenKey(upstreamKeyDir(), false); err == nil || !errors.Is(err, upstream.ErrKeyMissing) {
		// Present-but-unreadable (or readable but not installed) — never
		// mint over an existing file.
		if err == nil {
			return upstreamOpenKey(), nil
		}
		return nil, errors.New("key_unusable: the credential key cannot be read")
	}
	k, err := upstream.OpenKey(upstreamKeyDir(), true)
	if err != nil {
		return nil, fmt.Errorf("key_unusable: %w", err)
	}
	upstreamPool.SetKey(k, "")
	setUpstreamState(func(st *upstreamState) { st.Key = upstreamKeyState{State: "present", KeyID: k.KeyID()} })
	return k, nil
}

// upstreamLegacyFromDocument renders the credential-free legacy list of a
// managed document (the downgrade-compatible representation).
func upstreamLegacyFromDocument(doc upstream.Document) []UpstreamEntry {
	out := make([]UpstreamEntry, 0, len(doc.Entries))
	for i := range doc.Entries {
		out = append(out, UpstreamEntry{URL: doc.Entries[i].LegacyURL()})
	}
	return out
}

// applyUpstreamV2 is the boot-time load (called from applyAdminNetwork,
// AFTER the startup slice seeded the YAML-owned entries):
//  1. a v2 document wins and the legacy key is ignored;
//  2. else a legacy sentinel triggers the durable-or-nothing migration;
//  3. else (pre-feature file) nothing beyond the YAML seed.
func applyUpstreamV2(s *AdminSettings) {
	upstreamOpenKey()
	switch {
	case s.UpstreamProxiesV2 != nil:
		doc := s.UpstreamProxiesV2.Clone()
		if err := upstreamPool.SetDocument(doc); err != nil {
			upstreamNoteDegraded(err)
			logger.Printf("Upstream: v2 document refused at load (%s); managed entries NOT published, YAML-owned entries only", upstreamBoundedReason(err))
			return
		}
		setUpstreamState(func(st *upstreamState) { st.Degraded = nil; st.Migration = upstreamMigrationState{State: "ok"} })
		applyUpstreamProxy()
	case s.UpstreamProxiesSaved:
		upstreamMigrateLegacy(s)
	}
}

// upstreamMigrateLegacy converts the legacy credential-bearing list into a
// sealed v2 document durable-or-nothing (C10): parse everything first, open
// or mint the key only when safe, seal in memory, atomically persist the
// complete document + credential-free legacy key, and swap memory only
// after a nil write. Any failure leaves the file untouched, publishes
// nothing beyond the YAML seed, and surfaces a bounded degraded reason.
func upstreamMigrateLegacy(s *AdminSettings) {
	now := time.Now().UTC().Format(time.RFC3339)
	degrade := func(reason string) {
		setUpstreamState(func(st *upstreamState) {
			st.Migration = upstreamMigrationState{State: "degraded", Reason: reason, At: now}
		})
		logger.Printf("Upstream: legacy pool migration DEGRADED (%s); managed entries NOT published, legacy file untouched", reason)
	}
	items, needKey, ok := upstreamParseLegacy(s.UpstreamProxies)
	if !ok {
		degrade("parse_failed")
		return
	}
	var key *upstream.Keyring
	if needKey {
		k, _ := upstreamPool.Key()
		if k == nil {
			// Mint only here: no v2 state exists (we are migrating) and no
			// ciphertext exists anywhere (the legacy key is plaintext).
			nk, err := upstream.OpenKey(upstreamKeyDir(), true)
			if err != nil {
				degrade("key_unusable")
				return
			}
			k = nk
		}
		key = k
	}
	doc, sealed, yamlOwned, err := upstreamBuildMigratedDocument(items, key, now)
	if err != nil {
		degrade("seal_failed")
		return
	}
	if err := upstream.ValidateEffective(upstreamPool.YAMLEntries(), doc.Entries); err != nil {
		degrade(upstreamBoundedReason(err))
		return
	}
	// Atomic persistence of the COMPLETE v2 document + credential-free
	// legacy key into the file that was just loaded (only these two fields
	// change; every other section is carried verbatim).
	target := *s
	docCopy := doc.Clone()
	target.UpstreamProxiesV2 = &docCopy
	target.UpstreamProxies = upstreamLegacyFromDocument(doc)
	data, err := json.MarshalIndent(target, "", "  ")
	if err != nil {
		degrade("persist_failed")
		return
	}
	if adminSettingsPath != "" {
		if err := fileutil.AtomicWrite(adminSettingsPath, data, 0o600); err != nil {
			degrade("persist_failed")
			return
		}
	}
	if key != nil {
		upstreamPool.SetKey(key, "")
		setUpstreamState(func(st *upstreamState) { st.Key = upstreamKeyState{State: "present", KeyID: key.KeyID()} })
	}
	if err := upstreamPool.SetDocument(doc); err != nil {
		degrade(upstreamBoundedReason(err))
		return
	}
	*s = target
	setUpstreamState(func(st *upstreamState) {
		st.Degraded = nil
		st.Migration = upstreamMigrationState{State: "ok", At: now, Migrated: len(doc.Entries), Sealed: sealed, YAMLOwned: yamlOwned}
	})
	applyUpstreamProxy()
	logger.Printf("Upstream: migrated %d legacy parent-proxy entries to the v2 document (%d credential(s) sealed, %d YAML-owned skipped)", len(doc.Entries), sealed, yamlOwned)
}

// upstreamLegacyItem is one parsed legacy URL awaiting migration.
type upstreamLegacyItem struct {
	spec  upstream.Spec
	pw    string
	hasPW bool
}

// upstreamParseLegacy parses EVERY legacy URL before anything is touched;
// ok is false on the first parse failure (nothing is migrated).
func upstreamParseLegacy(in []UpstreamEntry) (items []upstreamLegacyItem, needKey, ok bool) {
	items = make([]upstreamLegacyItem, 0, len(in))
	for i := range in {
		spec, pw, has, err := upstream.SpecFromURL(in[i].URL)
		if err != nil {
			return nil, false, false
		}
		hasPW := has && pw != ""
		items = append(items, upstreamLegacyItem{spec: spec, pw: pw, hasPW: hasPW})
		needKey = needKey || hasPW
	}
	return items, needKey, true
}

// upstreamBuildMigratedDocument seals the parsed items into a fresh managed
// document in memory (YAML-owned authorities are skipped and counted).
func upstreamBuildMigratedDocument(items []upstreamLegacyItem, key *upstream.Keyring, now string) (doc upstream.Document, sealed, yamlOwned int, err error) {
	yamlAuth := map[string]struct{}{}
	yaml := upstreamPool.YAMLEntries()
	for i := range yaml {
		yamlAuth[yaml[i].AuthorityHash()] = struct{}{}
	}
	doc = upstream.Document{Schema: upstream.DocumentSchema, Revision: 1}
	for i := range items {
		it := &items[i]
		if _, owned := yamlAuth[it.spec.AuthorityHash()]; owned {
			yamlOwned++
			continue
		}
		e := upstream.ManagedEntry{
			ID: upstream.NewManagedID(), Scheme: it.spec.Scheme, Host: it.spec.Host, Port: it.spec.Port, Username: it.spec.Username,
			Revision: 1, Source: upstream.SourceManaged, CreatedAt: now, UpdatedAt: now,
		}
		if it.hasPW {
			c, serr := key.Seal(it.pw, it.spec.AuthorityHash(), now, "migration")
			if serr != nil {
				return upstream.Document{}, 0, 0, serr
			}
			e.Credential = c
			sealed++
		}
		doc.Entries = append(doc.Entries, e)
	}
	return doc, sealed, yamlOwned, nil
}

// upstreamBoundedReason renders a typed engine error as a bounded reason.
func upstreamBoundedReason(err error) string {
	var dup *upstream.DuplicateAuthorityError
	if errors.As(err, &dup) {
		return "duplicate_authority"
	}
	var inv *upstream.InvalidEntryError
	if errors.As(err, &inv) {
		return "invalid_entry"
	}
	return "invalid_entry"
}

func upstreamNoteDegraded(err error) {
	d := &upstreamDegraded{Reason: upstreamBoundedReason(err)}
	var dup *upstream.DuplicateAuthorityError
	if errors.As(err, &dup) {
		d.Count = dup.Count
	}
	setUpstreamState(func(st *upstreamState) { st.Degraded = d })
}

// upstreamRedactedPasswordMarker is the placeholder net/url renders for a
// password (url.URL.Redacted); a client echoing an exported URL back may carry
// it, and it means "keep the credential this authority already has".
const upstreamRedactedPasswordMarker = "xxxxx"

// upstreamImportError is a bounded import refusal (code + index, never the URL).
type upstreamImportError struct {
	Code  string
	Index int
	Msg   string
}

func (e *upstreamImportError) Error() string {
	return fmt.Sprintf("%s (upstream entry %d): %s", e.Code, e.Index, e.Msg)
}

// upstreamImportDocument builds the managed document a config import would
// install, judging ONLY the incoming payload before any store mutation:
//   - parse failure / real password ⇒ error (invalid_entry / credentials_not_importable)
//   - a YAML-owned authority is skipped (read-only, never adopted)
//   - an authority already managed keeps its identity AND its sealed credential
//   - merge mode keeps every live managed entry; replace mode keeps only the
//     credentialed ones that the import omitted (a credential is never removed
//     by omission — clearing is an explicit T3 operation)
//   - effective-pool authority uniqueness is validated against the YAML seed.
//
// A nil document with a nil error means the payload carries no upstream
// section (nothing to apply).
func upstreamImportDocument(in []UpstreamEntry, replace bool) (*upstream.Document, error) {
	if len(in) == 0 {
		return nil, nil
	}
	cur := upstreamPool.Document()
	yaml := upstreamPool.YAMLEntries()
	yamlAuth := map[string]struct{}{}
	for i := range yaml {
		yamlAuth[yaml[i].AuthorityHash()] = struct{}{}
	}
	byAuth := map[string]int{}
	for i := range cur.Entries {
		byAuth[cur.Entries[i].AuthorityHash()] = i
	}
	next := upstream.Document{Schema: upstream.DocumentSchema, Revision: cur.Revision + 1}
	now := time.Now().UTC().Format(time.RFC3339)
	seen := map[string]struct{}{}
	for i := range in {
		spec, err := upstreamImportSpec(i, in[i].URL)
		if err != nil {
			return nil, err
		}
		h := spec.AuthorityHash()
		if _, owned := yamlAuth[h]; owned {
			continue
		}
		if _, dup := seen[h]; dup {
			return nil, &upstreamImportError{Code: "duplicate_authority", Index: i, Msg: "the same authority appears twice in the import"}
		}
		seen[h] = struct{}{}
		if idx, ok := byAuth[h]; ok {
			next.Entries = append(next.Entries, cur.Entries[idx])
			continue
		}
		next.Entries = append(next.Entries, upstream.ManagedEntry{
			ID: upstreamNewID(cur), Scheme: spec.Scheme, Host: spec.Host, Port: spec.Port, Username: spec.Username,
			Revision: 1, Source: upstream.SourceManaged, CreatedAt: now, UpdatedAt: now,
		})
	}
	// Live entries the import did not name.
	for i := range cur.Entries {
		h := cur.Entries[i].AuthorityHash()
		if _, named := seen[h]; named {
			continue
		}
		if !replace || cur.Entries[i].Credential != nil {
			next.Entries = append(next.Entries, cur.Entries[i])
		}
	}
	if err := upstream.ValidateEffective(yaml, next.Entries); err != nil {
		return nil, err
	}
	return &next, nil
}

// upstreamImportSpec parses one imported URL: unparseable ⇒ invalid_entry;
// a REAL password ⇒ credentials_not_importable (the redaction marker is
// accepted and means "keep the credential this authority already has").
func upstreamImportSpec(index int, raw string) (upstream.Spec, error) {
	spec, pw, hasPW, err := upstream.SpecFromURL(raw)
	if err != nil {
		return spec, &upstreamImportError{Code: "invalid_entry", Index: index, Msg: err.Error()}
	}
	if hasPW && pw != upstreamRedactedPasswordMarker {
		return spec, &upstreamImportError{Code: "credentials_not_importable", Index: index,
			Msg: "a proxy URL in a backup must not carry a password; set the credential through the credential endpoint after import"}
	}
	return spec, nil
}

// writeUpstreamImportRefusal renders an upstream pre-validation failure as a
// 400 with a bounded code (a 409 for a duplicate authority against the YAML
// seed, mirroring the v2 endpoints); the URL is never echoed.
func writeUpstreamImportRefusal(w http.ResponseWriter, err error) {
	var ie *upstreamImportError
	if errors.As(err, &ie) {
		http.Error(w, "invalid upstream proxies: "+ie.Code+" at entry "+strconv.Itoa(ie.Index)+": "+ie.Msg, http.StatusBadRequest)
		return
	}
	var dup *upstream.DuplicateAuthorityError
	if errors.As(err, &dup) {
		http.Error(w, "invalid upstream proxies: duplicate_authority ("+strconv.Itoa(dup.Count)+")", http.StatusConflict)
		return
	}
	http.Error(w, "invalid upstream proxies: "+upstreamBoundedReason(err), http.StatusBadRequest)
}
