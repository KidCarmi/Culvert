package main

// upstream_downgrade.go — `culvert --prepare-downgrade --target-schema <n>
// [--confirm <word>]` (2F-D, contract C10).
//
// The frozen predecessor (2F-B, admin-settings schema 1) reads its parent
// proxies from the legacy `upstream_proxies` list as credential-BEARING
// URLs and knows nothing about `upstream_proxies_v2`, the sealed records or
// the node-local key. This binary (schema 2) persists the legacy list
// CREDENTIAL-FREE. So a node that must run the predecessor again needs its
// settings file rewritten ONCE, deliberately, by the binary that holds the
// key: every sealed credential is unsealed IN MEMORY, the legacy list is
// rewritten with full authenticated URLs, `upstream_proxies_v2` is removed
// in the SAME atomic write (0600, fsync, rename) and a marker records the
// operation so the next boot of THIS binary re-migrates and reports
// `re-migrated_after_prepare` instead of treating the file as a pristine
// legacy install.
//
// Guard rails: a dry-run is mandatory (it prints the confirmation word,
// derived from the data-directory basename plus the target schema); the
// supported target is exactly the frozen predecessor's schema + SHA
// recorded in docs/design/FRONTEND-MIGRATION-PLAN.md; the command refuses
// while any credential is unusable, mismatch or requiresReplacement, or
// when the key is missing/unreadable, because a downgrade that silently
// drops a credential would hand the predecessor an unauthenticated parent;
// output, log and audit carry COUNTS only — never a URL, username,
// password, ciphertext or transport error.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/upstream"
)

// Admin-settings schema numbers (2F-D). The file records the schema it was
// written under (`admin_settings_schema`); absent ⇒ 1 (every file written
// before 2F-D, including everything the frozen predecessor writes).
const (
	adminSettingsSchemaPredecessor = 1 // 2F-B frozen predecessor: credential-bearing legacy list, no v2 document
	adminSettingsSchemaCurrent     = 2 // 2F-C/2F-D: sealed upstream_proxies_v2 + credential-free legacy list
)

// downgradePredecessorSHA is the frozen 2F-B predecessor this command's
// output is bound to (the only binary the rewritten file is meant for),
// recorded in docs/design/FRONTEND-MIGRATION-PLAN.md (2F-D record).
const downgradePredecessorSHA = "1e3578d93021563df61685f5c669f6742fc72081"

// upstreamDowngradeMarker is persisted beside the rewritten legacy list so
// the next boot of the CURRENT binary knows the credential-bearing file was
// produced by prepare-downgrade (re-migrated_after_prepare), not by a
// pristine legacy install. The predecessor ignores it (lenient decoder) and
// drops it on its first save.
type upstreamDowngradeMarker struct {
	At           string `json:"at"`
	TargetSchema int    `json:"target_schema"`
	FromSchema   int    `json:"from_schema"`
	Credentials  int    `json:"credentials"` // count only
}

// upstreamMigrationReasonAfterPrepare is the migration-state reason the
// next boot reports when it re-seals a prepare-downgrade file.
const upstreamMigrationReasonAfterPrepare = "re-migrated_after_prepare"

// downgradeConfirmWord derives the Tier-3 confirmation word: the
// data-directory basename plus the target schema.
func downgradeConfirmWord(dir string, target int) string {
	return filepath.Base(filepath.Clean(dir)) + "-schema" + strconv.Itoa(target)
}

// downgradeRefusal is a bounded refusal (never a URL/credential).
type downgradeRefusal struct{ Code, Msg string }

func (e *downgradeRefusal) Error() string { return e.Code + ": " + e.Msg }

// downgradePlan is the counts-only plan of one prepare-downgrade run.
type downgradePlan struct {
	Entries     int // managed entries that will appear in the legacy list
	Credentials int // sealed credentials that will be unsealed into it
	YAMLOwned   int // YAML-owned entries (untouched; they live in config.yaml)
}

// runPrepareDowngrade is the one-shot entry point. confirm=="" is the
// mandatory dry-run: it validates everything, prints the plan and the exact
// commit command, and writes nothing. With the correct word it performs
// the atomic rewrite. Every refusal is bounded.
func runPrepareDowngrade(dir string, target int, confirm string, out io.Writer) error {
	if target != adminSettingsSchemaPredecessor {
		return &downgradeRefusal{Code: "unsupported_target_schema",
			Msg: fmt.Sprintf("only --target-schema %d (the frozen 2F-B predecessor %s) is supported; this binary writes schema %d",
				adminSettingsSchemaPredecessor, downgradePredecessorSHA[:8], adminSettingsSchemaCurrent)}
	}
	path := filepath.Join(dir, "admin_settings.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured data dir
	if err != nil {
		return &downgradeRefusal{Code: "settings_unreadable", Msg: "admin_settings.json could not be read from the data directory"}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		return &downgradeRefusal{Code: "settings_invalid", Msg: "admin_settings.json is not a JSON object"}
	}
	var typed AdminSettings
	if err := json.Unmarshal(raw, &typed); err != nil {
		return &downgradeRefusal{Code: "settings_invalid", Msg: "admin_settings.json does not decode"}
	}
	if typed.UpstreamProxiesV2 == nil {
		if typed.UpstreamPreparedDowngrade != nil {
			return &downgradeRefusal{Code: "already_prepared", Msg: "this data directory was already prepared for the predecessor; boot the predecessor (or boot this binary to re-migrate)"}
		}
		return &downgradeRefusal{Code: "nothing_to_prepare", Msg: "no upstream_proxies_v2 document is present; the file is already predecessor-compatible"}
	}
	doc := typed.UpstreamProxiesV2.Clone()

	// The key is opened READ-ONLY (never minted here).
	key, kerr := upstream.OpenKey(dir, false)
	needKey := false
	for i := range doc.Entries {
		if doc.Entries[i].Credential != nil {
			needKey = true
		}
	}
	if needKey && (kerr != nil || key == nil) {
		return &downgradeRefusal{Code: "key_unusable", Msg: "the node-local credential key is missing or unreadable; a downgrade cannot unseal the credentials it must carry"}
	}

	// Every entry must be cleanly resolvable: unusable/mismatch/
	// requiresReplacement would silently hand the predecessor an
	// unauthenticated parent.
	urls, plan, err := downgradeResolveEntries(doc, key)
	if err != nil {
		return err
	}

	word := downgradeConfirmWord(dir, target)
	fmt.Fprintf(out, "Prepare downgrade (admin-settings schema %d → %d, predecessor %s)\n", adminSettingsSchemaCurrent, target, downgradePredecessorSHA[:8])
	fmt.Fprintf(out, "  data directory:            %s\n", dir)
	fmt.Fprintf(out, "  managed parent proxies:    %d\n", plan.Entries)
	fmt.Fprintf(out, "  credentials to unseal:     %d (in memory only; written into the legacy list for the predecessor)\n", plan.Credentials)
	fmt.Fprintf(out, "  upstream_proxies_v2:       removed in the same atomic write\n")
	fmt.Fprintf(out, "  node-local key:            untouched (never deleted); the next boot of this binary re-migrates (%s)\n", upstreamMigrationReasonAfterPrepare)
	if confirm == "" {
		fmt.Fprintf(out, "\nThis was a dry-run. No files were written.\n")
		fmt.Fprintf(out, "To commit: culvert --prepare-downgrade --target-schema %d --confirm %s\n", target, word)
		return nil
	}
	if confirm != word {
		return &downgradeRefusal{Code: "confirm_mismatch", Msg: "the confirmation word does not match this data directory and target schema; run the dry-run first"}
	}

	// Rewrite: legacy list WITH credentials, v2 document removed, schema
	// marker removed (the predecessor's own shape), operation marker added.
	legacy := make([]map[string]any, 0, len(urls))
	for _, u := range urls {
		legacy = append(legacy, map[string]any{"url": u})
	}
	root["upstream_proxies"] = legacy
	root["upstream_proxies_saved"] = true
	delete(root, "upstream_proxies_v2")
	delete(root, "admin_settings_schema")
	root["upstream_prepared_downgrade"] = upstreamDowngradeMarker{
		At: time.Now().UTC().Format(time.RFC3339), TargetSchema: target, FromSchema: adminSettingsSchemaCurrent, Credentials: plan.Credentials,
	}
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return &downgradeRefusal{Code: "persist_failed", Msg: "the predecessor-compatible settings file could not be serialized; nothing was changed"}
	}
	if err := fileutil.AtomicWrite(path, data, 0o600); err != nil {
		return &downgradeRefusal{Code: "persist_failed", Msg: "the predecessor-compatible settings file could not be written; nothing was changed"}
	}
	// Headless audit line (counts only) into the durable audit log beside
	// the settings file; best-effort — a CLI one-shot has no request actor.
	auditPrepareDowngrade(dir, plan)
	fmt.Fprintf(out, "\nPrepared: admin_settings.json rewritten for the predecessor (%d entr(y/ies), %d credential(s)).\n", plan.Entries, plan.Credentials)
	fmt.Fprintf(out, "Boot the predecessor binary (%s) now, or boot this binary to re-migrate.\n", downgradePredecessorSHA[:8])
	return nil
}

// downgradeResolveEntries unseals every managed credential IN MEMORY and
// renders the predecessor's legacy URL list; any entry that cannot be
// resolved cleanly refuses the whole run with a bounded, index-only reason.
func downgradeResolveEntries(doc upstream.Document, key *upstream.Keyring) (urls []string, plan downgradePlan, err error) {
	urls = make([]string, 0, len(doc.Entries))
	n := len(doc.Entries)
	for i := range doc.Entries {
		e := &doc.Entries[i]
		switch {
		case e.Credential == nil && e.RequiresReplacement:
			return nil, plan, &downgradeRefusal{Code: "credential_requires_replacement",
				Msg: fmt.Sprintf("entry %d of %d requires its credential to be set again before a downgrade", i+1, n)}
		case e.Credential == nil:
			urls = append(urls, e.LegacyURL())
		default:
			if e.Credential.EntryID != e.ID || e.Credential.AuthorityHash != e.AuthorityHash() {
				return nil, plan, &downgradeRefusal{Code: "credential_mismatch",
					Msg: fmt.Sprintf("entry %d of %d holds a credential bound to another entry or authority", i+1, n)}
			}
			pw, uerr := key.Unseal(e.Credential, e.ID, e.AuthorityHash())
			if uerr != nil {
				code := "credential_unusable"
				if errors.Is(uerr, upstream.ErrCredentialMismatch) {
					code = "credential_mismatch"
				}
				return nil, plan, &downgradeRefusal{Code: code, Msg: fmt.Sprintf("entry %d of %d cannot be unsealed on this node", i+1, n)}
			}
			urls = append(urls, upstreamAuthenticatedLegacyURL(e, pw))
			plan.Credentials++
		}
		plan.Entries++
	}
	return urls, plan, nil
}

// upstreamAuthenticatedLegacyURL renders the predecessor's credential-
// bearing URL (`scheme://user:pw@host:port`, userinfo escaped by net/url).
// It exists ONLY for the downgrade writer and is never logged or returned.
func upstreamAuthenticatedLegacyURL(e *upstream.ManagedEntry, pw string) string {
	// LegacyURL is the credential-free `scheme://[user@]host:port` form.
	u := e.LegacyURL()
	scheme, rest, _ := strings.Cut(u, "://")
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	return scheme + "://" + url.UserPassword(e.Username, pw).String() + "@" + rest
}

// auditPrepareDowngrade appends a counts-only line to the durable audit
// log when one is configured under dir (best-effort).
func auditPrepareDowngrade(dir string, plan downgradePlan) {
	defer func() { _ = recover() }()
	audit.Add(audit.Entry{
		Actor: "cli", Action: "upstream.prepare_downgrade", Object: "admin_settings.json",
		Detail: fmt.Sprintf("entries=%d credentials=%d target_schema=%d scope=node-local", plan.Entries, plan.Credentials, adminSettingsSchemaPredecessor),
	})
	_ = dir
}

// confirmFlag is the shared `--confirm` flag: a bare `--confirm` (restore
// and cleanup commits) sets it true; `--confirm=<word>` / `--confirm <word>`
// (prepare-downgrade) carries the Tier-3 word. IsBoolFlag keeps the bare
// form working; the word form is recovered by prepareDowngradeConfirmWord.
type confirmFlag struct {
	set   bool
	value string
}

func (c *confirmFlag) String() string   { return c.value }
func (c *confirmFlag) IsBoolFlag() bool { return true }
func (c *confirmFlag) Set(v string) error {
	c.set = true
	c.value = v
	return nil
}

// Bool reports the legacy boolean meaning (any form of --confirm counts).
func (c *confirmFlag) Bool() bool { return c.set && c.value != "false" && c.value != "0" }

// prepareDowngradeConfirmWord resolves the Tier-3 word: `--confirm=<word>`
// carries it directly; the documented `--confirm <word>` form leaves the
// word as the single positional argument after a bare `--confirm`.
func prepareDowngradeConfirmWord(c *confirmFlag, args []string) (string, error) {
	if !c.set {
		if len(args) > 0 {
			return "", fmt.Errorf("unexpected argument(s) %q; the confirmation word must follow --confirm", args)
		}
		return "", nil
	}
	if c.value != "" && c.value != "true" {
		if len(args) > 0 {
			return "", fmt.Errorf("unexpected argument(s) %q", args)
		}
		return c.value, nil
	}
	switch len(args) {
	case 0:
		return "", fmt.Errorf("--confirm requires the confirmation word printed by the dry-run (--confirm <word>)")
	case 1:
		return args[0], nil
	}
	return "", fmt.Errorf("unexpected argument(s) %q", args[1:])
}
