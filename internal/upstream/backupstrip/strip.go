package backupstrip

// strip.go — backup secret stripping + restore reporting
// for the Upstream v2 sealed credentials (2F-D, contract C5/C12).
//
// admin_settings.json is the ONLY portable artifact that carries the sealed
// upstream credentials, and its node-local key (.upstream_cred_key) is
// never archived — so an archived copy of the sealed record would be
// ciphertext nobody can unwrap on a restored node and key material the
// operator would have to protect for nothing. Both backup modes (plain and
// encrypted) therefore archive a SANITIZED representation of the settings
// file: every `credential` record under upstream_proxies_v2.entries[] is
// removed and the entry is marked `requiresReplacement: true`, so a restore
// boots each formerly credentialed entry into the DISTINCT durable
// CredentialRequiresReplacement state (ineligible, never sent
// unauthenticated) instead of `none` or `configured`. The manifest records
// `credentialsOmitted: true` unconditionally (the archive never carries
// material). The live file and the live pool are untouched — the sanitizer
// works on the bytes read for packing, never on disk.
//
// The rewrite is a generic-JSON transform (json.Number preserved, every
// other key carried verbatim) so it needs no knowledge of the rest of the
// settings schema and can never drop an unrelated section.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// upstreamSettingsCredentialKeys are the keys a sealed record carries; none
// may survive inside the archived v2 document (pinned by the RED matrix).
var upstreamSettingsCredentialKeys = []string{`"ciphertext"`, `"keyId"`, `"authorityHash"`}

// Strip returns the sanitized representation
// of an admin_settings.json body and the number of credentials removed. A
// body without an upstream_proxies_v2 document is returned unchanged (0).
// A body that is not a JSON object is an error (a corrupt settings file
// must not be archived as if it were sound).
func Strip(body []byte) (sanitized []byte, stripped int, err error) {
	// PR-C20 R11-A: a repeated key is refused BEFORE the body is decoded
	// into a map. encoding/json keeps only the LAST value of a repeated
	// key, so a settings object that repeats `upstream_proxies` (a
	// credential-bearing list first, an empty list last), a repeated
	// nested `url`, or a repeated `upstream_proxies_v2` document had the
	// credential gate inspect only the surviving value while the no-op
	// path handed back the ORIGINAL bytes, secret included. A sound
	// settings file never repeats a key at any nesting level.
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return nil, 0, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		return nil, 0, fmt.Errorf("admin_settings.json is not a JSON object: %w", err)
	}
	// PR-C28 R18-A: the JSON literal `null` decodes into a NIL map without
	// error, so every check below saw an empty document and the zero-strip
	// branch handed the original `null` back to be archived — a restore of
	// that archive silently boots zero-valued settings. A null root is not
	// a settings object and refuses the backup like every other non-object
	// root.
	if root == nil {
		return nil, 0, errors.New("admin_settings.json is not a JSON object: the settings root is null")
	}
	// PR-C19 R10-A: ONE settings object and nothing after it but
	// whitespace. Decode reads a single value and never looks at the
	// remaining bytes, so a credential-free leading object followed by a
	// second value or trailing garbage carrying a plaintext legacy
	// upstream URL was returned unchanged (the no-op path hands back the
	// ORIGINAL body) and packed verbatim while the manifest asserted
	// credentialsOmitted. A body with trailing data is not a sound
	// settings file and is refused before any of it is inspected.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, 0, errors.New("admin_settings.json carries data after the settings object; a backup archives only a sound settings file")
	}
	// PR-C17 R8-A: a settings file in the prepared-downgrade state (after
	// `--prepare-downgrade`, before the next boot re-migrates) carries NO v2
	// document and the UNSEALED passwords in the legacy `upstream_proxies`
	// URLs by design — a pre-v2 file never booted on this binary can carry
	// them too. An archive never carries material and the manifest asserts
	// credentialsOmitted unconditionally, so such a body is REFUSED rather
	// than packed verbatim: the operator boots this binary once (it
	// re-migrates and seals the credentials) or completes the downgrade
	// before taking a backup. Counts only — never a URL or a password.
	if err := refuseCredentialBearingLegacyUpstreams(root); err != nil {
		return nil, 0, err
	}
	// PR-C23 R14-A: the v2 CONTAINER shape is part of what the sanitizer
	// reads. A present document that is not an object, a present `entries`
	// that is not an array, an item that is not an object, or a present
	// `credential` that is not an object is a settings file the strip
	// cannot sanitize — and it used to fall through a failed type assertion
	// to the no-op path, which hands back the ORIGINAL bytes, sealed
	// material included. Every such shape now refuses the archive.
	stripped, err = stripV2Credentials(root)
	if err != nil {
		return nil, 0, err
	}
	// PR-C25 R15-A: the post-strip check verifies removal WITHIN the v2
	// document, never by forbidding the sealed-record key names throughout
	// the sanitized settings — an operator-controlled map (`otlp_headers`)
	// or an unrelated section may legitimately use `keyId` or `ciphertext`
	// as a name, and refusing a sound backup after the credential had been
	// removed was the defect. The v2 document is upstream-owned in full, so
	// any of these names surviving anywhere inside it is material the
	// strip cannot account for and refuses the archive.
	//
	// PR-C26 R16-A: the verification runs whenever a v2 document is PRESENT,
	// whether or not a credential object was stripped — it used to run only
	// after a strip, so a document carrying misplaced sealed fields with no
	// recognized `credential` object (a document-level `ciphertext`, an
	// entry-level `keyId`) returned the ORIGINAL bytes at the zero-strip
	// branch before the verifier ever ran.
	if doc, present := root["upstream_proxies_v2"]; present {
		if err := verifyV2CredentialsRemoved(doc); err != nil {
			return nil, 0, err
		}
	}
	if stripped == 0 {
		return body, 0, nil
	}
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("re-serialize sanitized admin_settings.json: %w", err)
	}
	return out, stripped, nil
}

// verifyV2CredentialsRemoved walks the v2 document's object KEYS at every
// depth and refuses it if any sealed-record key name — or a `credential`
// key the strip did not remove — is present after the strip; for a document
// that carried no credential object that means anywhere the strip could
// not reach (PR-C26 R16-A). PR-C27 R17-A: it inspects KEYS only, never
// values — a sound entry whose username is `keyId` or `ciphertext` is
// ordinary, and the earlier byte scan of the serialized subtree refused
// every backup over it.
func verifyV2CredentialsRemoved(doc any) error {
	return walkV2Keys(doc)
}

// walkV2Keys recurses through objects and arrays and refuses the first
// sealed-record key it meets. PR-C29 R19-A: the comparison folds CASE —
// the loader decodes case-insensitively, and the duplicate-key walker
// folds case only for the keys BOUND at a structural role, so a
// case-variant sealed field placed OUTSIDE its normal role (a
// document-level `Ciphertext`, an entry-level `KeyId`, a nested
// `AuthorityHash`, a misplaced `Credential`) passed both the walker and an
// exact comparison here and was archived unchanged at the zero-strip
// branch. The v2 document is upstream-owned in full, so any spelling of
// its owned key names at any depth is refused.
func walkV2Keys(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			for _, name := range upstreamSettingsCredentialKeys {
				if strings.EqualFold(`"`+k+`"`, name) {
					return fmt.Errorf("sanitized upstream_proxies_v2 still carries %s", k)
				}
			}
			if strings.EqualFold(k, "credential") {
				return errors.New("sanitized upstream_proxies_v2 still carries credential")
			}
			if err := walkV2Keys(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range t {
			if err := walkV2Keys(child); err != nil {
				return err
			}
		}
	}
	return nil
}

// errUpstreamSettingsDuplicateKey is the refusal for a settings body that
// repeats a key inside one JSON object — exactly, or differing only by
// case (see rejectDuplicateJSONKeys).
var errUpstreamSettingsDuplicateKey = errors.New("admin_settings.json repeats a key inside one JSON object; a backup archives only a sound settings file")

// errUpstreamSettingsKeyCase is the refusal for a settings body that spells
// a key the sanitizer reads in a case variant the settings loader would
// still accept (see upstreamBoundKeys).
var errUpstreamSettingsKeyCase = errors.New("admin_settings.json spells an upstream key in a case variant; a backup archives only a sound settings file")

// errUpstreamSettingsV2Malformed is the refusal for a settings body whose
// upstream_proxies_v2 document, entries, item or credential is not the
// persisted shape the strip can sanitize (PR-C23 R14-A).
var errUpstreamSettingsV2Malformed = errors.New("admin_settings.json carries an upstream_proxies_v2 document the sanitizer cannot read; a backup archives only a sound settings file")

// jsonRole is the structural position of a JSON container in a settings
// body, as the settings loader would bind it. PR-C23 R14-B: the case
// checks below apply ONLY where the loader could bind a key to an upstream
// field. An operator-controlled map such as `otlp_headers`
// (map[string]string, where encoding/json keeps case-distinct keys apart)
// legitimately carries a header named `URL` or `KeyId`, and an unrelated
// section may use any of these names; neither reaches an upstream field.
type jsonRole uint8

const (
	roleOther      jsonRole = iota // not bound to an upstream field
	roleRoot                       // the AdminSettings object
	roleLegacyList                 // upstream_proxies (array)
	roleLegacyItem                 // one upstream_proxies item (object)
	roleV2Doc                      // upstream_proxies_v2 (object)
	roleV2Entries                  // upstream_proxies_v2.entries (array)
	roleV2Entry                    // one v2 entry (object)
	roleV2Cred                     // a v2 entry's credential (object)
)

// upstreamBoundKeys are, per role, the keys the sanitizer reads by exact
// spelling and the settings loader binds case-insensitively (PR-C22
// R13-A): a case variant of one of these, in that role, is a spelling the
// loader accepts and the sanitizer cannot read — the appliance never
// writes one, so it refuses the archive.
var upstreamBoundKeys = map[jsonRole][]string{
	roleRoot:       {"upstream_proxies", "upstream_proxies_v2", "upstream_prepared_downgrade"},
	roleLegacyItem: {"url"},
	roleV2Doc:      {"entries"},
	roleV2Entry:    {"credential", "requiresReplacement"},
	roleV2Cred:     {"ciphertext", "keyId", "authorityHash"},
}

// childRole is the role of the value stored under key in a container of
// role parent (arrays hand their element role down through elemRole).
func childRole(parent jsonRole, key string) jsonRole {
	switch {
	case parent == roleRoot && key == "upstream_proxies":
		return roleLegacyList
	case parent == roleRoot && key == "upstream_proxies_v2":
		return roleV2Doc
	case parent == roleV2Doc && key == "entries":
		return roleV2Entries
	case parent == roleV2Entry && key == "credential":
		return roleV2Cred
	}
	return roleOther
}

// elemRole is the role of one element of an array of role parent.
func elemRole(parent jsonRole) jsonRole {
	switch parent {
	case roleLegacyList:
		return roleLegacyItem
	case roleV2Entries:
		return roleV2Entry
	}
	return roleOther
}

// rejectDuplicateJSONKeys walks the raw token stream of body and refuses
// any JSON object that carries the same key twice, at every nesting level
// (an object inside an array inside an object included) — and, inside the
// containers the settings loader binds to upstream fields, any two keys
// that differ only by case and any case variant of a key the sanitizer
// reads. It reports nothing about VALUES — the same key in two different
// objects is normal — and never decodes into a map, which is exactly the
// representation that discards the earlier value. Syntax errors are left
// to the decoder that follows.
func rejectDuplicateJSONKeys(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	w := jsonKeyWalker{nextRole: roleRoot}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil // io.EOF, or a syntax error the decoder that follows reports
		}
		if err := w.step(tok); err != nil {
			return err
		}
	}
}

// jsonObjectFrame is one open JSON container on the walker's stack: its
// role, and for an object the keys seen so far, whether the next token is
// a key, and the role the value under the last key will take.
type jsonObjectFrame struct {
	object    bool
	role      jsonRole
	keys      []string
	expectKey bool
	valueRole jsonRole
}

// jsonKeyWalker tracks the open containers of a token stream and reports a
// key repeated inside one object.
type jsonKeyWalker struct {
	stack    []*jsonObjectFrame
	nextRole jsonRole // the role of the next container opened
}

// step consumes one token and reports a duplicate or case-variant key.
func (w *jsonKeyWalker) step(tok json.Token) error {
	if top := w.top(); top != nil && top.object && top.expectKey {
		return w.stepKeyPosition(top, tok)
	}
	if top := w.top(); top != nil {
		if top.object {
			top.expectKey = true // the value has been consumed, or begins below
			w.nextRole = top.valueRole
		} else {
			w.nextRole = elemRole(top.role)
		}
	}
	w.stepDelim(tok)
	return nil
}

// stepKeyPosition handles a token where an object expects a key: the closing
// brace, or the key itself (an exact duplicate anywhere; inside an
// upstream-bound container also a duplicate under case folding or a case
// variant of a bound key).
func (w *jsonKeyWalker) stepKeyPosition(top *jsonObjectFrame, tok json.Token) error {
	if d, ok := tok.(json.Delim); ok && d == '}' {
		w.pop()
		return nil
	}
	key, ok := tok.(string)
	if !ok {
		return nil // not a key where one is required: a syntax error
	}
	bound := upstreamBoundKeys[top.role]
	for _, seen := range top.keys {
		if seen == key {
			return errUpstreamSettingsDuplicateKey
		}
		if len(bound) > 0 && top.role != roleRoot && strings.EqualFold(seen, key) {
			return errUpstreamSettingsDuplicateKey
		}
	}
	for _, name := range bound {
		if key != name && strings.EqualFold(key, name) {
			return errUpstreamSettingsKeyCase
		}
	}
	top.keys = append(top.keys, key)
	top.expectKey = false
	top.valueRole = childRole(top.role, key)
	return nil
}

// stepDelim opens or closes a container for a delimiter token.
func (w *jsonKeyWalker) stepDelim(tok json.Token) {
	d, ok := tok.(json.Delim)
	if !ok {
		return
	}
	switch d {
	case '{':
		w.stack = append(w.stack, &jsonObjectFrame{object: true, role: w.nextRole, expectKey: true})
	case '[':
		w.stack = append(w.stack, &jsonObjectFrame{role: w.nextRole})
	case '}', ']':
		w.pop()
	}
	w.nextRole = roleOther
}

func (w *jsonKeyWalker) top() *jsonObjectFrame {
	if len(w.stack) == 0 {
		return nil
	}
	return w.stack[len(w.stack)-1]
}

func (w *jsonKeyWalker) pop() {
	if len(w.stack) > 0 {
		w.stack = w.stack[:len(w.stack)-1]
	}
}

// stripV2Credentials removes every sealed credential from the v2 document
// in root (marking its entry requiresReplacement) and returns the count. An
// absent document or entries key strips nothing; a present document,
// entries, item or credential of any other shape is refused (PR-C23 R14-A).
func stripV2Credentials(root map[string]any) (int, error) {
	rawDoc, present := root["upstream_proxies_v2"]
	if !present {
		return 0, nil
	}
	doc, ok := rawDoc.(map[string]any)
	if !ok {
		return 0, errUpstreamSettingsV2Malformed
	}
	rawEntries, present := doc["entries"]
	if !present {
		return 0, nil
	}
	entries, ok := rawEntries.([]any)
	if !ok {
		return 0, errUpstreamSettingsV2Malformed
	}
	stripped := 0
	for i := range entries {
		e, ok := entries[i].(map[string]any)
		if !ok {
			return 0, errUpstreamSettingsV2Malformed
		}
		rawCred, has := e["credential"]
		if !has {
			continue
		}
		if _, ok := rawCred.(map[string]any); !ok {
			return 0, errUpstreamSettingsV2Malformed
		}
		delete(e, "credential")
		e["requiresReplacement"] = true
		stripped++
	}
	return stripped, nil
}

// CountRequiringReplacement counts the entries an
// archived admin_settings.json would boot into requiresReplacement (the
// restore dry-run's exact count). A body without the document counts 0.
func CountRequiringReplacement(body []byte) int {
	var s struct {
		V2 *struct {
			Entries []struct {
				RequiresReplacement bool `json:"requiresReplacement"`
			} `json:"entries"`
		} `json:"upstream_proxies_v2"`
	}
	if err := json.Unmarshal(body, &s); err != nil || s.V2 == nil {
		return 0
	}
	n := 0
	for _, e := range s.V2.Entries {
		if e.RequiresReplacement {
			n++
		}
	}
	return n
}

// errUpstreamBackupPreparedDowngrade is the refusal for a settings file that
// holds credential material in its legacy upstream list (see
// refuseCredentialBearingLegacyUpstreams).
var errUpstreamBackupPreparedDowngrade = errors.New("admin_settings.json carries upstream credential material in its legacy upstream_proxies list (prepared-downgrade state, or a pre-v2 file never booted on this binary); an archive never carries credential material — boot this binary once so the credentials are re-migrated and sealed, or complete the downgrade, then back up")

// refuseCredentialBearingLegacyUpstreams refuses a settings body whose
// legacy upstream_proxies list carries a password in any URL, or that
// carries the prepared-downgrade marker (the mid-transition predecessor
// shape). The message carries counts only.
//
// PR-C18 R9-A: a legacy URL the sanitizer cannot READ is refused too. The
// only question this gate answers is "does this URL carry a password?",
// and an unparseable URL (a malformed escape in the password itself, a
// scheme-less `user:pw@host` spelling that parses as an OPAQUE URL with no
// host) cannot answer it — treating a parse failure as "no password" let
// the material through verbatim while the manifest asserted
// credentialsOmitted. Fail CLOSED: every URL in the list must parse to an
// absolute URL with a host, and none may carry a password; anything else
// is counted as unparseable and refuses the archive.
//
// PR-C21 R12-A: the CONTAINER shape is part of what the gate reads. The
// persisted shape of AdminSettings.UpstreamProxies is an array of objects
// each carrying a `url` string, and the settings loader can read nothing
// else — so a present `upstream_proxies` that is not an array, an item
// that is not an object, an object with no `url`, or a `url` that is not
// a non-empty string is a settings file the gate cannot inspect, and it
// used to be SKIPPED (a type assertion that silently failed) with the
// material inside it archived verbatim. Every such shape now fails the
// backup closed, counted as malformed.
func refuseCredentialBearingLegacyUpstreams(root map[string]any) error {
	_, prepared := root["upstream_prepared_downgrade"]
	withPassword, unparseable, malformed := 0, 0, 0
	if rawList, present := root["upstream_proxies"]; present {
		list, ok := rawList.([]any)
		if !ok {
			malformed++
		}
		for _, item := range list {
			raw, ok := legacyUpstreamItemURL(item)
			if !ok {
				malformed++
				continue
			}
			u, err := url.Parse(strings.TrimSpace(raw))
			switch {
			case err != nil, u.Opaque != "", u.Host == "":
				unparseable++
			case u.User != nil:
				if _, has := u.User.Password(); has {
					withPassword++
				}
			}
		}
	}
	if prepared || withPassword > 0 || unparseable > 0 || malformed > 0 {
		return fmt.Errorf("%w (prepared_downgrade=%t, legacy_urls_with_password=%d, legacy_urls_unparseable=%d, legacy_items_malformed=%d)", errUpstreamBackupPreparedDowngrade, prepared, withPassword, unparseable, malformed)
	}
	return nil
}

// legacyUpstreamItemURL returns the `url` of one persisted legacy upstream
// item — an object whose `url` is a non-empty string — and false for every
// other shape.
func legacyUpstreamItemURL(item any) (string, bool) {
	obj, ok := item.(map[string]any)
	if !ok {
		return "", false
	}
	raw, ok := obj["url"].(string)
	if !ok || raw == "" {
		return "", false
	}
	return raw, true
}
