package upstream

// entry.go — the Upstream v2 entry, authority and credential model (2F
// contract C4/C10, docs/design/FRONTEND-MIGRATION-PLAN.md).
//
// A parent proxy is a ManagedEntry with a server-generated, immutable ULID
// identity (YAML-owned entries carry a deterministic authority-derived id
// and are read-only), a NORMALIZED scheme/host/port/username, a per-entry
// revision fence, and an optional SEALED credential. A credential is bound
// to exactly two things — the IMMUTABLE ENTRY ID and the canonical
// authority `scheme://username@host:port` (by authority hash) — and both
// are AEAD additional data: a credential is never matched by name,
// position, URL similarity or a client-supplied id, and ciphertext whose
// entry id OR authority hash differs from the entry it is attached to
// (transplanted, or re-created under the same authority) is `mismatch` —
// never unsealed, never sent. An inline credential from config.yaml
// (`http://user:pw@host:port`) is RETAINED in memory only (`yamlSecret`),
// never persisted or returned, and its entry is read-only through the API.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/oklog/ulid/v2"
	"golang.org/x/net/idna"
)

// Source says who owns an entry.
type Source string

// Entry sources.
const (
	SourceManaged Source = "managed"
	SourceYAML    Source = "yaml"
)

// Derived credential states (C4).
const (
	CredentialNone       = "none"       // no credential material
	CredentialConfigured = "configured" // sealed material, unwrappable, authority matches
	CredentialUnusable   = "unusable"   // ciphertext present, node-local key cannot unwrap it
	CredentialMismatch   = "mismatch"   // credential authority ≠ entry authority
)

// Sealed is a credential at rest: ciphertext under the node-local key,
// bound to the entry id AND the authority it was set for. It never carries
// plaintext.
type Sealed struct {
	// EntryID is the immutable entry the credential was sealed FOR; it is
	// bound cryptographically (AAD) and structurally, so ciphertext moved
	// onto another entry — even one with the same authority — is mismatch.
	EntryID       string `json:"entryId"`
	AuthorityHash string `json:"authorityHash"`
	Ciphertext    string `json:"ciphertext"` // base64(nonce || AES-GCM(pw, aad=entryID||0||authorityHash))
	KeyID         string `json:"keyId"`
	SetAt         string `json:"setAt"`
	SetBy         string `json:"setBy,omitempty"`
}

// ManagedEntry is one parent proxy (managed or YAML-owned).
type ManagedEntry struct {
	ID         string  `json:"id"`
	Scheme     string  `json:"scheme"`
	Host       string  `json:"host"`
	Port       int     `json:"port"`
	Username   string  `json:"username,omitempty"`
	Revision   int64   `json:"revision"`
	Source     Source  `json:"source"`
	Credential *Sealed `json:"credential,omitempty"`
	CreatedAt  string  `json:"createdAt,omitempty"`
	UpdatedAt  string  `json:"updatedAt,omitempty"`

	// yamlSecret is the inline password of a config.yaml parent, retained
	// IN MEMORY ONLY (never serialized: json:"-", never part of the managed
	// document, never returned, logged or audited). Empty for managed
	// entries, whose material is sealed under Credential instead.
	yamlSecret string `json:"-"`
}

// Document is the durable v2 representation of the MANAGED entries
// (upstream_proxies_v2). YAML-owned entries are not part of it.
type Document struct {
	Schema   int            `json:"schema"`
	Revision int64          `json:"revision"`
	Entries  []ManagedEntry `json:"entries"`
}

// DocumentSchema is the current v2 document schema.
const DocumentSchema = 1

// Spec is the client-facing shape of an entry's authority inputs.
type Spec struct {
	Scheme   string
	Host     string
	Port     int
	Username string
}

var schemeDefaultPort = map[string]int{"http": 80, "https": 443}

// Normalize validates and canonicalizes an authority specification: scheme
// lower-cased and restricted to http/https (the approved C4 grammar), host lower-cased,
// trailing-dot stripped and IDNA-encoded (bracketed IPv6 literals accepted),
// effective port defaulted per scheme, username free of ':' / '@' / '/'.
func Normalize(in Spec) (Spec, error) {
	out := Spec{}
	out.Scheme = strings.ToLower(strings.TrimSpace(in.Scheme))
	def, ok := schemeDefaultPort[out.Scheme]
	if !ok {
		return out, fmt.Errorf("scheme must be http or https")
	}
	host, err := normalizeHost(in.Host)
	if err != nil {
		return out, err
	}
	out.Host = host
	port := in.Port
	if port == 0 {
		port = def
	}
	if port < 1 || port > 65535 {
		return out, errors.New("port must be 1..65535")
	}
	out.Port = port
	user := strings.TrimSpace(in.Username)
	if strings.ContainsAny(user, ":@/\\ \t\r\n") || len(user) > 255 {
		return out, errors.New("username contains an invalid character or is too long")
	}
	out.Username = user
	return out, nil
}

// normalizeHost lower-cases, strips a trailing dot and IDNA-encodes a host
// name; bracketed IPv6 literals are accepted and bare IPv6 literals bracketed.
func normalizeHost(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	if host == "" {
		return "", errors.New("host is required")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	switch {
	case strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]"):
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip == nil || ip.To4() != nil {
			return "", errors.New("bracketed host must be an IPv6 literal")
		}
	case net.ParseIP(host) != nil:
		if ip := net.ParseIP(host); ip.To4() == nil {
			host = "[" + host + "]"
		}
	default:
		if strings.ContainsAny(host, " /?#@:\\") {
			return "", errors.New("host contains an invalid character")
		}
		ascii, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return "", fmt.Errorf("host is not a valid IDNA host name")
		}
		host = ascii
	}
	return host, nil
}

// SpecFromURL parses a legacy `scheme://[user[:pass]@]host[:port]` URL into
// a normalized Spec plus the plaintext password it carried (empty when
// none). Path, query and fragment are refused unless empty or "/".
func SpecFromURL(raw string) (spec Spec, password string, hasPassword bool, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return spec, "", false, errors.New("URL is not parseable")
	}
	if u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return spec, "", false, errors.New("URL must be scheme://host[:port] with no path, query or fragment")
	}
	port := 0
	if ps := u.Port(); ps != "" {
		n, perr := strconv.Atoi(ps)
		if perr != nil {
			return spec, "", false, errors.New("port is not a number")
		}
		port = n
	}
	spec, err = Normalize(Spec{Scheme: u.Scheme, Host: u.Hostname(), Port: port, Username: u.User.Username()})
	if err != nil {
		return spec, "", false, err
	}
	if u.User != nil {
		password, hasPassword = u.User.Password()
	}
	return spec, password, hasPassword, nil
}

// Authority is the canonical `scheme://username@host:port` (username part
// omitted when empty). It never carries a password.
func (s Spec) Authority() string {
	if s.Username != "" {
		return s.Scheme + "://" + url.PathEscape(s.Username) + "@" + s.Host + ":" + strconv.Itoa(s.Port)
	}
	return s.Scheme + "://" + s.Host + ":" + strconv.Itoa(s.Port)
}

// AuthorityHash is the hex SHA-256 of the canonical authority.
func (s Spec) AuthorityHash() string {
	sum := sha256.Sum256([]byte(s.Authority()))
	return hex.EncodeToString(sum[:])
}

// YAMLID is the deterministic identity of a YAML-owned entry:
// "yaml-" + base32(SHA-256(authority)[0:16]) (128 bits).
func (s Spec) YAMLID() string {
	sum := sha256.Sum256([]byte(s.Authority()))
	return "yaml-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:16]))
}

// Spec returns the entry's authority inputs.
func (e *ManagedEntry) Spec() Spec {
	return Spec{Scheme: e.Scheme, Host: e.Host, Port: e.Port, Username: e.Username}
}

// Authority is the entry's canonical, credential-free authority.
func (e *ManagedEntry) Authority() string { return e.Spec().Authority() }

// AuthorityHash is the entry's canonical authority hash.
func (e *ManagedEntry) AuthorityHash() string { return e.Spec().AuthorityHash() }

// NewManagedID mints a server-generated ULID (collision-checked by the
// caller against every managed and YAML id).
func NewManagedID() string { return ulid.MustNew(ulid.Now(), rand.Reader).String() }

// IsULID reports whether id parses as a ULID (managed identity).
func IsULID(id string) bool {
	_, err := ulid.ParseStrict(id)
	return err == nil
}

// DuplicateAuthorityError reports duplicate canonical authorities in the
// complete effective pool. It carries a COUNT only (never an authority,
// username or credential).
type DuplicateAuthorityError struct{ Count int }

func (e *DuplicateAuthorityError) Error() string {
	return fmt.Sprintf("duplicate canonical authority in the effective pool (%d)", e.Count)
}

// InvalidEntryError names the offending entry by index/id, never by URL.
type InvalidEntryError struct {
	Index  int
	ID     string
	Reason string
}

func (e *InvalidEntryError) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("entry %s: %s", e.ID, e.Reason)
	}
	return fmt.Sprintf("entry %d: %s", e.Index, e.Reason)
}

// ValidateEffective checks the complete effective pool (YAML-owned + managed):
// every entry normalizes, identities are unique across both sets, and the
// canonical authorities are unique across YAML/YAML, managed/managed and
// YAML/managed. Errors are typed so callers report bounded reasons only.
func ValidateEffective(yaml, managed []ManagedEntry) error {
	all := make([]ManagedEntry, 0, len(yaml)+len(managed))
	all = append(all, yaml...)
	all = append(all, managed...)
	for i := range all {
		spec, err := Normalize(all[i].Spec())
		if err != nil {
			return &InvalidEntryError{Index: i, ID: all[i].ID, Reason: err.Error()}
		}
		if all[i].ID == "" {
			return &InvalidEntryError{Index: i, Reason: "missing id"}
		}
		// Hash the CANONICAL spelling: entries are stored normalized, but a
		// caller-built entry is validated on its canonical form regardless.
		all[i].Scheme, all[i].Host, all[i].Port, all[i].Username = spec.Scheme, spec.Host, spec.Port, spec.Username
	}
	// Authority uniqueness is checked FIRST and independently of identity
	// collisions (binding clarification 1): two YAML spellings of one
	// authority collide on their deterministic id as well, and the operator
	// must see duplicate_authority, not an id error.
	auths := map[string]struct{}{}
	dups := 0
	for i := range all {
		a := all[i].AuthorityHash()
		if _, dup := auths[a]; dup {
			dups++
		}
		auths[a] = struct{}{}
	}
	if dups > 0 {
		return &DuplicateAuthorityError{Count: dups}
	}
	ids := map[string]struct{}{}
	for i := range all {
		if _, dup := ids[all[i].ID]; dup {
			return &InvalidEntryError{Index: i, ID: all[i].ID, Reason: "duplicate id"}
		}
		ids[all[i].ID] = struct{}{}
	}
	return nil
}

// YAMLEntries converts YAML-seeded legacy URLs into read-only YAML-owned
// entries. An inline password in a YAML URL is RETAINED in memory only
// (yamlSecret — never persisted, returned or audited); an unparseable URL
// is an InvalidEntryError.
func YAMLEntries(entries []Entry) ([]ManagedEntry, error) {
	out := make([]ManagedEntry, 0, len(entries))
	for i, e := range entries {
		spec, pw, _, err := SpecFromURL(e.URL)
		if err != nil {
			return nil, &InvalidEntryError{Index: i, Reason: err.Error()}
		}
		// An existing inline credential stays usable: retained in memory
		// only, read-only, never persisted into admin_settings.
		out = append(out, ManagedEntry{
			ID: spec.YAMLID(), Scheme: spec.Scheme, Host: spec.Host, Port: spec.Port, Username: spec.Username,
			Revision: 1, Source: SourceYAML, yamlSecret: pw,
		})
	}
	return out, nil
}

// LegacyURL is the credential-free `scheme://[username@]host:port` form
// persisted in the downgrade-compatible legacy list (admin_settings
// upstream_proxies) so a pre-v2 binary still sees the username.
func (e *ManagedEntry) LegacyURL() string { return e.Authority() }

// DisplayURL is the API/legacy-GET form: `scheme://host:port` with NO
// userinfo at all (the username is a separate field).
func (e *ManagedEntry) DisplayURL() string {
	return e.Scheme + "://" + e.Host + ":" + strconv.Itoa(e.Port)
}

// HasInlineSecret reports whether a YAML entry carries an in-memory inline
// credential (never the secret itself).
func (e *ManagedEntry) HasInlineSecret() bool { return e.yamlSecret != "" }

// cloneEntries deep-copies a slice of entries.
func cloneEntries(in []ManagedEntry) []ManagedEntry {
	out := make([]ManagedEntry, len(in))
	for i := range in {
		out[i] = in[i]
		if in[i].Credential != nil {
			c := *in[i].Credential
			out[i].Credential = &c
		}
	}
	return out
}

// Clone deep-copies the document.
func (d Document) Clone() Document {
	return Document{Schema: d.Schema, Revision: d.Revision, Entries: cloneEntries(d.Entries)}
}
