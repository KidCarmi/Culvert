// Package provider defines the narrow, listener-independent credential-provider
// boundary for the PR-4 MCP credential broker. A provider models Vault / KMS /
// workload-identity / secret-manager semantics but performs NO network I/O in
// PR-4: fetch/rotate/revoke/inspect are in-memory contracts exercised by
// deterministic test providers. A provider returns an OPAQUE single-use secret
// handle (secret.Sealed) plus non-secret lease metadata — never raw bytes,
// strings, or secret-bearing errors.
package provider

import (
	"encoding/binary"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/secret"
)

// FieldName is the stable, non-secret name of a secret field within a credential
// (e.g. "token", "username", "password", "private_key"). The NAME is not secret;
// the value is.
type FieldName string

// Well-known field names. Providers may use others (opaque kinds).
const (
	FieldToken       FieldName = "token"
	FieldAPIKey      FieldName = "api_key"
	FieldUsername    FieldName = "username"
	FieldPassword    FieldName = "password"
	FieldCertificate FieldName = "certificate"
	FieldPrivateKey  FieldName = "private_key"
	FieldAssertion   FieldName = "assertion"
	FieldOpaque      FieldName = "opaque"
)

// Field is a transient (name, value) secret field used by provider adapters to
// build sealed material. The Value bytes are owned by the caller until SealFields
// takes ownership.
type Field struct {
	Name  FieldName
	Value []byte
}

// SealFields encodes fields into a single opaque secret.Sealed handle. It COPIES
// each field value into one length-prefixed blob, ZEROIZES the source field values
// (so the provider adapter retains no plaintext), and wraps the blob via
// secret.NewSealed (which takes ownership and redacts/zeroizes it). The names are
// not secret and are carried in the blob so the broker can present typed fields to
// the materialization callback.
func SealFields(fields []Field) *secret.Sealed {
	// Compute size.
	buf := make([]byte, 0, 64)
	var hdr [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(hdr[:], uint64(len(fields)))
	buf = append(buf, hdr[:n]...)
	for i := range fields {
		name := []byte(fields[i].Name)
		n = binary.PutUvarint(hdr[:], uint64(len(name)))
		buf = append(buf, hdr[:n]...)
		buf = append(buf, name...)
		n = binary.PutUvarint(hdr[:], uint64(len(fields[i].Value)))
		buf = append(buf, hdr[:n]...)
		buf = append(buf, fields[i].Value...)
		// Zeroize the caller's source plaintext now that it is copied into the blob.
		zeroBytes(fields[i].Value)
	}
	return secret.NewSealed(buf)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Material is a lifetime-scoped, read-only view of decoded secret fields. It is
// valid ONLY inside the broker's materialization callback: its field bytes alias
// the scoped plaintext buffer that the broker zeroizes on callback return, and a
// defensive live flag rejects any access after the scope closes. Material exposes
// NO byte-returning accessor outside a Field lookup by name, and it is never
// formatted.
type Material struct {
	kind   profile.CredentialKind
	fields map[FieldName][]byte
	live   bool
}

// Kind returns the credential kind of the material.
func (m *Material) Kind() profile.CredentialKind {
	if m == nil {
		return profile.KindUnset
	}
	return m.kind
}

// Field returns the bytes for a named field and whether it is present. The bytes
// are valid ONLY while the scoped callback runs; the caller MUST NOT retain them.
// After the scope closes the lookup returns (nil, false).
func (m *Material) Field(name FieldName) ([]byte, bool) {
	if m == nil || !m.live {
		return nil, false
	}
	b, ok := m.fields[name]
	return b, ok
}

// Close marks the material dead so a retained reference cannot read the (now
// zeroized) buffer. The broker calls it after the scoped callback returns.
func (m *Material) Close() {
	if m == nil {
		return
	}
	m.live = false
	m.fields = nil
}

// DecodeMaterial decodes a plaintext blob (produced by SealFields) into a Material
// whose field slices ALIAS pt (so zeroizing pt zeroizes the fields). It bounds the
// field count and sizes so a corrupted/hostile blob cannot drive unbounded work.
// The broker calls this ONLY inside secret.WithPlaintext, so pt is a scoped,
// about-to-be-zeroized buffer.
func DecodeMaterial(kind profile.CredentialKind, pt []byte, maxFields, maxFieldBytes int) (*Material, error) {
	count, n := binary.Uvarint(pt)
	if n <= 0 || !leWithin(count, maxFields) {
		return nil, matErr("material field count is malformed or too large")
	}
	pos := n
	fields := make(map[FieldName][]byte, count)
	for i := uint64(0); i < count; i++ {
		name, adv, err := readChunk(pt[pos:], maxFieldBytes)
		if err != nil {
			return nil, err
		}
		pos += adv
		val, adv2, err := readChunk(pt[pos:], maxFieldBytes)
		if err != nil {
			return nil, err
		}
		pos += adv2
		fields[FieldName(name)] = val // aliases pt
	}
	return &Material{kind: kind, fields: fields, live: true}, nil
}

// readChunk reads one uvarint-length-prefixed chunk, returning a sub-slice (alias)
// and the total bytes advanced. It rejects a length that overflows the buffer or
// exceeds the per-field bound.
func readChunk(b []byte, maxLen int) (chunk []byte, advanced int, err error) {
	l, n := binary.Uvarint(b)
	if n <= 0 || !leWithin(l, maxLen) {
		return nil, 0, matErr("material field is malformed or too large")
	}
	start := n
	end := start + int(l) // #nosec G115 -- l <= maxLen (a non-negative int) verified by leWithin above
	if end > len(b) || end < start {
		return nil, 0, matErr("material field length overflows the buffer")
	}
	return b[start:end], end, nil
}

// leWithin reports whether v <= limit, treating a negative limit as unreachable. It
// centralizes the only uint64↔int comparison so the bound check is provably safe.
func leWithin(v uint64, limit int) bool {
	if limit < 0 {
		return false
	}
	return v <= uint64(limit) // #nosec G115 -- limit checked non-negative
}

func matErr(detail string) error {
	return mcperr.New(mcperr.ReasonProviderInvalidMaterial, "credentials.provider", detail)
}
