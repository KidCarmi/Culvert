package urlcatfeed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Strict + canonical JSON handling (Finding 1). The producer and the verifier
// share ONE canonical encoder and ONE strict decoder so a signed document is
// accepted only if it is byte-for-byte the exact canonical form the producer
// emits. This closes the gaps DisallowUnknownFields alone leaves open: trailing
// values, duplicate keys, non-canonical field order/whitespace, HTML escaping,
// and alternate encodings that decode to the same struct.

var (
	// ErrJSONTrailing marks input with more than one JSON value.
	ErrJSONTrailing = errors.New("urlcatfeed: trailing data after JSON value")
	// ErrJSONDuplicateKey marks a duplicate object key at any nesting depth.
	ErrJSONDuplicateKey = errors.New("urlcatfeed: duplicate JSON object key")
	// ErrNoncanonical marks a signed document whose bytes are not the exact
	// canonical serialization of their decoded value.
	ErrNoncanonical = errors.New("urlcatfeed: document is not in canonical form")
)

// canonicalJSON is the ONE canonical encoder: compact, HTML-escaping DISABLED
// (so '<', '>', '&' are emitted literally — the "escape-free" contract is now
// actually implemented and pinned by golden tests), no trailing newline. Struct
// inputs have fixed field order and pre-sorted, deduplicated slices, so the bytes
// are deterministic across runs and platforms.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("urlcatfeed: canonical encode: %w", err)
	}
	b := buf.Bytes()
	// Encoder.Encode appends exactly one '\n'; strip it for the canonical form.
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	return append([]byte(nil), b...), nil
}

// strictUnmarshal decodes exactly one JSON value into v with: unknown fields
// rejected, duplicate object keys rejected (any depth), and a required EOF after
// the single value (no trailing data). It does NOT enforce canonical byte form —
// callers that verify signed documents additionally call requireCanonical.
func strictUnmarshal(data []byte, v any) error {
	if err := scanStrict(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// requireCanonical asserts that data is byte-identical to the canonical
// serialization of the value it decoded into (v must already hold the decoded
// value). This is the belt-and-suspenders that rejects field reordering,
// whitespace, HTML escaping, and alternate scalar encodings on SIGNED documents.
func requireCanonical(data []byte, v any) error {
	canon, err := canonicalJSON(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(canon, data) {
		return ErrNoncanonical
	}
	return nil
}

// scanStrict walks the token stream once, rejecting duplicate object keys at any
// depth and requiring exactly one top-level value followed by EOF.
func scanStrict(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := scanValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrJSONTrailing
	}
	return nil
}

// scanValue consumes one JSON value, recursing into objects/arrays and rejecting
// duplicate keys within each object.
func scanValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar consumed
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := kt.(string)
			if !ok {
				return fmt.Errorf("urlcatfeed: non-string object key")
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("%w: %q", ErrJSONDuplicateKey, key)
			}
			seen[key] = struct{}{}
			if err := scanValue(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // closing '}'
			return err
		}
	case '[':
		for dec.More() {
			if err := scanValue(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // closing ']'
			return err
		}
	}
	return nil
}
