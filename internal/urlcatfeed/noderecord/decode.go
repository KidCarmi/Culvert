package noderecord

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Envelope is one record kind's size bound and the errors it answers an
// envelope refusal with. The record's owner supplies its own sentinels, so a
// caller's errors.Is against them keeps working and no two record kinds share
// an error value.
type Envelope struct {
	// Name prefixes a strict-decode refusal: "<Name>: decode: <cause>".
	Name string
	// MaxBytes is the largest accepted record, inclusive.
	MaxBytes int

	Empty        error // zero-length input
	Oversize     error // longer than MaxBytes; wrapped as "<Oversize>: <len> > <MaxBytes>"
	Trailing     error // a second JSON value follows the record
	Noncanonical error // the bytes are not the record's canonical bytes
}

// Decode accepts data as one T only if it is, byte for byte, T's canonical
// record. The steps run in this order, and the first refusal is returned:
//
//  1. zero length: e.Empty.
//  2. longer than e.MaxBytes: e.Oversize, wrapped with both lengths.
//  3. strict JSON decode (unknown fields refused): "<e.Name>: decode: ...",
//     wrapping encoding/json's error.
//  4. another JSON value after the record: e.Trailing.
//  5. re-encoding the decoded value with Canonical does not reproduce data:
//     e.Noncanonical. This is the check that refuses reordered or duplicate
//     keys, whitespace, HTML escaping and alternate scalar encodings.
//
// On refusal the returned T is the zero value. Decode does not validate
// fields and does not check the seal: the record's owner does both next.
//
// Decode never reports success for a refused input. A sentinel left nil in e
// is answered with an unnamed error, not with nil.
func Decode[T any](data []byte, e Envelope) (T, error) {
	var zero T
	if len(data) == 0 {
		return zero, refusal(e.Empty, "empty record")
	}
	if len(data) > e.MaxBytes {
		return zero, fmt.Errorf("%w: %d > %d", refusal(e.Oversize, "record exceeds max size"), len(data), e.MaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rec T
	if err := dec.Decode(&rec); err != nil {
		return zero, fmt.Errorf("%s: decode: %w", e.Name, err)
	}
	if dec.More() {
		return zero, refusal(e.Trailing, "trailing data after record")
	}
	canon, err := Canonical(rec)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(canon, data) {
		return zero, refusal(e.Noncanonical, "record is not in canonical form")
	}
	return rec, nil
}

// refusal returns the owner's sentinel, or an unnamed error when the owner
// left it nil, so a missing sentinel can never turn a refusal into success.
func refusal(sentinel error, what string) error {
	if sentinel != nil {
		return sentinel
	}
	return errors.New("noderecord: " + what)
}
