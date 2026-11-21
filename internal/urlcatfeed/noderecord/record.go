package noderecord

import (
	"errors"
	"fmt"
	"hash/crc32"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// checksumHexLen is the stored checksum width: a CRC-32 printed with %08x.
const checksumHexLen = 8

// Canonical returns the canonical bytes of v: the feed protocol's canonical
// JSON (compact, HTML escaping disabled, fixed struct field order, no trailing
// newline). The returned slice is the caller's.
//
// An encode failure keeps the text the records' callers have always returned
// ("saas feed floor: canonical encode: ..."), wrapping the underlying
// encoding/json error, so the move from package main changes no message.
func Canonical(v any) ([]byte, error) {
	b, err := urlcatfeed.CanonicalJSON(v)
	if err != nil {
		cause := errors.Unwrap(err)
		if cause == nil {
			cause = err
		}
		return nil, fmt.Errorf("saas feed floor: canonical encode: %w", cause)
	}
	return b, nil
}

// Checksum returns the CRC-32C (Castagnoli) of canon as exactly 8 lowercase
// hex digits. It detects corruption; it does not authenticate.
func Checksum(canon []byte) string {
	// MakeTable returns the standard library's shared Castagnoli table, so
	// this is not a per-call table build and the package needs no variable.
	return fmt.Sprintf("%08x", crc32.Checksum(canon, crc32.MakeTable(crc32.Castagnoli)))
}

// Seal returns the checksum a record stores: Checksum over the canonical
// bytes of sansChecksum, the record's view with the checksum field ABSENT
// (not empty, not zero). The checksum is never computed over the full record.
func Seal(sansChecksum any) (string, error) {
	b, err := Canonical(sansChecksum)
	if err != nil {
		return "", err
	}
	return Checksum(b), nil
}

// ValidChecksum reports whether s has the stored checksum's form: exactly 8
// lowercase hex digits. It says nothing about whether the value matches.
func ValidChecksum(s string) bool {
	if len(s) != checksumHexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
