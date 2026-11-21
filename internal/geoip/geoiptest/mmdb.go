// Package geoiptest builds a minimal, valid MaxMind DB (.mmdb) file for tests.
//
// No GeoLite2 file ships in the tree (its licence does not allow it), so until
// this package every test of a LOADED database went through a seam. The file
// written here is a real MaxMind DB v2.0 that geoip2.Open accepts: an IPv4
// search tree with a single node that maps 0.0.0.0/1 to one country record and
// leaves 128.0.0.0/1 without data. Tests only; nothing in the product imports
// this package.
package geoiptest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

// MaxMind DB data-section type numbers (format specification v2.0).
const (
	typeString = 2
	typeUint16 = 5
	typeUint32 = 6
	typeMap    = 7
	typeUint64 = 9
	typeArray  = 11
)

// maxInlineSize is the first size that no longer fits a control byte.
const maxInlineSize = 29

// MatchedIP is an address inside the one network the file carries data for.
const MatchedIP = "1.2.3.4"

// UnmatchedIP is an address in the half of the tree that carries no data.
const UnmatchedIP = "200.1.2.3"

// control writes a field's control byte(s). Callers pass a type from the
// constants above and a size below 29, so the size fits the control byte's low
// five bits.
func control(b *bytes.Buffer, typ, size uint8) {
	if typ <= 7 {
		b.WriteByte(typ<<5 | size)
		return
	}
	b.WriteByte(size) // extended type: type bits are zero
	b.WriteByte(typ - 7)
}

func str(b *bytes.Buffer, s string) {
	control(b, typeString, uint8(len(s))) // #nosec G115 -- every string here is shorter than 29 bytes
	b.WriteString(s)
}

func uintField(b *bytes.Buffer, typ, width uint8, v uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], v)
	control(b, typ, width)
	b.Write(raw[8-width:])
}

// CountryDB returns the bytes of a GeoLite2-Country database whose only record
// maps 0.0.0.0/1 to the country (isoCode, name), built at the given time.
func CountryDB(isoCode, name string, built time.Time) ([]byte, error) {
	if len(isoCode) >= maxInlineSize || len(name) >= maxInlineSize {
		return nil, fmt.Errorf("geoiptest: country code and name must be shorter than 29 bytes")
	}
	const nodeCount = 1
	var b bytes.Buffer

	// Search tree: one node, two 24-bit records. Left (first bit 0) points at
	// data offset 0; a data pointer is nodeCount + 16 + offset. Right (first
	// bit 1) holds nodeCount, which means "no data".
	b.Write([]byte{0, 0, nodeCount + 16, 0, 0, nodeCount})
	b.Write(make([]byte, 16)) // data-section separator

	// Data section: {"country": {"iso_code": isoCode, "names": {"en": name}}}.
	control(&b, typeMap, 1)
	str(&b, "country")
	control(&b, typeMap, 2)
	str(&b, "iso_code")
	str(&b, isoCode)
	str(&b, "names")
	control(&b, typeMap, 1)
	str(&b, "en")
	str(&b, name)

	// Metadata.
	b.WriteString("\xab\xcd\xefMaxMind.com")
	control(&b, typeMap, 9)
	str(&b, "binary_format_major_version")
	uintField(&b, typeUint16, 2, 2)
	str(&b, "binary_format_minor_version")
	uintField(&b, typeUint16, 2, 0)
	str(&b, "build_epoch")
	epoch := built.Unix()
	if epoch < 0 {
		epoch = 0
	}
	uintField(&b, typeUint64, 8, uint64(epoch))
	str(&b, "database_type")
	str(&b, "GeoLite2-Country")
	str(&b, "description")
	control(&b, typeMap, 1)
	str(&b, "en")
	str(&b, "Culvert test database")
	str(&b, "ip_version")
	uintField(&b, typeUint16, 2, 4)
	str(&b, "languages")
	control(&b, typeArray, 1)
	str(&b, "en")
	str(&b, "node_count")
	uintField(&b, typeUint32, 4, nodeCount)
	str(&b, "record_size")
	uintField(&b, typeUint16, 2, 24)
	return b.Bytes(), nil
}

// WriteCountryDB writes CountryDB's bytes to path, replacing any existing file
// by rename so a reader never observes a partial database.
func WriteCountryDB(path, isoCode, name string, built time.Time) error {
	raw, err := CountryDB(isoCode, name, built)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("geoiptest: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("geoiptest: rename %s: %w", tmp, err)
	}
	return nil
}
