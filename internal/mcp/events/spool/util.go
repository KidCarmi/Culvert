package spool

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"syscall"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

// isENOSPC reports whether err is (or wraps) a no-space-left-on-device error.
func isENOSPC(err error) bool {
	return errors.Is(err, syscall.ENOSPC)
}

// unmarshalEvent strictly decodes canonical event bytes back into an Event. It
// rejects unknown fields so a tampered/foreign record cannot smuggle extra data
// past recovery.
func unmarshalEvent(b []byte, e *model.Event) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(e)
}

// peekSchemaVersion reads ONLY the envelope's schema version from an AUTHENTICATED
// record plaintext, leniently — no DisallowUnknownFields, no full-struct decode.
//
// That leniency is the entire point. The strict decode and the intrinsic digest both
// depend on knowing every field, so a record written by a NEWER build fails both
// before anything can observe that it is simply newer, and recovery reports SPOOL
// CORRUPTION — the alarm reserved for tampering and disk damage — on an ordinary
// version rollback. Reading one integer first is what lets the reader say "this
// record is newer than me". It is safe because the plaintext has already been
// authenticated by verifyRecord (AEAD open with the record's AAD); the intrinsic
// digest is a producer-bug backstop, not the tamper seal.
//
// ok is false when the plaintext is not even JSON, which is genuine corruption and
// is left to the strict decode to report as such.
func peekSchemaVersion(b []byte) (version int, ok bool) {
	var hdr struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(b, &hdr); err != nil {
		return 0, false
	}
	return hdr.SchemaVersion, true
}

// hexChain hex-encodes a 32-byte chain digest for durable metadata.
func hexChain(c [32]byte) string { return hex.EncodeToString(c[:]) }

// parseHexChain decodes a hex chain digest; a bad value yields the zero chain and
// false so recovery treats it as corrupt.
func parseHexChain(s string) ([32]byte, bool) {
	var out [32]byte
	if s == "" {
		return out, true // genesis
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, false
	}
	copy(out[:], b)
	return out, true
}
