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
