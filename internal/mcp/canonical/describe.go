package canonical

import (
	"crypto/sha256"
	"strings"
	"unicode"
	"unicode/utf8"
)

// NormalizeDescription applies the one exact, whitespace-only normalization the
// description hash is defined over:
//
//   - reject invalid UTF-8;
//   - trim leading/trailing Unicode whitespace;
//   - collapse each internal run of Unicode whitespace to a single ASCII space;
//   - preserve case, punctuation and every non-whitespace code point exactly.
//
// It performs NO Unicode normalization (NFC/NFKC), case folding or semantic
// rewriting: a change to the description's actual content can never be hidden by
// normalization — only cosmetic whitespace re-wrapping is absorbed. maxBytes
// bounds the input; an over-bound or non-UTF-8 description is rejected.
func NormalizeDescription(s string, maxBytes int) (string, error) {
	if maxBytes <= 0 || len(s) > maxBytes {
		return "", resourceLimit("description bytes")
	}
	if !utf8.ValidString(s) {
		return "", malformed("description is not valid UTF-8")
	}
	var b strings.Builder
	b.Grow(len(s))
	inRun := false // currently inside a whitespace run
	started := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			inRun = true
			continue
		}
		if inRun && started {
			b.WriteByte(' ') // one ASCII space between tokens (leading run is dropped)
		}
		inRun = false
		started = true
		b.WriteRune(r)
	}
	return b.String(), nil
}

// HashDescription returns the SHA-256 of the normalized description.
func HashDescription(s string, maxBytes int) ([32]byte, error) {
	norm, err := NormalizeDescription(s, maxBytes)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256([]byte(norm)), nil
}
