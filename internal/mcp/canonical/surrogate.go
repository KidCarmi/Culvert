package canonical

// This file re-implements the byte-level unpaired-surrogate rejection that the
// PR-1 jsonrpc decoder also carries. The duplication is deliberate and bounded:
// the algorithm is a pure, individually-tested function over raw bytes with no
// JSON-RPC-envelope semantics, and canonical must reject the same class up front
// so that two distinct escaped strings ("\ud800" and "\udc00") cannot decode to
// the same U+FFFD and collapse to the same hash. Keeping a local copy (with the
// canonical error op) avoids exporting an envelope-shaped helper from jsonrpc;
// both copies are pinned by their own tests so they cannot silently drift.

// rejectUnpairedSurrogateEscapes rejects any \uXXXX escape naming a high
// surrogate not immediately followed by a \u low surrogate, and any lone low
// surrogate. A `\\` escapes the backslash, so literal "\\uD800" data is skipped.
func rejectUnpairedSurrogateEscapes(raw []byte) error {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		if i+1 >= len(raw) {
			break
		}
		if raw[i+1] != 'u' {
			i++
			continue
		}
		consumed, err := checkUnicodeEscape(raw, i)
		if err != nil {
			return err
		}
		i += consumed
	}
	return nil
}

// checkUnicodeEscape validates the \uXXXX escape at raw[i] and returns the number
// of extra bytes to advance (5 for a lone escape, 11 for a valid surrogate pair);
// the caller's loop adds the final +1.
func checkUnicodeEscape(raw []byte, i int) (int, error) {
	hi, ok := hex4(raw, i+2)
	if !ok {
		return 0, malformed("malformed \\u escape")
	}
	if hi >= 0xDC00 && hi <= 0xDFFF {
		return 0, malformed("lone low surrogate escape")
	}
	if hi < 0xD800 || hi > 0xDBFF {
		return 5, nil
	}
	if i+6 >= len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
		return 0, malformed("unpaired high surrogate escape")
	}
	lo, ok := hex4(raw, i+8)
	if !ok || lo < 0xDC00 || lo > 0xDFFF {
		return 0, malformed("unpaired high surrogate escape")
	}
	return 11, nil
}

// hex4 reads exactly four hex digits at raw[pos:pos+4].
func hex4(raw []byte, pos int) (int, bool) {
	if pos+4 > len(raw) {
		return 0, false
	}
	v := 0
	for i := 0; i < 4; i++ {
		c := raw[pos+i]
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | int(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | int(c-'a'+10)
		case c >= 'A' && c <= 'F':
			v = v<<4 | int(c-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}
