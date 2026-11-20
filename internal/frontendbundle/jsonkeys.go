package frontendbundle

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// rejectDuplicateJSONKeys walks the raw JSON token stream and
// rejects duplicate keys in ANY object (top-level manifest keys and chunk
// fields alike) — the generic decoder's last-value-wins behavior must never
// hide an ambiguous build artifact. Iterative (explicit frame stack): a
// hostile deeply-nested document cannot recurse the goroutine stack.
func rejectDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var sc dupKeyScanner
	for {
		tok, err := dec.Token()
		if err != nil {
			// io.EOF ends a well-formed document; malformed JSON is caught
			// again (with a stable message) by the real decode.
			return nil //nolint:nilerr // malformed JSON is rejected by the caller's Unmarshal
		}
		if err := sc.step(tok); err != nil {
			return err
		}
	}
}

// dupKeyScanner holds the explicit frame stack for the duplicate-key
// walk; one step processes one JSON token.
type dupKeyScanner struct {
	stack []*jsonFrame
}

type jsonFrame struct {
	isObject  bool
	expectKey bool
	keys      map[string]bool
}

func (sc *dupKeyScanner) top() *jsonFrame {
	if len(sc.stack) == 0 {
		return nil
	}
	return sc.stack[len(sc.stack)-1]
}

// afterValue marks that the current object (if any) expects a key next.
func (sc *dupKeyScanner) afterValue() {
	if f := sc.top(); f != nil && f.isObject {
		f.expectKey = true
	}
}

func (sc *dupKeyScanner) step(tok json.Token) error {
	switch t := tok.(type) {
	case json.Delim:
		sc.stepDelim(t)
	case string:
		if f := sc.top(); f != nil && f.isObject && f.expectKey {
			if f.keys[t] {
				return fmt.Errorf("manifest.json has a duplicate object key")
			}
			f.keys[t] = true
			f.expectKey = false
			return nil
		}
		sc.afterValue()
	default:
		sc.afterValue()
	}
	return nil
}

func (sc *dupKeyScanner) stepDelim(t json.Delim) {
	switch t {
	case '{':
		sc.stack = append(sc.stack, &jsonFrame{isObject: true, expectKey: true, keys: map[string]bool{}})
	case '[':
		sc.stack = append(sc.stack, &jsonFrame{})
	case '}', ']':
		sc.stack = sc.stack[:len(sc.stack)-1]
		sc.afterValue()
	}
}
