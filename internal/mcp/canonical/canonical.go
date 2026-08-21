// Package canonical turns already-received (never network-fetched) JSON and JSON
// Schema bytes into ONE deterministic canonical form and its SHA-256 hash, so the
// tool catalog can fingerprint tools and detect drift independent of cosmetic
// re-formatting. It is a pure, listener-independent leaf: it binds no socket,
// makes no outbound call, and shares the PR-1 error model (mcperr).
//
// The three load-bearing properties, all asserted by tests:
//
//   - Determinism. The same value canonicalizes to the same bytes on every
//     process, architecture and run — object keys are byte-sorted, Go map
//     iteration order is never used, and numbers keep their exact source token
//     (never rounded through float64).
//   - Single semantic parse. Hostile bytes pass through exactly one strict decode
//     (Decode → *Node); every consumer walks that trusted tree. There is no
//     second, differently-behaving decoder on the same input.
//   - Set-like vs ordered arrays. Only the reviewed JSON Schema set-like keyword
//     arrays (enum, required, anyOf) are sorted (CanonicalizeSchema); every other
//     array (tuples, examples, user data) preserves order, so re-ordering that
//     changes meaning is never hidden.
package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/big"
	"sort"
	"unicode/utf8"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Bounds are the structural limits the decoder enforces so a hostile input can
// never drive unbounded allocation, recursion or work. A zero Bounds rejects
// everything (fail closed); callers pass a validated set derived from
// limits.CatalogLimits.
type Bounds struct {
	MaxBytes         int // max bytes of the whole input
	MaxDepth         int // max JSON nesting depth
	MaxObjectMembers int // max members in any one object
	MaxArrayElements int // max elements in any one array
	MaxStringBytes   int // max bytes of any one string or number token
}

func malformed(detail string) error {
	return mcperr.New(mcperr.ReasonMalformedJSON, "canonical", detail)
}

func canonFail(detail string) error {
	return mcperr.New(mcperr.ReasonCanonicalizationFailed, "canonical", detail)
}

func resourceLimit(detail string) error {
	return mcperr.New(mcperr.ReasonResourceLimit, "canonical", detail)
}

// Decode strictly validates raw and returns its canonical Node tree. It rejects
// empty input, over-bound frames, invalid UTF-8, unpaired surrogate escapes,
// duplicate object keys, trailing data / multiple top-level values, and any value
// exceeding the structural bounds. It never panics on arbitrary input and never
// echoes hostile bytes in its error.
func Decode(raw []byte, b Bounds) (*Node, error) {
	if len(raw) == 0 {
		return nil, malformed("empty input")
	}
	if b.MaxBytes <= 0 || len(raw) > b.MaxBytes {
		return nil, resourceLimit("input bytes")
	}
	if !utf8.Valid(raw) {
		return nil, malformed("invalid UTF-8")
	}
	if err := rejectUnpairedSurrogateEscapes(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // exact numbers; never float64
	d := &decoder{dec: dec, b: b}
	root, err := d.value(1)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, canonFail("trailing bytes or multiple top-level values")
	}
	return root, nil
}

// Canonicalize is Decode followed by the deterministic serialization: it returns
// the canonical bytes for raw. Object keys are sorted; arrays keep their order.
func Canonicalize(raw []byte, b Bounds) ([]byte, error) {
	n, err := Decode(raw, b)
	if err != nil {
		return nil, err
	}
	return Encode(n), nil
}

// Hash returns the SHA-256 of the canonical form of raw. Equal canonical form ⇒
// equal hash is the fingerprint invariant the catalog relies on.
func Hash(raw []byte, b Bounds) ([32]byte, error) {
	n, err := Decode(raw, b)
	if err != nil {
		return [32]byte{}, err
	}
	return HashNode(n), nil
}

// HashNode returns the SHA-256 of a node's canonical serialization.
func HashNode(n *Node) [32]byte {
	return sha256.Sum256(Encode(n))
}

// decoder walks the json.Decoder token stream into a Node tree under Bounds.
type decoder struct {
	dec *json.Decoder
	b   Bounds
}

func (d *decoder) value(depth int) (*Node, error) {
	if depth > d.b.MaxDepth {
		return nil, resourceLimit("nesting depth")
	}
	t, err := d.dec.Token()
	if err != nil {
		return nil, malformed("not well-formed JSON")
	}
	switch tok := t.(type) {
	case json.Delim:
		switch tok {
		case '{':
			return d.object(depth)
		case '[':
			return d.array(depth)
		default:
			return nil, malformed("unbalanced delimiter")
		}
	case string:
		if len(tok) > d.b.MaxStringBytes {
			return nil, resourceLimit("string length")
		}
		return &Node{Kind: KindString, Str: tok}, nil
	case json.Number:
		if len(tok) > d.b.MaxStringBytes {
			return nil, resourceLimit("number token length")
		}
		return &Node{Kind: KindNumber, Num: tok.String()}, nil
	case bool:
		return &Node{Kind: KindBool, Bool: tok}, nil
	case nil:
		return &Node{Kind: KindNull}, nil
	default:
		return nil, malformed("unexpected token")
	}
}

func (d *decoder) object(depth int) (*Node, error) {
	type kv struct {
		k string
		v *Node
	}
	var pairs []kv
	seen := map[string]struct{}{}
	for d.dec.More() {
		kt, err := d.dec.Token()
		if err != nil {
			return nil, malformed("bad object key")
		}
		key, ok := kt.(string)
		if !ok {
			return nil, malformed("non-string object key")
		}
		if len(key) > d.b.MaxStringBytes {
			return nil, resourceLimit("object key length")
		}
		if len(pairs)+1 > d.b.MaxObjectMembers {
			return nil, resourceLimit("object member count")
		}
		if _, dup := seen[key]; dup {
			return nil, malformed("duplicate object key")
		}
		seen[key] = struct{}{}
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, kv{key, v})
	}
	if _, err := d.dec.Token(); err != nil { // consume '}'
		return nil, malformed("unterminated object")
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })
	n := &Node{Kind: KindObject, Keys: make([]string, len(pairs)), Vals: make([]*Node, len(pairs))}
	for i, p := range pairs {
		n.Keys[i] = p.k
		n.Vals[i] = p.v
	}
	return n, nil
}

func (d *decoder) array(depth int) (*Node, error) {
	var elems []*Node
	for d.dec.More() {
		if len(elems)+1 > d.b.MaxArrayElements {
			return nil, resourceLimit("array element count")
		}
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		elems = append(elems, v)
	}
	if _, err := d.dec.Token(); err != nil { // consume ']'
		return nil, malformed("unterminated array")
	}
	return &Node{Kind: KindArray, Arr: elems}, nil
}

// Encode serializes a canonical Node to deterministic JSON bytes: object keys in
// sorted order, arrays in stored order, numbers as their exact token, strings via
// the canonical escaper. The output re-decodes to an Equal tree (round-trip).
func Encode(n *Node) []byte {
	var b bytes.Buffer
	encodeNode(&b, n)
	return b.Bytes()
}

func encodeNode(b *bytes.Buffer, n *Node) {
	if n == nil {
		b.WriteString("null")
		return
	}
	switch n.Kind {
	case KindNull:
		b.WriteString("null")
	case KindBool:
		if n.Bool {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case KindNumber:
		b.WriteString(n.Num)
	case KindString:
		encodeString(b, n.Str)
	case KindArray:
		b.WriteByte('[')
		for i, e := range n.Arr {
			if i > 0 {
				b.WriteByte(',')
			}
			encodeNode(b, e)
		}
		b.WriteByte(']')
	case KindObject:
		b.WriteByte('{')
		for i, k := range n.Keys {
			if i > 0 {
				b.WriteByte(',')
			}
			encodeString(b, k)
			b.WriteByte(':')
			encodeNode(b, n.Vals[i])
		}
		b.WriteByte('}')
	}
}

// encodeString writes a deterministic JSON string literal. The input is already
// valid UTF-8 (the decoder checked); control bytes and the two structural
// characters (" and \) are escaped, everything else is emitted verbatim. This
// escaping is fixed and independent of encoding/json's HTML-escaping mode.
func encodeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20:
			b.WriteString(`\u00`)
			const hex = "0123456789abcdef"
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
}

// NumCmp returns -1, 0, +1 comparing two exact numeric tokens by value (so
// "1" == "1.0" == "1e0"), using exact rationals so there is no float64 rounding.
// ok is false if either token is not a value big.Rat accepts. The canonical hash
// still preserves the exact token — this comparator is used only by the schema
// differ to decide whether a numeric BOUND tightened or relaxed.
func NumCmp(a, b string) (int, bool) {
	ra, ok1 := new(big.Rat).SetString(a)
	rb, ok2 := new(big.Rat).SetString(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	return ra.Cmp(rb), true
}
