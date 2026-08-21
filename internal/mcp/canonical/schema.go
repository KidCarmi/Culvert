package canonical

import (
	"bytes"
	"sort"
)

// setLikeKeywords are the ONLY JSON Schema keyword arrays the accepted design
// (TOOL-DISCOVERY-AND-DRIFT §1) defines as order-insensitive. Their member lists
// are sorted before hashing so a pure re-ordering does not register as drift.
// Every other array — tuple `items`, `examples`, `oneOf`, `allOf`, user data — is
// order-SENSITIVE and preserved, so a re-order that changes meaning is never
// hidden. `oneOf`/`allOf` are deliberately NOT sorted: the spec blesses only
// these three, and sorting an order-bearing array we don't understand could mask
// a behavioral change.
var setLikeKeywords = map[string]struct{}{
	"enum": {}, "required": {}, "anyOf": {},
}

// schemaSubschemaKeywords map JSON Schema keywords whose VALUE is itself a
// subschema (recursed as a schema, not as opaque data).
var schemaSubschemaKeywords = map[string]struct{}{
	"not": {}, "additionalProperties": {}, "propertyNames": {}, "items": {},
	"contains": {}, "additionalItems": {}, "if": {}, "then": {}, "else": {},
}

// schemaSubschemaMaps map keywords whose VALUE is an object of {name: subschema}.
var schemaSubschemaMaps = map[string]struct{}{
	"properties": {}, "patternProperties": {}, "$defs": {}, "definitions": {}, "dependentSchemas": {},
}

// schemaSchemaArrays map keywords whose VALUE is an array of subschemas.
var schemaSchemaArrays = map[string]struct{}{
	"anyOf": {}, "oneOf": {}, "allOf": {},
}

// DecodeSchema strictly decodes raw and returns its SCHEMA-canonical Node tree:
// the plain canonical form (sorted object keys, preserved arrays, exact numbers)
// with the reviewed set-like keyword arrays additionally sorted at every schema
// position. It is JSON-Schema-structure-aware — a property literally named "enum"
// under `properties` is a property name, never the enum keyword, so it is not
// sorted — and it falls back to plain canonicalization for any keyword outside the
// documented subset (fail-safe: unknown arrays are never sorted).
func DecodeSchema(raw []byte, b Bounds) (*Node, error) {
	n, err := Decode(raw, b)
	if err != nil {
		return nil, err
	}
	return schemaCanon(n), nil
}

// CanonicalizeSchema is DecodeSchema followed by deterministic serialization.
func CanonicalizeSchema(raw []byte, b Bounds) ([]byte, error) {
	n, err := DecodeSchema(raw, b)
	if err != nil {
		return nil, err
	}
	return Encode(n), nil
}

// HashSchema returns the SHA-256 of the schema-canonical form of raw.
func HashSchema(raw []byte, b Bounds) ([32]byte, error) {
	n, err := DecodeSchema(raw, b)
	if err != nil {
		return [32]byte{}, err
	}
	return HashNode(n), nil
}

// SchemaFromNode returns the SCHEMA-canonical form of an already plain-canonical
// Node (as produced by Decode). It lets a caller that decoded a larger document
// ONCE schema-canonicalize a sub-value (e.g. one tool's inputSchema) without a
// second hostile-input parse — the input here is the trusted canonical tree.
func SchemaFromNode(n *Node) *Node { return schemaCanon(n) }

// schemaCanon returns a schema-canonicalized copy of a plain-canonical node,
// treating n as a JSON Schema object. Non-objects are already canonical and
// returned unchanged.
func schemaCanon(n *Node) *Node {
	if n == nil || n.Kind != KindObject {
		return n
	}
	out := &Node{Kind: KindObject, Keys: make([]string, len(n.Keys)), Vals: make([]*Node, len(n.Vals))}
	copy(out.Keys, n.Keys) // keys already sorted by plain canonicalization
	for i, k := range n.Keys {
		out.Vals[i] = schemaChild(k, n.Vals[i])
	}
	return out
}

// schemaChild canonicalizes the value of one schema keyword according to the
// documented subset, defaulting to a plain (non-set-sorting) canonical value for
// any keyword we do not model — so an unknown keyword's arrays are preserved.
func schemaChild(key string, v *Node) *Node {
	switch {
	case key == "enum" || key == "required":
		return sortValueArray(v) // members are data (or strings); sort a copy
	case isKey(schemaSchemaArrays, key):
		return schemaArray(key, v)
	case isKey(schemaSubschemaMaps, key):
		return schemaMap(v)
	case isKey(schemaSubschemaKeywords, key):
		return schemaSubschema(v)
	default:
		return v // scalar keyword (type, minimum, …) or unknown: leave plain-canonical
	}
}

func isKey(m map[string]struct{}, k string) bool { _, ok := m[k]; return ok }

// schemaArray canonicalizes an array-of-subschemas keyword. Members are each
// schema-canonicalized; anyOf (set-like) is then sorted, oneOf/allOf keep order.
func schemaArray(key string, v *Node) *Node {
	if v.Kind != KindArray {
		return v // type-confused (e.g. anyOf: 5) — leave as-is, never crash
	}
	out := &Node{Kind: KindArray, Arr: make([]*Node, len(v.Arr))}
	for i, e := range v.Arr {
		out.Arr[i] = schemaCanon(e)
	}
	if _, set := setLikeKeywords[key]; set {
		sortNodesByEncoding(out.Arr)
	}
	return out
}

// schemaMap canonicalizes a {name: subschema} keyword value (e.g. properties):
// keys stay sorted (plain canon did that), each value is a subschema.
func schemaMap(v *Node) *Node {
	if v.Kind != KindObject {
		return v
	}
	out := &Node{Kind: KindObject, Keys: make([]string, len(v.Keys)), Vals: make([]*Node, len(v.Vals))}
	copy(out.Keys, v.Keys)
	for i := range v.Vals {
		out.Vals[i] = schemaCanon(v.Vals[i])
	}
	return out
}

// schemaSubschema canonicalizes a keyword whose value is a single subschema, an
// array of subschemas (tuple `items` — order preserved), or a boolean.
func schemaSubschema(v *Node) *Node {
	switch v.Kind {
	case KindObject:
		return schemaCanon(v)
	case KindArray:
		out := &Node{Kind: KindArray, Arr: make([]*Node, len(v.Arr))}
		for i, e := range v.Arr {
			out.Arr[i] = schemaCanon(e) // tuple items: canonicalize each, PRESERVE order
		}
		return out
	default:
		return v
	}
}

// sortValueArray returns a copy of an array node with its elements sorted by
// canonical encoding (used for the set-like data arrays enum/required). A
// non-array is returned unchanged (type confusion is not a crash).
func sortValueArray(v *Node) *Node {
	if v.Kind != KindArray {
		return v
	}
	out := &Node{Kind: KindArray, Arr: make([]*Node, len(v.Arr))}
	copy(out.Arr, v.Arr)
	sortNodesByEncoding(out.Arr)
	return out
}

// sortNodesByEncoding sorts nodes in place by their canonical serialization,
// giving a deterministic, content-defined order independent of input order.
func sortNodesByEncoding(nodes []*Node) {
	enc := make([][]byte, len(nodes))
	for i, n := range nodes {
		enc[i] = Encode(n)
	}
	idx := make([]int, len(nodes))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return bytes.Compare(enc[idx[a]], enc[idx[b]]) < 0 })
	orig := make([]*Node, len(nodes))
	copy(orig, nodes)
	for i, j := range idx {
		nodes[i] = orig[j]
	}
}
