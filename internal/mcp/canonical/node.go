package canonical

// Node is a decoded, canonicalized JSON value. It is the single in-memory form
// produced by the one strict decode path (Decode), consumed both by the
// deterministic serializer (Encode) and by the catalog schema differ — so a
// hostile discovery result is parsed exactly once and every downstream consumer
// sees the same trusted tree, never a second semantic parse.
//
// Objects are stored as PARALLEL, KEY-SORTED slices (Keys[i] ↔ Vals[i]) rather
// than a Go map: map iteration order is non-deterministic and is never used.
// Keys are unique (the decoder rejects duplicates) and sorted lexicographically
// by their raw UTF-8 bytes, so serialization is deterministic across processes,
// architectures and runs.
type Node struct {
	Kind Kind
	// scalar payloads (exactly one is meaningful per Kind)
	Bool bool
	Num  string // exact numeric token (json.Number); never routed through float64
	Str  string
	// composite payloads
	Arr  []*Node
	Keys []string // object keys, sorted ascending by raw bytes, unique
	Vals []*Node  // object values, parallel to Keys
}

// Kind is the JSON value kind of a Node.
type Kind uint8

const (
	// KindNull — a JSON null.
	KindNull Kind = iota
	// KindBool — a JSON boolean.
	KindBool
	// KindNumber — a JSON number, kept as its exact source token.
	KindNumber
	// KindString — a JSON string (UTF-8, validated).
	KindString
	// KindArray — a JSON array; element order is preserved unless a schema
	// set-like keyword explicitly sorts it.
	KindArray
	// KindObject — a JSON object with unique, byte-sorted keys.
	KindObject
)

// Clone returns a deep copy of the node: fresh slices and child nodes, sharing no
// mutable state with the original. It lets a snapshot hand out schema trees a
// caller can inspect (or even mutate) without corrupting the immutable stored
// tree or racing lock-free readers.
func (n *Node) Clone() *Node {
	if n == nil {
		return nil
	}
	out := &Node{Kind: n.Kind, Bool: n.Bool, Num: n.Num, Str: n.Str}
	if n.Arr != nil {
		out.Arr = make([]*Node, len(n.Arr))
		for i, e := range n.Arr {
			out.Arr[i] = e.Clone()
		}
	}
	if n.Keys != nil {
		out.Keys = make([]string, len(n.Keys))
		copy(out.Keys, n.Keys)
		out.Vals = make([]*Node, len(n.Vals))
		for i, v := range n.Vals {
			out.Vals[i] = v.Clone()
		}
	}
	return out
}

// Get returns the value for key and whether it is present. Keys are sorted, so
// this is a binary search — O(log n), deterministic, and allocation-free.
func (n *Node) Get(key string) (*Node, bool) {
	if n == nil || n.Kind != KindObject {
		return nil, false
	}
	lo, hi := 0, len(n.Keys)
	for lo < hi {
		mid := lo + (hi-lo)/2 // overflow-safe midpoint (no int↔uint conversion)
		switch {
		case n.Keys[mid] < key:
			lo = mid + 1
		case n.Keys[mid] > key:
			hi = mid
		default:
			return n.Vals[mid], true
		}
	}
	return nil, false
}

// Equal reports structural equality of two canonical trees. Because both sides
// are canonical, this is exact and order-independent for objects (keys are
// sorted) while remaining order-sensitive for arrays (as canonical form dictates).
func (n *Node) Equal(o *Node) bool {
	if n == nil || o == nil {
		return n == o
	}
	if n.Kind != o.Kind {
		return false
	}
	switch n.Kind {
	case KindNull:
		return true
	case KindBool:
		return n.Bool == o.Bool
	case KindNumber:
		return n.Num == o.Num
	case KindString:
		return n.Str == o.Str
	case KindArray:
		return n.arrayEqual(o)
	case KindObject:
		return n.objectEqual(o)
	default:
		return false
	}
}

func (n *Node) arrayEqual(o *Node) bool {
	if len(n.Arr) != len(o.Arr) {
		return false
	}
	for i := range n.Arr {
		if !n.Arr[i].Equal(o.Arr[i]) {
			return false
		}
	}
	return true
}

func (n *Node) objectEqual(o *Node) bool {
	if len(n.Keys) != len(o.Keys) {
		return false
	}
	for i := range n.Keys {
		if n.Keys[i] != o.Keys[i] || !n.Vals[i].Equal(o.Vals[i]) {
			return false
		}
	}
	return true
}
