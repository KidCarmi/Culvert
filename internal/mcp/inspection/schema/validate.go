package schema

import (
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
)

// Validate checks value against the compiled schema and returns a stable Result.
// It performs bounded work (MaxValidationOps), compares numbers via exact
// rationals (never float64), and reports only a bounded JSON-pointer-like failure
// path — never a raw value. A nil value is treated as JSON null.
func (c *Compiled) Validate(value *canonical.Node) Result {
	vs := &valueState{lim: c.lim}
	if value == nil {
		value = &canonical.Node{Kind: canonical.KindNull}
	}
	st, path, detail := vs.validate(c.node, value, "")
	return Result{Status: st, Path: path, Detail: detail}
}

type valueState struct {
	lim interface{ MaxValidationOps() int } // narrow view — only the op bound
	ops int
}

func (vs *valueState) tick() bool {
	vs.ops++
	return vs.ops <= vs.lim.MaxValidationOps()
}

// validate returns (status, path, detail). path is "" for a valid result.
func (vs *valueState) validate(cn *compiledNode, v *canonical.Node, path string) (Status, string, string) {
	if !vs.tick() {
		return StatusLimitExceeded, path, "validation operations"
	}
	if cn.boolSchema {
		if cn.boolAccept {
			return StatusValid, "", ""
		}
		return StatusInvalid, path, "schema rejects all values"
	}
	if st, p, d, done := vs.checkTypeEnumConst(cn, v, path); done {
		return st, p, d
	}
	switch v.Kind {
	case canonical.KindObject:
		return vs.validateObject(cn, v, path)
	case canonical.KindArray:
		return vs.validateArray(cn, v, path)
	case canonical.KindString:
		return vs.validateString(cn, v, path)
	case canonical.KindNumber:
		return vs.validateNumber(cn, v, path)
	default:
		return StatusValid, "", ""
	}
}

// checkTypeEnumConst applies type/enum/const/anyOf; done==true short-circuits.
func (vs *valueState) checkTypeEnumConst(cn *compiledNode, v *canonical.Node, path string) (Status, string, string, bool) {
	if len(cn.types) > 0 && !typeMatches(cn.types, v) {
		return StatusInvalid, path, "type mismatch", true
	}
	if cn.konst != nil && !v.Equal(cn.konst) {
		return StatusInvalid, path, "const mismatch", true
	}
	if len(cn.enum) > 0 {
		ok := false
		for _, e := range cn.enum {
			if !vs.tick() {
				return StatusLimitExceeded, path, "validation operations", true
			}
			if v.Equal(e) {
				ok = true
				break
			}
		}
		if !ok {
			return StatusInvalid, path, "enum mismatch", true
		}
	}
	if len(cn.anyOf) > 0 {
		return vs.checkAnyOf(cn, v, path)
	}
	return StatusValid, "", "", false
}

func (vs *valueState) checkAnyOf(cn *compiledNode, v *canonical.Node, path string) (Status, string, string, bool) {
	for _, sub := range cn.anyOf {
		st, _, _ := vs.validate(sub, v, path)
		if st == StatusValid {
			return StatusValid, "", "", false // matched a branch; continue with siblings
		}
		if st == StatusLimitExceeded {
			return st, path, "validation operations", true
		}
	}
	return StatusInvalid, path, "no anyOf branch matched", true
}

func (vs *valueState) validateObject(cn *compiledNode, v *canonical.Node, path string) (Status, string, string) {
	// required members present
	for _, req := range cn.required {
		if !vs.tick() {
			return StatusLimitExceeded, path, "validation operations"
		}
		if _, ok := v.Get(req); !ok {
			return StatusInvalid, join(path, req), "missing required property"
		}
	}
	for i, k := range v.Keys {
		if !vs.tick() {
			return StatusLimitExceeded, join(path, k), "validation operations"
		}
		child := v.Vals[i]
		if sub, ok := cn.properties[k]; ok {
			if st, p, d := vs.validate(sub, child, join(path, k)); st != StatusValid {
				return st, p, d
			}
			continue
		}
		// additionalProperties handling
		if st, p, d, handled := vs.checkAdditional(cn, k, child, path); handled {
			if st != StatusValid {
				return st, p, d
			}
		}
	}
	return StatusValid, "", ""
}

func (vs *valueState) checkAdditional(cn *compiledNode, k string, child *canonical.Node, path string) (Status, string, string, bool) {
	if cn.addlIsBool {
		if !cn.addlBool {
			return StatusInvalid, join(path, k), "additional property not allowed", true
		}
		return StatusValid, "", "", true
	}
	if cn.addlIsNode {
		st, p, d := vs.validate(cn.addlNode, child, join(path, k))
		return st, p, d, true
	}
	return StatusValid, "", "", false
}

func (vs *valueState) validateArray(cn *compiledNode, v *canonical.Node, path string) (Status, string, string) {
	if cn.minItems != nil && int64(len(v.Arr)) < *cn.minItems {
		return StatusInvalid, path, "too few items"
	}
	if cn.maxItems != nil && int64(len(v.Arr)) > *cn.maxItems {
		return StatusInvalid, path, "too many items"
	}
	if cn.uniqueArr {
		seen := make(map[string]struct{}, len(v.Arr))
		for _, e := range v.Arr {
			if !vs.tick() {
				return StatusLimitExceeded, path, "validation operations"
			}
			kk := string(canonical.Encode(e))
			if _, dup := seen[kk]; dup {
				return StatusInvalid, path, "duplicate array item"
			}
			seen[kk] = struct{}{}
		}
	}
	if !cn.hasItems {
		return StatusValid, "", ""
	}
	return vs.validateItems(cn, v, path)
}

func (vs *valueState) validateItems(cn *compiledNode, v *canonical.Node, path string) (Status, string, string) {
	for i, e := range v.Arr {
		if !vs.tick() {
			return StatusLimitExceeded, joinIdx(path, i), "validation operations"
		}
		var sub *compiledNode
		switch {
		case cn.items != nil:
			sub = cn.items
		case i < len(cn.tuple):
			sub = cn.tuple[i]
		default:
			continue // tuple with no additional-items schema: extra elements unconstrained
		}
		if st, p, d := vs.validate(sub, e, joinIdx(path, i)); st != StatusValid {
			return st, p, d
		}
	}
	return StatusValid, "", ""
}

func (vs *valueState) validateString(cn *compiledNode, v *canonical.Node, path string) (Status, string, string) {
	rc := int64(utf8.RuneCountInString(v.Str))
	if cn.minLength != nil && rc < *cn.minLength {
		return StatusInvalid, path, "string shorter than minLength"
	}
	if cn.maxLength != nil && rc > *cn.maxLength {
		return StatusInvalid, path, "string longer than maxLength"
	}
	if cn.format != "" && !formatOK(cn.format, v.Str) {
		return StatusInvalid, path, "string does not match format"
	}
	return StatusValid, "", ""
}

func (vs *valueState) validateNumber(cn *compiledNode, v *canonical.Node, path string) (Status, string, string) {
	if cn.minimum != "" {
		if cmp, ok := canonical.NumCmp(v.Num, cn.minimum); !ok || cmp < 0 {
			return StatusInvalid, path, "below minimum"
		}
	}
	if cn.maximum != "" {
		if cmp, ok := canonical.NumCmp(v.Num, cn.maximum); !ok || cmp > 0 {
			return StatusInvalid, path, "above maximum"
		}
	}
	if cn.exclusiveMinimum != "" {
		if cmp, ok := canonical.NumCmp(v.Num, cn.exclusiveMinimum); !ok || cmp <= 0 {
			return StatusInvalid, path, "at or below exclusiveMinimum"
		}
	}
	if cn.exclusiveMaximum != "" {
		if cmp, ok := canonical.NumCmp(v.Num, cn.exclusiveMaximum); !ok || cmp >= 0 {
			return StatusInvalid, path, "at or above exclusiveMaximum"
		}
	}
	return StatusValid, "", ""
}

// typeMatches reports whether v satisfies any allowed JSON type name.
func typeMatches(types []string, v *canonical.Node) bool {
	for _, t := range types {
		if oneTypeMatches(t, v) {
			return true
		}
	}
	return false
}

func oneTypeMatches(t string, v *canonical.Node) bool {
	switch t {
	case "object":
		return v.Kind == canonical.KindObject
	case "array":
		return v.Kind == canonical.KindArray
	case "string":
		return v.Kind == canonical.KindString
	case "boolean":
		return v.Kind == canonical.KindBool
	case "null":
		return v.Kind == canonical.KindNull
	case "number":
		return v.Kind == canonical.KindNumber
	case "integer":
		return v.Kind == canonical.KindNumber && isIntegerToken(v.Num)
	}
	return false
}

// isIntegerToken reports whether an exact numeric token is integer-valued
// (5, 5.0, 5e0 all true) using exact rationals — never float64.
func isIntegerToken(tok string) bool {
	r, ok := new(big.Rat).SetString(tok)
	if !ok {
		return false
	}
	return r.IsInt()
}

// join appends an object key to a JSON-pointer-like path with ~ escaping.
func join(path, key string) string {
	return path + "/" + escapePtr(key)
}

func joinIdx(path string, i int) string {
	return path + "/" + strconv.Itoa(i)
}

// escapePtr applies RFC 6901 escaping and bounds the segment so a hostile key can
// never blow up the path (the path is safe evidence, never the value).
func escapePtr(k string) string {
	if len(k) > 64 {
		k = k[:64]
	}
	k = strings.ReplaceAll(k, "~", "~0")
	k = strings.ReplaceAll(k, "/", "~1")
	return k
}
