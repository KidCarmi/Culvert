package policy

import (
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Condition operators (the closed matcher vocabulary). There is deliberately NO
// regular-expression operator in V1; glob is the only pattern operator, and it is
// anchored + bounded + backtracking-free.
const (
	opExact       = "exact"        // scalar string/enum equality
	opOneOf       = "one_of"       // scalar ∈ an explicit set (values OR'd)
	opPrefix      = "prefix"       // scalar has the given prefix
	opGlob        = "glob"         // scalar matches an anchored, bounded glob
	opContains    = "contains"     // a set field contains the value
	opContainsAny = "contains_any" // a set field intersects the value set
	opBool        = "bool"         // a bool field equals the value ("true"/"false")
	opMinAssur    = "min_assurance"
	opMaxPower    = "max_power" // a power field is at most the ceiling
	opMinPower    = "min_power" // a power field is at least the floor
	opTimeWindow  = "time_window"
)

// fieldKind is the value kind of a policy field, constraining which operators apply.
type fieldKind uint8

const (
	kindString fieldKind = iota
	kindSet
	kindBool
	kindAssurance
	kindPower
	kindTime
)

// compiledCond is a compiled condition: a stable id (for the explain trace) plus a
// PURE match closure over the immutable input. The closure is built from a CLOSED
// (field, op) vocabulary — it is not a free-form executable expression.
type compiledCond struct {
	id    string
	match func(*DecisionInput) bool
}

// rawCondition is the parsed (pre-compile) condition form.
type rawCondition struct {
	Field  string   `json:"field"`
	Op     string   `json:"op"`
	Value  string   `json:"value,omitempty"`
	Values []string `json:"values,omitempty"`
	Start  string   `json:"start,omitempty"`
	End    string   `json:"end,omitempty"`
}

func condErr(detail string) error {
	return mcperr.New(mcperr.ReasonPolicyConditionInvalid, "policy.condition", detail)
}

// compileCondition validates a raw condition against the closed field/op vocabulary
// and the limits, then builds its pure match closure. It rejects unknown fields,
// incompatible operators, over-limit value sets/strings and malformed patterns.
func compileCondition(rc rawCondition, lim Limits) (compiledCond, error) {
	kind, ok := fieldKinds[rc.Field]
	attrKey := ""
	if !ok {
		// resource.attr:<key> is the one parameterized field family.
		if k, key, isAttr := resourceAttrField(rc.Field); isAttr {
			kind, attrKey = k, key
		} else {
			return compiledCond{}, condErr("unknown condition field")
		}
	}
	id := rc.Field + "|" + rc.Op
	switch kind {
	case kindString:
		return compileStringCond(rc, lim, id, attrKey)
	case kindSet:
		return compileSetCond(rc, lim, id)
	case kindBool:
		return compileBoolCond(rc, id)
	case kindAssurance:
		return compileAssuranceCond(rc, id)
	case kindPower:
		return compilePowerCond(rc, id)
	case kindTime:
		return compileTimeCond(rc, id)
	default:
		return compiledCond{}, condErr("unsupported field kind")
	}
}

func compileStringCond(rc rawCondition, lim Limits, id, attrKey string) (compiledCond, error) {
	get := func(in *DecisionInput) (string, bool) {
		if attrKey != "" {
			return resourceAttr(in, attrKey)
		}
		return stringFields[rc.Field](in)
	}
	switch rc.Op {
	case opExact:
		if err := boundStr(rc.Value, lim); err != nil {
			return compiledCond{}, err
		}
		want := rc.Value
		return compiledCond{id, func(in *DecisionInput) bool {
			v, ok := get(in)
			return ok && v == want
		}}, nil
	case opOneOf:
		set, err := boundSet(rc.Values, lim)
		if err != nil {
			return compiledCond{}, err
		}
		return compiledCond{id, func(in *DecisionInput) bool {
			v, ok := get(in)
			if !ok {
				return false
			}
			_, hit := set[v]
			return hit
		}}, nil
	case opPrefix:
		if err := boundStr(rc.Value, lim); err != nil {
			return compiledCond{}, err
		}
		want := rc.Value
		return compiledCond{id, func(in *DecisionInput) bool {
			v, ok := get(in)
			return ok && strings.HasPrefix(v, want)
		}}, nil
	case opGlob:
		g, err := compileGlob(rc.Value, lim)
		if err != nil {
			return compiledCond{}, err
		}
		return compiledCond{id, func(in *DecisionInput) bool {
			v, ok := get(in)
			return ok && g.match(v)
		}}, nil
	default:
		return compiledCond{}, condErr("operator not valid for a string field")
	}
}

func compileSetCond(rc rawCondition, lim Limits, id string) (compiledCond, error) {
	get := setFields[rc.Field]
	switch rc.Op {
	case opContains:
		if err := boundStr(rc.Value, lim); err != nil {
			return compiledCond{}, err
		}
		want := rc.Value
		return compiledCond{id, func(in *DecisionInput) bool {
			for _, v := range get(in) {
				if v == want {
					return true
				}
			}
			return false
		}}, nil
	case opContainsAny:
		set, err := boundSet(rc.Values, lim)
		if err != nil {
			return compiledCond{}, err
		}
		return compiledCond{id, func(in *DecisionInput) bool {
			for _, v := range get(in) {
				if _, hit := set[v]; hit {
					return true
				}
			}
			return false
		}}, nil
	default:
		return compiledCond{}, condErr("operator not valid for a set field")
	}
}

func compileBoolCond(rc rawCondition, id string) (compiledCond, error) {
	if rc.Op != opBool {
		return compiledCond{}, condErr("operator not valid for a bool field")
	}
	var want bool
	switch rc.Value {
	case "true":
		want = true
	case "false":
		want = false
	default:
		return condErrCond("bool condition value must be \"true\" or \"false\"")
	}
	get := boolFields[rc.Field]
	return compiledCond{id, func(in *DecisionInput) bool { return get(in) == want }}, nil
}

func compileAssuranceCond(rc rawCondition, id string) (compiledCond, error) {
	if rc.Op != opMinAssur {
		return compiledCond{}, condErr("operator not valid for an assurance field")
	}
	floor, ok := parseAssurance(rc.Value)
	if !ok {
		return compiledCond{}, condErr("invalid assurance level")
	}
	get := assuranceFields[rc.Field]
	return compiledCond{id, func(in *DecisionInput) bool { return get(in) >= floor }}, nil
}

func compilePowerCond(rc rawCondition, id string) (compiledCond, error) {
	want, ok := parsePower(rc.Value)
	if !ok || want == PowerUnset {
		return compiledCond{}, condErr("invalid credential power")
	}
	get := powerFields[rc.Field]
	switch rc.Op {
	case opMaxPower:
		return compiledCond{id, func(in *DecisionInput) bool {
			p := get(in)
			return p != PowerUnset && p <= want
		}}, nil
	case opMinPower:
		return compiledCond{id, func(in *DecisionInput) bool {
			p := get(in)
			return p != PowerUnset && p >= want
		}}, nil
	default:
		return compiledCond{}, condErr("operator not valid for a power field")
	}
}

func compileTimeCond(rc rawCondition, id string) (compiledCond, error) {
	if rc.Op != opTimeWindow || rc.Field != "time" {
		return compiledCond{}, condErr("operator not valid for the time field")
	}
	start, err := time.Parse(time.RFC3339, rc.Start)
	if err != nil {
		return compiledCond{}, condErr("invalid time-window start (RFC3339 UTC required)")
	}
	end, err := time.Parse(time.RFC3339, rc.End)
	if err != nil {
		return compiledCond{}, condErr("invalid time-window end (RFC3339 UTC required)")
	}
	start, end = start.UTC(), end.UTC()
	if !end.After(start) {
		return compiledCond{}, condErr("time-window end must be after start")
	}
	return compiledCond{id, func(in *DecisionInput) bool {
		t := in.EvalTime.UTC()
		return !t.Before(start) && !t.After(end)
	}}, nil
}

func condErrCond(detail string) (compiledCond, error) { return compiledCond{}, condErr(detail) }

func boundStr(s string, lim Limits) error {
	if len(s) > lim.MaxStringBytes() {
		return condErr("condition string value exceeds the byte bound")
	}
	return nil
}

func boundSet(values []string, lim Limits) (map[string]struct{}, error) {
	if len(values) == 0 {
		return nil, condErr("set operator requires a non-empty value set")
	}
	if len(values) > lim.MaxSetValues() {
		return nil, condErr("condition value set exceeds the bound")
	}
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		if len(v) > lim.MaxStringBytes() {
			return nil, condErr("condition set value exceeds the byte bound")
		}
		set[v] = struct{}{}
	}
	return set, nil
}
