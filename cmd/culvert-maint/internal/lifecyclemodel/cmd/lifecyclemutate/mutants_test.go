//go:build lifecycle_conformance

package main

import (
	"reflect"
	"testing"
)

func ops(line string) []string {
	var out []string
	for _, m := range lineMutants("f.go", 1, line) {
		out = append(out, m.Op+" => "+m.New)
	}
	return out
}

func TestLineMutants(t *testing.T) {
	for line, want := range map[string][]string{
		// never inside string, rune or raw-string literals, never inside comments
		`	x := "a == b && true" // c != d`: nil,
		"	y := `a >= b` + 'x'":             nil,
		`	s := "esc \" == " // done`:       nil,
		`// if a == b {`:                   nil,
		`	return a == b // a != b`:         {`== -> != => 	return a != b // a != b`},
		// whole identifiers only
		`	ok := true || isfalse(trueish)`: {`|| -> && => 	ok := true && isfalse(trueish)`, `true -> false => 	ok := false || isfalse(trueish)`},
		// `>` and `<` are not found inside ->, <-, >=, <=, << (the first `>` of `>>` is: kept
		// as the campaign has always sampled it, so results stay comparable)
		`	ch <- v << 1`: nil,
		`	v >> 2`:       {`> -> >= => 	v >=> 2`},
		`	a >= b`:       {`>= -> > => 	a > b`},
		`	a <= b`:       nil,
		`	a > b`:        {`> -> >= => 	a >= b`},
		`	a < b`:        {`< -> <= => 	a <= b`},
		`	if a < b && c {`: {`&& -> || => 	if a < b || c {`, `< -> <= => 	if a <= b && c {`,
			`negate condition => 	if !(a < b && c) {`},
		`	if v, ok := m[k]; ok {`:    nil,
		`	acc.Phase = next`:          {`delete statement => 	// mutant: deleted`},
		`	x == y //nolint:something`: nil,
		`import "a==b"`:              nil,
	} {
		if got := ops(line); !reflect.DeepEqual(got, want) {
			t.Errorf("%q:\n got  %q\n want %q", line, got, want)
		}
	}
}

func TestStrideIsDeterministicAndCapped(t *testing.T) {
	all := make([]mutant, 361)
	for i := range all {
		all[i].Line = i
	}
	chosen, step := stride(all, 8)
	if step != 46 || len(chosen) != 8 || chosen[1].Line != 46 {
		t.Errorf("step=%d n=%d", step, len(chosen))
	}
	if chosen, step = stride(all, 1000); step != 1 || len(chosen) != 361 {
		t.Errorf("step=%d n=%d", step, len(chosen))
	}
}
