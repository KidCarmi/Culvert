package main

import (
	"strings"
	"testing"
)

func TestCheckGeoDatabaseForRules(t *testing.T) {
	off := false
	country := func(name string, en *bool) PolicyRule {
		return PolicyRule{Name: name, DestCountry: []string{"RU"}, Enabled: en}
	}

	// No DB loaded in the unit-test process (geoip.Enabled() is false).
	if got := checkGeoDatabaseForRules(nil); got != nil {
		t.Fatalf("no rules: want no row, got %+v", got)
	}
	if got := checkGeoDatabaseForRules([]PolicyRule{{Name: "plain"}, country("disabled", &off)}); got != nil {
		t.Fatalf("no enabled country rule: want no row, got %+v", got)
	}

	rows := checkGeoDatabaseForRules([]PolicyRule{{Name: "plain"}, country("block-ru", nil), country("off", &off)})
	if len(rows) != 1 {
		t.Fatalf("want exactly one row, got %+v", rows)
	}
	r := rows[0]
	if r.Code != "geoip_database_for_rules" || r.Status != diagWarn {
		t.Fatalf("unexpected row %+v", r)
	}
	if !strings.Contains(r.Message, `"block-ru"`) || strings.Contains(r.Message, `"off"`) || !strings.HasPrefix(r.Message, "1 enabled") {
		t.Fatalf("message must name only the enabled country rule: %q", r.Message)
	}
	if r.OperatorAction == "" {
		t.Fatal("row must carry an operator action")
	}

	many := make([]PolicyRule, 0, 8)
	for i := 0; i < 8; i++ {
		many = append(many, country("r", nil))
	}
	if m := checkGeoDatabaseForRules(many)[0].Message; !strings.Contains(m, "and 3 more") {
		t.Fatalf("list must be capped with a remainder count: %q", m)
	}
}
