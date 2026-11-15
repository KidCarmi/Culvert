package main

import (
	"strings"
	"testing"
)

func TestCheckUpstreamPoolConfig(t *testing.T) {
	prev := getUpstreamState()
	t.Cleanup(func() { setUpstreamState(func(st *upstreamState) { *st = prev }) })

	setUpstreamState(func(st *upstreamState) {
		*st = upstreamState{Migration: upstreamMigrationState{State: "ok"}, Key: upstreamKeyState{State: "present"}}
	})
	if rows := checkUpstreamPoolConfig(); len(rows) != 0 {
		t.Fatalf("healthy pool: want no rows, got %+v", rows)
	}

	cases := []struct {
		name string
		set  func(st *upstreamState)
		want []string
	}{
		{"managed document rejected", func(st *upstreamState) {
			st.Degraded = &upstreamDegraded{Reason: "duplicate_authority", Count: 2}
		}, []string{"stored upstream document", "duplicate_authority, 2", "admin_settings.json"}},
		{"yaml seed rejected", func(st *upstreamState) {
			st.YAMLDegraded = &upstreamDegraded{Reason: "invalid_entry"}
		}, []string{"config.yaml upstream seed", "invalid_entry"}},
		{"legacy migration abandoned", func(st *upstreamState) {
			st.Migration = upstreamMigrationState{State: "degraded", Reason: "persist_failed"}
		}, []string{"legacy upstream pool migration", "persist_failed"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setUpstreamState(func(st *upstreamState) {
				*st = upstreamState{Migration: upstreamMigrationState{State: "ok"}, Key: upstreamKeyState{State: "present"}}
				tc.set(st)
			})
			rows := checkUpstreamPoolConfig()
			if len(rows) != 1 || rows[0].Code != "upstream_pool_config" || rows[0].Status != diagWarn || rows[0].OperatorAction == "" {
				t.Fatalf("want one upstream_pool_config WARN row, got %+v", rows)
			}
			text := rows[0].Message + " " + rows[0].OperatorAction
			for _, w := range tc.want {
				if !strings.Contains(text, w) {
					t.Errorf("row should mention %q, got %q", w, text)
				}
			}
		})
	}

	// All three latched together still yield exactly one row naming each.
	setUpstreamState(func(st *upstreamState) {
		st.Degraded = &upstreamDegraded{Reason: "invalid_entry"}
		st.YAMLDegraded = &upstreamDegraded{Reason: "duplicate_authority", Count: 3}
		st.Migration = upstreamMigrationState{State: "degraded", Reason: "seal_failed"}
	})
	rows := checkUpstreamPoolConfig()
	if len(rows) != 1 || strings.Count(rows[0].Message, ";") != 2 {
		t.Fatalf("want one row with three clauses, got %+v", rows)
	}

	// The row reaches the operator contract.
	found := false
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "upstream_pool_config" {
			found = true
		}
	}
	if !found {
		t.Error("upstream_pool_config row missing from the operator contract")
	}
}
