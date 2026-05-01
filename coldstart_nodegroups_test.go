package main

// D1.2b cold-start tests for /data/node_groups.json.
//
// Mirrors the bandwidth.json shape: NewNodeGroupStore always returns
// a non-nil *NodeGroupStore; load errors are logged and reset s.groups
// to nil (then the constructor's nil-check at nodegroup.go:52-54
// promotes nil to an empty slice). These tests pin the behavior across
// missing / empty / garbage / valid / unknown-field / missing-required-
// field inputs.
//
// Same D1.2-flag finding as bandwidth.json: missing required fields
// silently load as zero values. No validation in the loader.

import (
	"os"
	"path/filepath"
	"testing"
)

//nolint:funlen,dupl // See companion comment in coldstart_bandwidth_test.go.
// Table-driven case list is intentionally long; structural symmetry with
// bandwidth tests is a regression-guard property, not duplication to fix.
func TestColdStart_NodeGroups_Cases(t *testing.T) {
	cases := []struct {
		name       string
		body       []byte // nil = do not write the file
		wantGroups int
		verify     func(t *testing.T, s *NodeGroupStore)
	}{
		{
			name:       "missing_file",
			body:       nil,
			wantGroups: 0,
		},
		{
			name:       "empty_file",
			body:       []byte{},
			wantGroups: 0,
		},
		{
			name:       "empty_array",
			body:       []byte("[]"),
			wantGroups: 0,
		},
		{
			name: "empty_object",
			// `{}` cannot unmarshal into []NodeGroup → log + nil → constructor promotes to []NodeGroup{}.
			body:       []byte("{}"),
			wantGroups: 0,
		},
		{
			name:       "garbage_json",
			body:       []byte("not json at all"),
			wantGroups: 0,
		},
		{
			name:       "valid_one_group",
			body:       []byte(`[{"name":"edge","label_selector":{"role":"edge"},"priority":5}]`),
			wantGroups: 1,
			verify: func(t *testing.T, s *NodeGroupStore) {
				g := s.groups[0]
				if g.Name != "edge" {
					t.Errorf("Name = %q, want edge", g.Name)
				}
				if g.Priority != 5 {
					t.Errorf("Priority = %d, want 5", g.Priority)
				}
			},
		},
		{
			name:       "valid_with_unknown_field",
			body:       []byte(`[{"name":"core","label_selector":{},"future_field":"ignored"}]`),
			wantGroups: 1,
			verify: func(t *testing.T, s *NodeGroupStore) {
				if s.groups[0].Name != "core" {
					t.Errorf("Name = %q, want core", s.groups[0].Name)
				}
			},
		},
		{
			// D1.2-flag: missing required fields silently load as zero
			// values. A group with no Name and no LabelSelector still
			// loads — it just matches nothing at runtime.
			name:       "missing_required_fields",
			body:       []byte(`[{"priority":3}]`),
			wantGroups: 1,
			verify: func(t *testing.T, s *NodeGroupStore) {
				g := s.groups[0]
				if g.Name != "" {
					t.Errorf("Name should be zero value, got %q", g.Name)
				}
				if len(g.LabelSelector) != 0 {
					t.Errorf("LabelSelector should be empty, got %v", g.LabelSelector)
				}
				if g.Priority != 3 {
					t.Errorf("Priority = %d, want 3", g.Priority)
				}
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "node_groups.json")
			if tc.body != nil {
				if err := os.WriteFile(path, tc.body, 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
			}

			s := NewNodeGroupStore(path)
			if s == nil {
				t.Fatal("NewNodeGroupStore returned nil — contract is always non-nil")
			}
			if got := len(s.groups); got != tc.wantGroups {
				t.Errorf("groups len = %d, want %d", got, tc.wantGroups)
			}
			if tc.verify != nil {
				tc.verify(t, s)
			}
		})
	}
}
