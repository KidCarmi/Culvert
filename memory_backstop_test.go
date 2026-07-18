package main

// memory_backstop_test.go — P0-2 coverage for the GOMEMLIMIT backstop parsing.
// The soft limit must be set only for a real, finite container memory cap;
// "max"/unlimited/garbage must NOT produce a bogus limit that throttles a
// legitimate deployment.

import "testing"

func TestParseCgroupMemLimit(t *testing.T) {
	const gib = int64(1) << 30
	cases := []struct {
		raw     string
		want    int64
		wantOK  bool
		comment string
	}{
		{"1073741824\n", gib, true, "cgroup v2 finite limit (1 GiB)"},
		{"  536870912  ", gib / 2, true, "whitespace-trimmed 512 MiB"},
		{"max", 0, false, "cgroup v2 unlimited literal"},
		{"", 0, false, "empty file"},
		{"9223372036854771712", 0, false, "cgroup v1 unlimited sentinel (~max int64)"},
		{"0", 0, false, "zero is not a real cap"},
		{"-1", 0, false, "negative is not a real cap"},
		{"not-a-number", 0, false, "garbage"},
	}
	for _, c := range cases {
		got, ok := parseCgroupMemLimit(c.raw)
		if ok != c.wantOK || (ok && got != c.want) {
			t.Errorf("parseCgroupMemLimit(%q) = (%d,%v), want (%d,%v) — %s", c.raw, got, ok, c.want, c.wantOK, c.comment)
		}
	}
}

func TestIsFiniteMemLimit(t *testing.T) {
	const gib = int64(1) << 30
	if !isFiniteMemLimit(gib) {
		t.Error("1 GiB must be finite")
	}
	if isFiniteMemLimit(0) || isFiniteMemLimit(-5) {
		t.Error("non-positive must not be finite")
	}
	if isFiniteMemLimit(int64(1) << 62) {
		t.Error("unlimited sentinel (2^62) must not be treated as finite")
	}
}
