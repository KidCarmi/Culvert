package main

import (
	"path/filepath"
	"testing"
)

// The cluster CA is stored beside the cluster state file. A state file
// directly under the filesystem root (e.g. -cluster-db /cluster.json in a
// container) must put the CA in "/", not silently in the working directory.
func TestClusterCADir(t *testing.T) {
	cases := []struct{ in, want string }{
		{"cluster.json", "."},
		{"/data/cluster.json", "/data"},
		{"data/cluster.json", "data"},
		{"/cluster.json", "/"},
	}
	for _, c := range cases {
		if got := clusterCADir(filepath.FromSlash(c.in)); got != filepath.FromSlash(c.want) {
			t.Errorf("clusterCADir(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
