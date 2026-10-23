package runner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRunningRepositoryRefMirrorInspectShape(t *testing.T) {
	const mirror = "127.0.0.1:5055/culvert"
	local := mirror + "@sha256:" + strings.Repeat("e", 64)
	conflict := mirror + "@sha256:" + strings.Repeat("f", 64)
	for _, tc := range []struct {
		name      string
		refs      []string
		want      string
		ambiguous bool
	}{
		{"mirror and upstream differ", []string{testRepoRef, local}, local, false},
		{"reverse order", []string{local, testRepoRef}, local, false},
		{"duplicate mirror", []string{local, testRepoRef, local}, local, false},
		{"upstream only", []string{testRepoRef}, "", false},
		{"conflicting mirror", []string{testRepoRef, local, conflict}, "", true},
		{"repository prefix is not identity", []string{mirror + "-other@sha256:" + strings.Repeat("e", 64)}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Exercise the actual docker image inspect JSON parser, not just a
			// hand-built selection object. The config ID remains the running ID.
			b, err := json.Marshal([]map[string]any{{"Id": testImageID, "RepoDigests": tc.refs}})
			if err != nil {
				t.Fatal(err)
			}
			ri := &RunningProxyImage{RunningImageID: testImageID, RepoDigests: repoDigestsFromImageInspect(b)}
			got, ambiguous := ri.RepositoryRef(mirror)
			if got != tc.want || ambiguous != tc.ambiguous {
				t.Fatalf("RepositoryRef=(%q,%v), want(%q,%v)", got, ambiguous, tc.want, tc.ambiguous)
			}
		})
	}
}
