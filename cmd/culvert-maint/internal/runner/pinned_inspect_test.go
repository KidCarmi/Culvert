package runner

import (
	"strings"
	"testing"
)

func TestImageIDFromImageInspect(t *testing.T) {
	const id = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	got, err := imageIDFromImageInspect([]byte(`[{"Id":"` + id + `","RepoDigests":["r@sha256:x"],"Config":{"Env":["SECRET=hunter2"]}}]` + "\n"))
	if err != nil || got != id {
		t.Fatalf("got %q, %v", got, err)
	}
	for name, in := range map[string]string{
		"empty":        ``,
		"not an array": `{"Id":"` + id + `"}`,
		"no records":   `[]`,
		"two records":  `[{"Id":"` + id + `"},{"Id":"` + id + `"}]`,
		"not an id":    `[{"Id":"culvert/proxy:pinned SECRET=hunter2"}]`,
		"short id":     `[{"Id":"sha256:abc"}]`,
	} {
		got, err := imageIDFromImageInspect([]byte(in))
		if err == nil || got != "" {
			t.Errorf("%s: got %q, nil error", name, got)
		}
		// A parse failure must never quote the payload.
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: error repeats inspect output: %v", name, err)
		}
	}
}

// TestPinnedTagImageID_ArgvIsTheFixedTag: the only variable position of the
// image-inspect template is filled with the literal fixed tag, in both
// privilege modes, so the read needs no sudoers rule beyond the existing
// `docker image inspect *`.
func TestPinnedTagImageID_ArgvIsTheFixedTag(t *testing.T) {
	if err := validateImageRefShape(pinnedProxyTag); err != nil {
		t.Fatalf("the fixed tag must pass the image-ref argv gate: %v", err)
	}
	tmpl := templateByID(TemplateComposeImageInspect)
	if tmpl == nil || tmpl.StateChanging {
		t.Fatalf("image inspect must be a registered read-only template: %+v", tmpl)
	}
	if len(tmpl.SudoersLines) != 1 || tmpl.SudoersLines[0] != "/usr/bin/docker image inspect *" {
		t.Errorf("sudoers line changed: %v", tmpl.SudoersLines)
	}
}
