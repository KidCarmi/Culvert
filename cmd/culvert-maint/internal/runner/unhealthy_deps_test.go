package runner

import (
	"strings"
	"testing"
)

func TestUnhealthyDependencies(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"ndjson", `{"Service":"proxy","Health":"unhealthy"}` + "\n" + `{"Service":"clamav","Health":"unhealthy"}`, "clamav"},
		{"array", `[{"Service":"clamav","Health":"unhealthy"},{"Service":"origin","Health":"healthy"}]`, "clamav"},
		{"starting is not unhealthy", `{"Service":"clamav","Health":"starting"}`, ""},
		{"no healthcheck", `{"Service":"clamav","Health":""}`, ""},
		{"proxy alone never refuses", `{"Service":"proxy","Health":"unhealthy"}`, ""},
	}
	for _, c := range cases {
		got, err := UnhealthyDependencies([]byte(c.in))
		if err != nil || strings.Join(got, ",") != c.want {
			t.Errorf("%s: got %v %v, want %q", c.name, got, err, c.want)
		}
	}
	if _, err := UnhealthyDependencies([]byte("")); err == nil {
		t.Error("empty output must be an error (the caller proceeds), never an empty verdict")
	}
}
