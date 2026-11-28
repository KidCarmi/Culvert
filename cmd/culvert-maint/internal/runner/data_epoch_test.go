package runner

import (
	"strings"
	"testing"
)

func TestParseDataEpoch(t *testing.T) {
	ok := `{"schema":1,"epoch":2,"marker_present":true,"build_min":1,"build_max":3}` + "\n"
	got, err := parseDataEpoch([]byte(ok))
	if err != nil || got.Epoch != 2 || !got.MarkerPresent || got.BuildMin != 1 || got.BuildMax != 3 {
		t.Fatalf("parseDataEpoch(ok) = %+v, %v", got, err)
	}
	for name, out := range map[string]string{
		"empty":                      "",
		"usage text of an old image": "flag provided but not defined: -print-data-epoch\nUsage of ./culvert:",
		"two objects":                ok + ok,
		"trailing bytes on the line": `{"schema":1,"epoch":1,"marker_present":false,"build_min":1,"build_max":1}x`,
		"two objects on one line":    `{"schema":1,"epoch":1,"marker_present":false,"build_min":1,"build_max":1}{"schema":1}`,
		"unknown field":              `{"schema":1,"epoch":1,"marker_present":false,"build_min":1,"build_max":1,"x":1}`,
		"marker presence missing":    `{"schema":1,"epoch":1,"build_min":1,"build_max":1}`,
		"epoch zero":                 `{"schema":1,"epoch":0,"marker_present":false,"build_min":1,"build_max":1}`,
		"schema 2":                   `{"schema":2,"epoch":1,"marker_present":false,"build_min":1,"build_max":1}`,
		"inverted build range":       `{"schema":1,"epoch":1,"marker_present":false,"build_min":2,"build_max":1}`,
	} {
		if r, err := parseDataEpoch([]byte(out)); err == nil {
			t.Errorf("%s: parseDataEpoch = %+v, want an error", name, r)
		}
	}
}

func TestParseEpochLabels(t *testing.T) {
	insp := func(labels string) []byte {
		return []byte(`[{"Id":"sha256:` + strings.Repeat("a", 64) + `","Config":{"Labels":` + labels + `}}]`)
	}
	got, err := parseEpochLabels(insp(`{"io.culvert.data-epoch.min":"1","io.culvert.data-epoch.max":"2","other":"x"}`))
	if err != nil || !got.Labelled || got.Min != 1 || got.Max != 2 {
		t.Fatalf("labelled = %+v, %v", got, err)
	}
	for name, labels := range map[string]string{"no labels": `null`, "other labels only": `{"a":"b"}`} {
		got, err := parseEpochLabels(insp(labels))
		if err != nil || got.Labelled {
			t.Errorf("%s: = %+v, %v; want unlabelled, no error", name, got, err)
		}
	}
	for name, labels := range map[string]string{
		"only min":   `{"io.culvert.data-epoch.min":"1"}`,
		"only max":   `{"io.culvert.data-epoch.max":"1"}`,
		"zero":       `{"io.culvert.data-epoch.min":"0","io.culvert.data-epoch.max":"1"}`,
		"leading 0":  `{"io.culvert.data-epoch.min":"01","io.culvert.data-epoch.max":"1"}`,
		"plus sign":  `{"io.culvert.data-epoch.min":"+1","io.culvert.data-epoch.max":"1"}`,
		"spaces":     `{"io.culvert.data-epoch.min":" 1","io.culvert.data-epoch.max":"1"}`,
		"not number": `{"io.culvert.data-epoch.min":"one","io.culvert.data-epoch.max":"1"}`,
		"min > max":  `{"io.culvert.data-epoch.min":"3","io.culvert.data-epoch.max":"2"}`,
	} {
		if got, err := parseEpochLabels(insp(labels)); err == nil {
			t.Errorf("%s: = %+v, want an error", name, got)
		}
	}
	if _, err := parseEpochLabels([]byte(`[]`)); err == nil {
		t.Error("no inspect record was accepted")
	}
}

// The template is read-only and is the fixed argv the sudoers line names.
func TestDataEpochTemplate(t *testing.T) {
	tmpl := templateByID(TemplateComposeCLIDataEpoch)
	if tmpl == nil || tmpl.StateChanging || len(tmpl.WrapperArgv) != 0 {
		t.Fatalf("template = %+v", tmpl)
	}
	if got := strings.Join(tmpl.BaseArgv, " "); got != "docker compose -f {compose_path} --profile cli run --rm cli --print-data-epoch" {
		t.Fatalf("argv = %s", got)
	}
}
