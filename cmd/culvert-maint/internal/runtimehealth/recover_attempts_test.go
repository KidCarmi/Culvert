package runtimehealth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecoverAttempts_RoundTripAndKey(t *testing.T) {
	st := openTemp(t)
	if a, err := st.ReadRecoverAttempts(); a != nil || err != nil {
		t.Fatalf("empty store = %v, %v", a, err)
	}
	if n := (*RecoverAttempts)(nil).For("op", imgA); n != 0 {
		t.Fatalf("nil counts %d", n)
	}
	if err := st.WriteRecoverAttempts(RecoverAttempts{SourceOpID: "01JOP", ImageID: imgA, Begun: 1}); err != nil {
		t.Fatal(err)
	}
	a, err := st.ReadRecoverAttempts()
	if err != nil || a.For("01JOP", imgA) != 1 {
		t.Fatalf("read = %+v, %v", a, err)
	}
	// Another install, or another image, starts from zero.
	if a.For("01JOTHER", imgA) != 0 || a.For("01JOP", imgB) != 0 {
		t.Fatal("the count is not keyed by source and image")
	}
}

func TestRecoverAttempts_Refusals(t *testing.T) {
	st := openTemp(t)
	for name, a := range map[string]RecoverAttempts{
		"no source":       {ImageID: imgA, Begun: 1},
		"source with /":   {SourceOpID: "a/b", ImageID: imgA, Begun: 1},
		"malformed image": {SourceOpID: "01JOP", ImageID: "a", Begun: 1},
		"zero":            {SourceOpID: "01JOP", ImageID: imgA, Begun: 0},
		"over the cap":    {SourceOpID: "01JOP", ImageID: imgA, Begun: MaxRecoverAttempts + 1},
	} {
		if err := st.WriteRecoverAttempts(a); err == nil {
			t.Errorf("%s: written", name)
		}
	}
	// A file this agent cannot trust is an error, never zero.
	for name, body := range map[string]string{
		"not json":       "{",
		"unknown schema": `{"schema":2,"source_op_id":"01JOP","image_id":"` + imgA + `","begun":1}`,
		"over the cap":   `{"schema":1,"source_op_id":"01JOP","image_id":"` + imgA + `","begun":9}`,
	} {
		if err := os.WriteFile(filepath.Join(st.Dir(), recoverAttemptsName), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if a, err := st.ReadRecoverAttempts(); err == nil {
			t.Errorf("%s: read %+v", name, a)
		}
	}
}
