package runtimehealth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func always(string) bool { return true }

func TestRecoverAttempts_RoundTripAndKey(t *testing.T) {
	st := openTemp(t)
	if a, err := st.ReadRecoverAttempts(); a != nil || err != nil {
		t.Fatalf("empty store = %v, %v", a, err)
	}
	var none *RecoverAttempts
	if n := none.For("op", imgA); n != 0 {
		t.Fatalf("nil counts %d", n)
	}
	a, err := none.Counted("01JOP", imgA, 1, always)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WriteRecoverAttempts(a); err != nil {
		t.Fatal(err)
	}
	got, err := st.ReadRecoverAttempts()
	if err != nil || got.For("01JOP", imgA) != 1 {
		t.Fatalf("read = %+v, %v", got, err)
	}
	// Another install, or another image, starts from zero.
	if got.For("01JOTHER", imgA) != 0 || got.For("01JOP", imgB) != 0 {
		t.Fatal("the count is not keyed by source and image")
	}
}

// Every source still in force keeps its count when another is counted (the
// single slot it replaces let two sources alternate forever); a source no
// longer in force is dropped; the bound refuses instead of trimming.
func TestRecoverAttempts_KeepsEverySourceInForce(t *testing.T) {
	var a *RecoverAttempts
	b, _ := a.Counted("01JINSTALL", imgB, 1, always)
	c, _ := b.Counted("01JRECORD", imgA, 1, always)
	if c.For("01JINSTALL", imgB) != 1 || c.For("01JRECORD", imgA) != 1 {
		t.Fatalf("a count was forgotten: %+v", c)
	}
	d, _ := c.Counted("01JINSTALL", imgB, 2, always)
	if d.For("01JINSTALL", imgB) != 2 || d.For("01JRECORD", imgA) != 1 || len(d.Entries) != 2 {
		t.Fatalf("recount = %+v", d)
	}
	e, _ := d.Counted("01JINSTALL", imgB, 2, func(op string) bool { return op != "01JRECORD" })
	if len(e.Entries) != 1 || e.For("01JRECORD", imgA) != 0 {
		t.Fatalf("a source no longer in force was kept: %+v", e)
	}
	full := &RecoverAttempts{}
	for i := 0; i < MaxRecoverEntries; i++ {
		full.Entries = append(full.Entries, RecoverAttempt{SourceOpID: fmt.Sprintf("01JOP%02d", i), ImageID: imgA, Begun: 1})
	}
	if _, err := full.Counted("01JNEW", imgA, 1, always); !errors.Is(err, ErrRecoverEntriesFull) {
		t.Fatalf("over the bound = %v, want ErrRecoverEntriesFull", err)
	}
}

func TestRecoverAttempts_Refusals(t *testing.T) {
	st := openTemp(t)
	one := func(e RecoverAttempt) RecoverAttempts { return RecoverAttempts{Entries: []RecoverAttempt{e}} }
	for name, a := range map[string]RecoverAttempts{
		"empty":           {},
		"no source":       one(RecoverAttempt{ImageID: imgA, Begun: 1}),
		"source with /":   one(RecoverAttempt{SourceOpID: "a/b", ImageID: imgA, Begun: 1}),
		"malformed image": one(RecoverAttempt{SourceOpID: "01JOP", ImageID: "a", Begun: 1}),
		"zero":            one(RecoverAttempt{SourceOpID: "01JOP", ImageID: imgA, Begun: 0}),
		"over the cap":    one(RecoverAttempt{SourceOpID: "01JOP", ImageID: imgA, Begun: MaxRecoverAttempts + 1}),
		"repeated":        {Entries: []RecoverAttempt{{"01JOP", imgA, 1}, {"01JOP", imgA, 2}}},
	} {
		if err := st.WriteRecoverAttempts(a); err == nil {
			t.Errorf("%s: written", name)
		}
	}
	// A file this agent cannot trust is an error, never zero.
	for name, body := range map[string]string{
		"not json":       "{",
		"unknown schema": `{"schema":2,"entries":[{"source_op_id":"01JOP","image_id":"` + imgA + `","begun":1}]}`,
		"over the cap":   `{"schema":1,"entries":[{"source_op_id":"01JOP","image_id":"` + imgA + `","begun":9}]}`,
		"no entries":     `{"schema":1,"entries":[]}`,
	} {
		if err := os.WriteFile(filepath.Join(st.Dir(), recoverAttemptsName), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if a, err := st.ReadRecoverAttempts(); err == nil {
			t.Errorf("%s: read %+v", name, a)
		}
	}
}
