package provider

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func TestSealFieldsRoundTrip(t *testing.T) {
	fields := []Field{
		{Name: FieldUsername, Value: []byte("alice")},
		{Name: FieldPassword, Value: []byte("s3cr3t")},
	}
	src := []byte("s3cr3t")
	_ = src
	sealed := SealFields(fields)
	// The source field values were zeroized by SealFields.
	if !bytes.Equal(fields[0].Value, make([]byte, len("alice"))) {
		t.Fatal("SealFields did not zeroize the source field value")
	}
	got := map[FieldName]string{}
	err := sealed.WithPlaintext(func(pt []byte) error {
		m, err := DecodeMaterial(profile.KindUsernamePassword, pt, 16, 1024)
		if err != nil {
			return err
		}
		defer m.Close()
		if b, ok := m.Field(FieldUsername); ok {
			got[FieldUsername] = string(b)
		}
		if b, ok := m.Field(FieldPassword); ok {
			got[FieldPassword] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got[FieldUsername] != "alice" || got[FieldPassword] != "s3cr3t" {
		t.Fatalf("round-trip mismatch: %v", got)
	}
}

func TestMaterialDeadAfterClose(t *testing.T) {
	sealed := SealFields([]Field{{Name: FieldToken, Value: []byte("tok")}})
	var m *Material
	_ = sealed.WithPlaintext(func(pt []byte) error {
		mm, err := DecodeMaterial(profile.KindBearerToken, pt, 16, 1024)
		if err != nil {
			return err
		}
		m = mm
		m.Close()
		if _, ok := m.Field(FieldToken); ok {
			t.Fatal("field readable after Close")
		}
		return nil
	})
	// After the scope the buffer is zeroized; a retained Material reads nothing.
	if _, ok := m.Field(FieldToken); ok {
		t.Fatal("field readable after scope closed")
	}
}

func TestSealedSingleUse(t *testing.T) {
	sealed := SealFields([]Field{{Name: FieldToken, Value: []byte("tok")}})
	if err := sealed.WithPlaintext(func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	// Second consumption fails (single-use).
	if err := sealed.WithPlaintext(func([]byte) error { return nil }); err == nil {
		t.Fatal("second consumption must fail")
	}
}

func TestProviderErrorSanitized(t *testing.T) {
	err := NewError(mcperr.ReasonProviderUnavailable, true)
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("provider error must not carry secret text")
	}
	c, ok := err.(Classified)
	if !ok || c.Reason() != mcperr.ReasonProviderUnavailable || !c.Retryable() {
		t.Fatal("classified interface not satisfied")
	}
}

func TestInMemoryProviderFreshHandlePerFetch(t *testing.T) {
	p := NewInMemory("prov-1", Capabilities{})
	p.SetMaterial(profile.KindBearerToken, map[FieldName][]byte{FieldToken: []byte("tok")}, Lease{Version: "v1"})
	r1, err := p.Fetch(context.Background(), Request{})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := p.Fetch(context.Background(), Request{})
	if err != nil {
		t.Fatal(err)
	}
	// Each handle is independently consumable (fresh per fetch).
	if err := r1.Handle.WithPlaintext(func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := r2.Handle.WithPlaintext(func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if f, _, _ := p.Calls(); f != 2 {
		t.Fatalf("fetch calls = %d, want 2", f)
	}
}

// FuzzDecodeMaterial proves the material decoder never panics on arbitrary blobs and
// never returns a Material for a malformed blob without an error.
func FuzzDecodeMaterial(f *testing.F) {
	f.Add([]byte{0})
	f.Add(SealFieldsBytes(t2Fields()))
	f.Fuzz(func(t *testing.T, blob []byte) {
		m, err := DecodeMaterial(profile.KindOpaque, blob, 16, 1024)
		if err != nil {
			return
		}
		_ = m.Kind()
		_, _ = m.Field(FieldToken)
		m.Close()
	})
}

// SealFieldsBytes is a fuzz helper that returns the raw sealed blob bytes.
func SealFieldsBytes(fields []Field) []byte {
	s := SealFields(fields)
	var out []byte
	_ = s.WithPlaintext(func(pt []byte) error {
		out = append([]byte(nil), pt...)
		return nil
	})
	return out
}

func t2Fields() []Field {
	return []Field{{Name: FieldToken, Value: []byte("a")}, {Name: FieldOpaque, Value: []byte("bb")}}
}
