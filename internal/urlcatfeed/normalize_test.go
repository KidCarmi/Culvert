package urlcatfeed

import (
	"errors"
	"testing"
)

func TestNormalizeHost_Accepts(t *testing.T) {
	cases := map[string]string{
		"example.com":         "example.com",
		"Example.COM":         "example.com",
		"  example.com  ":     "example.com",
		"example.com.":        "example.com", // single trailing dot stripped
		"sub.example.com":     "sub.example.com",
		"a.b.c.example.co.uk": "a.b.c.example.co.uk",
		"Bücher.example.com":  "xn--bcher-kva.example.com", // IDNA A-label
		"münchen.example.org": "xn--mnchen-3ya.example.org",
	}
	for in, want := range cases {
		got, err := NormalizeHost(in)
		if err != nil {
			t.Errorf("NormalizeHost(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeHost(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestNormalizeHost_Rejects(t *testing.T) {
	// Specific sentinel expected.
	sentinel := []struct {
		in   string
		want error
	}{
		{"", ErrEmptyHost},
		{"   ", ErrEmptyHost},
		{"http://example.com", ErrBadChars},
		{"example.com/path", ErrBadChars},
		{"example.com:443", ErrBadChars},
		{"user@example.com", ErrBadChars},
		{"a b.example.com", ErrBadChars},
		{"2001:db8::1", ErrBadChars},
		{"*.example.com", ErrWildcard},
		{"1.2.3.4", ErrIPLiteral},
		{"192.168.0.1", ErrIPLiteral},
		{"com", ErrPublicSuffix},
		{"co.uk", ErrPublicSuffix},
		{"localhost", ErrPublicSuffix},
	}
	for _, c := range sentinel {
		_, err := NormalizeHost(c.in)
		if !errors.Is(err, c.want) {
			t.Errorf("NormalizeHost(%q) err = %v; want %v", c.in, err, c.want)
		}
	}

	// Library-dependent (IDNA/label) — assert rejection, not the exact class.
	rejectAny := []string{
		"under_score.example.com", // STD3 disallows underscore
		"example..com",            // empty label
		"-bad.example.com",        // leading hyphen
		"bad-.example.com",        // trailing hyphen
	}
	for _, in := range rejectAny {
		if _, err := NormalizeHost(in); err == nil {
			t.Errorf("NormalizeHost(%q) = nil error; want rejection", in)
		}
	}
}

func TestAssignHosts_MultiCategoryRejected(t *testing.T) {
	_, err := assignHosts([]SourceCategory{
		{Name: "AI", Hosts: []string{"example.com"}},
		{Name: "Marketing", Hosts: []string{"example.com"}},
	})
	if !errors.Is(err, ErrMultiCategory) {
		t.Fatalf("err = %v; want ErrMultiCategory", err)
	}
}

func TestAssignHosts_SameCategoryDeduped(t *testing.T) {
	ha, err := assignHosts([]SourceCategory{
		{Name: "AI", Hosts: []string{"example.com", "Example.com", "example.com."}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ha.catOf) != 1 {
		t.Fatalf("expected 1 unique host after dedup; got %d", len(ha.catOf))
	}
}

func TestAssignHosts_AncestorDescendantCrossCategoryRejected(t *testing.T) {
	_, err := assignHosts([]SourceCategory{
		{Name: "A", Hosts: []string{"example.com"}},
		{Name: "B", Hosts: []string{"sub.example.com"}},
	})
	if !errors.Is(err, ErrSuffixConflict) {
		t.Fatalf("err = %v; want ErrSuffixConflict", err)
	}
}

func TestAssignHosts_AncestorDescendantSameCategoryAllowed(t *testing.T) {
	if _, err := assignHosts([]SourceCategory{
		{Name: "A", Hosts: []string{"example.com", "sub.example.com", "deep.sub.example.com"}},
	}); err != nil {
		t.Fatalf("same-category ancestry should be allowed; got %v", err)
	}
}

func TestAssignHosts_CategoryCaseCollisionRejected(t *testing.T) {
	_, err := assignHosts([]SourceCategory{
		{Name: "AI", Hosts: []string{"a.example.com"}},
		{Name: "ai", Hosts: []string{"b.example.com"}},
	})
	if !errors.Is(err, ErrCategoryCase) {
		t.Fatalf("err = %v; want ErrCategoryCase", err)
	}
}

func TestAssignHosts_EmptyCategoryRejected(t *testing.T) {
	_, err := assignHosts([]SourceCategory{{Name: "  ", Hosts: []string{"a.example.com"}}})
	if !errors.Is(err, ErrEmptyCategory) {
		t.Fatalf("err = %v; want ErrEmptyCategory", err)
	}
}
