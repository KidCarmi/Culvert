package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed/noderecord"
)

// IM-028 (ADR-0059): decodeFloorRecord, decodeActivationRecord and
// decodeSaaSFeedAuthorityRecord bind the envelope steps they repeated (empty,
// size bound, strict decode, trailing data, canonical byte equality) to
// noderecord.Decode. Each keeps its own sentinels, message prefix, size limit
// and field validation.
//
// The digests and class counts below were captured from main BEFORE the bind
// (origin/main ef9431189), when each function carried its own copy of the
// steps. A record on disk is accepted or refused by these functions, so no
// verdict may move.

const (
	im028FloorInputs      = 4793
	im028FloorCounts      = "accepted=1 decode=2625 empty=3 field=1886 noncanonical=254 oversize=7 trailing=17"
	im028FloorDigest      = "40707418f46c0293980fc5955c81d3b4a1a63cd3734f0e141b72ede745dbd958"
	im028ActivationInputs = 8426
	im028ActivationCounts = "accepted=1 decode=4824 empty=3 field=3162 noncanonical=404 oversize=7 trailing=25"
	im028ActivationDigest = "c45b0f9c74ae03fc4939eb7a664331b822414871b84bbcaad345b9f6a16a15c8"
	im028AuthorityInputs  = 4165
	im028AuthorityCounts  = "accepted=1 decode=2804 empty=3 field=1148 noncanonical=180 oversize=7 trailing=22"
	im028AuthorityDigest  = "f9b6d7c453353a8f96cdea98a802bf36bd3469d2b3acdedd26e50ee6781e3345"
)

// im028Envelope names one record's decoder and the vocabulary it answers in.
type im028Envelope struct {
	name   string
	prefix string
	limit  int
	valid  []byte
	decode func([]byte) (string, error)

	empty, oversize, trailing, noncanonical error
}

func im028Envelopes(t *testing.T) []im028Envelope {
	t.Helper()
	floor := mustEncode(t, mkFloor(t, 42, floorTS0, "42", floorHexA, floorHexB))
	act, err := encodeActivationRecord(mkActivation())
	if err != nil {
		t.Fatal(err)
	}
	auth, err := encodeSaaSFeedAuthorityRecord(validAuthorityRecord())
	if err != nil {
		t.Fatal(err)
	}
	return []im028Envelope{
		{
			name: "floor", prefix: "saas feed floor", limit: maxFloorRecordBytes, valid: floor,
			decode: func(b []byte) (string, error) {
				r, err := decodeFloorRecord(b)
				return fmt.Sprintf("%+v", r), err
			},
			empty: errFloorEmpty, oversize: errFloorOversize, trailing: errFloorTrailing, noncanonical: errFloorNoncanonical,
		},
		{
			name: "activation", prefix: "saas feed activation", limit: maxActivationRecordBytes, valid: act,
			decode: func(b []byte) (string, error) {
				r, err := decodeActivationRecord(b)
				return fmt.Sprintf("%+v", r), err
			},
			empty: errActEmpty, oversize: errActOversize, trailing: errActTrailing, noncanonical: errActNoncanonical,
		},
		{
			name: "authority", prefix: "saas feed authority", limit: maxSaaSFeedAuthorityRecordBytes, valid: auth,
			decode: func(b []byte) (string, error) {
				r, err := decodeSaaSFeedAuthorityRecord(b)
				return fmt.Sprintf("%+v", r), err
			},
			empty: errAuthEmpty, oversize: errAuthOversize, trailing: errAuthTrailing, noncanonical: errAuthNoncanonical,
		},
	}
}

// im028Corpus derives the inputs from one valid record: every truncation,
// every single-byte deletion, a space inserted at every offset, eleven byte
// substitutions at every offset, and a fixed list of whole-document shapes
// around the size bound.
func im028Corpus(valid []byte, limit int) [][]byte {
	base := string(valid)
	out := [][]byte{nil, {}, valid}
	for i := 0; i < len(valid); i++ {
		out = append(out,
			[]byte(base[:i]),
			[]byte(base[:i]+base[i+1:]),
			[]byte(base[:i]+" "+base[i:]),
		)
		for _, c := range []byte{'0', '9', '"', '{', '}', ',', ':', 'a', 'Z', 0x00, 0xff} {
			if valid[i] == c {
				continue
			}
			m := append([]byte(nil), valid...)
			m[i] = c
			out = append(out, m)
		}
	}
	firstComma := strings.IndexByte(base, ',')
	firstField := base[1:firstComma]
	pad := func(n int) string { return base + strings.Repeat(" ", n-len(base)) }
	for _, s := range []string{
		base + base, base + " " + base, base + "\n" + base, base + "\n", base + " ", base + "\t",
		" " + base, "\n" + base, "\xef\xbb\xbf" + base, base + "x", base + "{}", base + "null", base + ",",
		base + "]", "[" + base + "]",
		"null", "{}", "[]", "1", `""`, "true", " ", "\n", "{", "}", `{"schema_version":1}`,
		"{" + firstField + "," + base[1:],
		"{" + base[firstComma+1:len(base)-1] + "," + firstField + "}",
		strings.Replace(base, `"schema_version"`, `"Schema_Version"`, 1),
		strings.Replace(base, `"schema_version"`, `"SCHEMA_VERSION"`, 1),
		strings.Replace(base, `"schema_version":1`, `"schema_version":1.0`, 1),
		strings.Replace(base, `"schema_version":1`, `"schema_version":1e0`, 1),
		strings.Replace(base, `"schema_version":1`, `"schema_version":01`, 1),
		strings.Replace(base, `"schema_version":1`, `"schema_version":"1"`, 1),
		strings.Replace(base, `"schema_version":1`, `"schema_version":null`, 1),
		strings.Replace(base, `"schema_version":1`, `"schema_version":2`, 1),
		strings.Replace(base, `"schema_version":1`, `"schema_version":-1`, 1),
		strings.Replace(base, `"schema_version":1`, `"schema_version":99999999999999999999`, 1),
		strings.Replace(base, `"protocol":"s`, `"protocol":"`+"\\u0073", 1),
		strings.Replace(base, `"protocol":"s`, `"protocol":"\/s`, 1),
		strings.Replace(base, `"protocol":"`, `"protocol":"<>&`, 1),
		strings.Replace(base, `"protocol":"`, `"protocol":"`+"\\u003c", 1),
		strings.Replace(base, `"protocol":"`, "\"protocol\":\"\u2028", 1),
		base[:len(base)-1] + `,"evil":true}`,
		base[:len(base)-1] + `,"crc32c":"00000000"}`,
		base[:len(base)-1] + `,"":""}`,
		`{"evil":true,` + base[1:],
		pad(limit - 1), pad(limit), pad(limit + 1), pad(limit + 2), pad(2 * limit),
		"{" + strings.Repeat(" ", limit-2) + "}",
		"{" + strings.Repeat(" ", limit-1) + "}",
		"{" + strings.Repeat(" ", limit) + "}",
		strings.Repeat("x", limit), strings.Repeat("x", limit+1),
		strings.Repeat("[", limit), strings.Repeat("[", limit+1),
	} {
		out = append(out, []byte(s))
	}
	return out
}

// im028Verdict is what a caller can observe for one input: the accepted
// record, or the refusal's class and text. A strict-decode refusal is recorded
// by class and prefix only, because the text after the prefix is
// encoding/json's and belongs to the toolchain, not to this contract.
func im028Verdict(e im028Envelope, in []byte) (class, verdict string) {
	rec, err := e.decode(in)
	switch {
	case err == nil:
		return "accepted", "accepted " + rec
	case errors.Is(err, e.empty):
		class = "empty"
	case errors.Is(err, e.oversize):
		class = "oversize"
	case errors.Is(err, e.trailing):
		class = "trailing"
	case errors.Is(err, e.noncanonical):
		class = "noncanonical"
	case strings.HasPrefix(err.Error(), e.prefix+": decode: ") && errors.Unwrap(err) != nil:
		return "decode", "decode " + e.prefix
	default:
		class = "field"
	}
	return class, class + " " + err.Error()
}

func TestIM028_RecordDecodeVerdictsUnchangedByBinding(t *testing.T) {
	want := map[string]struct {
		inputs int
		digest string
		counts string
	}{
		"floor":      {im028FloorInputs, im028FloorDigest, im028FloorCounts},
		"activation": {im028ActivationInputs, im028ActivationDigest, im028ActivationCounts},
		"authority":  {im028AuthorityInputs, im028AuthorityDigest, im028AuthorityCounts},
	}
	for _, e := range im028Envelopes(t) {
		t.Run(e.name, func(t *testing.T) {
			corpus := im028Corpus(e.valid, e.limit)
			h := sha256.New()
			counts := map[string]int{}
			for _, in := range corpus {
				class, verdict := im028Verdict(e, in)
				counts[class]++
				fmt.Fprintf(h, "%d:%s\n%s\n", len(in), in, verdict)
			}
			var parts []string
			for k, n := range counts {
				parts = append(parts, fmt.Sprintf("%s=%d", k, n))
			}
			sort.Strings(parts)
			gotCounts := strings.Join(parts, " ")
			gotDigest := hex.EncodeToString(h.Sum(nil))
			w := want[e.name]
			if len(corpus) != w.inputs || gotCounts != w.counts || gotDigest != w.digest {
				t.Fatalf("%s decode verdicts moved:\n got inputs=%d counts=%q digest=%s\nwant inputs=%d counts=%q digest=%s",
					e.name, len(corpus), gotCounts, gotDigest, w.inputs, w.counts, w.digest)
			}
			// The table is not vacuous: every envelope class and a field
			// refusal are reached, and the one valid record is accepted.
			for _, class := range []string{"accepted", "empty", "oversize", "trailing", "noncanonical", "decode", "field"} {
				if counts[class] == 0 {
					t.Fatalf("%s corpus never reaches class %q: %s", e.name, class, gotCounts)
				}
			}
		})
	}
}

// The texts a caller or an operator log can see are pinned outside the digest
// too, so a failure names the line that moved.
func TestIM028_RecordDecodeRefusalTexts(t *testing.T) {
	for _, e := range im028Envelopes(t) {
		over := []byte(string(e.valid) + strings.Repeat(" ", e.limit+1-len(e.valid)))
		for _, c := range []struct {
			in   []byte
			want string
		}{
			{nil, e.prefix + ": empty record"},
			{over, fmt.Sprintf("%s: record exceeds max size: %d > %d", e.prefix, e.limit+1, e.limit)},
			{[]byte(string(e.valid) + "{}"), e.prefix + ": trailing data after record"},
			{[]byte(string(e.valid) + "\n"), e.prefix + ": record is not in canonical form"},
		} {
			_, err := e.decode(c.in)
			if err == nil || err.Error() != c.want {
				t.Errorf("%s: got %v, want %q", e.name, err, c.want)
			}
		}
		// A strict-decode refusal keeps its prefix and wraps encoding/json's error.
		_, err := e.decode([]byte(`{"evil":true}`))
		if err == nil || !strings.HasPrefix(err.Error(), e.prefix+": decode: ") || errors.Unwrap(err) == nil {
			t.Errorf("%s: unknown-field refusal moved: %v", e.name, err)
		}
		// Exactly at the bound is not an oversize refusal (the bound is inclusive).
		at := []byte(string(e.valid) + strings.Repeat(" ", e.limit-len(e.valid)))
		if _, err := e.decode(at); errors.Is(err, e.oversize) || !errors.Is(err, e.noncanonical) {
			t.Errorf("%s: a record of exactly %d bytes: %v", e.name, e.limit, err)
		}
	}
}

// The three decoders are bindings, not copies: each answers exactly as
// noderecord.Decode does with that record's envelope, before field validation.
func TestIM028_RootDecodersBindNodeRecord(t *testing.T) {
	type probe struct {
		env    noderecord.Envelope
		direct func([]byte, noderecord.Envelope) error
	}
	probes := map[string]probe{
		"floor": {floorEnvelope(), func(b []byte, e noderecord.Envelope) error {
			_, err := noderecord.Decode[floorRecord](b, e)
			return err
		}},
		"activation": {activationEnvelope(), func(b []byte, e noderecord.Envelope) error {
			_, err := noderecord.Decode[activationRecord](b, e)
			return err
		}},
		"authority": {saasFeedAuthorityEnvelope(), func(b []byte, e noderecord.Envelope) error {
			_, err := noderecord.Decode[saasFeedAuthorityRecord](b, e)
			return err
		}},
	}
	for _, e := range im028Envelopes(t) {
		p := probes[e.name]
		if p.env.Name != e.prefix || p.env.MaxBytes != e.limit || p.env.Empty != e.empty ||
			p.env.Oversize != e.oversize || p.env.Trailing != e.trailing || p.env.Noncanonical != e.noncanonical {
			t.Fatalf("%s envelope does not carry this record's own vocabulary: %+v", e.name, p.env)
		}
		agreed := 0
		for _, in := range im028Corpus(e.valid, e.limit) {
			class, _ := im028Verdict(e, in)
			_, rootErr := e.decode(in)
			pkgErr := p.direct(in, p.env)
			if class == "field" || class == "accepted" {
				// The envelope accepted it; what follows is the root's field validation.
				if pkgErr != nil {
					t.Fatalf("%s: root reached field validation but the envelope refused %q: %v", e.name, in, pkgErr)
				}
				continue
			}
			if pkgErr == nil || rootErr.Error() != pkgErr.Error() {
				t.Fatalf("%s: %q: root %v, noderecord %v", e.name, in, rootErr, pkgErr)
			}
			agreed++
		}
		if agreed < 100 {
			t.Fatalf("%s: only %d envelope refusals compared", e.name, agreed)
		}
	}
}
