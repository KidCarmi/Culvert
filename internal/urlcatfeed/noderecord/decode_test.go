package noderecord

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// sample is a record shape like the ones package main stores: fixed field
// order, strings, integers, a boolean and a checksum field.
type sample struct {
	SchemaVersion int    `json:"schema_version"`
	Protocol      string `json:"protocol"`
	FeedVersion   int64  `json:"feed_version"`
	Managed       bool   `json:"managed"`
	ETag          string `json:"etag"`
	CRC32C        string `json:"crc32c"`
}

// other is a second record kind with its own sentinels, for the tests that
// show two kinds do not share an error value or a result.
type other struct {
	Epoch int64  `json:"epoch"`
	Note  string `json:"note"`
}

var (
	errSampleEmpty        = errors.New("sample: empty record")
	errSampleOversize     = errors.New("sample: record exceeds max size")
	errSampleTrailing     = errors.New("sample: trailing data after record")
	errSampleNoncanonical = errors.New("sample: record is not in canonical form")

	errOtherEmpty        = errors.New("other: empty record")
	errOtherOversize     = errors.New("other: record exceeds max size")
	errOtherTrailing     = errors.New("other: trailing data after record")
	errOtherNoncanonical = errors.New("other: record is not in canonical form")
)

const sampleMax = 256

func sampleEnvelope() Envelope {
	return Envelope{
		Name: "sample", MaxBytes: sampleMax,
		Empty: errSampleEmpty, Oversize: errSampleOversize,
		Trailing: errSampleTrailing, Noncanonical: errSampleNoncanonical,
	}
}

func otherEnvelope() Envelope {
	return Envelope{
		Name: "other", MaxBytes: 64,
		Empty: errOtherEmpty, Oversize: errOtherOversize,
		Trailing: errOtherTrailing, Noncanonical: errOtherNoncanonical,
	}
}

func validSample(t testing.TB) []byte {
	t.Helper()
	b, err := Canonical(sample{SchemaVersion: 1, Protocol: "signed_manifest_v1", FeedVersion: 42, Managed: true, ETag: `"v42"`, CRC32C: "43d5a692"})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// oracleDecodeSample is a frozen copy of the decoder body package main carried
// three times before IM-028 (decodeFloorRecord, decodeActivationRecord and
// decodeSaaSFeedAuthorityRecord at origin/main ef9431189), with the record
// type and sentinels of this test substituted and the field validation, which
// did not move, left out. It must not be edited to follow Decode.
func oracleDecodeSample(data []byte) (sample, error) {
	if len(data) == 0 {
		return sample{}, errSampleEmpty
	}
	if len(data) > sampleMax {
		return sample{}, fmt.Errorf("%w: %d > %d", errSampleOversize, len(data), sampleMax)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r sample
	if err := dec.Decode(&r); err != nil {
		return sample{}, fmt.Errorf("sample: decode: %w", err)
	}
	if dec.More() {
		return sample{}, errSampleTrailing
	}
	canon, err := oracleCanonicalBytes(r)
	if err != nil {
		return sample{}, err
	}
	if !bytes.Equal(canon, data) {
		return sample{}, errSampleNoncanonical
	}
	return r, nil
}

// decodeCorpus derives inputs from one valid record: every truncation, every
// single-byte deletion, a space at every offset, every byte value at every
// offset, and whole-document shapes around the size bound.
func decodeCorpus(valid []byte, limit int) [][]byte {
	base := string(valid)
	out := [][]byte{nil, {}, valid}
	for i := 0; i < len(valid); i++ {
		out = append(out, []byte(base[:i]), []byte(base[:i]+base[i+1:]), []byte(base[:i]+" "+base[i:]))
		for c := 0; c < 256; c++ {
			if valid[i] == byte(c) {
				continue
			}
			m := append([]byte(nil), valid...)
			m[i] = byte(c)
			out = append(out, m)
		}
	}
	pad := func(n int) string { return base + strings.Repeat(" ", n-len(base)) }
	for _, s := range []string{
		base + base, base + " " + base, base + "\n", base + " ", " " + base, "\xef\xbb\xbf" + base,
		base + "x", base + "{}", base + "null", base + ",", "[" + base + "]",
		"null", "{}", "[]", "1", `""`, "true", " ", "{", "}",
		`{"schema_version":1,` + base[1:],
		strings.Replace(base, `"schema_version"`, `"Schema_Version"`, 1),
		strings.Replace(base, `"schema_version":1`, `"schema_version":1.0`, 1),
		strings.Replace(base, `"schema_version":1`, `"schema_version":1e0`, 1),
		strings.Replace(base, `"schema_version":1`, `"schema_version":"1"`, 1),
		strings.Replace(base, `"schema_version":1`, `"schema_version":null`, 1),
		strings.Replace(base, `"schema_version":1`, `"schema_version":99999999999999999999`, 1),
		strings.Replace(base, `"protocol":"s`, `"protocol":"\u0073`, 1),
		strings.Replace(base, `"protocol":"`, `"protocol":"<>&`, 1),
		strings.Replace(base, `"protocol":"`, `"protocol":"\u003c`, 1),
		base[:len(base)-1] + `,"evil":true}`,
		base[:len(base)-1] + `,"crc32c":"00000000"}`,
		pad(limit - 1), pad(limit), pad(limit + 1), pad(2 * limit),
		"{" + strings.Repeat(" ", limit-2) + "}", "{" + strings.Repeat(" ", limit-1) + "}",
		strings.Repeat("x", limit), strings.Repeat("x", limit+1),
		strings.Repeat("[", limit), strings.Repeat("[", limit+1),
	} {
		out = append(out, []byte(s))
	}
	return out
}

func sameError(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Error() != b.Error() {
		return false
	}
	for _, s := range []error{errSampleEmpty, errSampleOversize, errSampleTrailing, errSampleNoncanonical} {
		if errors.Is(a, s) != errors.Is(b, s) {
			return false
		}
	}
	// A strict-decode refusal wraps encoding/json's error on both sides.
	var sa, sb *json.SyntaxError
	return errors.As(a, &sa) == errors.As(b, &sb)
}

func TestDecode_MatchesRootOracle(t *testing.T) {
	corpus := decodeCorpus(validSample(t), sampleMax)
	classes := map[string]int{}
	for _, in := range corpus {
		got, gerr := Decode[sample](in, sampleEnvelope())
		want, werr := oracleDecodeSample(in)
		if got != want || !sameError(gerr, werr) {
			t.Fatalf("input %q:\n got %+v, %v\nwant %+v, %v", in, got, gerr, want, werr)
		}
		switch {
		case gerr == nil:
			classes["accepted"]++
		case errors.Is(gerr, errSampleEmpty):
			classes["empty"]++
		case errors.Is(gerr, errSampleOversize):
			classes["oversize"]++
		case errors.Is(gerr, errSampleTrailing):
			classes["trailing"]++
		case errors.Is(gerr, errSampleNoncanonical):
			classes["noncanonical"]++
		default:
			classes["decode"]++
		}
	}
	if len(corpus) < 20000 {
		t.Fatalf("corpus is %d inputs", len(corpus))
	}
	for _, c := range []string{"accepted", "empty", "oversize", "trailing", "noncanonical", "decode"} {
		if classes[c] == 0 {
			t.Fatalf("corpus never reaches %q: %v", c, classes)
		}
	}
}

func TestDecode_StepOrderAndTexts(t *testing.T) {
	valid := validSample(t)
	base := string(valid)
	e := sampleEnvelope()
	for _, c := range []struct {
		name string
		in   string
		is   error
		text string
	}{
		{"empty", "", errSampleEmpty, "sample: empty record"},
		// Size is tested before the bytes are parsed: garbage past the bound is "oversize".
		{"oversize garbage", strings.Repeat("x", sampleMax+1), errSampleOversize, "sample: record exceeds max size: 257 > 256"},
		{"oversize padded", base + strings.Repeat(" ", sampleMax+1-len(base)), errSampleOversize, "sample: record exceeds max size: 257 > 256"},
		// The bound is inclusive: exactly MaxBytes is parsed, then refused as non-canonical.
		{"at the bound", base + strings.Repeat(" ", sampleMax-len(base)), errSampleNoncanonical, "sample: record is not in canonical form"},
		// Trailing data is tested before canonical form.
		{"second value", base + " " + base, errSampleTrailing, "sample: trailing data after record"},
		{"trailing newline", base + "\n", errSampleNoncanonical, "sample: record is not in canonical form"},
		{"duplicate key", `{"schema_version":1,` + base[1:], errSampleNoncanonical, "sample: record is not in canonical form"},
		{"key case", strings.Replace(base, `"protocol"`, `"Protocol"`, 1), errSampleNoncanonical, "sample: record is not in canonical form"},
		{"escaped scalar", strings.Replace(base, `"protocol":"s`, `"protocol":"\u0073`, 1), errSampleNoncanonical, "sample: record is not in canonical form"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec, err := Decode[sample]([]byte(c.in), e)
			if !errors.Is(err, c.is) || err.Error() != c.text {
				t.Fatalf("got %v, want %q", err, c.text)
			}
			if rec != (sample{}) {
				t.Fatalf("a refusal returned a non-zero record: %+v", rec)
			}
		})
	}

	// Unknown fields are refused by the strict decode, under the record's name,
	// wrapping encoding/json's error; none of the four sentinels matches.
	_, err := Decode[sample]([]byte(base[:len(base)-1]+`,"evil":true}`), e)
	if err == nil || !strings.HasPrefix(err.Error(), "sample: decode: ") || errors.Unwrap(err) == nil {
		t.Fatalf("unknown field: %v", err)
	}
	for _, s := range []error{errSampleEmpty, errSampleOversize, errSampleTrailing, errSampleNoncanonical} {
		if errors.Is(err, s) {
			t.Fatalf("a strict-decode refusal matched %v", s)
		}
	}

	rec, err := Decode[sample](valid, e)
	if err != nil || rec.FeedVersion != 42 || rec.ETag != `"v42"` || rec.CRC32C != "43d5a692" {
		t.Fatalf("the canonical record was not accepted: %+v, %v", rec, err)
	}
}

// Decode does not check the seal or any field: a canonical record with a
// wrong checksum and a nonsense version is the owner's to refuse.
func TestDecode_DoesNotValidateFieldsOrSeal(t *testing.T) {
	b, err := Canonical(sample{SchemaVersion: -7, Protocol: "", FeedVersion: -1, CRC32C: "not-a-crc"})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := Decode[sample](b, sampleEnvelope())
	if err != nil || rec.SchemaVersion != -7 || rec.CRC32C != "not-a-crc" {
		t.Fatalf("got %+v, %v", rec, err)
	}
}

// A sentinel the owner forgot must not turn a refusal into success.
func TestDecode_NilSentinelStillRefuses(t *testing.T) {
	valid := string(validSample(t))
	bare := Envelope{Name: "bare", MaxBytes: sampleMax}
	for name, in := range map[string]string{
		"empty":        "",
		"oversize":     strings.Repeat("x", sampleMax+1),
		"trailing":     valid + " " + valid,
		"noncanonical": valid + "\n",
		"decode":       "{",
	} {
		rec, err := Decode[sample]([]byte(in), bare)
		if err == nil {
			t.Fatalf("%s: a refused input was accepted with a nil sentinel", name)
		}
		if rec != (sample{}) {
			t.Fatalf("%s: non-zero record on refusal", name)
		}
	}
	// The zero Envelope accepts nothing at all: MaxBytes 0 refuses every non-empty input.
	if _, err := Decode[sample]([]byte(valid), Envelope{}); err == nil {
		t.Fatal("the zero Envelope accepted a record")
	}
	// A negative bound refuses too.
	if _, err := Decode[sample]([]byte(valid), Envelope{MaxBytes: -1}); err == nil {
		t.Fatal("a negative bound accepted a record")
	}
}

// Two record kinds keep their own vocabulary, and concurrent decodes of both
// do not affect one another (there is no state to share).
func TestDecode_KindsAreIndependent(t *testing.T) {
	valid := validSample(t)
	otherValid, err := Canonical(other{Epoch: 7, Note: "n"})
	if err != nil {
		t.Fatal(err)
	}
	_, serr := Decode[sample](nil, sampleEnvelope())
	_, oerr := Decode[other](nil, otherEnvelope())
	if !errors.Is(serr, errSampleEmpty) || errors.Is(serr, errOtherEmpty) ||
		!errors.Is(oerr, errOtherEmpty) || errors.Is(oerr, errSampleEmpty) {
		t.Fatalf("sentinels crossed kinds: %v / %v", serr, oerr)
	}
	// One kind's canonical record is not another kind's.
	if _, err := Decode[other](valid, Envelope{Name: "other", MaxBytes: sampleMax}); err == nil {
		t.Fatal("a sample record decoded as an other record")
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				var err error
				if i%2 == 0 {
					err = decodeSampleBothWays(valid)
				} else {
					err = decodeOtherBothWays(otherValid)
				}
				if err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

func decodeSampleBothWays(valid []byte) error {
	r, err := Decode[sample](valid, sampleEnvelope())
	if err != nil || r.FeedVersion != 42 {
		return fmt.Errorf("sample: %+v %v", r, err)
	}
	if _, err := Decode[sample](append(append([]byte(nil), valid...), '\n'), sampleEnvelope()); !errors.Is(err, errSampleNoncanonical) {
		return fmt.Errorf("sample refusal: %v", err)
	}
	return nil
}

func decodeOtherBothWays(valid []byte) error {
	r, err := Decode[other](valid, otherEnvelope())
	if err != nil || r.Epoch != 7 {
		return fmt.Errorf("other: %+v %v", r, err)
	}
	if _, err := Decode[other](nil, otherEnvelope()); !errors.Is(err, errOtherEmpty) {
		return fmt.Errorf("other refusal: %v", err)
	}
	return nil
}

// Decode does not keep or change the caller's bytes.
func TestDecode_LeavesInputUntouched(t *testing.T) {
	valid := validSample(t)
	in := append([]byte(nil), valid...)
	if _, err := Decode[sample](in, sampleEnvelope()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in, valid) {
		t.Fatal("Decode changed its input")
	}
}

func FuzzDecode(f *testing.F) {
	valid := validSample(f)
	f.Add(valid)
	f.Add([]byte(nil))
	f.Add(append(append([]byte(nil), valid...), '\n'))
	f.Add([]byte(`{"schema_version":1,"evil":true}`))
	f.Add(bytes.Repeat([]byte("x"), sampleMax+1))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, gerr := Decode[sample](data, sampleEnvelope())
		want, werr := oracleDecodeSample(data)
		if got != want || !sameError(gerr, werr) {
			t.Fatalf("input %q:\n got %+v, %v\nwant %+v, %v", data, got, gerr, want, werr)
		}
		if gerr == nil {
			// Accepted means: the input IS the canonical bytes of the result.
			canon, err := Canonical(got)
			if err != nil || !bytes.Equal(canon, data) {
				t.Fatalf("accepted non-canonical input %q", data)
			}
		}
	})
}
