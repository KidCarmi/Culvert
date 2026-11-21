package noderecord

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// Differential oracles: verbatim copies of the codec package main kept in
// saas_feed_floor.go (floorCanonicalBytes, floorCRCTable, validCRC32Hex over
// isLowerHex/isHexByte) before it bound to this package. They are frozen here
// so a later edit to the exported rules cannot silently diverge from the form
// the records already on disk were written in.
var oracleCRCTable = crc32.MakeTable(crc32.Castagnoli)

func oracleCanonicalBytes(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("saas feed floor: canonical encode: %w", err)
	}
	b := buf.Bytes()
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	return append([]byte(nil), b...), nil
}

func oracleSeal(sans any) (string, error) {
	b, err := oracleCanonicalBytes(sans)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08x", crc32.Checksum(b, oracleCRCTable)), nil
}

func oracleIsHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

func oracleValidCRC32Hex(s string) bool {
	if len(s) != 8 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !oracleIsHexByte(s[i]) {
			return false
		}
	}
	return true
}

// record mirrors the shape of the root records: fixed field order, strings,
// integers and booleans.
type record struct {
	SchemaVersion int    `json:"schema_version"`
	Protocol      string `json:"protocol"`
	Version       int64  `json:"feed_version"`
	Managed       bool   `json:"managed"`
	ETag          string `json:"etag"`
}

type nested struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
}

func encodable() []any {
	return []any{
		record{},
		record{SchemaVersion: 1, Protocol: "signed_manifest_v1", Version: 42, Managed: true, ETag: `"v42"`},
		record{Protocol: "<script>&amp;</script>", ETag: "a b c"},
		record{Protocol: "tab\there\nnewline\x00nul", Version: -1},
		record{Protocol: "café \U0001F512", ETag: "bad\xffutf8"},
		&record{SchemaVersion: 2},
		[]nested{{Name: "ai", Hosts: []string{"a.example", "b.example"}}, {Name: "empty"}},
		nested{Name: "nilhosts"},
		map[string]string{"b": "2", "a": "1", "<": ">"},
		"", "plain", 0, int64(1) << 62, true, nil,
		[]byte("bytes become base64"),
	}
}

func unencodable() []any {
	return []any{
		make(chan int),
		func() {},
		map[string]any{"a": func() {}},
		struct{ C chan int }{},
		complex(1, 2),
	}
}

func TestCanonical_MatchesRootOracle(t *testing.T) {
	for i, v := range encodable() {
		got, err := Canonical(v)
		want, werr := oracleCanonicalBytes(v)
		if err != nil || werr != nil {
			t.Fatalf("case %d: Canonical err=%v, oracle err=%v", i, err, werr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d: Canonical=%s, root oracle=%s", i, got, want)
		}
		if bytes.HasSuffix(got, []byte("\n")) {
			t.Fatalf("case %d: trailing newline in %q", i, got)
		}
	}
}

// The encoder is the feed protocol's, not a copy: the same value has the same
// bytes through both names.
func TestCanonical_IsTheProtocolEncoder(t *testing.T) {
	for i, v := range encodable() {
		got, err := Canonical(v)
		proto, perr := urlcatfeed.CanonicalJSON(v)
		if err != nil || perr != nil || !bytes.Equal(got, proto) {
			t.Fatalf("case %d: Canonical=%s (%v), urlcatfeed.CanonicalJSON=%s (%v)", i, got, err, proto, perr)
		}
	}
}

// The failure text is what package main returned before the move, byte for
// byte, and still wraps the encoding/json cause.
func TestCanonical_ErrorTextMatchesRootOracle(t *testing.T) {
	for i, v := range unencodable() {
		got, err := Canonical(v)
		_, werr := oracleCanonicalBytes(v)
		if err == nil || werr == nil {
			t.Fatalf("case %d: expected both to fail: %v / %v", i, err, werr)
		}
		if got != nil {
			t.Fatalf("case %d: bytes returned with an error: %q", i, got)
		}
		if err.Error() != werr.Error() {
			t.Fatalf("case %d: error %q, root oracle %q", i, err, werr)
		}
		if !strings.HasPrefix(err.Error(), "saas feed floor: canonical encode: json: ") {
			t.Fatalf("case %d: unexpected text %q", i, err)
		}
		if _, sealErr := Seal(v); sealErr == nil || sealErr.Error() != werr.Error() {
			t.Fatalf("case %d: Seal error %v, want %q", i, sealErr, werr)
		}
	}
	if _, err := Canonical(make(chan int)); err == nil ||
		err.Error() != "saas feed floor: canonical encode: json: unsupported type: chan int" {
		t.Fatalf("pinned text drifted: %v", err)
	}
}

func TestCanonical_ReturnsCallerOwnedBytes(t *testing.T) {
	v := record{Protocol: "p", Version: 7}
	a, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	keep := append([]byte(nil), a...)
	for i := range a {
		a[i] = 'x'
	}
	b, err := Canonical(v)
	if err != nil || !bytes.Equal(b, keep) {
		t.Fatalf("a caller's write reached a later result: %s (%v)", b, err)
	}
}

func TestChecksum_KnownVectorsAndForm(t *testing.T) {
	// CRC-32C check values (RFC 3720 appendix B.4 and the common "123456789").
	for in, want := range map[string]string{
		"":                         "00000000",
		"123456789":                "e3069283",
		strings.Repeat("\x00", 32): "8a9136aa",
		strings.Repeat("\xff", 32): "62a8ab43",
	} {
		if got := Checksum([]byte(in)); got != want {
			t.Fatalf("Checksum(%q)=%s, want %s", in, got, want)
		}
	}
	// It is Castagnoli, not the IEEE polynomial.
	if Checksum([]byte("123456789")) == fmt.Sprintf("%08x", crc32.ChecksumIEEE([]byte("123456789"))) {
		t.Fatal("checksum is the IEEE polynomial")
	}
	// Leading zeros are kept: the stored form is always 8 digits.
	for i := 0; i < 4096; i++ {
		b := []byte(fmt.Sprintf("record-%d", i))
		got := Checksum(b)
		if want := fmt.Sprintf("%08x", crc32.Checksum(b, oracleCRCTable)); got != want {
			t.Fatalf("%q: Checksum=%s, root oracle=%s", b, got, want)
		}
		if !ValidChecksum(got) {
			t.Fatalf("%q: Checksum produced %q, which ValidChecksum rejects", b, got)
		}
	}
}

func TestSeal_MatchesRootOracle(t *testing.T) {
	for i, v := range encodable() {
		got, err := Seal(v)
		want, werr := oracleSeal(v)
		if err != nil || werr != nil || got != want {
			t.Fatalf("case %d: Seal=%s (%v), root oracle=%s (%v)", i, got, err, want, werr)
		}
	}
}

// The seal covers every byte of the checksum-omitted view: changing any one
// field changes it.
func TestSeal_BindsEveryField(t *testing.T) {
	base := record{SchemaVersion: 1, Protocol: "p", Version: 42, Managed: true, ETag: "e"}
	want, err := Seal(base)
	if err != nil {
		t.Fatal(err)
	}
	muts := map[string]func(*record){
		"schema":   func(r *record) { r.SchemaVersion++ },
		"protocol": func(r *record) { r.Protocol += "x" },
		"version":  func(r *record) { r.Version++ },
		"managed":  func(r *record) { r.Managed = !r.Managed },
		"etag":     func(r *record) { r.ETag = "" },
	}
	for name, mut := range muts {
		r := base
		mut(&r)
		got, err := Seal(r)
		if err != nil || got == want {
			t.Fatalf("%s: seal did not change (%s, %v)", name, got, err)
		}
	}
}

func TestValidChecksum_MatchesRootOracle(t *testing.T) {
	cases := []string{
		"", "0", "0000000", "00000000", "000000000", "deadbeef", "DEADBEEF", "deadbeeF",
		"0123456g", "0123456 ", " 1234567", "01234567\n", "0x123456", "+1234567", "-1234567",
		"12345678", "abcdef01", "abcdefgh", "/0000000", ":0000000", "`0000000", "g0000000",
		"\x00\x00\x00\x00\x00\x00\x00\x00", "\xff\xff\xff\xff\xff\xff\xff\xff",
		"éééé", "０１２３４５６７", "0000000٠", strings.Repeat("a", 64),
	}
	// Every single byte at one position decides the boundary of the digit set.
	for c := 0; c < 256; c++ {
		cases = append(cases, "0000000"+string([]byte{byte(c)}), string([]byte{byte(c)})+"0000000")
	}
	for _, in := range cases {
		if got, want := ValidChecksum(in), oracleValidCRC32Hex(in); got != want {
			t.Fatalf("%q: ValidChecksum=%v, root oracle=%v", in, got, want)
		}
	}
	if !ValidChecksum("43d5a692") || ValidChecksum("43D5A692") || ValidChecksum("43d5a69") {
		t.Fatal("the 8-lowercase-hex rule drifted")
	}
}

// No shared state: concurrent callers on different values each get their own
// value's bytes and seal.
func TestConcurrentCallsAreIndependent(t *testing.T) {
	const workers, rounds = 16, 200
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			v := record{SchemaVersion: w, Protocol: fmt.Sprintf("p-%d", w), Version: int64(w) * 1000}
			wantB, _ := oracleCanonicalBytes(v)
			wantS, _ := oracleSeal(v)
			for i := 0; i < rounds; i++ {
				b, err := Canonical(v)
				s, serr := Seal(v)
				if err != nil || serr != nil || !bytes.Equal(b, wantB) || s != wantS || Checksum(b) != wantS {
					errs <- fmt.Sprintf("worker %d round %d: %s %s (%v %v)", w, i, b, s, err, serr)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func FuzzSealAndValidChecksum(f *testing.F) {
	f.Add("signed_manifest_v1", int64(42), `"v42"`, "43d5a692")
	f.Add("<&> ", int64(-1), "", "DEADBEEF")
	f.Add("\xff\x00", int64(0), "\n", "")
	f.Fuzz(func(t *testing.T, proto string, ver int64, etag, crc string) {
		v := record{SchemaVersion: 1, Protocol: proto, Version: ver, ETag: etag}
		b, err := Canonical(v)
		want, werr := oracleCanonicalBytes(v)
		if err != nil || werr != nil || !bytes.Equal(b, want) {
			t.Fatalf("Canonical=%q (%v), root oracle=%q (%v)", b, err, want, werr)
		}
		s, err := Seal(v)
		ws, _ := oracleSeal(v)
		if err != nil || s != ws || !ValidChecksum(s) {
			t.Fatalf("Seal=%q (%v), root oracle=%q", s, err, ws)
		}
		if ValidChecksum(crc) != oracleValidCRC32Hex(crc) {
			t.Fatalf("ValidChecksum(%q) disagrees with the root oracle", crc)
		}
	})
}
