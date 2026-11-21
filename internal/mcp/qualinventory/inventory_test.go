package qualinventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// writeInv writes an inventory document to a temp file and returns its path.
func writeInv(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	return p
}

// ── moved from the root mcp_inventory_test.go, names unchanged ───────────────

func TestInventory_TraversalPathRejected(t *testing.T) {
	if _, err := ReadFile("../../etc/passwd"); err == nil {
		t.Fatal("path traversal must be rejected")
	}
}

func TestInventory_OversizedFileRejected(t *testing.T) {
	big := make([]byte, MaxFileBytes+1)
	for i := range big {
		big[i] = ' '
	}
	p := writeInv(t, string(big))
	if _, err := ReadFile(p); err == nil {
		t.Fatal("oversized inventory file must be rejected")
	}
}

func TestInventory_Deterministic(t *testing.T) {
	// Two documents with the same servers in DIFFERENT order must produce identical
	// registry revisions and identical tool fingerprints (order-independent seeding).
	a := `{"schema_version":1,"tenant":"qualification","servers":[
	  {"server_id":"a","endpoint":"ea","pinned_identity":"ida","tools":[{"name":"t","input_schema":{"type":"object"}}]},
	  {"server_id":"b","endpoint":"eb","pinned_identity":"idb"}
	]}`
	b := `{"schema_version":1,"tenant":"qualification","servers":[
	  {"server_id":"b","endpoint":"eb","pinned_identity":"idb"},
	  {"server_id":"a","endpoint":"ea","pinned_identity":"ida","tools":[{"name":"t","input_schema":{"type":"object"}}]}
	]}`
	docA, err := Decode([]byte(a))
	if err != nil {
		t.Fatalf("decode a: %v", err)
	}
	docB, err := Decode([]byte(b))
	if err != nil {
		t.Fatalf("decode b: %v", err)
	}
	regA, catA, err := Seed(docA, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed a: %v", err)
	}
	regB, catB, err := Seed(docB, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed b: %v", err)
	}
	if regA.Current().Revision() != regB.Current().Revision() {
		t.Fatalf("registry revisions differ: %d vs %d", regA.Current().Revision(), regB.Current().Revision())
	}
	fpA, _ := catA.Current().Get(catalog.ToolKey{Server: "a", Name: "t"})
	fpB, _ := catB.Current().Get(catalog.ToolKey{Server: "a", Name: "t"})
	if fpA.Fingerprint.Sum() != fpB.Fingerprint.Sum() {
		t.Fatal("tool fingerprints differ across input order")
	}
}

// ── the read bound ───────────────────────────────────────────────────────────

func TestReadFile_Bounds(t *testing.T) {
	exact := strings.Repeat(" ", MaxFileBytes)
	if raw, err := ReadFile(writeInv(t, exact)); err != nil || len(raw) != MaxFileBytes {
		t.Fatalf("a file of exactly the bound must be read: len=%d err=%v", len(raw), err)
	}
	for name, tc := range map[string]struct{ path, want string }{
		"over":      {writeInv(t, exact+" "), "mcp qualification inventory: inventory file exceeds byte bound"},
		"empty":     {writeInv(t, ""), "mcp qualification inventory: inventory file is empty"},
		"missing":   {filepath.Join(t.TempDir(), "absent.json"), "mcp qualification inventory: inventory file is not readable"},
		"directory": {t.TempDir(), "mcp qualification inventory: inventory file is not readable"},
		"traversal": {"../inventory.json", "mcp qualification inventory: path traversal not allowed"},
	} {
		_, err := ReadFile(tc.path)
		if err == nil || err.Error() != tc.want {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
		// The phrase is fixed: it never echoes the path it was handed.
		if err != nil && tc.path != "" && strings.Contains(err.Error(), filepath.Base(tc.path)) {
			t.Errorf("%s: error echoes the path: %v", name, err)
		}
	}
}

// ── verdict table captured from main before the move ─────────────────────────

func oracleCorpus() []string {
	base := func(servers string) string {
		return `{"schema_version":1,"tenant":"qualification","servers":` + servers + `}`
	}
	srv := func(body string) string { return base(`[{` + body + `}]`) }
	ok := `"server_id":"s1","endpoint":"e1","pinned_identity":"id1"`
	docs := []string{
		``, ` `, `null`, `[]`, `{}`, `{"schema_version":1,`, `{"schema_version":"1"}`,
		`{"schema_version":2,"tenant":"t","servers":[{` + ok + `}]}`,
		`{"schema_version":0,"tenant":"t","servers":[{` + ok + `}]}`,
		`{"schema_version":1,"tenant":"t","servers":[],"extra":1}`,
		`{"schema_version":1,"tenant":"","servers":[{` + ok + `}]}`,
		`{"schema_version":1,"tenant":" t","servers":[{` + ok + `}]}`,
		`{"schema_version":1,"tenant":"t\u0001","servers":[{` + ok + `}]}`,
		`{"schema_version":1,"tenant":"t\u007f","servers":[{` + ok + `}]}`,
		`{"schema_version":1,"tenant":"` + strings.Repeat("a", 1024) + `","servers":[{` + ok + `}]}`,
		`{"schema_version":1,"tenant":"` + strings.Repeat("a", 1025) + `","servers":[{` + ok + `}]}`,
		`{"schema_version":1,"tenant":"t","servers":[]}`,
		`{"schema_version":1,"tenant":"t","servers":null}`,
		`{"schema_version":1,"tenant":"t"}`,
		base(`[{`+ok+`}]`) + `{}`,
		base(`[{`+ok+`}]`) + ` `,
		base(`[{`+ok+`}]`) + ` x`,
		srv(ok),
		srv(ok + `,"private_key":"x"`),
		srv(ok + `,"capability":"gateway"`),
		srv(ok + `,"capability":"management"`),
		srv(ok + `,"capability":"Gateway"`),
		srv(ok + `,"credential_profile":"profile:ro"`),
		srv(ok + `,"enabled":true`),
		srv(ok + `,"enabled":false`),
		srv(ok + `,"enabled":null`),
		srv(`"server_id":"s1","endpoint":"e1"`),
		srv(`"server_id":"s1","pinned_identity":"id1"`),
		srv(`"server_id":"","endpoint":"e1","pinned_identity":"id1"`),
		srv(`"server_id":" s","endpoint":"e1","pinned_identity":"id1"`),
		srv(`"server_id":"s\n","endpoint":"e1","pinned_identity":"id1"`),
		srv(`"server_id":"` + strings.Repeat("s", 1025) + `","endpoint":"e1","pinned_identity":"id1"`),
		srv(`"server_id":"` + strings.Repeat("s", 300) + `","endpoint":"e1","pinned_identity":"id1"`),
		srv(`"server_id":"s1","endpoint":"e 1","pinned_identity":"id1"`),
		srv(`"server_id":"s1","endpoint":"e1","pinned_identity":"id 1"`),
		srv(`"server_id":"s1","endpoint":"e1","pinned_identity":"id1","credential_profile":"bad profile"`),
		base(`[{"server_id":"s1","endpoint":"e1","pinned_identity":"id1"},{"server_id":"s1","endpoint":"e2","pinned_identity":"id2"}]`),
		base(`[{"server_id":"s1","endpoint":"e1","pinned_identity":"id1"},{"server_id":"s2","endpoint":"e1","pinned_identity":"id2"}]`),
		base(`[{"server_id":"b","endpoint":"eb","pinned_identity":"idb"},{"server_id":"a","endpoint":"ea","pinned_identity":"ida","tools":[{"name":"t","input_schema":{"type":"object"}}]}]`),
		base(`[{"server_id":"a","endpoint":"ea","pinned_identity":"ida","tools":[{"name":"t","input_schema":{"type":"object"}}]},{"server_id":"b","endpoint":"eb","pinned_identity":"idb"}]`),
		base(`[{"server_id":"good","endpoint":"e1","pinned_identity":"id1","tools":[{"name":"t","input_schema":{}}]},{"server_id":"bad","endpoint":"e2","pinned_identity":""}]`),
	}
	for _, id := range []string{"team/srv", ".", "..", "a%2f", "a?b", "a#b", `a\\b`, "a b", "a.b", "...", "a-b_c", "ü"} {
		docs = append(docs, srv(`"server_id":"`+id+`","endpoint":"e1","pinned_identity":"id1"`))
	}
	tool := func(t string) string { return srv(ok + `,"tools":[` + t + `]`) }
	docs = append(docs,
		tool(``),
		tool(`{"name":"t"}`),
		tool(`{"input_schema":{}}`),
		tool(`{"name":"","input_schema":{}}`),
		tool(`{"name":"t","input_schema":{}}`),
		tool(`{"name":"t","input_schema":"nope"}`),
		tool(`{"name":"t","input_schema":null}`),
		tool(`{"name":"t","input_schema":[]}`),
		tool(`{"name":"t","input_schema":{},"unknown":1}`),
		tool(`{"name":"t","input_schema":{}},{"name":"t","input_schema":{}}`),
		tool(`{"name":"b","input_schema":{}},{"name":"a","input_schema":{"type":"object"}}`),
		tool(`{"name":"a","input_schema":{"type":"object"}},{"name":"b","input_schema":{}}`),
		tool(`{"name":"t","input_schema":{"type":"object","properties":{"text":{"type":"string"}}},"output_schema":{"type":"object"},"description":"d","title":"T","annotations":{"readOnlyHint":true}}`),
		tool(`{"name":"t","input_schema":{},"output_schema":"x"}`),
		tool(`{"name":"t","input_schema":{},"annotations":"x"}`),
		tool(`{"name":"t","input_schema":{},"annotations":{"bogus":1}}`),
		tool(`{"name":"bad name","input_schema":{}}`),
		tool(`{"name":"`+strings.Repeat("n", 600)+`","input_schema":{}}`),
		tool(`{"name":"t","input_schema":{},"description":"`+strings.Repeat("d", 70000)+`"}`),
		srv(ok+`,"enabled":false,"tools":[{"name":"t","input_schema":{}}]`),
	)
	for _, dc := range []string{"", "unknown", "none", "approved", "internal", "arbitrary", "space", "None", " none"} {
		docs = append(docs, tool(`{"name":"t","input_schema":{},"destination_class":"`+dc+`"}`))
	}
	return docs
}

// oracleOutcome renders everything observable about one document: the exact
// error phrase, or both revisions and every seeded server and tool record.
func oracleOutcome(raw string) string {
	doc, err := Decode([]byte(raw))
	if err != nil {
		return "decode: " + err.Error()
	}
	reg, cat, err := Seed(doc, limits.DefaultCatalog())
	if err != nil {
		return "seed: " + err.Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ok reg=%d cat=%d", reg.Current().Revision(), cat.Current().Revision())
	servers := reg.Current().Servers()
	sort.Slice(servers, func(i, j int) bool { return servers[i].ID < servers[j].ID })
	for i := range servers {
		s := servers[i]
		fmt.Fprintf(&b, "|S %q %q %q %v %q %q en=%v v=%v u=%v", s.ID, s.Endpoint, s.PinnedIdentity, s.Capability, s.CredentialProfile, s.OwnerScope, s.Enabled, s.Verification, s.Usable())
	}
	tools := cat.Current().Records()
	sort.Slice(tools, func(i, j int) bool {
		if tools[i].Key.Server != tools[j].Key.Server {
			return tools[i].Key.Server < tools[j].Key.Server
		}
		return tools[i].Key.Name < tools[j].Key.Name
	})
	for i := range tools {
		t := tools[i]
		fmt.Fprintf(&b, "|T %q %q fp=%x el=%v rev=%d obs=%+v", t.Key.Server, t.Key.Name, t.Fingerprint.Sum(), t.Eligibility, t.Revision, t.Observed)
	}
	return b.String()
}

// oracleDigest is the SHA-256 over oracleOutcome of every oracleCorpus entry,
// captured by running this same corpus through the root decodeInventory and
// seedInventory on main 6795ec63a, before the code moved here. A change to any
// accept/reject verdict, error phrase, revision, stamped server field, tool
// fingerprint or eligibility changes it.
const oracleDigest = "c79077e907f4d702b4539f194a21ee6919d892ac62596c09c58155ce9020b848"

func corpusDigest(outcome func(string) string) (digest string, accepted int) {
	h := sha256.New()
	for i, d := range oracleCorpus() {
		o := outcome(d)
		if strings.HasPrefix(o, "ok") {
			accepted++
		}
		fmt.Fprintf(h, "%d\x00%s\n", i, o)
	}
	return hex.EncodeToString(h.Sum(nil)), accepted
}

func TestSeed_VerdictTableMatchesMain(t *testing.T) {
	got, accepted := corpusDigest(oracleOutcome)
	if n := len(oracleCorpus()); n != 87 || accepted != 28 {
		t.Fatalf("corpus is %d documents with %d accepted, want 87 and 28", n, accepted)
	}
	if got != oracleDigest {
		t.Fatalf("verdict table digest = %s, want %s", got, oracleDigest)
	}
}

// The digest must move when one verdict moves, or it pins nothing.
func TestSeed_VerdictTableDetectsOneChangedOutcome(t *testing.T) {
	for _, target := range []int{0, 29, 43, 86} {
		i := -1
		got, _ := corpusDigest(func(d string) string {
			i++
			o := oracleOutcome(d)
			if i == target {
				return o + " "
			}
			return o
		})
		if got == oracleDigest {
			t.Fatalf("digest did not change when outcome %d changed", target)
		}
	}
}

// ── seeding contracts ────────────────────────────────────────────────────────

const twoServers = `{"schema_version":1,"tenant":"qualification","servers":[
  {"server_id":"a","endpoint":"ea","pinned_identity":"ida","tools":[{"name":"t","input_schema":{"type":"object"},"destination_class":"none"}]},
  {"server_id":"b","endpoint":"eb","pinned_identity":"idb","enabled":false,"tools":[{"name":"u","input_schema":{}}]}
]}`

func mustDecode(t *testing.T, raw string) *Doc {
	t.Helper()
	doc, err := Decode([]byte(raw))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return doc
}

func TestSeed_ToolsAreQuarantinedAndCarryNoPeerObservation(t *testing.T) {
	doc := mustDecode(t, twoServers)
	reg, cat, err := Seed(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	recs := cat.Current().Records()
	if len(recs) != 2 {
		t.Fatalf("tools = %d, want 2", len(recs))
	}
	for i := range recs {
		if recs[i].Eligibility != catalog.Quarantined {
			t.Errorf("%v eligibility = %v, want quarantined", recs[i].Key, recs[i].Eligibility)
		}
		if recs[i].Provenance() != catalog.OperatorSeeded {
			t.Errorf("%v provenance = %v, want operator-seeded", recs[i].Key, recs[i].Provenance())
		}
	}
	a, _ := reg.Current().Get("a")
	b, _ := reg.Current().Get("b")
	if !a.Usable() || b.Usable() || b.Verification != registry.VerifyVerified {
		t.Fatalf("a usable=%v b usable=%v b verification=%v", a.Usable(), b.Usable(), b.Verification)
	}
}

// A failed seed returns no pair: the caller can never publish a partial fleet.
func TestSeed_FailureReturnsNoPair(t *testing.T) {
	for name, raw := range map[string]string{
		"second server bad": `{"schema_version":1,"tenant":"q","servers":[
		  {"server_id":"good","endpoint":"e1","pinned_identity":"id1","tools":[{"name":"t","input_schema":{}}]},
		  {"server_id":"zbad","endpoint":"e2","pinned_identity":""}]}`,
		"second tool bad": `{"schema_version":1,"tenant":"q","servers":[
		  {"server_id":"s1","endpoint":"e1","pinned_identity":"id1","tools":[{"name":"ok","input_schema":{}},{"name":"zbad"}]}]}`,
	} {
		doc, err := Decode([]byte(raw))
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		reg, cat, err := Seed(doc, limits.DefaultCatalog())
		if err == nil || reg != nil || cat != nil {
			t.Errorf("%s: reg=%v cat=%v err=%v, want nil pair and an error", name, reg, cat, err)
		}
	}
}

// Seed sorts copies: the caller's document is not reordered or otherwise written.
func TestSeed_DoesNotMutateTheDocument(t *testing.T) {
	raw := `{"schema_version":1,"tenant":"q","servers":[
	  {"server_id":"z","endpoint":"ez","pinned_identity":"idz","tools":[{"name":"y","input_schema":{}},{"name":"x","input_schema":{}}]},
	  {"server_id":"a","endpoint":"ea","pinned_identity":"ida"}]}`
	doc, err := Decode([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Seed(doc, limits.DefaultCatalog()); err != nil {
		t.Fatal(err)
	}
	if doc.Servers[0].ServerID != "z" || doc.Servers[1].ServerID != "a" ||
		doc.Servers[0].Tools[0].Name != "y" || doc.Servers[0].Tools[1].Name != "x" {
		t.Fatalf("Seed reordered the caller's document: %+v", doc.Servers)
	}
}

// Every Seed call builds its own pair, so two fleets seeded from one document
// share nothing: a write to one is invisible in the other.
func TestSeed_PairsAreIndependent(t *testing.T) {
	doc := mustDecode(t, twoServers)
	reg1, cat1, err := Seed(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	reg2, cat2, err := Seed(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if reg1 == reg2 || cat1 == cat2 {
		t.Fatal("two seeds returned a shared registry or catalog")
	}
	before := reg2.Current().Revision()
	if _, err := reg1.SetEnabled("a", false); err != nil {
		t.Fatal(err)
	}
	if a2, _ := reg2.Current().Get("a"); !a2.Usable() || reg2.Current().Revision() != before {
		t.Fatal("disabling a server in one seeded registry changed the other")
	}
	if cat1.Current().Len() != cat2.Current().Len() {
		t.Fatal("catalogs diverged in size")
	}
}

// Concurrent loads share no state (run under -race).
func TestSeed_ConcurrentCallsAreIndependent(t *testing.T) {
	want := oracleOutcome(twoServers)
	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := oracleOutcome(twoServers); got != want {
				errs <- got
			}
		}()
	}
	wg.Wait()
	close(errs)
	for got := range errs {
		t.Fatalf("concurrent seed outcome differs:\n got %s\nwant %s", got, want)
	}
}

// The limits are the caller's: a pair seeded under a smaller server cap fails
// closed with the bounded capacity phrase instead of using a package default.
func TestSeed_UsesTheCallersLimits(t *testing.T) {
	doc := mustDecode(t, twoServers)
	d := limits.DefaultCatalog()
	lim, err := limits.NewCatalog(limits.CatalogConfig{
		MaxServers:          1,
		MaxToolsPerServer:   d.MaxToolsPerServer(),
		MaxCatalogEntries:   d.MaxCatalogEntries(),
		MaxDiscoveryBytes:   d.MaxDiscoveryBytes(),
		MaxSchemaBytes:      d.MaxSchemaBytes(),
		MaxDescriptionBytes: d.MaxDescriptionBytes(),
		MaxSchemaDepth:      d.MaxSchemaDepth(),
		MaxObjectMembers:    d.MaxObjectMembers(),
		MaxArrayElements:    d.MaxArrayElements(),
		MaxDiffOps:          d.MaxDiffOps(),
		MaxNameBytes:        d.MaxNameBytes(),
		MaxEndpointBytes:    d.MaxEndpointBytes(),
		MaxIdentityBytes:    d.MaxIdentityBytes(),
		MaxServerIDBytes:    d.MaxServerIDBytes(),
		MaxCredProfileBytes: d.MaxCredProfileBytes(),
		MaxOwnerScopeBytes:  d.MaxOwnerScopeBytes(),
	})
	if err != nil {
		t.Fatalf("limits: %v", err)
	}
	reg, cat, err := Seed(doc, lim)
	if reg != nil || cat != nil || err == nil ||
		err.Error() != "mcp qualification inventory: server registration failed: server capacity reached" {
		t.Fatalf("reg=%v cat=%v err=%v", reg, cat, err)
	}
}

func FuzzDecodeSeed(f *testing.F) {
	for _, d := range oracleCorpus() {
		if len(d) < 4096 {
			f.Add([]byte(d))
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		doc, err := Decode(raw)
		if err != nil {
			if doc != nil {
				t.Fatal("Decode returned a document with an error")
			}
			return
		}
		reg, cat, err := Seed(doc, limits.DefaultCatalog())
		if (err == nil) != (reg != nil && cat != nil) || (err != nil && (reg != nil || cat != nil)) {
			t.Fatalf("Seed returned reg=%v cat=%v err=%v", reg != nil, cat != nil, err)
		}
		if err != nil {
			if !strings.HasPrefix(err.Error(), "mcp qualification inventory: ") {
				t.Fatalf("unbounded error phrase: %v", err)
			}
			return
		}
		recs := cat.Current().Records()
		for i := range recs {
			if recs[i].Eligibility != catalog.Quarantined {
				t.Fatalf("a seeded tool is %v, want quarantined", recs[i].Eligibility)
			}
		}
		if reg.Current().Len() != len(doc.Servers) {
			t.Fatalf("registry holds %d servers, document has %d", reg.Current().Len(), len(doc.Servers))
		}
	})
}

// Seeding order is sorted, not file order. Revisions and fingerprints do not
// show that (TestInventory_Deterministic passes either way), but which of two
// different failures is reported does: it is the one that sorts first.
func TestSeed_ReportsTheFirstFailureInSortedOrder(t *testing.T) {
	for name, tc := range map[string]struct{ raw, want string }{
		"servers": {
			`{"schema_version":1,"tenant":"q","servers":[
			  {"server_id":"z","endpoint":"ez","pinned_identity":""},
			  {"server_id":"a","endpoint":"ea","pinned_identity":"ida","capability":"management"}]}`,
			"mcp qualification inventory: server capability must be gateway",
		},
		"tools": {
			`{"schema_version":1,"tenant":"q","servers":[
			  {"server_id":"s","endpoint":"e","pinned_identity":"id","tools":[
			    {"name":"z"},
			    {"name":"a","input_schema":{},"destination_class":"space"}]}]}`,
			"mcp qualification inventory: tool has an unsupported destination_class",
		},
	} {
		doc := mustDecode(t, tc.raw)
		_, _, err := Seed(doc, limits.DefaultCatalog())
		if err == nil || err.Error() != tc.want {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}
