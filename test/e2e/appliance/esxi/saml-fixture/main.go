// saml-fixture is a host-only synthetic IdP for disposable ESXi qualification.
// It does not configure or connect to the appliance. Its signing key exists
// only in memory; the operator imports the emitted public metadata via the UI.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"html"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

type fixture struct {
	idp    *saml.IdentityProvider
	sp     *saml.EntityDescriptor
	client netip.Addr
	mu     sync.Mutex
	issued map[string]bool
}

func (f *fixture) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	if id != f.sp.EntityID {
		return nil, os.ErrNotExist
	}
	return f.sp, nil
}

func newFixture(base string, client netip.Addr, sp *saml.EntityDescriptor) (*fixture, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial,
		Subject:   pkix.Name{CommonName: "DISPOSABLE Culvert ESXi synthetic IdP"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	metadata, err := url.Parse(base + "/metadata")
	if err != nil {
		return nil, err
	}
	sso, err := url.Parse(base + "/sso")
	if err != nil {
		return nil, err
	}
	f := &fixture{sp: sp, client: client, issued: make(map[string]bool)}
	f.idp = &saml.IdentityProvider{Key: key, Certificate: cert,
		MetadataURL: *metadata, SSOURL: *sso, ServiceProviderProvider: f,
		SignatureMethod: dsig.RSASHA256SignatureMethod}
	return f, nil
}

func (f *fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	peer, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || peer.Unmap() != f.client {
		http.Error(w, "fixture client refused", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet || len(r.RequestURI) > 65536 {
		http.Error(w, "fixture request refused", http.StatusBadRequest)
		return
	}
	if r.URL.Path == "/metadata" {
		f.idp.ServeMetadata(w, r)
		return
	}
	if r.URL.Path != "/sso" {
		http.NotFound(w, r)
		return
	}
	req, err := saml.NewIdpAuthnRequest(f.idp, r)
	if err != nil {
		http.Error(w, "invalid SAML request", 400)
		return
	}
	if err := req.Validate(); err != nil {
		http.Error(w, "unregistered SAML request", 400)
		return
	}
	user := r.URL.Query().Get("fixture_user")
	if user == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><title>Disposable lab IdP</title><h1>Synthetic lab identities only</h1>")
		for _, name := range []string{"alice", "bob"} {
			q := r.URL.Query()
			q.Set("fixture_user", name)
			fmt.Fprintf(w, `<p><a id="login-%s" href="/sso?%s">Sign in as %s</a></p>`, name, html.EscapeString(q.Encode()), name)
		}
		return
	}
	group := ""
	switch user {
	case "alice":
		group = "engineering"
	case "bob":
		group = "finance"
	}
	if group == "" {
		http.Error(w, "unknown fixture identity", 400)
		return
	}
	f.mu.Lock()
	if f.issued[req.Request.ID] || len(f.issued) >= 1000 {
		f.mu.Unlock()
		http.Error(w, "fixture request already issued or capacity reached", 409)
		return
	}
	f.issued[req.Request.ID] = true
	f.mu.Unlock()
	session := &saml.Session{NameID: user + "@example.com", NameIDFormat: string(saml.EmailAddressNameIDFormat),
		UserEmail: user + "@example.com", UserCommonName: "Synthetic " + user, Groups: []string{group}}
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		http.Error(w, "fixture assertion failed", 500)
		return
	}
	if err := req.WriteResponse(w); err != nil {
		http.Error(w, "fixture response failed", 500)
	}
}

func validateSP(raw []byte, expected, base string) (*saml.EntityDescriptor, error) {
	hash := sha256.Sum256(raw)
	if len(expected) != 64 || hex.EncodeToString(hash[:]) != expected {
		return nil, errors.New("SP metadata hash mismatch")
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, errors.New("exact HTTPS appliance origin required")
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil || !netip.MustParsePrefix("192.168.1.0/24").Contains(addr) {
		return nil, errors.New("appliance outside approved lab subnet")
	}
	var sp saml.EntityDescriptor
	if err := xml.Unmarshal(raw, &sp); err != nil {
		return nil, errors.New("invalid SP metadata")
	}
	if sp.EntityID != base || len(sp.SPSSODescriptors) != 1 {
		return nil, errors.New("SP entity mismatch")
	}
	acs := sp.SPSSODescriptors[0].AssertionConsumerServices
	post := false
	for _, endpoint := range acs {
		if endpoint.Location != base+"/auth/saml/callback" || (endpoint.Binding != saml.HTTPPostBinding && endpoint.Binding != saml.HTTPArtifactBinding) {
			return nil, errors.New("SP callback mismatch")
		}
		post = post || endpoint.Binding == saml.HTTPPostBinding
	}
	if !post {
		return nil, errors.New("SP callback mismatch")
	}
	return &sp, nil
}

func run() error {
	listen := flag.String("listen", "192.168.1.189:18443", "explicit host fixture address")
	spFile := flag.String("sp-metadata", "", "saved real appliance metadata XML")
	spHash := flag.String("sp-metadata-sha256", "", "expected metadata SHA256")
	spBase := flag.String("sp-base", "", "exact https://guest:9090 origin")
	out := flag.String("out", "", "new output directory (must not exist)")
	flag.Parse()
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || host != "192.168.1.189" || *out == "" {
		return errors.New("explicit approved bind and new output directory required")
	}
	raw, err := os.ReadFile(*spFile)
	if err != nil || len(raw) > 1<<20 {
		return errors.New("SP metadata unreadable or too large")
	}
	sp, err := validateSP(raw, *spHash, *spBase)
	if err != nil {
		return err
	}
	f, err := newFixture("http://"+*listen, netip.MustParseAddr(host), sp)
	if err != nil {
		return errors.New("fixture initialization failed")
	}
	metadata, err := xml.MarshalIndent(f.idp.Metadata(), "", "  ")
	if err != nil {
		return errors.New("fixture metadata failed")
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return errors.New("fixture bind failed")
	}
	defer ln.Close()
	if err := os.Mkdir(*out, 0700); err != nil {
		return errors.New("new fixture output directory required")
	}
	if err := os.WriteFile(filepath.Join(*out, "idp-metadata.xml"), metadata, 0600); err != nil {
		return errors.New("metadata write failed")
	}
	digest := sha256.Sum256(metadata)
	receipt, _ := json.MarshalIndent(map[string]any{"schema": 1, "synthetic": true,
		"protocol": "SAML", "bind": *listen, "allowed_browser_peer": host, "sp_base": *spBase,
		"sp_metadata_sha256": *spHash, "idp_metadata_sha256": hex.EncodeToString(digest[:]),
		"private_key_persisted": false, "lifetime_seconds": 3600}, "", "  ")
	if err := os.WriteFile(filepath.Join(*out, "fixture-ready.json"), receipt, 0600); err != nil {
		return errors.New("receipt write failed")
	}
	srv := &http.Server{Handler: f, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 65536}
	timer := time.AfterFunc(time.Hour, func() { _ = srv.Close() })
	defer timer.Stop()
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
