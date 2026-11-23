//go:build socks5_e2e

// Command ldapserver is the directory the SOCKS5 real-network suite points
// Culvert's IdP-registry LDAP profile at.
//
// The LDAP protocol layer is github.com/jimlambrt/gldap (an independent,
// third-party LDAPv3 server implementation, fetched from the Go module proxy
// and pinned by this module's go.sum) — not code written for this suite and
// not Culvert's own go-ldap client. This file only supplies the directory
// semantics, deliberately strict so a sloppy client cannot pass by accident:
//
//   - simple bind only; the DN must match an entry exactly (case-insensitive)
//     and the password byte-for-byte, otherwise result 49
//     (invalidCredentials); an unauthenticated bind (empty password) is 53;
//   - search is refused (50, insufficientAccessRights) unless the connection
//     is bound as the service account, mirroring a directory that does not
//     allow anonymous search;
//   - the base DN must be the configured people subtree (or an ancestor of an
//     entry in it) and the filter must be exactly one equality on the
//     configured user attribute, e.g. (uid=alice) — anything else returns no
//     entries; RFC 4515 escapes are decoded before the exact comparison;
//   - the password attribute is never returned.
//
// Every bind and search is appended to -events as one JSON line (DN, filter
// and result — never a password) so the suite can prove a SOCKS5 USER/PASS
// exchange really reached the directory.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jimlambrt/gldap"
)

// fixture is the directory content, written by the driver.
type fixture struct {
	PeopleBase string  `json:"peopleBase"`
	UserAttr   string  `json:"userAttr"`
	Service    account `json:"service"`
	Users      []user  `json:"users"`
}

type account struct {
	DN       string `json:"dn"`
	Password string `json:"password"`
}

type user struct {
	UID         string   `json:"uid"`
	DN          string   `json:"dn"`
	Password    string   `json:"password"`
	Mail        string   `json:"mail"`
	DisplayName string   `json:"displayName"`
	MemberOf    []string `json:"memberOf"`
}

type event struct {
	TS      string `json:"ts"`
	Conn    int    `json:"conn"`
	Op      string `json:"op"`
	DN      string `json:"dn,omitempty"`
	Base    string `json:"base,omitempty"`
	Filter  string `json:"filter,omitempty"`
	Entries int    `json:"entries"`
	Result  string `json:"result"`
}

type directory struct {
	fx       fixture
	filterRE *regexp.Regexp

	mu     sync.Mutex
	bound  map[int]string // connection ID → bound DN
	events *os.File
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "listen address")
	fixturePath := flag.String("fixture", "", "directory fixture JSON")
	readyPath := flag.String("ready-file", "", "file the bound address is written to once listening")
	eventsPath := flag.String("events", "", "JSONL event log (bind/search; never passwords)")
	flag.Parse()

	raw, err := os.ReadFile(*fixturePath)
	if err != nil {
		log.Fatalf("ldapserver: read fixture: %v", err)
	}
	var fx fixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		log.Fatalf("ldapserver: parse fixture: %v", err)
	}
	ev, err := os.OpenFile(*eventsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Fatalf("ldapserver: open events: %v", err)
	}
	d := &directory{
		fx:       fx,
		filterRE: regexp.MustCompile(`^\(` + regexp.QuoteMeta(fx.UserAttr) + `=([^()*=]+)\)$`),
		bound:    map[int]string{},
		events:   ev,
	}

	// Reserve the port first so the ready file can carry the real address;
	// gldap binds by address string.
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("ldapserver: listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv, err := gldap.NewServer()
	if err != nil {
		log.Fatalf("ldapserver: new server: %v", err)
	}
	mux, err := gldap.NewMux()
	if err != nil {
		log.Fatalf("ldapserver: new mux: %v", err)
	}
	must(mux.Bind(d.handleBind))
	must(mux.Search(d.handleSearch))
	must(mux.Unbind(d.handleUnbind))
	must(mux.DefaultRoute(d.handleOther))
	must(srv.Router(mux))

	go func() {
		if err := srv.Run(addr); err != nil {
			log.Printf("ldapserver: run: %v", err)
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !srv.Ready() {
		if time.Now().After(deadline) {
			log.Fatalf("ldapserver: not ready after 10s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.WriteFile(*readyPath, []byte(addr), 0o600); err != nil {
		log.Fatalf("ldapserver: write ready file: %v", err)
	}
	log.Printf("ldapserver: listening on %s (%d users)", addr, len(fx.Users))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	<-sig
	_ = srv.Stop()
}

func must(err error) {
	if err != nil {
		log.Fatalf("ldapserver: %v", err)
	}
}

func (d *directory) record(e event) {
	e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(e)
	d.mu.Lock()
	defer d.mu.Unlock()
	_, _ = d.events.Write(append(b, '\n'))
}

// passwordFor returns the stored password of an exact DN match.
func (d *directory) passwordFor(dn string) (string, bool) {
	if strings.EqualFold(dn, d.fx.Service.DN) {
		return d.fx.Service.Password, true
	}
	for _, u := range d.fx.Users {
		if strings.EqualFold(dn, u.DN) {
			return u.Password, true
		}
	}
	return "", false
}

func (d *directory) handleBind(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer func() { _ = w.Write(resp) }()

	m, err := r.GetSimpleBindMessage()
	if err != nil || m.AuthChoice != gldap.SimpleAuthChoice {
		d.record(event{Conn: r.ConnectionID(), Op: "bind", Result: "not_simple"})
		resp.SetResultCode(gldap.ResultAuthMethodNotSupported)
		return
	}
	d.mu.Lock()
	delete(d.bound, r.ConnectionID()) // a new bind always drops the previous one
	d.mu.Unlock()
	if m.Password == "" {
		d.record(event{Conn: r.ConnectionID(), Op: "bind", DN: m.UserName, Result: "unwilling_unauthenticated"})
		resp.SetResultCode(gldap.ResultUnwillingToPerform)
		return
	}
	want, ok := d.passwordFor(m.UserName)
	if !ok || string(m.Password) != want {
		d.record(event{Conn: r.ConnectionID(), Op: "bind", DN: m.UserName, Result: "invalid_credentials"})
		return
	}
	d.mu.Lock()
	d.bound[r.ConnectionID()] = m.UserName
	d.mu.Unlock()
	d.record(event{Conn: r.ConnectionID(), Op: "bind", DN: m.UserName, Result: "success"})
	resp.SetResultCode(gldap.ResultSuccess)
}

func (d *directory) handleUnbind(_ *gldap.ResponseWriter, r *gldap.Request) {
	d.mu.Lock()
	delete(d.bound, r.ConnectionID())
	d.mu.Unlock()
}

func (d *directory) handleOther(w *gldap.ResponseWriter, r *gldap.Request) {
	_ = w.Write(r.NewResponse(gldap.WithResponseCode(gldap.ResultUnwillingToPerform)))
}

func (d *directory) handleSearch(w *gldap.ResponseWriter, r *gldap.Request) {
	done := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess))
	defer func() { _ = w.Write(done) }()

	m, err := r.GetSearchMessage()
	if err != nil {
		done.SetResultCode(gldap.ResultProtocolError)
		return
	}
	d.mu.Lock()
	who := d.bound[r.ConnectionID()]
	d.mu.Unlock()
	if !strings.EqualFold(who, d.fx.Service.DN) {
		d.record(event{Conn: r.ConnectionID(), Op: "search", Base: m.BaseDN, Filter: m.Filter, Result: "insufficient_access"})
		done.SetResultCode(gldap.ResultInsufficientAccessRights)
		return
	}
	var hits []user
	if baseCovers(m.BaseDN, d.fx.PeopleBase) {
		if sm := d.filterRE.FindStringSubmatch(m.Filter); sm != nil {
			if want, ok := unescapeFilterValue(sm[1]); ok {
				for _, u := range d.fx.Users {
					if strings.EqualFold(u.UID, want) {
						hits = append(hits, u)
					}
				}
			}
		}
	}
	for _, u := range hits {
		e := r.NewSearchResponseEntry(u.DN)
		addRequested(e, m.Attributes, "mail", []string{u.Mail})
		addRequested(e, m.Attributes, "displayName", []string{u.DisplayName})
		addRequested(e, m.Attributes, "cn", []string{u.UID})
		addRequested(e, m.Attributes, d.fx.UserAttr, []string{u.UID})
		if len(u.MemberOf) > 0 {
			addRequested(e, m.Attributes, "memberOf", u.MemberOf)
		}
		if err := w.Write(e); err != nil {
			return
		}
	}
	d.record(event{Conn: r.ConnectionID(), Op: "search", Base: m.BaseDN, Filter: m.Filter, Entries: len(hits), Result: "success"})
}

// addRequested adds an attribute when the client asked for it (or asked for
// all user attributes). RFC 4511: an empty list or "*" means all.
func addRequested(e *gldap.SearchResponseEntry, requested []string, name string, values []string) {
	if len(requested) == 0 {
		e.AddAttribute(name, values)
		return
	}
	for _, a := range requested {
		if a == "*" || strings.EqualFold(a, name) {
			e.AddAttribute(name, values)
			return
		}
	}
}

// baseCovers reports whether a search rooted at base can see entries under
// people (base equals people or is an ancestor of it).
func baseCovers(base, people string) bool {
	b := strings.ToLower(strings.TrimSpace(base))
	p := strings.ToLower(strings.TrimSpace(people))
	return b == p || strings.HasSuffix(p, ","+b)
}

// unescapeFilterValue decodes RFC 4515 \XX escapes. A malformed escape is a
// non-match, never a wildcard.
func unescapeFilterValue(v string) (string, bool) {
	if !strings.Contains(v, `\`) {
		return v, true
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' {
			b.WriteByte(v[i])
			continue
		}
		if i+2 >= len(v) {
			return "", false
		}
		x, err := hex.DecodeString(v[i+1 : i+3])
		if err != nil {
			return "", false
		}
		b.Write(x)
		i += 2
	}
	return b.String(), true
}
