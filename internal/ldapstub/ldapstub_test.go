package ldapstub

import (
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func dial(t *testing.T, s *Server) *ldap.Conn {
	t.Helper()
	c, err := ldap.DialURL(s.URL())
	if err != nil {
		t.Fatal(err)
	}
	c.SetTimeout(3 * time.Second)
	return c
}

func TestStub_BindAndBaseSearchSucceed(t *testing.T) {
	s, err := Listen("127.0.0.1:0", Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := dial(t, s)
	defer c.Close()
	if err := c.Bind("cn=svc,dc=example", "pw"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	res, err := c.Search(ldap.NewSearchRequest("dc=example", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{"dn"}, nil))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].DN != "dc=example" {
		t.Fatalf("entries = %+v", res.Entries)
	}
	if s.Binds() != 1 {
		t.Fatalf("binds = %d", s.Binds())
	}
}

func TestStub_RejectBindAndUnknownBase(t *testing.T) {
	s, err := Listen("127.0.0.1:0", Options{RejectBind: true, KnownBases: []string{"dc=known"}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := dial(t, s)
	defer c.Close()
	err = c.Bind("cn=svc,dc=example", "pw")
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Fatalf("bind err = %v, want invalid credentials", err)
	}
	if err := c.UnauthenticatedBind(""); err != nil {
		t.Fatalf("anonymous bind: %v", err)
	}
	_, err = c.Search(ldap.NewSearchRequest("dc=unknown", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{"dn"}, nil))
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		t.Fatalf("search err = %v, want no such object", err)
	}
}
