package main

import (
	"crypto/rand"
	"fmt"
	"github.com/KidCarmi/Culvert/internal/ldapstub"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fencedIdPPath builds the fenced /api/idp/{id} path for a PUT/DELETE in
// tests: the entry's CURRENT server-minted revision is echoed as the
// `revision` query parameter (FE-6A.0 C2), plus any extra query terms.
func fencedIdPPath(id string, extra ...string) string {
	rev := int64(1)
	if p := idpRegistry.Get(id); p != nil {
		rev = idpEntryRevision(p)
	}
	q := []string{"revision=" + strconv.FormatInt(rev, 10)}
	q = append(q, extra...)
	return "/api/idp/" + id + "?" + strings.Join(q, "&")
}

// fencedUsersPath builds the fenced /api/auth/users path carrying the
// current roster revision (plus extra query terms, e.g. username=…).
func fencedUsersPath(extra ...string) string {
	q := []string{"revision=" + strconv.FormatInt(cfg.RosterRevision(), 10)}
	q = append(q, extra...)
	return "/api/auth/users?" + strings.Join(q, "&")
}

// fencedIdPCreatePath returns POST /api/idp fenced on the CURRENT registry
// document revision (FE-6A.0 correction, Blocker 4).
func fencedIdPCreatePath(extra ...string) string {
	q := []string{"documentRevision=" + idpRegistry.DocumentRevision()}
	q = append(q, extra...)
	return "/api/idp?" + strings.Join(q, "&")
}

// fencedChangePasswordPath returns POST /api/auth/change-password fenced on
// the user's CURRENT security generation (Blocker 1).
func fencedChangePasswordPath(user string) string {
	gen, _ := cfg.UserSecurityGeneration(user)
	return "/api/auth/change-password?generation=" + strconv.FormatInt(gen, 10)
}

// fencedLockoutsPath returns POST /api/auth/lockouts fenced on the CURRENT
// lock-set generation (Blocker 4).
func fencedLockoutsPath() string {
	return "/api/auth/lockouts?generation=" + strconv.FormatInt(loginLimiter.Generation(), 10)
}

// testOperationID mints a client operationId (UUID v4 shape) for a
// cutover-bearing IdP write (Blocker 9).
// fe6aStubDirectory starts an in-process LDAP responder (bind + base-object
// search) and returns its URL. FE-6A.2 correction (Blocker 3): an ENABLED
// LDAP write crosses the directory connection preflight at the write
// boundary unconditionally, so a test that enables a profile must point it
// at a directory that answers.
func fe6aStubDirectory(t *testing.T) string {
	t.Helper()
	s, err := ldapstub.Listen("127.0.0.1:0", ldapstub.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s.URL()
}

func testOperationID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// makeIdPRegistryDurable binds an in-memory test registry to a temp file
// and persists its current profiles, so admin mutations are accepted
// (Blocker 7 refuses them on a registry with no persistence path). The
// operation-intent ring is rebound beside it.
func makeIdPRegistryDurable(t *testing.T, reg *IdPRegistry) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "idp_profiles.json")
	reg.mu.Lock()
	reg.path = path
	reg.ops = newIdPOperationStore(path)
	profiles := reg.profiles
	reg.mu.Unlock()
	if err := reg.persist(profiles); err != nil {
		t.Fatalf("persist test registry: %v", err)
	}
}

// fe6aSince returns an audit watermark that is STRICTLY later than every
// entry already in the ring: the audit TS has millisecond resolution, so a
// watermark taken in the same millisecond as a preceding legitimate write
// would count that write as "after". It spins (sub-millisecond) until the
// clock advances — a harness alignment, not evidence.
func fe6aSince() int64 {
	s := time.Now().UnixMilli()
	for time.Now().UnixMilli() == s {
	}
	return time.Now().UnixMilli()
}

// fencedDeleteReq builds an admin DELETE request against a fenced path.
func fencedDeleteReq(path string) *http.Request {
	r := httptest.NewRequest(http.MethodDelete, path, http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	return adminCtx(r)
}
