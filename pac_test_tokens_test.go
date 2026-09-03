package main

// pac_test_tokens_test.go — 2F-A: the legacy PAC test helpers behave like a
// well-formed client and echo the AUTHORITATIVE precondition token they would
// have loaded immediately before each mutation (query-parameter form, which
// the handlers accept alongside the body form). A test that wants to exercise
// the fence itself passes the token explicitly (query or body); the injector
// never overrides a token the test already supplied. The fencing contract is
// pinned separately, without injection, in pac_fencing_test.go.

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/KidCarmi/Culvert/internal/pac"
)

func pacTestWithTokens(method, path, body string) string {
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodDelete {
		return path
	}
	u, err := url.Parse(path)
	if err != nil {
		return path
	}
	q := u.Query()
	has := func(k string) bool { return q.Get(k) != "" || strings.Contains(body, `"`+k+`"`) }
	set := func(k string, v any) {
		switch t := v.(type) {
		case string:
			q.Set(k, t)
		case int64:
			q.Set(k, strconv.FormatInt(t, 10))
		}
	}
	p := u.Path
	switch {
	case p == "/api/pac-config":
		if !has("revision") {
			set("revision", pacStore.Get().Revision)
		}
	case p == "/api/pac/profiles" || p == "/api/pac/pools":
		if !has("collectionEtag") {
			set("collectionEtag", pac.ConfigETag(pacProfiles.Get()))
		}
	case strings.HasSuffix(p, "/lifecycle"):
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/api/pac/profiles/"), "/lifecycle")
		if !has("expectedActiveRevision") && !has("collectionEtag") {
			if a, ok := pacProfiles.ProfileByID(id); ok {
				set("expectedActiveRevision", a.Revision)
			} else {
				set("collectionEtag", pac.ConfigETag(pacProfiles.Get()))
			}
		}
		if !has("draftRevision") {
			if lc, ok := pacLifecycle.Get(id); ok && lc.DraftRevision > 0 {
				set("draftRevision", lc.DraftRevision)
			}
		}
	case strings.HasPrefix(p, "/api/pac/profiles/"):
		if !has("revision") {
			if a, ok := pacProfiles.ProfileByID(strings.TrimPrefix(p, "/api/pac/profiles/")); ok {
				set("revision", a.Revision)
			}
		}
	case strings.HasPrefix(p, "/api/pac/pools/"):
		if !has("etag") {
			if pl, ok := pacProfiles.PoolByID(strings.TrimPrefix(p, "/api/pac/pools/")); ok {
				set("etag", pac.PoolETag(pl))
			}
		}
	case strings.HasPrefix(p, "/api/pac/posture/exceptions/"):
		if !has("revision") {
			if rec, ok := pacExceptions.Get(strings.TrimPrefix(p, "/api/pac/posture/exceptions/")); ok {
				set("revision", rec.Revision)
			}
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
