package main

// pac_test_tokens_test.go — 2F-A: the legacy PAC test helpers behave like a
// well-formed client and echo the AUTHORITATIVE precondition token they would
// have loaded immediately before each mutation (query-parameter form, which
// the handlers accept alongside the body form). A test that wants to exercise
// the fence itself passes the token explicitly (query or body); the injector
// never overrides a token the test already supplied. The fencing contract is
// pinned separately, without injection, in pac_fencing_test.go.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/google/uuid"
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
	// Only TOP-LEVEL body keys count: a 2F-B confirm.binding nests the same
	// key names and must not suppress the token injection.
	var top map[string]json.RawMessage
	if body != "" {
		_ = json.Unmarshal([]byte(body), &top)
	}
	has := func(k string) bool {
		if q.Get(k) != "" {
			return true
		}
		_, ok := top[k]
		return ok
	}
	set := func(k string, v any) {
		switch t := v.(type) {
		case string:
			q.Set(k, t)
		case int64:
			q.Set(k, strconv.FormatInt(t, 10))
		}
	}
	pacTestInjectTokens(u.Path, has, set)
	u.RawQuery = q.Encode()
	return u.String()
}

// pacTestInjectTokens sets the authoritative fence token(s) a request to
// path needs, unless the caller already supplied them (has).
func pacTestInjectTokens(p string, has func(string) bool, set func(string, any)) {
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
		pacTestInjectLifecycleTokens(strings.TrimSuffix(strings.TrimPrefix(p, "/api/pac/profiles/"), "/lifecycle"), has, set)
	case strings.HasPrefix(p, "/api/pac/profiles/"):
		if a, ok := pacProfiles.ProfileByID(strings.TrimPrefix(p, "/api/pac/profiles/")); ok && !has("revision") {
			set("revision", a.Revision)
		}
	case strings.HasPrefix(p, "/api/pac/pools/"):
		if pl, ok := pacProfiles.PoolByID(strings.TrimPrefix(p, "/api/pac/pools/")); ok && !has("etag") {
			set("etag", pac.PoolETag(pl))
		}
	case strings.HasPrefix(p, "/api/pac/posture/exceptions/"):
		if rec, ok := pacExceptions.Get(strings.TrimPrefix(p, "/api/pac/posture/exceptions/")); ok && !has("revision") {
			set("revision", rec.Revision)
		}
	}
}

// pacTestInjectLifecycleTokens is the lifecycle sub-resource's token set: the
// active revision (or the collection token for a first publish), the draft
// token, and a fresh UUID operationId (2F-B: publish/rollback/repair).
func pacTestInjectLifecycleTokens(id string, has func(string) bool, set func(string, any)) {
	if !has("expectedActiveRevision") && !has("collectionEtag") {
		if a, ok := pacProfiles.ProfileByID(id); ok {
			set("expectedActiveRevision", a.Revision)
		} else {
			set("collectionEtag", pac.ConfigETag(pacProfiles.Get()))
		}
	}
	if lc, ok := pacLifecycle.Get(id); ok && lc.DraftRevision > 0 && !has("draftRevision") {
		set("draftRevision", lc.DraftRevision)
	}
	if !has("operationId") {
		set("operationId", uuid.NewString())
	}
}

// pacTestConfirmFragment turns a 409 confirm_required challenge into the
// `,"confirm":{…}` body fragment a well-formed client echoes (2F-B, C2): the
// opaque challenge, the server-selected typed value and the reviewed binding.
func pacTestConfirmFragment(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var m struct {
		Code         string          `json:"code"`
		Challenge    string          `json:"challenge"`
		ConfirmValue string          `json:"confirmValue"`
		Binding      json.RawMessage `json:"binding"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || m.Code != "confirm_required" || m.Challenge == "" {
		t.Fatalf("expected a confirm_required challenge, got %d %s", rec.Code, rec.Body.String())
	}
	return fmt.Sprintf(`,"confirm":{"challenge":%q,"value":%q,"binding":%s}`, m.Challenge, m.ConfirmValue, m.Binding)
}

// pacTestWithConfirm splices the confirm fragment into a JSON object body.
func pacTestWithConfirm(body, fragment string) string {
	i := strings.LastIndex(body, "}")
	return body[:i] + fragment + body[i:]
}
