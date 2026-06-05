package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"golang.org/x/net/html"
)

func TestSimpleSAMLphpInterop_CompilesProviderFromMetadataURL(t *testing.T) {
	metadataURL := strings.TrimSpace(os.Getenv("CULVERT_SIMPLESAML_METADATA_URL"))
	if metadataURL == "" {
		t.Skip("set CULVERT_SIMPLESAML_METADATA_URL to run SimpleSAMLphp interop test")
	}

	origDial := ssrfSafeDialContext
	ssrfSafeDialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	t.Cleanup(func() { ssrfSafeDialContext = origDial })

	origBaseURL := cfg.ProxyBaseURL()
	SetProxyBaseURL("https://proxy.example.test/culvert")
	t.Cleanup(func() { SetProxyBaseURL(origBaseURL) })

	prov := newSimpleSAMLphpInteropProvider(t, metadataURL)
	loginURL := simpleSAMLphpLoginURL(t, prov)
	client := simpleSAMLphpClient(t)
	loginPageURL, loginBody := fetchSimpleSAMLphpLoginPage(t, client, loginURL)
	postBody := postSimpleSAMLphpCredentials(t, client, loginPageURL, loginBody)
	assertSimpleSAMLphpAssertionExchange(t, prov, postBody)
}

func newSimpleSAMLphpInteropProvider(t *testing.T, metadataURL string) *SAMLProvider {
	t.Helper()
	prov, err := NewSAMLProvider(&IdPProfile{
		ID:      "simplesamlphp",
		Name:    "SimpleSAMLphp",
		Type:    IdPTypeSAML,
		Enabled: true,
		SAML: &SAMLProfileConfig{
			MetadataURL:     metadataURL,
			NameIDFormat:    string(saml.EmailAddressNameIDFormat),
			GroupsAttribute: "groups",
			EmailAttribute:  "email",
			NameAttribute:   "displayName",
		},
	})
	if err != nil {
		t.Fatalf("NewSAMLProvider with SimpleSAMLphp metadata: %v", err)
	}
	if prov == nil || prov.sp == nil {
		t.Fatalf("provider or service provider is nil: %+v", prov)
	}
	if prov.sp.AuthnNameIDFormat != saml.EmailAddressNameIDFormat {
		t.Fatalf("AuthnNameIDFormat = %q, want %q", prov.sp.AuthnNameIDFormat, saml.EmailAddressNameIDFormat)
	}
	if prov.sp.EntityID != "https://proxy.example.test/culvert" {
		t.Fatalf("EntityID = %q, want configured proxy base URL", prov.sp.EntityID)
	}
	return prov
}

func simpleSAMLphpLoginURL(t *testing.T, prov *SAMLProvider) string {
	t.Helper()
	loginURL := prov.CaptiveLoginURL("https://app.example.test/", nil)
	if loginURL == "" {
		t.Fatal("CaptiveLoginURL returned empty URL")
	}
	if !strings.Contains(loginURL, "SAMLRequest=") || !strings.Contains(loginURL, "RelayState=") {
		t.Fatalf("login URL does not look like an SP-initiated SAML redirect: %q", loginURL)
	}
	return loginURL
}

func simpleSAMLphpClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create SimpleSAMLphp cookie jar: %v", err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Jar:     jar,
	}
}

func fetchSimpleSAMLphpLoginPage(t *testing.T, client *http.Client, loginURL string) (*url.URL, []byte) {
	t.Helper()
	// #nosec G107 -- integration test intentionally follows the IdP login URL from trusted CI fixture metadata.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
	if err != nil {
		t.Fatalf("build SimpleSAMLphp login request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET SimpleSAMLphp login URL: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read SimpleSAMLphp login response: %v", err)
	}
	assertSimpleSAMLphpHTTPResponse(t, "login URL", resp.StatusCode, body)
	return resp.Request.URL, body
}

func assertSimpleSAMLphpHTTPResponse(t *testing.T, label string, statusCode int, body []byte) {
	t.Helper()
	bodyText := string(body)
	if statusCode == http.StatusNotFound {
		t.Fatalf("SimpleSAMLphp rejected SP-initiated login URL with 404; body=%q", bodyText)
	}
	if statusCode >= 500 {
		t.Fatalf("SimpleSAMLphp %s returned HTTP %d; body=%q", label, statusCode, bodyText)
	}
	if strings.Contains(bodyText, "SimpleSAML\\Error") {
		t.Fatalf("SimpleSAMLphp %s returned an error page; status=%d body=%q", label, statusCode, bodyText)
	}
}

func postSimpleSAMLphpCredentials(t *testing.T, client *http.Client, loginURL *url.URL, loginBody []byte) []byte {
	t.Helper()
	loginForm := simpleSAMLphpCredentialForm(t, loginBody)
	loginAction, err := resolveFormAction(loginURL, loginForm.action)
	if err != nil {
		t.Fatalf("resolve SimpleSAMLphp login form action: %v", err)
	}
	postReq := simpleSAMLphpCredentialRequest(t, loginAction, loginForm.values)
	postResp, err := client.Do(postReq)
	if err != nil {
		t.Fatalf("POST SimpleSAMLphp credentials: %v", err)
	}
	defer postResp.Body.Close()
	postBody, err := io.ReadAll(io.LimitReader(postResp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read SimpleSAMLphp credential response: %v", err)
	}
	assertSimpleSAMLphpHTTPResponse(t, "credential POST", postResp.StatusCode, postBody)
	return postBody
}

func simpleSAMLphpCredentialForm(t *testing.T, loginBody []byte) htmlForm {
	t.Helper()
	loginForm, err := findHTMLForm(loginBody, func(f htmlForm) bool {
		return f.hasPasswordInput()
	})
	if err != nil {
		t.Fatalf("find SimpleSAMLphp login form: %v", err)
	}
	usernameField := loginForm.firstInputNameByType("text")
	passwordField := loginForm.firstInputNameByType("password")
	if usernameField == "" || passwordField == "" {
		t.Fatalf("SimpleSAMLphp login form missing username/password fields: %+v", loginForm.inputs)
	}
	loginForm.values.Set(usernameField, "alice")
	loginForm.values.Set(passwordField, "alice-password")
	return loginForm
}

func simpleSAMLphpCredentialRequest(t *testing.T, loginAction string, values url.Values) *http.Request {
	t.Helper()
	// #nosec G107 -- integration test intentionally posts to the trusted CI fixture IdP form action.
	postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, loginAction, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatalf("build SimpleSAMLphp credential POST: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return postReq
}

func assertSimpleSAMLphpAssertionExchange(t *testing.T, prov *SAMLProvider, postBody []byte) {
	t.Helper()
	acsForm, err := findHTMLForm(postBody, func(f htmlForm) bool {
		return f.values.Get("SAMLResponse") != ""
	})
	if err != nil {
		t.Fatalf("find SimpleSAMLphp SAMLResponse form: %v", err)
	}
	callbackReq := httptestSAMLCallbackRequest(t, acsForm.values)
	id, relayURL, err := prov.ExchangeAssertion(callbackReq)
	if err != nil {
		t.Fatalf("ExchangeAssertion from SimpleSAMLphp response: %v", err)
	}
	if relayURL != "https://app.example.test/" {
		t.Fatalf("relayURL = %q, want original destination", relayURL)
	}
	if id.Sub != "alice@example.com" || id.Email != "alice@example.com" {
		t.Fatalf("identity = %+v, want alice@example.com subject/email", id)
	}
	if !containsSAMLInteropString(id.Groups, "engineering") {
		t.Fatalf("groups = %v, want engineering", id.Groups)
	}
}

type htmlForm struct {
	action string
	values url.Values
	inputs []htmlInput
}

type htmlInput struct {
	name  string
	typ   string
	value string
}

func findHTMLForm(body []byte, match func(htmlForm) bool) (htmlForm, error) {
	root, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return htmlForm{}, err
	}
	var found htmlForm
	var ok bool
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if ok {
			return
		}
		if n.Type == html.ElementNode && n.Data == "form" {
			form := parseHTMLForm(n)
			if match(form) {
				found = form
				ok = true
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	if !ok {
		return htmlForm{}, fmt.Errorf("matching form not found")
	}
	return found, nil
}

func parseHTMLForm(formNode *html.Node) htmlForm {
	f := htmlForm{values: make(url.Values)}
	f.action = attrValue(formNode, "action")
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			input := htmlInput{
				name:  attrValue(n, "name"),
				typ:   strings.ToLower(attrValue(n, "type")),
				value: attrValue(n, "value"),
			}
			if input.typ == "" {
				input.typ = "text"
			}
			if input.name != "" {
				f.inputs = append(f.inputs, input)
				f.values.Set(input.name, input.value)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(formNode)
	return f
}

func (f htmlForm) hasPasswordInput() bool {
	return f.firstInputNameByType("password") != ""
}

func (f htmlForm) firstInputNameByType(typ string) string {
	for _, input := range f.inputs {
		if input.typ == typ {
			return input.name
		}
	}
	return ""
}

func attrValue(n *html.Node, name string) string {
	for _, attr := range n.Attr {
		if attr.Key == name {
			return attr.Val
		}
	}
	return ""
}

func resolveFormAction(base *url.URL, action string) (string, error) {
	if base == nil {
		return "", fmt.Errorf("missing base URL")
	}
	if action == "" {
		return base.String(), nil
	}
	u, err := url.Parse(action)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(u).String(), nil
}

func httptestSAMLCallbackRequest(t *testing.T, values url.Values) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/saml/callback", strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatalf("build callback request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func containsSAMLInteropString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
