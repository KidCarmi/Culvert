package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestKeycloakOIDCInterop_ResolveIdentity(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("CULVERT_KEYCLOAK_BASE_URL"), "/")
	if baseURL == "" {
		t.Skip("set CULVERT_KEYCLOAK_BASE_URL to run Keycloak OIDC interop test")
	}

	realm := envOrDefault("CULVERT_KEYCLOAK_REALM", "culvert")
	clientID := envOrDefault("CULVERT_KEYCLOAK_CLIENT_ID", "culvert-proxy")
	clientSecret := requiredEnv(t, "CULVERT_KEYCLOAK_CLIENT_SECRET")
	username := envOrDefault("CULVERT_KEYCLOAK_USERNAME", "alice")
	password := requiredEnv(t, "CULVERT_KEYCLOAK_PASSWORD")

	client := &http.Client{Timeout: 10 * time.Second}
	token, err := keycloakPasswordGrant(client, baseURL, realm, clientID, clientSecret, username, password)
	if err != nil {
		t.Fatalf("get Keycloak token: %v", err)
	}

	introspectionEndpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", baseURL, url.PathEscape(realm))
	prov := &OIDCFlowProvider{
		profile: &IdPProfile{ID: "keycloak", Name: "Keycloak", Type: IdPTypeOIDC},
		cfg: &OIDCProfileConfig{
			Issuer:       fmt.Sprintf("%s/realms/%s", baseURL, url.PathEscape(realm)),
			ClientID:     clientID,
			ClientSecret: clientSecret,
			GroupsClaim:  "groups",
		},
		disc:   &oidcDiscoveryDoc{IntrospectionEndpoint: introspectionEndpoint},
		client: client,
	}

	id, ok := prov.ResolveIdentity(username, token)
	if !ok || id == nil {
		t.Fatalf("ResolveIdentity failed: ok=%v id=%+v", ok, id)
	}
	if id.Sub == "" {
		t.Fatalf("Sub is empty: %+v", id)
	}
	if id.Provider != "keycloak" {
		t.Fatalf("Provider = %q, want keycloak", id.Provider)
	}
	if id.Email != "alice@example.com" {
		t.Fatalf("Email = %q, want alice@example.com", id.Email)
	}
	if !containsKeycloakGroup(id.Groups, "engineering") {
		t.Fatalf("Groups = %v, want engineering", id.Groups)
	}
}

func keycloakPasswordGrant(client *http.Client, baseURL, realm, clientID, clientSecret, username, password string) (string, error) {
	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"username":      {username},
		"password":      {password},
		"scope":         {"openid email profile"},
	}
	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", baseURL, url.PathEscape(realm))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("missing access_token")
	}
	return tokenResp.AccessToken, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func requiredEnv(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	if value == "" {
		t.Fatalf("%s must be set when CULVERT_KEYCLOAK_BASE_URL is set", key)
	}
	return value
}

func containsKeycloakGroup(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
