package handlers

// Fork-only guarantee (VD-4128): a static OAuth test against Microsoft Entra
// requests offline_access and omits the resource parameter, so the verified
// connection gets a refresh token. The behavior used to live in the fork's
// nanobot pin; VD-7833 moved it here when Obot stopped depending on nanobot.
// Kept in its own file so an upstream sync cannot drop it by merging over a
// shared one.

import (
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func staticOAuthTestAuthURL(t *testing.T, authEndpoint string, scopes []string) url.Values {
	t.Helper()
	conf := &oauth2.Config{
		ClientID:    "client",
		Endpoint:    oauth2.Endpoint{AuthURL: authEndpoint, TokenURL: "https://example.com/token"},
		RedirectURL: "https://obot.example.com/callback",
		Scopes:      scopes,
	}
	original := strings.Join(conf.Scopes, " ")
	raw, err := staticOAuthAuthCodeURL(conf, authEndpoint, "https://mcp.example.com/mcp", "state", oauth2.GenerateVerifier())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(conf.Scopes, " "); got != original {
		t.Fatalf("expected the caller's scopes to stay %q, got %q", original, got)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Query()
}

func TestStaticOAuthAuthCodeURLRequestsOfflineAccessFromEntra(t *testing.T) {
	query := staticOAuthTestAuthURL(t, "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize", []string{"api://app/.default"})
	if got := query.Get("scope"); got != "api://app/.default offline_access" {
		t.Fatalf("expected Entra scope to gain offline_access, got %q", got)
	}
	if query.Has("resource") {
		t.Fatalf("expected no resource parameter for Entra, got %q", query.Get("resource"))
	}
}

func TestStaticOAuthAuthCodeURLDoesNotDuplicateOfflineAccess(t *testing.T) {
	query := staticOAuthTestAuthURL(t, "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize", []string{"offline_access", "User.Read"})
	if got := query.Get("scope"); got != "offline_access User.Read" {
		t.Fatalf("expected scope unchanged, got %q", got)
	}
}

func TestStaticOAuthAuthCodeURLLeavesEmptyEntraScopeUnset(t *testing.T) {
	query := staticOAuthTestAuthURL(t, "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize", nil)
	if query.Has("scope") {
		t.Fatalf("expected no scope parameter, got %q", query.Get("scope"))
	}
}

func TestStaticOAuthAuthCodeURLLeavesOtherProvidersScopeAlone(t *testing.T) {
	query := staticOAuthTestAuthURL(t, "https://auth.example.com/authorize", []string{"read"})
	if got := query.Get("scope"); got != "read" {
		t.Fatalf("expected non-Entra scope unchanged, got %q", got)
	}
	if got := query.Get("resource"); got != "https://mcp.example.com/mcp" {
		t.Fatalf("expected resource parameter for non-Entra provider, got %q", got)
	}
}
