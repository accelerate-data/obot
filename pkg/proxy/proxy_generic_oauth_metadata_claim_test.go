package proxy

// Fork-only guarantee (generic OAuth provider plumbing, restored by VD-6903): the
// provider's issuer and email-verified claims reach the gateway as user extras, so
// a generic OAuth identity can be linked by email only for a trusted issuer that
// verified the address. Kept in its own file so an upstream sync cannot drop this
// test by merging over a shared one.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticateRequestPassesGenericOAuthMetadata(t *testing.T) {
	emailVerified := true
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/obot-get-state" {
			t.Errorf("unexpected path %q", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if err := json.NewEncoder(w).Encode(serializableState{
			AccessToken:       "access-token",
			PreferredUsername: "alice@example.com",
			User:              "alice",
			Email:             "alice@example.com",
			Issuer:            "https://issuer.example.com/",
			EmailVerified:     &emailVerified,
		}); err != nil {
			t.Error(err)
		}
	}))
	defer provider.Close()

	p, err := newProxy("default", "generic-oauth-auth-provider", provider.URL, "")
	if err != nil {
		t.Fatal(err)
	}

	resp, ok, err := p.authenticateRequest(httptest.NewRequest(http.MethodGet, "http://obot.example.com/", nil))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected authentication to succeed")
	}

	extra := resp.User.GetExtra()
	if got := extra["auth_provider_issuer"]; len(got) != 1 || got[0] != "https://issuer.example.com/" {
		t.Fatalf("auth_provider_issuer = %#v, want the provider issuer", got)
	}
	if resp.User.GetUID() != "alice" {
		t.Fatalf("UID = %q, want the raw provider subject", resp.User.GetUID())
	}
	if got := extra["auth_provider_user_id"]; len(got) != 1 || got[0] != "alice" {
		t.Fatalf("auth_provider_user_id = %#v, want the raw provider subject", got)
	}
	if got := extra["auth_provider_email_verified"]; len(got) != 1 || got[0] != "true" {
		t.Fatalf("auth_provider_email_verified = %#v, want true", got)
	}
}
