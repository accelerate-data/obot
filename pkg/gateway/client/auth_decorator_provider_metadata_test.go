package client

// Fork-only guarantee (VD-7328): admin vMCP OAuth revocation resolves the Studio
// subject from the auth provider metadata on the decorated user, so that
// metadata must survive UID decoration. The test that held this assertion also
// covered email linking, which upstream #8415 removed (VD-7833). Kept in its own
// file so an upstream sync cannot drop it by merging over a shared one.

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/system"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

func TestUserDecoratorKeepsAuthProviderMetadataAfterUIDDecoration(t *testing.T) {
	const (
		providerName = "generic-oauth-auth-provider"
		issuer       = "https://idp.example.com"
	)
	c := newIdentityUserLimitTestClient(t)
	decorator := NewUserDecorator(staticAuthenticator{
		response: &authenticator.Response{
			User: &user.DefaultInfo{
				Name: "studio-user",
				UID:  "studio-subject",
				Extra: map[string][]string{
					"email":                   {"alice@example.com"},
					"auth_provider_name":      {providerName},
					"auth_provider_namespace": {system.DefaultNamespace},
					"auth_provider_issuer":    {issuer},
				},
			},
		},
	}, c, unlimitedUserLimitProvider())

	resp, ok, err := decorator.AuthenticateRequest(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected decorated authentication response")
	}

	userID, err := strconv.ParseUint(resp.User.GetUID(), 10, 64)
	if err != nil {
		t.Fatalf("expected UID to be the Obot user ID, got %q", resp.User.GetUID())
	}
	identities, err := c.FindIdentitiesForUser(t.Context(), uint(userID))
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 1 || identities[0].ProviderUserID != types.QualifyProviderUserID(issuer, "studio-subject") {
		t.Fatalf("expected the decorated user to own the studio-subject identity, got %+v", identities)
	}
	if got := resp.User.GetExtra()["auth_provider_name"]; len(got) != 1 || got[0] != providerName {
		t.Fatalf("expected provider name to survive UID decoration, got %v", got)
	}
	if got := resp.User.GetExtra()["auth_provider_namespace"]; len(got) != 1 || got[0] != system.DefaultNamespace {
		t.Fatalf("expected provider namespace to survive UID decoration, got %v", got)
	}
	if got := resp.User.GetExtra()["auth_provider_groups"]; got == nil {
		t.Fatal("expected auth provider groups to be present in response extra")
	}
}
