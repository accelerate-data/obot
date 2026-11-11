package client

import (
	"net/http"
	"testing"

	apitypes "github.com/obot-platform/obot/apiclient/types"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/user"
)

// signInWithGatewayToken signs in as the gateway token reviewer and the user decorator do for a generic OAuth token
// of userID that records the bare subject, and returns the user the sign-in resolves to, or the refusal.
func signInWithGatewayToken(t *testing.T, c *Client, userID uint, subject string) (*gatewaytypes.User, error) {
	t.Helper()

	sub, issuer, err := c.GatewayTokenSignIn(t.Context(), userID, system.DefaultNamespace, genericOAuthTestProviderName, subject)
	require.NoError(t, err)
	info := &user.DefaultInfo{UID: sub, Extra: map[string][]string{}}
	if issuer != "" {
		info.Extra["auth_provider_issuer"] = []string{issuer}
	}
	providerUserID, err := signInProviderUserID(genericOAuthTestProviderName, info)
	if err != nil {
		return nil, err
	}
	return c.EnsureIdentity(t.Context(), genericOAuthSignIn(providerUserID), "", UserLimit{Unlimited: true})
}

func requireRefused(t *testing.T, err error) {
	t.Helper()

	var httpErr *apitypes.ErrHTTP
	require.ErrorAs(t, err, &httpErr)
	require.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

func TestGatewayTokenBeforeTheBackfillSignsInAsItsUser(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")
	configureGenericOAuthIssuer(t, c, issuerA)

	u, err := signInWithGatewayToken(t, c, legacyUserID, "alice")

	require.NoError(t, err)
	require.Equal(t, legacyUserID, u.ID, "an existing user's gateway token keeps working across the upgrade")
}

func TestGatewayTokenAfterTheBackfillSignsInAsItsUser(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")
	configureGenericOAuthIssuer(t, c, issuerA)
	require.NoError(t, c.BackfillIdentityIssuerBinding(t.Context()))

	u, err := signInWithGatewayToken(t, c, legacyUserID, "alice")

	require.NoError(t, err)
	require.Equal(t, legacyUserID, u.ID)
}

func TestGatewayTokenAfterTheIssuerChangesStaysWithItsUser(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")
	configureGenericOAuthIssuer(t, c, issuerA)
	require.NoError(t, c.BackfillIdentityIssuerBinding(t.Context()))
	configureGenericOAuthIssuer(t, c, issuerB)
	colliding := signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerB, "alice"))

	u, err := signInWithGatewayToken(t, c, legacyUserID, "alice")

	require.NoError(t, err)
	require.Equal(t, legacyUserID, u.ID, "the token is bound to its own user's issuer, not the configured one")
	require.NotEqual(t, colliding.ID, u.ID)
}

func TestGatewayTokenWhoseUserHasNoIdentityWithItsSubjectIsRefused(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	configureGenericOAuthIssuer(t, c, issuerA)
	bob := signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerA, "bob"))
	signInGenericOAuth(t, c, gatewaytypes.QualifyProviderUserID(issuerA, "alice"))

	_, err := signInWithGatewayToken(t, c, bob.ID, "alice")

	requireRefused(t, err)
}

func TestGatewayTokenBeforeTheBackfillWithNoConfiguredIssuerIsRefused(t *testing.T) {
	c := newIssuerBindingTestClient(t)
	legacyUserID := insertLegacyGenericOAuthIdentity(t, c, "alice")

	_, err := signInWithGatewayToken(t, c, legacyUserID, "alice")

	requireRefused(t, err)
}

func TestGatewayTokenSignInOfAnotherProviderPassesTheSubjectThrough(t *testing.T) {
	c := newIssuerBindingTestClient(t)

	sub, issuer, err := c.GatewayTokenSignIn(t.Context(), 1, system.DefaultNamespace, "github-auth-provider", "alice")

	require.NoError(t, err)
	require.Equal(t, "alice", sub)
	require.Empty(t, issuer)
}

func TestGatewayTokenSignInOfAnIssuerBoundTokenUsesItsIssuer(t *testing.T) {
	c := newIssuerBindingTestClient(t)

	sub, issuer, err := c.GatewayTokenSignIn(t.Context(), 1, system.DefaultNamespace, genericOAuthTestProviderName,
		gatewaytypes.QualifyProviderUserID(issuerA, "alice"))

	require.NoError(t, err)
	require.Equal(t, "alice", sub)
	require.Equal(t, gatewaytypes.NormalizeIssuer(issuerA), issuer)
}
