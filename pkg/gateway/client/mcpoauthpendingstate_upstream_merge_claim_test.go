package client

// Fork-only guarantees that meet upstream v0.28.0 code (VD-7833): the fork's
// callback claim must also hide a state from upstream's live-attempt lookup, and
// the fork's commit paths must carry upstream's challenge onto the stored grant.
// Kept in its own file so an upstream sync cannot drop these tests by merging over
// a shared one.

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

func TestFindMCPOAuthPendingStateIgnoresClaimedState(t *testing.T) {
	client := newTestClient(t)
	require.NoError(t, client.CreateMCPOAuthPendingState(t.Context(), "user", "component", "https://provider/mcp", "", "request", "state", "verifier", "resource", &oauth2.Config{ClientID: "registered"}, "challenge"))

	_, err := client.FindMCPOAuthPendingState(t.Context(), "user", "component", "https://provider/mcp", "request", "challenge")
	require.NoError(t, err)

	_, err = client.ClaimMCPOAuthPendingState(t.Context(), "state")
	require.NoError(t, err)

	_, err = client.FindMCPOAuthPendingState(t.Context(), "user", "component", "https://provider/mcp", "request", "challenge")
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestCommitMCPOAuthPendingStateTokenKeepsUpstreamChallenge(t *testing.T) {
	t.Run("unfenced grant", func(t *testing.T) {
		client := newTestClient(t)
		conf := &oauth2.Config{ClientID: "registered"}
		require.NoError(t, client.CreateMCPOAuthPendingState(t.Context(), "user", "component", "https://provider/mcp", "", "request", "state", "verifier", "resource", conf, "challenge"))
		pending, err := client.ClaimMCPOAuthPendingState(t.Context(), "state")
		require.NoError(t, err)

		require.NoError(t, client.CommitMCPOAuthPendingStateToken(t.Context(), pending, pending.OAuthAuthRequestID, conf, &oauth2.Token{AccessToken: "access"}))

		stored, err := client.GetMCPOAuthToken(t.Context(), "user", "component", "https://provider/mcp")
		require.NoError(t, err)
		require.Equal(t, "challenge", stored.UpstreamChallenge)
	})

	t.Run("catalog generation fenced grant", func(t *testing.T) {
		c := newFenceTestClient(t, true)
		seedFenceTestCredential(t, c, fenceTestEntry, fenceTestSecrets("client-1", "secret-1", "generation-1"))
		conf := &oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"}
		require.NoError(t, c.CreateMCPOAuthPendingStateWithTunnel(t.Context(), fenceTestUser, fenceTestMCPID, fenceTestURL, "", "request-1", fenceTestEntry, "state-1", "verifier", "", conf, "challenge"))
		pending, err := c.ClaimMCPOAuthPendingState(t.Context(), "state-1")
		require.NoError(t, err)
		require.Equal(t, "generation-1", pending.CatalogCredentialGeneration)

		require.NoError(t, c.CommitMCPOAuthPendingStateToken(t.Context(), pending, pending.OAuthAuthRequestID, conf, &oauth2.Token{AccessToken: "access"}))

		stored, err := c.GetMCPOAuthToken(t.Context(), fenceTestUser, fenceTestMCPID, fenceTestURL)
		require.NoError(t, err)
		require.Equal(t, "challenge", stored.UpstreamChallenge)
	})
}
