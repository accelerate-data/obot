package oauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/obot-platform/obot/pkg/mcp"
	"github.com/stretchr/testify/require"
)

// The gateway handler and the MCP OAuth handler factory both build their
// credential-carrying exchange client here. These tests guard that single
// constructor, because every existing OAuth test supplies its own client and so
// none of them notice if the production wiring loses the policy.
func TestNewOAuthExchangeClientBlocksLoopbackUnlessOperatorAllowsIt(t *testing.T) {
	// httptest listens on 127.0.0.1, so it stands in for a token endpoint that
	// metadata discovery resolved to a loopback address.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	blocked := newOAuthExchangeClient(mcp.RemoteMCPURLValidationConfig{})
	_, err := blocked.Get(server.URL)
	require.Error(t, err)
	require.Contains(t, err.Error(), "blocked loopback")

	allowed := newOAuthExchangeClient(mcp.RemoteMCPURLValidationConfig{AllowLocalhostMCP: true})
	resp, err := allowed.Get(server.URL)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestNewOAuthExchangeClientRejectsTokenEndpointRedirect(t *testing.T) {
	var followed bool
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	// Loopback is allowed here so the refusal can only come from the redirect
	// policy, not from the address check.
	client := newOAuthExchangeClient(mcp.RemoteMCPURLValidationConfig{AllowLocalhostMCP: true})
	_, err := client.Post(redirector.URL, "application/x-www-form-urlencoded", http.NoBody)
	require.Error(t, err)
	require.Contains(t, err.Error(), "refusing to follow redirect")
	require.False(t, followed, "credentials must not reach the redirect target")
}
