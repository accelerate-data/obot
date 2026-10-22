package client

// Fork-only guarantee (fork #37, restored by VD-6903): shared fixtures for the
// static OAuth credential test, proof, and commit guarantees. Kept in its own file
// so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	apitypes "github.com/obot-platform/obot/apiclient/types"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	"k8s.io/apiserver/pkg/storage/value"
)

const (
	staticOAuthTestURL = "https://mcp.example/api"
)

// commitMCPStaticOAuthCredential runs the claim and commit halves the save handler
// runs, so a test can drive one save as a single step.
func (c *Client) commitMCPStaticOAuthCredential(ctx context.Context, proof, userID, mcpID, mcpURL, clientID, clientSecret string, replace bool, reconcileMCPIDs ...string) error {
	claim, err := c.ClaimMCPStaticOAuthCredentialProof(ctx, proof, userID, mcpID, mcpURL, clientID, clientSecret)
	if err != nil {
		return err
	}
	return c.CommitClaimedMCPStaticOAuthCredential(ctx, claim, replace, reconcileMCPIDs...)
}

// staticOAuthTestEncryption encrypts both the pending proof and the credential it
// commits, which is the configuration a static OAuth save requires.
func staticOAuthTestEncryption() *encryptionconfig.EncryptionConfiguration {
	return &encryptionconfig.EncryptionConfiguration{
		Transformers: map[schema.GroupResource]value.Transformer{
			mcpOAuthPendingStateGroupResource: leaseTestTransformer{},
			credentialGroupResource:           leaseTestTransformer{},
		},
	}
}

func staticOAuthTestConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "candidate-client-id",
		ClientSecret: "candidate-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://provider.example/authorize",
			TokenURL:  "https://provider.example/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: "https://obot.example/oauth/mcp/callback",
	}
}

// createStaticOAuthTest starts a test for leaseTestEntry, keeping any encryption
// configuration the caller already chose.
func createStaticOAuthTest(t *testing.T, c *Client) (MCPStaticOAuthTestStart, *oauth2.Config) {
	t.Helper()
	if c.encryptionConfig == nil {
		c.encryptionConfig = staticOAuthTestEncryption()
	}
	conf := staticOAuthTestConfig()
	started, err := c.CreateMCPStaticOAuthTest(t.Context(), leaseTestUser, leaseTestEntry, staticOAuthTestURL, "pkce-verifier", conf)
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	return started, conf
}

func completeSuccessfulStaticOAuthTest(t *testing.T, c *Client, started MCPStaticOAuthTestStart) string {
	t.Helper()
	if err := c.CompleteMCPStaticOAuthTest(t.Context(), started.CallbackState, apitypes.MCPStaticOAuthTestStatusSucceeded, ""); err != nil {
		t.Fatalf("complete successful test: %v", err)
	}
	result := readLeaseTestStatus(t, c, started)
	if result.Proof == "" || result.Proof == started.CallbackState || result.Proof == started.TestState {
		t.Fatalf("save proof was not independently minted: %+v", result)
	}
	return result.Proof
}

// createStaticOAuthProof returns a save proof for a fresh successful test.
func createStaticOAuthProof(t *testing.T, c *Client) (string, *oauth2.Config) {
	t.Helper()
	started, conf := createStaticOAuthTest(t, c)
	return completeSuccessfulStaticOAuthTest(t, c, started), conf
}

// assertStaticOAuthTestResult also proves the status payload, which reaches the
// browser, carries none of the candidate application or provider details.
func assertStaticOAuthTestResult(t *testing.T, result apitypes.MCPStaticOAuthTestResult, wantStatus apitypes.MCPStaticOAuthTestStatus, wantFailure apitypes.MCPStaticOAuthTestFailureCategory) {
	t.Helper()
	requireLeaseTestResult(t, result, wantStatus, wantFailure)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	for _, sensitive := range []string{"candidate-client-id", "candidate-client-secret", "pkce-verifier", "provider.example", "mcp.example", "secret-code", "secret-token"} {
		if strings.Contains(string(encoded), sensitive) {
			t.Fatalf("status result exposed sensitive value %q: %s", sensitive, encoded)
		}
	}
}
