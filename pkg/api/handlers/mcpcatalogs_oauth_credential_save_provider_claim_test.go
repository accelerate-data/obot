package handlers

// Fork-only guarantee (fork #37, restored by VD-6903): a static OAuth Save
// replaces credentials bound to a previous or missing provider, consumes its
// proof on rejection, serializes same-proof saves, and refuses a provider
// change made while it waited. Kept in its own file so an upstream sync cannot
// drop these tests by merging over a shared one.

import (
	"strings"
	"testing"
	"time"

	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	"k8s.io/apiserver/pkg/storage/value"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSetOAuthCredentialsReplacesCredentialBoundToPreviousCatalogURL(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://new-mcp.example/api")
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.MCPOAuthCredentialName(entry.Name),
		Name:    "oauth",
		Secrets: map[string]string{
			"CLIENT_ID":     "old-client",
			"CLIENT_SECRET": "old-secret",
			"MCP_URL":       "https://old-mcp.example/api",
			"GENERATION":    "old-generation",
		},
	}); err != nil {
		t.Fatalf("seed old-provider credential: %v", err)
	}
	proof := successfulStaticOAuthCredentialProofFor(
		t,
		gateway,
		entry.Name,
		entry.Spec.Manifest.RemoteConfig.FixedURL,
		"user-1",
		"new-client",
		"new-secret",
	)
	req, _ := newSetOAuthCredentialRequest(t, gateway, entry, "user-1", "new-client", "new-secret", proof)

	if err := (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).SetOAuthCredentials(req); err != nil {
		t.Fatalf("save new-provider credential: %v", err)
	}
	credential, err := gateway.RevealCredential(t.Context(), []string{system.MCPOAuthCredentialName(entry.Name)}, "oauth")
	if err != nil {
		t.Fatalf("reveal new-provider credential: %v", err)
	}
	if credential.Secrets["CLIENT_ID"] != "new-client" ||
		credential.Secrets["CLIENT_SECRET"] != "new-secret" ||
		credential.Secrets["MCP_URL"] != entry.Spec.Manifest.RemoteConfig.FixedURL {
		t.Fatalf("new-provider credential = %#v", credential.Secrets)
	}
}

func TestSetOAuthCredentialsReplacesCredentialWithoutProviderBinding(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	require.NoError(t, gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.MCPOAuthCredentialName(entry.Name),
		Name:    "oauth",
		Secrets: map[string]string{
			"CLIENT_ID":     "legacy-client",
			"CLIENT_SECRET": "legacy-secret",
		},
	}))
	proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
	req, _ := newSetOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)

	require.NoError(t, (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).SetOAuthCredentials(req))
	credential, err := gateway.RevealCredential(t.Context(), []string{system.MCPOAuthCredentialName(entry.Name)}, "oauth")
	require.NoError(t, err)
	require.Equal(t, "candidate-client", credential.Secrets["CLIENT_ID"])
	require.Equal(t, entry.Spec.Manifest.RemoteConfig.FixedURL, credential.Secrets["MCP_URL"])
	require.NotEmpty(t, credential.Secrets["GENERATION"])
}

func TestSetOAuthCredentialsReplacesSameProviderCredentialWithoutGeneration(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	require.NoError(t, gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.MCPOAuthCredentialName(entry.Name),
		Name:    "oauth",
		Secrets: map[string]string{
			"CLIENT_ID":     "legacy-client",
			"CLIENT_SECRET": "legacy-secret",
			"MCP_URL":       entry.Spec.Manifest.RemoteConfig.FixedURL,
		},
	}))
	proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
	req, _ := newSetOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)

	require.NoError(t, (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).SetOAuthCredentials(req))
	credential, err := gateway.RevealCredential(t.Context(), []string{system.MCPOAuthCredentialName(entry.Name)}, "oauth")
	require.NoError(t, err)
	require.Equal(t, "candidate-client", credential.Secrets["CLIENT_ID"])
	require.Equal(t, entry.Spec.Manifest.RemoteConfig.FixedURL, credential.Secrets["MCP_URL"])
	require.NotEmpty(t, credential.Secrets["GENERATION"])
}

func TestSetOAuthCredentialsProofConsumptionOnRejectedSave(t *testing.T) {
	t.Run("storage failure", func(t *testing.T) {
		transformer := &toggleCredentialWriteErrorTransformer{failWrite: true}
		gateway := newOAuthCredentialClaimGatewayWithEncryption(t, &encryptionconfig.EncryptionConfiguration{Transformers: map[schema.GroupResource]value.Transformer{
			{Group: "obot.obot.ai", Resource: "credentials"}: transformer,
		}})
		entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
		proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
		req, _ := newSetOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)
		if err := (&MCPCatalogHandler{gatewayClient: gateway}).SetOAuthCredentials(req); err == nil {
			t.Fatal("Save succeeded despite credential storage failure")
		}
		transformer.failWrite = false
		retry, _ := newSetOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)
		if err := (&MCPCatalogHandler{gatewayClient: gateway}).SetOAuthCredentials(retry); err == nil || !strings.Contains(err.Error(), "invalid or expired OAuth credential test") {
			t.Fatalf("storage failure left proof reusable: %v", err)
		}
	})

	t.Run("existing credential", func(t *testing.T) {
		gateway := newOAuthCredentialTestGatewayClient(t)
		entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
		if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: system.MCPOAuthCredentialName(entry.Name), Name: "oauth", Secrets: map[string]string{
			"CLIENT_ID": "existing", "CLIENT_SECRET": "existing-secret",
			"MCP_URL": entry.Spec.Manifest.RemoteConfig.FixedURL, "GENERATION": "existing-generation",
		}}); err != nil {
			t.Fatalf("seed existing credential: %v", err)
		}
		proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
		req, _ := newSetOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)
		if err := (&MCPCatalogHandler{gatewayClient: gateway}).SetOAuthCredentials(req); err == nil {
			t.Fatal("Save overwrote existing credential")
		}
		retry := newReplaceOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)
		if err := (&MCPCatalogHandler{gatewayClient: gateway}).ReplaceOAuthCredentials(retry); err == nil || !strings.Contains(err.Error(), "invalid or expired OAuth credential test") {
			t.Fatalf("existing-credential rejection left proof reusable: %v", err)
		}
	})
}

func TestSetOAuthCredentialsSerializesConcurrentSameProofSaves(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
	credName := system.MCPOAuthCredentialName(entry.Name)

	release, err := gateway.AcquireCredentialLock(t.Context(), credName)
	if err != nil {
		t.Fatalf("hold credential lock: %v", err)
	}
	defer release()

	handler := &MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		req, _ := newSetOAuthCredentialRequest(t, gateway, entry.DeepCopy(), "user-1", "candidate-client", "candidate-secret", proof)
		go func() {
			<-start
			results <- handler.SetOAuthCredentials(req)
		}()
	}
	close(start)

	select {
	case err := <-results:
		t.Fatalf("concurrent Save bypassed the held credential lock: %v", err)
	case <-time.After(250 * time.Millisecond):
	}
	release()

	var successes int
	for range 2 {
		select {
		case err := <-results:
			if err == nil {
				successes++
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for serialized Save")
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent Save successes = %d, want exactly 1", successes)
	}

	credential, err := gateway.RevealCredential(t.Context(), []string{credName}, "oauth")
	if err != nil {
		t.Fatalf("verified credential did not remain configured: %v", err)
	}
	if credential.Secrets["CLIENT_ID"] != "candidate-client" || credential.Secrets["CLIENT_SECRET"] != "candidate-secret" {
		t.Fatalf("configured credential = %#v", credential.Secrets)
	}
}

func TestSetOAuthCredentialsRejectsProviderChangeWhileWaitingForCredentialLock(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://new-mcp.example/api")
	credName := system.MCPOAuthCredentialName(entry.Name)
	require.NoError(t, gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: credName,
		Name:    "oauth",
		Secrets: map[string]string{
			"CLIENT_ID":     "old-client",
			"CLIENT_SECRET": "old-secret",
			"MCP_URL":       "https://old-mcp.example/api",
			"GENERATION":    "old-generation",
		},
	}))
	proof := successfulStaticOAuthCredentialProofFor(
		t,
		gateway,
		entry.Name,
		entry.Spec.Manifest.RemoteConfig.FixedURL,
		"user-1",
		"new-client",
		"new-secret",
	)
	req, _ := newSetOAuthCredentialRequest(t, gateway, entry, "user-1", "new-client", "new-secret", proof)

	release, err := gateway.AcquireCredentialLock(t.Context(), credName)
	require.NoError(t, err)
	result := make(chan error, 1)
	go func() {
		result <- (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).SetOAuthCredentials(req)
	}()
	select {
	case err := <-result:
		t.Fatalf("Save bypassed held credential lock: %v", err)
	case <-time.After(250 * time.Millisecond):
	}

	var currentEntry v1.MCPServerCatalogEntry
	require.NoError(t, req.Storage.Get(t.Context(), kclient.ObjectKey{Namespace: entry.Namespace, Name: entry.Name}, &currentEntry))
	currentEntry.Spec.Manifest.RemoteConfig.FixedURL = "https://old-mcp.example/api"
	require.NoError(t, req.Storage.Update(t.Context(), &currentEntry))
	release()

	select {
	case err := <-result:
		require.Error(t, err)
		require.Contains(t, err.Error(), "provider changed")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for rejected Save")
	}
	credential, err := gateway.RevealCredential(t.Context(), []string{credName}, "oauth")
	require.NoError(t, err)
	require.Equal(t, "old-client", credential.Secrets["CLIENT_ID"])
	require.Equal(t, "old-generation", credential.Secrets["GENERATION"])

	retry, _ := newSetOAuthCredentialRequest(t, gateway, entry, "user-1", "new-client", "new-secret", proof)
	err = (&MCPCatalogHandler{gatewayClient: gateway}).SetOAuthCredentials(retry)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid or expired OAuth credential test")
}
