package handlers

// Fork-only guarantee (fork #37, restored by VD-6903): a static OAuth Save
// persists credentials only for an exact, successful, unconsumed, caller-bound
// test proof, and consumes that proof once. Kept in its own file so an
// upstream sync cannot drop these tests by merging over a shared one.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
)

func TestSetOAuthCredentialsRejectsProoflessSaveWithoutPersistingCredentials(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	recorder := httptest.NewRecorder()
	req := newStaticOAuthTestRequest(t, http.MethodPost, "/", `{"clientID":"candidate-client","clientSecret":"candidate-secret"}`, recorder, gateway,
		&v1.MCPCatalog{Name: "default", Namespace: system.DefaultNamespace}, entry)
	req.SetPathValue("catalog_id", "default")
	req.SetPathValue("entry_id", entry.Name)

	handler := &MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}
	if err := handler.SetOAuthCredentials(req); err == nil {
		t.Fatal("proofless credential Save succeeded")
	}
	if _, err := gateway.RevealCredential(t.Context(), []string{system.MCPOAuthCredentialName(entry.Name)}, "oauth"); err == nil {
		t.Fatal("proofless credential Save persisted credentials")
	}
}

func TestSetOAuthCredentialsRequiresExactSuccessfulOneUseProof(t *testing.T) {
	t.Run("successful exact proof is consumed after credential persistence", func(t *testing.T) {
		gateway := newOAuthCredentialTestGatewayClient(t)
		entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
		proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
		req, recorder := newSetOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)

		if err := (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).SetOAuthCredentials(req); err != nil {
			t.Fatalf("save verified credentials: %v", err)
		}
		credential, err := gateway.RevealCredential(t.Context(), []string{system.MCPOAuthCredentialName(entry.Name)}, "oauth")
		if err != nil {
			t.Fatalf("reveal stored credential: %v", err)
		}
		if credential.Secrets["CLIENT_ID"] != "candidate-client" || credential.Secrets["CLIENT_SECRET"] != "candidate-secret" {
			t.Fatalf("stored credential = %#v", credential.Secrets)
		}
		if err := commitMCPStaticOAuthCredential(t.Context(), gateway, proof, "user-1", entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "candidate-client", "candidate-secret", true); !errors.Is(err, gatewayclient.ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("saved proof was reusable: %v", err)
		}
		if strings.Contains(recorder.Body.String(), "candidate-secret") {
			t.Fatalf("Save response exposed secret: %s", recorder.Body.String())
		}
		var updated v1.MCPServerCatalogEntry
		if err := req.Get(&updated, entry.Name); err != nil {
			t.Fatalf("get reconciled entry: %v", err)
		}
		if updated.Annotations[v1.MCPServerCatalogEntrySyncAnnotation] != "true" {
			t.Fatalf("entry was not marked for reconciliation: %#v", updated.Annotations)
		}
	})

	for _, tt := range []struct {
		name          string
		userID        string
		requestClient string
		requestSecret string
		prepare       func(t *testing.T, gateway *gatewayclient.Client, entry *v1.MCPServerCatalogEntry) string
	}{
		{name: "wrong proof", userID: "user-1", requestClient: "candidate-client", requestSecret: "candidate-secret", prepare: func(*testing.T, *gatewayclient.Client, *v1.MCPServerCatalogEntry) string { return "wrong-proof" }},
		{name: "proof with surrounding whitespace", userID: "user-1", requestClient: "candidate-client", requestSecret: "candidate-secret", prepare: func(t *testing.T, gateway *gatewayclient.Client, entry *v1.MCPServerCatalogEntry) string {
			t.Helper()
			return " " + successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1") + " "
		}},
		{name: "wrong caller", userID: "user-2", requestClient: "candidate-client", requestSecret: "candidate-secret", prepare: func(t *testing.T, gateway *gatewayclient.Client, entry *v1.MCPServerCatalogEntry) string {
			t.Helper()
			return successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
		}},
		{name: "changed client ID", userID: "user-1", requestClient: "changed-client", requestSecret: "candidate-secret", prepare: func(t *testing.T, gateway *gatewayclient.Client, entry *v1.MCPServerCatalogEntry) string {
			t.Helper()
			return successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
		}},
		{name: "changed client secret", userID: "user-1", requestClient: "candidate-client", requestSecret: "changed-secret", prepare: func(t *testing.T, gateway *gatewayclient.Client, entry *v1.MCPServerCatalogEntry) string {
			t.Helper()
			return successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
		}},
		{name: "pending proof", userID: "user-1", requestClient: "candidate-client", requestSecret: "candidate-secret", prepare: func(t *testing.T, gateway *gatewayclient.Client, entry *v1.MCPServerCatalogEntry) string {
			t.Helper()
			return pendingStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1").TestState
		}},
		{name: "failed proof", userID: "user-1", requestClient: "candidate-client", requestSecret: "candidate-secret", prepare: func(t *testing.T, gateway *gatewayclient.Client, entry *v1.MCPServerCatalogEntry) string {
			t.Helper()
			started := pendingStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
			if err := gateway.CompleteMCPStaticOAuthTest(t.Context(), started.CallbackState, types.MCPStaticOAuthTestStatusFailed, types.MCPStaticOAuthTestFailureTokenExchange); err != nil {
				t.Fatalf("fail static OAuth test: %v", err)
			}
			return started.TestState
		}},
		{name: "consumed proof", userID: "user-1", requestClient: "candidate-client", requestSecret: "candidate-secret", prepare: func(t *testing.T, gateway *gatewayclient.Client, entry *v1.MCPServerCatalogEntry) string {
			t.Helper()
			proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
			if err := commitMCPStaticOAuthCredential(t.Context(), gateway, proof, "user-1", entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "candidate-client", "candidate-secret", false); err != nil {
				t.Fatalf("consume proof through commit: %v", err)
			}
			if _, err := gateway.DeleteCredential(t.Context(), system.MCPOAuthCredentialName(entry.Name), system.StaticOAuthCredentialName); err != nil {
				t.Fatalf("remove committed test credential: %v", err)
			}
			return proof
		}},
		{name: "stale proof", userID: "user-1", requestClient: "candidate-client", requestSecret: "candidate-secret", prepare: func(t *testing.T, gateway *gatewayclient.Client, entry *v1.MCPServerCatalogEntry) string {
			t.Helper()
			proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
			if err := gateway.CleanupExpiredMCPOAuthPendingStates(t.Context(), 0); err != nil {
				t.Fatalf("expire proof: %v", err)
			}
			return proof
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gateway := newOAuthCredentialTestGatewayClient(t)
			entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
			proof := tt.prepare(t, gateway, entry)
			req, _ := newSetOAuthCredentialRequest(t, gateway, entry, tt.userID, tt.requestClient, tt.requestSecret, proof)
			if err := (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).SetOAuthCredentials(req); err == nil {
				t.Fatal("Save accepted invalid proof")
			}
			if _, err := gateway.RevealCredential(t.Context(), []string{system.MCPOAuthCredentialName(entry.Name)}, "oauth"); err == nil {
				t.Fatal("invalid proof persisted credentials")
			}
		})
	}
}
