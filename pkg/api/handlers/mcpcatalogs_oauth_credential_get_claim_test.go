package handlers

// Fork-only guarantee (fork #37, restored by VD-6903): reading static OAuth
// credential status never exposes the secret and fails closed for an unbound,
// ungenerated, provider-changed or unreadable credential; Save and Replace
// never overwrite an unreadable one. Kept in its own file so an upstream sync
// cannot drop these tests by merging over a shared one.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	"k8s.io/apiserver/pkg/storage/value"
)

func TestGetOAuthCredentialsReturnsCallbackAndNeverSecret(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.MCPOAuthCredentialName(entry.Name),
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "saved-client", "CLIENT_SECRET": "saved-secret", "MCP_URL": entry.Spec.Manifest.RemoteConfig.FixedURL, "GENERATION": "safe-generation"},
	}); err != nil {
		t.Fatalf("seed OAuth credential: %v", err)
	}
	recorder := httptest.NewRecorder()
	req := newStaticOAuthTestRequest(t, http.MethodGet, "/", "", recorder, gateway,
		&v1.MCPCatalog{Name: "default", Namespace: system.DefaultNamespace}, entry)
	req.SetPathValue("catalog_id", "default")
	req.SetPathValue("entry_id", entry.Name)

	if err := (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).GetOAuthCredentials(req); err != nil {
		t.Fatalf("get OAuth credential status: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode credential status: %v", err)
	}
	if len(got) != 4 || got["configured"] != true || got["clientID"] != "saved-client" || got["generation"] != "safe-generation" || got["callbackURL"] != "https://obot.example/oauth/mcp/callback" {
		t.Fatalf("credential status = %#v", got)
	}
	if strings.Contains(recorder.Body.String(), "saved-secret") {
		t.Fatalf("credential status exposed secret: %s", recorder.Body.String())
	}
}

func TestGetOAuthCredentialsFailsClosedWithoutProviderBinding(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	require.NoError(t, gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.MCPOAuthCredentialName(entry.Name),
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "legacy-client", "CLIENT_SECRET": "legacy-secret"},
	}))
	recorder := httptest.NewRecorder()
	req := newStaticOAuthTestRequest(t, http.MethodGet, "/", "", recorder, gateway,
		&v1.MCPCatalog{Name: "default", Namespace: system.DefaultNamespace}, entry)
	req.SetPathValue("catalog_id", "default")
	req.SetPathValue("entry_id", entry.Name)

	require.NoError(t, (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).GetOAuthCredentials(req))
	var got types.MCPServerOAuthCredentialStatus
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &got))
	require.False(t, got.Configured)
	require.Empty(t, got.ClientID)
	require.Empty(t, got.Generation)
}

func TestGetOAuthCredentialsFailsClosedWithoutGeneration(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
	require.NoError(t, gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.MCPOAuthCredentialName(entry.Name),
		Name:    "oauth",
		Secrets: map[string]string{
			"CLIENT_ID": "legacy-client", "CLIENT_SECRET": "legacy-secret",
			"MCP_URL": entry.Spec.Manifest.RemoteConfig.FixedURL,
		},
	}))
	recorder := httptest.NewRecorder()
	req := newStaticOAuthTestRequest(t, http.MethodGet, "/", "", recorder, gateway,
		&v1.MCPCatalog{Name: "default", Namespace: system.DefaultNamespace}, entry)
	req.SetPathValue("catalog_id", "default")
	req.SetPathValue("entry_id", entry.Name)

	require.NoError(t, (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).GetOAuthCredentials(req))
	var got types.MCPServerOAuthCredentialStatus
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &got))
	require.False(t, got.Configured)
	require.Empty(t, got.ClientID)
	require.Empty(t, got.Generation)
}

func TestGetOAuthCredentialsFailsClosedAfterCatalogURLChanges(t *testing.T) {
	gateway := newOAuthCredentialTestGatewayClient(t)
	entry := staticOAuthTestEntry("entry-1", "default", "https://new-mcp.example/api")
	if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: system.MCPOAuthCredentialName(entry.Name),
		Name:    "oauth",
		Secrets: map[string]string{
			"CLIENT_ID":     "saved-client",
			"CLIENT_SECRET": "saved-secret",
			"MCP_URL":       "https://old-mcp.example/api",
			"GENERATION":    "safe-generation",
		},
	}); err != nil {
		t.Fatalf("seed OAuth credential: %v", err)
	}
	recorder := httptest.NewRecorder()
	req := newStaticOAuthTestRequest(t, http.MethodGet, "/", "", recorder, gateway,
		&v1.MCPCatalog{Name: "default", Namespace: system.DefaultNamespace}, entry)
	req.SetPathValue("catalog_id", "default")
	req.SetPathValue("entry_id", entry.Name)

	if err := (&MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}).GetOAuthCredentials(req); err != nil {
		t.Fatalf("get OAuth credential status: %v", err)
	}
	var got types.MCPServerOAuthCredentialStatus
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode credential status: %v", err)
	}
	if got.Configured || got.ClientID != "" || got.Generation != "" {
		t.Fatalf("changed provider reported stale credential configured: %#v", got)
	}
}

func TestOAuthCredentialsFailClosedOnCredentialReadErrors(t *testing.T) {
	for _, tt := range []struct {
		name   string
		method string
		run    func(t *testing.T, handler *MCPCatalogHandler, req api.Context)
	}{
		{
			name:   "GET does not report an unreadable credential as unconfigured",
			method: http.MethodGet,
			run: func(t *testing.T, handler *MCPCatalogHandler, req api.Context) {
				t.Helper()
				recorder := req.ResponseWriter.(*httptest.ResponseRecorder)
				if err := handler.GetOAuthCredentials(req); err == nil {
					t.Fatal("GET reported unreadable OAuth credential status")
				}
				if strings.Contains(recorder.Body.String(), `"configured":false`) {
					t.Fatalf("GET failed open with response %s", recorder.Body.String())
				}
			},
		},
		{
			name:   "Save does not overwrite an unreadable credential",
			method: http.MethodPost,
			run: func(t *testing.T, handler *MCPCatalogHandler, req api.Context) {
				t.Helper()
				if err := handler.SetOAuthCredentials(req); err == nil {
					t.Fatal("Save overwrote an unreadable OAuth credential")
				}
			},
		},
		{
			name:   "Replace does not overwrite an unreadable credential",
			method: http.MethodPut,
			run: func(t *testing.T, handler *MCPCatalogHandler, req api.Context) {
				t.Helper()
				if err := handler.ReplaceOAuthCredentials(req); err == nil {
					t.Fatal("Replace overwrote an unreadable OAuth credential")
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			transformer := &toggleCredentialReadErrorTransformer{}
			gateway := newOAuthCredentialClaimGatewayWithEncryption(t, &encryptionconfig.EncryptionConfiguration{Transformers: map[schema.GroupResource]value.Transformer{
				{Group: "obot.obot.ai", Resource: "credentials"}: transformer,
			}})
			entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
			credName := system.MCPOAuthCredentialName(entry.Name)
			if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
				Context: credName,
				Name:    "oauth",
				Secrets: map[string]string{"CLIENT_ID": "existing", "CLIENT_SECRET": "existing-secret"},
			}); err != nil {
				t.Fatalf("seed OAuth credential: %v", err)
			}

			var req api.Context
			switch tt.method {
			case http.MethodPost:
				proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
				req, _ = newSetOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)
			case http.MethodPut:
				proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
				req = newReplaceOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)
			default:
				recorder := httptest.NewRecorder()
				req = newStaticOAuthTestRequest(t, tt.method, "/", "", recorder, gateway,
					&v1.MCPCatalog{Name: "default", Namespace: system.DefaultNamespace}, entry)
				req.SetPathValue("catalog_id", "default")
				req.SetPathValue("entry_id", entry.Name)
			}

			transformer.failRead = true
			tt.run(t, &MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}, req)
			transformer.failRead = false

			credential, err := gateway.RevealCredential(t.Context(), []string{credName}, "oauth")
			if err != nil {
				t.Fatalf("reveal original credential: %v", err)
			}
			if credential.Secrets["CLIENT_ID"] != "existing" || credential.Secrets["CLIENT_SECRET"] != "existing-secret" {
				t.Fatalf("credential changed after read failure: %#v", credential.Secrets)
			}
		})
	}
}

func TestOAuthCredentialsFailClosedOnTransientDatabaseReadErrors(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			gateway, rawDB := newOAuthCredentialTestGatewayClientWithOptionsAndDB(t, nil, nil)
			entry := staticOAuthTestEntry("entry-1", "default", "https://mcp.example/api")
			credName := system.MCPOAuthCredentialName(entry.Name)
			if err := gateway.UpsertCredential(t.Context(), gatewaytypes.Credential{
				Context: credName,
				Name:    "oauth",
				Secrets: map[string]string{"CLIENT_ID": "existing", "CLIENT_SECRET": "existing-secret"},
			}); err != nil {
				t.Fatalf("seed OAuth credential: %v", err)
			}

			var req api.Context
			switch method {
			case http.MethodPost:
				proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
				req, _ = newSetOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)
			case http.MethodPut:
				proof := successfulStaticOAuthCredentialProof(t, gateway, entry.Name, entry.Spec.Manifest.RemoteConfig.FixedURL, "user-1")
				req = newReplaceOAuthCredentialRequest(t, gateway, entry, "user-1", "candidate-client", "candidate-secret", proof)
			default:
				recorder := httptest.NewRecorder()
				req = newStaticOAuthTestRequest(t, method, "/", "", recorder, gateway,
					&v1.MCPCatalog{Name: "default", Namespace: system.DefaultNamespace}, entry)
				req.SetPathValue("catalog_id", "default")
				req.SetPathValue("entry_id", entry.Name)
			}

			failCredentialRead := true
			callbackName := "test:transient_oauth_credential_read_" + strings.ToLower(method)
			if err := rawDB.Callback().Query().Before("gorm:query").Register(callbackName, func(tx *gorm.DB) {
				if failCredentialRead && tx.Statement.Table == "credentials" {
					_ = tx.AddError(errors.New("transient credential database failure"))
				}
			}); err != nil {
				t.Fatalf("register transient credential read failure: %v", err)
			}
			t.Cleanup(func() { _ = rawDB.Callback().Query().Remove(callbackName) })

			handler := &MCPCatalogHandler{serverURL: "https://obot.example", gatewayClient: gateway}
			var err error
			switch method {
			case http.MethodPost:
				err = handler.SetOAuthCredentials(req)
			case http.MethodPut:
				err = handler.ReplaceOAuthCredentials(req)
			default:
				err = handler.GetOAuthCredentials(req)
			}
			if err == nil {
				t.Fatalf("%s failed open on transient credential database error", method)
			}

			failCredentialRead = false
			credential, err := gateway.RevealCredential(t.Context(), []string{credName}, "oauth")
			if err != nil {
				t.Fatalf("reveal original credential: %v", err)
			}
			if credential.Secrets["CLIENT_ID"] != "existing" || credential.Secrets["CLIENT_SECRET"] != "existing-secret" {
				t.Fatalf("credential changed after transient read failure: %#v", credential.Secrets)
			}
		})
	}
}
