package handlers

// Fork-only guarantee (fork #37, restored by VD-6903): shared fixtures for the
// static OAuth credential Save/Replace/Get/Delete claim tests. Kept in its own
// file so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/storage"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storagescheme "github.com/obot-platform/obot/pkg/storage/scheme"
	"github.com/obot-platform/obot/pkg/system"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	"k8s.io/apiserver/pkg/storage/value"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testStaticOAuthCredentialGeneration = "generation-1"
)

type oauthInstanceListErrorStorage struct {
	storage.Client
}

type toggleCredentialReadErrorTransformer struct {
	failRead bool
}

type mcpIDRecordingBackend struct {
	trigger func(context.Context, string) error
}

func (s oauthInstanceListErrorStorage) List(ctx context.Context, list kclient.ObjectList, opts ...kclient.ListOption) error {
	if _, ok := list.(*v1.MCPServerInstanceList); ok {
		return errors.New("server instance list unavailable")
	}
	return s.Client.List(ctx, list, opts...)
}

// newOAuthCredentialClaimStorage indexes servers and instances by catalog entry
// because Save, Replace and Delete resolve their token reconciliation targets
// through that field selector.
func newOAuthCredentialClaimStorage(entry *v1.MCPServerCatalogEntry, objects ...kclient.Object) storage.Client {
	allObjects := append([]kclient.Object{
		&v1.MCPCatalog{Name: "default", Namespace: system.DefaultNamespace},
		entry,
	}, objects...)
	return storage.Client(fake.NewClientBuilder().
		WithScheme(storagescheme.Scheme).
		WithIndex(&v1.MCPServer{}, "spec.mcpServerCatalogEntryName", func(object kclient.Object) []string {
			return []string{object.(*v1.MCPServer).Spec.MCPServerCatalogEntryName}
		}).
		WithIndex(&v1.MCPServerInstance{}, "spec.mcpServerCatalogEntryName", func(object kclient.Object) []string {
			return []string{object.(*v1.MCPServerInstance).Spec.MCPServerCatalogEntryName}
		}).
		WithObjects(allObjects...).
		Build())
}

func newOAuthCredentialClaimRequest(t *testing.T, method, body, userID string, gateway *gatewayclient.Client, entry *v1.MCPServerCatalogEntry, objects ...kclient.Object) (api.Context, *httptest.ResponseRecorder) {
	t.Helper()
	recorder := httptest.NewRecorder()
	req := api.Context{
		Request:        httptest.NewRequest(method, "/", strings.NewReader(body)),
		ResponseWriter: recorder,
		Storage:        newOAuthCredentialClaimStorage(entry, objects...),
		GatewayClient:  gateway,
		User:           &user.DefaultInfo{Name: "owner", UID: userID},
	}
	req.SetPathValue("catalog_id", "default")
	req.SetPathValue("entry_id", entry.Name)
	return req, recorder
}

func newDeleteOAuthCredentialRequest(t *testing.T, gateway *gatewayclient.Client, entry *v1.MCPServerCatalogEntry, objects ...kclient.Object) api.Context {
	t.Helper()
	req, _ := newOAuthCredentialClaimRequest(t, http.MethodDelete,
		`{"expectedGeneration":"`+testStaticOAuthCredentialGeneration+`"}`, "user-1", gateway, entry, objects...)
	return req
}

func newSetOAuthCredentialRequest(t *testing.T, gateway *gatewayclient.Client, entry *v1.MCPServerCatalogEntry, userID, clientID, clientSecret, proof string, objects ...kclient.Object) (api.Context, *httptest.ResponseRecorder) {
	t.Helper()
	return newOAuthCredentialClaimRequest(t, http.MethodPost, oauthCredentialRequestBody(clientID, clientSecret, proof), userID, gateway, entry, objects...)
}

func newReplaceOAuthCredentialRequest(t *testing.T, gateway *gatewayclient.Client, entry *v1.MCPServerCatalogEntry, userID, clientID, clientSecret, proof string, objects ...kclient.Object) api.Context {
	t.Helper()
	req, _ := newOAuthCredentialClaimRequest(t, http.MethodPut, oauthCredentialRequestBody(clientID, clientSecret, proof), userID, gateway, entry, objects...)
	return req
}

func oauthCredentialRequestBody(clientID, clientSecret, proof string) string {
	return fmt.Sprintf(`{"clientID":%q,"clientSecret":%q,"proof":%q}`, clientID, clientSecret, proof)
}

func successfulStaticOAuthCredentialProof(t *testing.T, gateway *gatewayclient.Client, entryName, fixedURL, userID string) string {
	t.Helper()
	return successfulStaticOAuthCredentialProofFor(t, gateway, entryName, fixedURL, userID, "candidate-client", "candidate-secret")
}

func successfulStaticOAuthCredentialProofFor(t *testing.T, gateway *gatewayclient.Client, entryName, fixedURL, userID, clientID, clientSecret string) string {
	t.Helper()
	started, err := gateway.CreateMCPStaticOAuthTest(t.Context(), userID, entryName, fixedURL, "verifier", staticOAuthClaimConfig(clientID, clientSecret))
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	if err := gateway.CompleteMCPStaticOAuthTest(t.Context(), started.CallbackState, types.MCPStaticOAuthTestStatusSucceeded, ""); err != nil {
		t.Fatalf("complete static OAuth test: %v", err)
	}
	result, err := gateway.GetMCPStaticOAuthTestStatus(t.Context(), started.TestState, userID, entryName)
	if err != nil {
		t.Fatalf("read successful static OAuth test: %v", err)
	}
	if result.Proof == "" {
		t.Fatal("successful static OAuth test did not mint a Save proof")
	}
	return result.Proof
}

func seedCatalogOwnedOAuthToken(t *testing.T, db *gorm.DB, userID, mcpID, mcpURL, entryName, accessToken string) {
	t.Helper()
	if err := db.WithContext(t.Context()).Create(&gatewaytypes.MCPOAuthToken{
		MCPID: mcpID, UserID: userID, URL: mcpURL,
		CatalogEntryName: entryName, AccessToken: accessToken,
	}).Error; err != nil {
		t.Fatalf("seed catalog-owned OAuth token for %s: %v", mcpID, err)
	}
}

func (*toggleCredentialReadErrorTransformer) TransformToStorage(_ context.Context, data []byte, _ value.Context) ([]byte, error) {
	return append([]byte("encrypted:"), data...), nil
}

func (t *toggleCredentialReadErrorTransformer) TransformFromStorage(_ context.Context, data []byte, _ value.Context) ([]byte, bool, error) {
	if t.failRead {
		return nil, false, errors.New("transient credential decryption failure")
	}
	return bytes.TrimPrefix(data, []byte("encrypted:")), false, nil
}

func staticOAuthClaimConfig(clientID, clientSecret string) *oauth2.Config {
	return &oauth2.Config{
		ClientID: clientID, ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{AuthURL: "https://provider.example/authorize", TokenURL: "https://provider.example/token"},
	}
}

func newOAuthCredentialClaimGatewayWithEncryption(t *testing.T, encryptionConfig *encryptionconfig.EncryptionConfiguration) *gatewayclient.Client {
	t.Helper()
	return newOAuthCredentialTestGatewayClientWithOptions(t, encryptionConfig, nil)
}

// newOAuthCredentialClaimGatewayWithTrigger routes the gateway's real token
// cleanup trigger through mcpIDRecordingBackend, so a test asserts on the MCP
// IDs production would enqueue rather than on a stubbed trigger.
func newOAuthCredentialClaimGatewayWithTrigger(t *testing.T, trigger func(context.Context, string) error) (*gatewayclient.Client, *gorm.DB) {
	t.Helper()
	return newOAuthCredentialTestGatewayClientWithOptionsAndDB(t, staticOAuthTestEncryptionConfig(), &mcpIDRecordingBackend{trigger: trigger})
}

func (b *mcpIDRecordingBackend) Trigger(ctx context.Context, gvk schema.GroupVersionKind, key string, _ time.Duration) error {
	if b.trigger == nil {
		return nil
	}
	if want := v1.SchemeGroupVersion.WithKind("MCPServer"); gvk != want {
		return fmt.Errorf("triggered kind %s, want %s", gvk, want)
	}
	namespace, name, ok := strings.Cut(key, "/")
	if !ok || namespace != system.DefaultNamespace {
		return fmt.Errorf("triggered key %q is not namespace-qualified under %s", key, system.DefaultNamespace)
	}
	return b.trigger(ctx, name)
}
