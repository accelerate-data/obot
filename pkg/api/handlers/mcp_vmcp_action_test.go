package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/obot-platform/nah/pkg/router"
	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	"github.com/obot-platform/obot/pkg/controller/handlers/mcpserverinstance"
	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/mcp"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storagescheme "github.com/obot-platform/obot/pkg/storage/scheme"
	storageServices "github.com/obot-platform/obot/pkg/storage/services"
	"github.com/obot-platform/obot/pkg/system"
	vmcpconfig "github.com/obot-platform/obot/pkg/vmcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	kuser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/rest"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type recordingMCPAuthChecker struct {
	server   v1.MCPServer
	config   mcp.ServerConfig
	oauthURL string
}

type recordingMCPServerTrigger struct {
	keys []string
}

// vmcpActionInitialEventsClient supplies the watch-list behavior that the
// Kubernetes API server provides but controller-runtime's fake watch omits.
type vmcpActionInitialEventsClient struct {
	kclient.WithWatch
}

func TestLaunchServerVMCPUsesDeclaredComponentsOnly(t *testing.T) {
	const (
		vmcpID      = "vmcp1launch"
		userID      = "user-launch"
		componentID = "component-a"
	)
	vmcp, instance, component, unrelated := vmcpActionObjects(vmcpID, userID, componentID, false)
	manager, storage, _ := newVMCPActionSessionManager(t, vmcp, instance, component, unrelated)

	req := httptest.NewRequest(http.MethodPost, "/api/vmcps/"+vmcpID+"/launch", nil)
	req.SetPathValue("vmcp_id", vmcpID)
	err := (&MCPHandler{mcpSessionManager: manager}).LaunchServer(api.Context{
		ResponseWriter: httptest.NewRecorder(),
		Request:        req,
		Storage:        storage,
		User:           testUser(userID),
	})
	require.NoError(t, err)
}

func TestCheckOAuthVMCPChecksDeclaredRemoteComponents(t *testing.T) {
	const (
		vmcpID      = "vmcp1oauth"
		userID      = "user-oauth"
		componentID = "component-a"
	)
	vmcp, instance, component, unrelated := vmcpActionObjects(vmcpID, userID, componentID, true)
	manager, storage, _ := newVMCPActionSessionManager(t, vmcp, instance, component, unrelated)

	req := httptest.NewRequest(http.MethodPost, "/api/vmcps/"+vmcpID+"/check-oauth", nil)
	req.SetPathValue("vmcp_id", vmcpID)
	recorder := httptest.NewRecorder()
	err := (&MCPHandler{mcpSessionManager: manager}).CheckOAuth(api.Context{
		ResponseWriter: recorder,
		Request:        req,
		Storage:        storage,
		User:           testUser(userID),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusPreconditionFailed, recorder.Code)
}

func TestGetOAuthURLVMCPResolvesAggregateConfiguration(t *testing.T) {
	const (
		vmcpID      = "vmcp1oauth-url"
		userID      = "user-oauth-url"
		componentID = "component-a"
	)
	vmcp, instance, component, unrelated := vmcpActionObjects(vmcpID, userID, componentID, false)
	manager, storage, _ := newVMCPActionSessionManager(t, vmcp, instance, component, unrelated)
	checker := newRecordingMCPAuthChecker("https://oauth.example/authorize")

	req := httptest.NewRequest(http.MethodGet, "/api/vmcps/"+vmcpID+"/oauth-url", nil)
	req.SetPathValue("vmcp_id", vmcpID)
	recorder := httptest.NewRecorder()
	err := (&MCPHandler{
		mcpSessionManager: manager,
		mcpOAuthChecker:   checker,
	}).GetOAuthURL(api.Context{
		ResponseWriter: recorder,
		Request:        req,
		Storage:        storage,
		User:           testUser(userID),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, vmcpID, checker.server.Name)
	assert.Equal(t, types.RuntimeVMCP, checker.server.Spec.Manifest.Runtime)
	assert.Equal(t, types.RuntimeVMCP, checker.config.Runtime)
	assert.Len(t, checker.config.Components, 1)
	assert.Equal(t, component.Name, checker.config.Components[0].Name)

	var response map[string]string
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Equal(t, "https://oauth.example/authorize", response["oauthURL"])
}

func TestClearOAuthCredentialsVMCPUsesDeclaredRemoteComponents(t *testing.T) {
	const (
		vmcpID      = "vmcp1clear-oauth"
		userID      = "user-clear-oauth"
		componentID = "component-a"
	)
	vmcp, instance, component, unrelated := vmcpActionObjects(vmcpID, userID, componentID, false)
	manager, storage, gatewayClient := newVMCPActionSessionManager(t, vmcp, instance, component, unrelated)
	trigger := &recordingMCPServerTrigger{}

	req := httptest.NewRequest(http.MethodDelete, "/api/vmcps/"+vmcpID+"/oauth", nil)
	req.SetPathValue("vmcp_id", vmcpID)
	recorder := httptest.NewRecorder()
	err := (&MCPHandler{
		mcpSessionManager: manager,
		controllerBackend: trigger,
	}).ClearOAuthCredentials(api.Context{
		ResponseWriter: recorder,
		Request:        req,
		Storage:        storage,
		GatewayClient:  gatewayClient,
		User:           testUser(userID),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, recorder.Code)
	// MCPServer is namespace-scoped; a bare name resolves to no object (VD-4889).
	assert.Equal(t, []string{system.DefaultNamespace + "/" + component.Name}, trigger.keys)
}

func TestClearOAuthCredentialsVMCPComponentOnlyClearsThatComponent(t *testing.T) {
	const (
		vmcpID      = "vmcp1clear-component-oauth"
		userID      = "user-clear-component-oauth"
		componentID = "component-a"
		otherID     = "component-b"
	)
	vmcp, instance, component, unrelated := vmcpActionObjects(vmcpID, userID, componentID, false)
	otherComponent := vmcp.Spec.Manifest.Components[0]
	otherComponent.ID = otherID
	otherComponent.Name = otherID
	otherComponent.MCPServerCatalogEntryID = "entry-b"
	vmcp.Spec.Manifest.Components = append(vmcp.Spec.Manifest.Components, otherComponent)
	other := component.DeepCopy()
	other.Name = "ms1component-b"
	other.Spec.VMCPComponentID = otherID
	other.Spec.Manifest.Name = otherID
	other.Spec.Manifest.RemoteConfig = &types.RemoteRuntimeConfig{URL: "https://other.example.com/mcp"}
	syncedVMCPInstance(instance, vmcp)
	manager, storage, gatewayClient := newVMCPActionSessionManager(t, vmcp, instance, component, other, unrelated)

	for _, server := range []*v1.MCPServer{component, other} {
		require.NoError(t, gatewayClient.ReplaceMCPOAuthToken(t.Context(), userID, server.Name, server.Spec.Manifest.RemoteConfig.URL, "", &oauth2.Config{}, &oauth2.Token{AccessToken: "token-" + server.Name}))
	}

	clearComponent := func(componentID string) (*recordingMCPServerTrigger, error) {
		trigger := &recordingMCPServerTrigger{}
		req := httptest.NewRequest(http.MethodDelete, "/api/vmcps/"+vmcpID+"/components/"+componentID+"/oauth", nil)
		req.SetPathValue("vmcp_id", vmcpID)
		req.SetPathValue("component_id", componentID)
		recorder := httptest.NewRecorder()
		err := (&MCPHandler{
			mcpSessionManager: manager,
			controllerBackend: trigger,
		}).ClearOAuthCredentials(api.Context{
			ResponseWriter: recorder,
			Request:        req,
			Storage:        storage,
			GatewayClient:  gatewayClient,
			User:           testUser(userID),
		})
		if err == nil {
			assert.Equal(t, http.StatusNoContent, recorder.Code)
		}
		return trigger, err
	}

	authenticatedComponents := func() []string {
		req := httptest.NewRequest(http.MethodGet, "/api/vmcps/"+vmcpID+"/oauth-status", nil)
		req.SetPathValue("vmcp_id", vmcpID)
		recorder := httptest.NewRecorder()
		require.NoError(t, (&MCPHandler{mcpSessionManager: manager}).GetVMCPOAuthStatus(api.Context{
			ResponseWriter: recorder,
			Request:        req,
			Storage:        storage,
			GatewayClient:  gatewayClient,
			User:           testUser(userID),
		}))
		var status vmcpOAuthStatus
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &status))
		return status.AuthenticatedComponents
	}
	assert.ElementsMatch(t, []string{componentID, otherID}, authenticatedComponents())

	trigger, err := clearComponent(otherID)
	require.NoError(t, err)
	assert.Equal(t, []string{componentID}, authenticatedComponents())
	assert.Equal(t, []string{system.DefaultNamespace + "/" + other.Name}, trigger.keys)

	_, err = gatewayClient.GetMCPOAuthToken(t.Context(), userID, other.Name, other.Spec.Manifest.RemoteConfig.URL)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	token, err := gatewayClient.GetMCPOAuthToken(t.Context(), userID, component.Name, component.Spec.Manifest.RemoteConfig.URL)
	require.NoError(t, err)
	assert.Equal(t, "token-"+component.Name, token.AccessToken)

	_, err = clearComponent("missing")
	var httpErr *types.ErrHTTP
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)
}

func TestClearOAuthCredentialsVMCPComponentClearsTokenFromPreviousURL(t *testing.T) {
	const (
		vmcpID      = "vmcp1clear-moved-oauth"
		userID      = "user-clear-moved-oauth"
		componentID = "component-a"
	)
	vmcp, instance, component, unrelated := vmcpActionObjects(vmcpID, userID, componentID, false)
	manager, storage, gatewayClient := newVMCPActionSessionManager(t, vmcp, instance, component, unrelated)

	// The user authenticated before the component's URL changed. Token lookups
	// still fall back to this token, so the reset must remove it too.
	require.NoError(t, gatewayClient.ReplaceMCPOAuthToken(t.Context(), userID, component.Name, "https://old.example.com/mcp", "", &oauth2.Config{}, &oauth2.Token{AccessToken: "old-token"}))
	_, err := gatewayClient.GetMCPOAuthToken(t.Context(), userID, component.Name, component.Spec.Manifest.RemoteConfig.URL)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/vmcps/"+vmcpID+"/components/"+componentID+"/oauth", nil)
	req.SetPathValue("vmcp_id", vmcpID)
	req.SetPathValue("component_id", componentID)
	recorder := httptest.NewRecorder()
	require.NoError(t, (&MCPHandler{
		mcpSessionManager: manager,
		controllerBackend: &recordingMCPServerTrigger{},
	}).ClearOAuthCredentials(api.Context{
		ResponseWriter: recorder,
		Request:        req,
		Storage:        storage,
		GatewayClient:  gatewayClient,
		User:           testUser(userID),
	}))
	assert.Equal(t, http.StatusNoContent, recorder.Code)

	_, err = gatewayClient.GetMCPOAuthToken(t.Context(), userID, component.Name, component.Spec.Manifest.RemoteConfig.URL)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestRevokeVMCPUserOAuthCredentialsScopesGrantAndFencesLateCallback(t *testing.T) {
	const (
		targetSubject = "studio-departing-user"
		vmcpID        = "vmcp1offboarding"
	)
	_, storage, gatewayClient := newVMCPActionSessionManager(t, studioOffboardingDefaultRole())
	targetUser := seedStudioOffboardingUser(t, gatewayClient, targetSubject)
	vmcp, instance, component, unrelated := vmcpActionObjects(vmcpID, targetUser, "component-a", false)
	sharedConnection := &v1.MCPServerInstance{
		ObjectMeta: objectMetaForVMCPActionTest("msi1shared-offboarding"),
		Spec: v1.MCPServerInstanceSpec{
			VMCPInstanceID:  instance.Name,
			VMCPComponentID: "shared-component",
			UserID:          targetUser,
			MCPServerName:   "ms1shared-offboarding",
		},
	}
	for _, object := range []kclient.Object{vmcp, instance, component, unrelated, sharedConnection} {
		require.NoError(t, storage.Create(t.Context(), object))
	}
	for _, userID := range []string{targetUser, "other-user"} {
		for _, mcpID := range []string{component.Name, sharedConnection.Name, "ms1other-vmcp"} {
			require.NoError(t, gatewayClient.ReplaceMCPOAuthToken(t.Context(), userID, mcpID, "https://mcp.example/", "", &oauth2.Config{}, &oauth2.Token{AccessToken: userID + mcpID}))
		}
	}
	const callbackState = "offboarding-pending-state"
	require.NoError(t, gatewayClient.CreateMCPOAuthPendingState(t.Context(), targetUser, component.Name, "https://mcp.example/", "", "", callbackState, "verifier", "https://mcp.example/", &oauth2.Config{}))
	pending, err := gatewayClient.GetMCPOAuthPendingState(t.Context(), callbackState)
	require.NoError(t, err)

	revoke := func(user kuser.Info, pathUser string) error {
		req := httptest.NewRequest(http.MethodDelete, "/api/vmcps/"+vmcpID+"/users/"+pathUser+"/oauth", nil)
		req.SetPathValue("vmcp_id", vmcpID)
		req.SetPathValue("user_id", pathUser)
		return (&MCPHandler{}).RevokeVMCPUserOAuthCredentials(api.Context{
			ResponseWriter: httptest.NewRecorder(),
			Request:        req,
			Storage:        storage,
			GatewayClient:  gatewayClient,
			User:           user,
		})
	}

	err = revoke(testUser("other-user"), targetSubject)
	var httpErr *types.ErrHTTP
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	_, err = gatewayClient.GetMCPOAuthToken(t.Context(), targetUser, component.Name, "https://mcp.example/")
	require.NoError(t, err)

	err = revoke(testUserWithRole("offboarding-admin", types.GroupAdmin), targetSubject)
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusForbidden, httpErr.Code)
	_, err = gatewayClient.GetMCPOAuthToken(t.Context(), targetUser, component.Name, "https://mcp.example/")
	require.NoError(t, err)

	err = revoke(studioOffboardingAdmin(), targetUser)
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)
	_, err = gatewayClient.GetMCPOAuthToken(t.Context(), targetUser, component.Name, "https://mcp.example/")
	require.NoError(t, err)

	require.NoError(t, revoke(studioOffboardingAdmin(), targetSubject))
	_, err = gatewayClient.GetMCPOAuthToken(t.Context(), targetUser, component.Name, "https://mcp.example/")
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	_, err = gatewayClient.GetMCPOAuthToken(t.Context(), targetUser, sharedConnection.Name, "https://mcp.example/")
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	_, err = gatewayClient.GetMCPOAuthToken(t.Context(), targetUser, "ms1other-vmcp", "https://mcp.example/")
	require.NoError(t, err)
	_, err = gatewayClient.GetMCPOAuthToken(t.Context(), "other-user", component.Name, "https://mcp.example/")
	require.NoError(t, err)
	err = gatewayClient.ReplaceMCPOAuthToken(t.Context(), targetUser, component.Name, "https://mcp.example/", "", &oauth2.Config{}, &oauth2.Token{AccessToken: "late-callback"})
	assert.ErrorIs(t, err, gatewayclient.ErrMCPOAuthConnectionRevoked)
	err = gatewayClient.ReplaceMCPOAuthToken(t.Context(), targetUser, sharedConnection.Name, "https://mcp.example/", "", &oauth2.Config{}, &oauth2.Token{AccessToken: "late-callback"})
	assert.ErrorIs(t, err, gatewayclient.ErrMCPOAuthConnectionRevoked)
	err = gatewayClient.CommitMCPOAuthPendingStateToken(t.Context(), pending, "", &oauth2.Config{}, &oauth2.Token{AccessToken: "late-callback"})
	assert.ErrorIs(t, err, gatewayclient.ErrMCPOAuthConnectionRevoked)
	_, err = gatewayClient.GetMCPOAuthPendingState(t.Context(), callbackState)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	require.NoError(t, revoke(studioOffboardingAdmin(), targetSubject))
}

func TestRevokeVMCPUserOAuthCredentialsReportsMissingConnection(t *testing.T) {
	_, storage, gatewayClient := newVMCPActionSessionManager(t, studioOffboardingDefaultRole())
	targetUser := seedStudioOffboardingUser(t, gatewayClient, "studio-departing-user")
	vmcp, _, _, _ := vmcpActionObjects("vmcp1missing-connection", targetUser, "component-a", false)
	require.NoError(t, storage.Create(t.Context(), vmcp))
	require.NoError(t, gatewayClient.ReplaceMCPOAuthToken(t.Context(), targetUser, "msi1orphan", "https://mcp.example/", "", &oauth2.Config{}, &oauth2.Token{AccessToken: "orphan"}))
	req := httptest.NewRequest(http.MethodDelete, "/api/vmcps/"+vmcp.Name+"/users/studio-departing-user/oauth", nil)
	req.SetPathValue("vmcp_id", vmcp.Name)
	req.SetPathValue("user_id", "studio-departing-user")
	err := (&MCPHandler{}).RevokeVMCPUserOAuthCredentials(api.Context{
		ResponseWriter: httptest.NewRecorder(),
		Request:        req,
		Storage:        storage,
		GatewayClient:  gatewayClient,
		User:           studioOffboardingAdmin(),
	})
	var httpErr *types.ErrHTTP
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)
	_, err = gatewayClient.GetMCPOAuthToken(t.Context(), targetUser, "msi1orphan", "https://mcp.example/")
	require.NoError(t, err)
}

func TestRevokeVMCPUserOAuthCredentialsKeepsAnotherProviderSubject(t *testing.T) {
	_, storage, gatewayClient := newVMCPActionSessionManager(t, studioOffboardingDefaultRole())
	targetUser := seedOffboardingUser(t, gatewayClient, "same-subject", "other-oidc")
	vmcp, instance, component, _ := vmcpActionObjects("vmcp1other-provider", targetUser, "component-a", false)
	for _, object := range []kclient.Object{vmcp, instance, component} {
		require.NoError(t, storage.Create(t.Context(), object))
	}
	require.NoError(t, gatewayClient.ReplaceMCPOAuthToken(t.Context(), targetUser, component.Name, "https://mcp.example/", "", &oauth2.Config{}, &oauth2.Token{AccessToken: "other-provider-grant"}))
	req := httptest.NewRequest(http.MethodDelete, "/api/vmcps/"+vmcp.Name+"/users/same-subject/oauth", nil)
	req.SetPathValue("vmcp_id", vmcp.Name)
	req.SetPathValue("user_id", "same-subject")
	err := (&MCPHandler{}).RevokeVMCPUserOAuthCredentials(api.Context{
		ResponseWriter: httptest.NewRecorder(),
		Request:        req,
		Storage:        storage,
		GatewayClient:  gatewayClient,
		User:           studioOffboardingAdmin(),
	})
	var httpErr *types.ErrHTTP
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)
	_, err = gatewayClient.GetMCPOAuthToken(t.Context(), targetUser, component.Name, "https://mcp.example/")
	require.NoError(t, err)
}

func TestRevokeVMCPUserOAuthCredentialsReportsMissingComponents(t *testing.T) {
	_, storage, gatewayClient := newVMCPActionSessionManager(t, studioOffboardingDefaultRole())
	targetUser := seedStudioOffboardingUser(t, gatewayClient, "studio-departing-user")
	vmcp, instance, _, _ := vmcpActionObjects("vmcp1missing-components", targetUser, "component-a", false)
	for _, object := range []kclient.Object{vmcp, instance} {
		require.NoError(t, storage.Create(t.Context(), object))
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/vmcps/"+vmcp.Name+"/users/studio-departing-user/oauth", nil)
	req.SetPathValue("vmcp_id", vmcp.Name)
	req.SetPathValue("user_id", "studio-departing-user")
	err := (&MCPHandler{}).RevokeVMCPUserOAuthCredentials(api.Context{
		ResponseWriter: httptest.NewRecorder(),
		Request:        req,
		Storage:        storage,
		GatewayClient:  gatewayClient,
		User:           studioOffboardingAdmin(),
	})
	var httpErr *types.ErrHTTP
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusNotFound, httpErr.Code)
}

func seedStudioOffboardingUser(t *testing.T, gatewayClient *gatewayclient.Client, subject string) string {
	t.Helper()
	return seedOffboardingUser(t, gatewayClient, subject, "studio-oidc")
}

func seedOffboardingUser(t *testing.T, gatewayClient *gatewayclient.Client, subject, providerName string) string {
	t.Helper()
	user, err := gatewayClient.EnsureIdentityWithRole(t.Context(), &gatewaytypes.Identity{
		Email:                 subject + "@example.com",
		ProviderUsername:      subject,
		ProviderUserID:        subject,
		AuthProviderName:      providerName,
		AuthProviderNamespace: system.DefaultNamespace,
	}, "", types.RoleBasic, gatewayclient.UserLimit{Unlimited: true})
	require.NoError(t, err)
	return strconv.FormatUint(uint64(user.ID), 10)
}

func studioOffboardingDefaultRole() *v1.UserDefaultRoleSetting {
	return &v1.UserDefaultRoleSetting{
		Name:      system.DefaultRoleSettingName,
		Namespace: system.DefaultNamespace,
		Spec:      v1.UserDefaultRoleSettingSpec{Role: types.RoleBasic},
	}
}

func studioOffboardingAdmin() kuser.Info {
	return &kuser.DefaultInfo{
		Name:   "studio-offboarding",
		UID:    "999",
		Groups: []string{types.GroupAuthenticated, types.GroupAdmin},
		Extra: map[string][]string{
			"auth_provider_name":      {"studio-oidc"},
			"auth_provider_namespace": {system.DefaultNamespace},
		},
	}
}

func TestAggregateComponentServersForActionVMCPUsesServerConfigComponents(t *testing.T) {
	declared := &v1.MCPServer{
		ObjectMeta: objectMetaForVMCPActionTest("ms1declared"),
	}
	unrelated := &v1.MCPServer{
		ObjectMeta: objectMetaForVMCPActionTest("ms1unrelated"),
	}
	storage := clientfake.NewClientBuilder().
		WithScheme(storagescheme.Scheme).
		WithObjects(declared, unrelated).
		Build()

	server := v1.MCPServer{
		ObjectMeta: objectMetaForVMCPActionTest("vmcp1aggregate"),
		Spec: v1.MCPServerSpec{
			Manifest: types.MCPServerManifest{
				Runtime: types.RuntimeVMCP,
			},
		},
	}
	serverConfig := mcp.ServerConfig{
		Runtime:    types.RuntimeVMCP,
		Components: []mcp.ComponentServer{{Name: declared.Name}},
	}

	components, err := (&MCPHandler{}).aggregateComponentServersForAction(
		api.Context{
			Request: httptest.NewRequest(http.MethodGet, "/", nil),
			Storage: storage,
		},
		server,
		serverConfig,
	)
	require.NoError(t, err)
	require.Len(t, components, 1)
	assert.Equal(t, declared.Name, components[0].Name)
}

func newRecordingMCPAuthChecker(oauthURL string) *recordingMCPAuthChecker {
	return &recordingMCPAuthChecker{oauthURL: oauthURL}
}

func (c *recordingMCPAuthChecker) CheckForMCPAuth(_ api.Context, server v1.MCPServer, config mcp.ServerConfig, _, _, _ string) (string, error) {
	c.server = server
	c.config = config
	return c.oauthURL, nil
}

func vmcpActionObjects(vmcpID, userID, componentID string, staticOAuth bool) (*v1.VMCP, *v1.VMCPInstance, *v1.MCPServer, *v1.MCPServer) {
	vmcp := &v1.VMCP{
		ObjectMeta: objectMetaForVMCPActionTest(vmcpID),
		Spec: v1.VMCPSpec{
			Manifest: types.VMCPManifest{
				DisplayName: "Test vMCP",
				Components: []types.VMCPComponent{{
					ID:                      componentID,
					Name:                    "component-a",
					ForceSingleUser:         true,
					MCPCatalogID:            system.DefaultCatalog,
					MCPServerCatalogEntryID: "entry-a",
				}},
				Profiles: []types.VMCPProfile{{
					Subjects:    []types.Subject{{Type: types.SubjectTypeSelector, ID: "*"}},
					Permissions: types.VMCPProfilePermissions{AllowAllComponents: true},
				}},
			},
		},
	}
	instance := &v1.VMCPInstance{
		ObjectMeta: objectMetaForVMCPActionTest(system.VMCPInstancePrefix + "action-instance"),
		Spec: v1.VMCPInstanceSpec{
			Manifest: types.VMCPInstanceManifest{VMCPID: vmcpID},
			UserID:   userID,
		},
	}
	remoteConfig := &types.RemoteRuntimeConfig{URL: "https://component.example.com/mcp"}
	if staticOAuth {
		remoteConfig.StaticOAuthRequired = true
	}
	component := &v1.MCPServer{
		ObjectMeta: objectMetaForVMCPActionTest("ms1component-a"),
		Spec: v1.MCPServerSpec{
			VMCPInstanceID:  instance.Name,
			VMCPComponentID: componentID,
			Manifest: types.MCPServerManifest{
				Name:         "component-a",
				Runtime:      types.RuntimeRemote,
				RemoteConfig: remoteConfig,
			},
		},
	}
	// This server shares the instance but is not declared by the vMCP. Its
	// invalid runtime configuration makes accidental list-all behavior fail
	// loudly.
	unrelated := &v1.MCPServer{
		ObjectMeta: objectMetaForVMCPActionTest("ms1unrelated"),
		Spec: v1.MCPServerSpec{
			VMCPInstanceID:  instance.Name,
			VMCPComponentID: "unrelated",
			Manifest: types.MCPServerManifest{
				Name:      "unrelated",
				Runtime:   types.RuntimeNPX,
				NPXConfig: &types.NPXRuntimeConfig{},
			},
		},
	}
	return vmcp, syncedVMCPInstance(instance, vmcp), component, unrelated
}

// syncedVMCPInstance records the configuration check the VMCPInstance controller
// performs for an instance without saved configuration. Call it again after
// changing the vMCP's components.
func syncedVMCPInstance(instance *v1.VMCPInstance, vmcp *v1.VMCP) *v1.VMCPInstance {
	enabled := vmcpconfig.EnabledComponents(&kuser.DefaultInfo{UID: instance.Spec.UserID}, *vmcp, vmcpconfig.ComponentsForInstance(*vmcp, *instance))
	instance.Status.ConfigurationCheckHash = vmcpconfig.ConfigurationCheckHash(enabled, "")
	return instance
}

func (r *recordingMCPServerTrigger) Trigger(_ context.Context, _ schema.GroupVersionKind, key string, _ time.Duration) error {
	r.keys = append(r.keys, key)
	return nil
}

func newVMCPActionSessionManager(t *testing.T, objects ...kclient.Object) (*mcp.SessionManager, kclient.WithWatch, *gatewayclient.Client) {
	t.Helper()

	storageClient := &vmcpActionInitialEventsClient{WithWatch: clientfake.NewClientBuilder().
		WithScheme(storagescheme.Scheme).
		WithStatusSubresource(&v1.MCPServerInstance{}).
		WithIndex(&v1.MCPServerInstance{}, "spec.vmcpInstanceID", func(obj kclient.Object) []string { return []string{obj.(*v1.MCPServerInstance).Spec.VMCPInstanceID} }).
		WithIndex(&v1.MCPServer{}, "spec.vmcpID", func(obj kclient.Object) []string { return []string{obj.(*v1.MCPServer).Spec.VMCPID} }).
		WithIndex(&v1.VMCPInstance{}, "spec.userID", func(obj kclient.Object) []string {
			return []string{obj.(*v1.VMCPInstance).Spec.UserID}
		}).
		WithIndex(&v1.VMCPInstance{}, "spec.manifest.vmcpID", func(obj kclient.Object) []string {
			return []string{obj.(*v1.VMCPInstance).Spec.Manifest.VMCPID}
		}).
		WithIndex(&v1.MCPServer{}, "spec.vmcpInstanceID", func(obj kclient.Object) []string {
			server := obj.(*v1.MCPServer)
			if server.Spec.VMCPInstanceID == "" {
				return nil
			}
			return []string{server.Spec.VMCPInstanceID}
		}).
		WithObjects(objects...).
		Build()}

	services, err := storageServices.New(storageServices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	gatewayDatabase, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, gatewayDatabase.AutoMigrate())
	gatewayClient := gatewayclient.New(t.Context(), gatewayDatabase, storageClient, nil, nil, nil, nil, time.Hour, 100, 90, 90, 90, false)
	t.Cleanup(func() { require.NoError(t, gatewayClient.Close()) })

	manager, err := mcp.NewSessionManager(
		t.Context(),
		false,
		false,
		nil,
		nil,
		"https://obot.example.com",
		8080,
		mcp.Options{
			MCPNamespace:      "obot-mcp",
			MCPRuntimeBackend: mcp.RuntimeBackendKubernetes,
		},
		nil,
		&rest.Config{Host: "https://127.0.0.1"},
		storageClient,
		storageClient,
		storageClient,
		gatewayClient,
		system.DefaultNamespace,
		nil,
	)
	require.NoError(t, err)
	return manager, storageClient, gatewayClient
}

func (c *vmcpActionInitialEventsClient) Watch(ctx context.Context, list kclient.ObjectList, opts ...kclient.ListOption) (watch.Interface, error) {
	upstream, err := c.WithWatch.Watch(ctx, list, opts...)
	if err != nil {
		return nil, err
	}

	initialList := list.DeepCopyObject().(kclient.ObjectList)
	listOptions := &kclient.ListOptions{}
	listOptions.ApplyOptions(opts)
	listOptions.Raw = nil
	if err := c.List(ctx, initialList, listOptions); err != nil {
		upstream.Stop()
		return nil, err
	}
	objects, err := meta.ExtractList(initialList)
	if err != nil {
		upstream.Stop()
		return nil, err
	}

	result := make(chan watch.Event)
	proxy := watch.NewProxyWatcher(result)
	go func() {
		defer close(result)
		defer upstream.Stop()
		for _, object := range objects {
			select {
			case result <- watch.Event{Type: watch.Added, Object: object}:
			case <-proxy.StopChan():
				return
			}
		}
		for {
			select {
			case event, ok := <-upstream.ResultChan():
				if !ok {
					return
				}
				select {
				case result <- event:
				case <-proxy.StopChan():
					return
				}
			case <-proxy.StopChan():
				return
			}
		}
	}()
	return proxy, nil
}

func objectMetaForVMCPActionTest(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: system.DefaultNamespace}
}

func TestSharedVMCPConnectionsPreserveSameUserConfiguration(t *testing.T) {
	vmcp, first, server, _ := vmcpActionObjects("vmcp1shared", "1", "one", false)
	vmcp.Spec.Manifest.Components[0].ForceSingleUser = false
	header := types.MCPConfig{Key: "TOKEN", Name: "X-Token", Required: true, Usage: types.Header}
	vmcp.Spec.Manifest.Components[0].CatalogEntry.Manifest.RemoteConfig = &types.RemoteCatalogConfig{}
	fixedHeader := types.MCPConfig{Key: "FIXED", Required: true, Usage: types.Header}
	vmcp.Spec.Manifest.Components[0].CatalogEntry.Manifest.Config = []types.MCPConfig{header, fixedHeader}
	vmcp.Spec.Manifest.Components[0].Configuration = []types.VMCPConfigurationPolicy{
		{Key: "TOKEN", Policy: types.VMCPConfigurationPolicyUserAllowed},
		{Key: "FIXED", Policy: types.VMCPConfigurationPolicyFixed},
	}
	server.Spec.VMCPInstanceID = ""
	server.Spec.VMCPID = vmcp.Name
	// The server owner's credential context differs from the connecting user's.
	server.Spec.UserID = ""
	server.Spec.Manifest.Config = []types.MCPConfig{header}
	syncedVMCPInstance(first, vmcp)
	second := first.DeepCopy()
	second.Name = "vmcpi1second"
	manager, storage, credentials := newVMCPActionSessionManager(t, vmcp, first, second, server)
	require.NoError(t, credentials.UpsertCredential(t.Context(), gatewaytypes.Credential{
		Context: server.CredentialContext(""),
		Name:    server.Name,
		Secrets: map[string]string{"FIXED": "fixed-value"},
	}))
	connections := []*v1.MCPServerInstance{}
	for _, instance := range []*v1.VMCPInstance{first, second} {
		require.NoError(t, credentials.UpsertCredential(t.Context(), gatewaytypes.Credential{
			Context: vmcpconfig.InstanceConfigurationCredentialContext(instance.Name),
			Name:    vmcpconfig.ConfigurationCredentialName(),
			Secrets: map[string]string{vmcpconfig.ConfigurationKey("one", "TOKEN"): "token-" + instance.Name},
		}))
		connection := &v1.MCPServerInstance{
			Name: system.MCPServerInstancePrefix + instance.Name, Namespace: instance.Namespace,
			Spec: v1.MCPServerInstanceSpec{UserID: instance.Spec.UserID, MCPServerName: server.Name, VMCPInstanceID: instance.Name, VMCPComponentID: "one"},
		}
		require.NoError(t, storage.Create(t.Context(), connection))
		require.NoError(t, mcpserverinstance.New(credentials).SyncVMCPConfiguration(router.Request{Ctx: t.Context(), Client: storage, Namespace: instance.Namespace, Object: connection}, nil))
		connections = append(connections, connection)
	}
	var previousScope string
	for _, i := range []int{0, 1, 0} {
		instance := []*v1.VMCPInstance{first, second}[i]
		cfg, err := manager.ServerConfigForVMCP(t.Context(), instance.Name, &kuser.DefaultInfo{UID: instance.Spec.UserID})
		require.NoError(t, err)
		require.Equal(t, instance.Name, cfg.MCPServerName)
		require.Equal(t, connections[i].Name, cfg.Components[0].ConnectID())
		require.Equal(t, system.LocalMCPConnectURL(connections[i].Name, 8080), mcp.MMMCPConfig(cfg, nil).Servers[0].URL)
		id, resolved, componentConfig, err := manager.ServerForActionWithConnectID(t.Context(), connections[i].Name, &kuser.DefaultInfo{UID: instance.Spec.UserID})
		require.NoError(t, err)
		require.Equal(t, connections[i].Name, id)
		require.Equal(t, server.Name, resolved.Name)
		require.Contains(t, componentConfig.PassthroughHeaderValues, "token-"+instance.Name)
		require.Contains(t, componentConfig.Headers, "FIXED=fixed-value")
		if previousScope != "" {
			require.Equal(t, previousScope, componentConfig.Scope)
		}
		previousScope = componentConfig.Scope
	}
	_, _, _, err := manager.ServerForActionWithConnectID(t.Context(), connections[0].Name, &kuser.DefaultInfo{UID: "other"})
	require.Error(t, err)

	// Revoking the policy must remove projected secrets, including values cached in Config.
	vmcp.Spec.Manifest.Components[0].Configuration[0].Policy = types.VMCPConfigurationPolicyFixed
	require.NoError(t, storage.Update(t.Context(), vmcp))
	require.NoError(t, mcpserverinstance.New(credentials).SyncVMCPConfiguration(router.Request{Ctx: t.Context(), Client: storage, Namespace: first.Namespace, Object: connections[0]}, nil))
	projected, err := credentials.RevealCredential(t.Context(), []string{MCPServerInstanceCredentialContext(*connections[0])}, connections[0].Name)
	require.NoError(t, err)
	require.Empty(t, projected.Secrets)
	require.Empty(t, connections[0].Spec.Config)
}
