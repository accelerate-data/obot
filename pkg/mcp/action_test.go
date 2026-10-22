package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/obot-platform/obot/apiclient/types"
	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	storageservices "github.com/obot-platform/obot/pkg/storage/services"
	"golang.org/x/oauth2"

	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storagescheme "github.com/obot-platform/obot/pkg/storage/scheme"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	kuser "k8s.io/apiserver/pkg/authentication/user"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type recordingContainerOAuthStore struct {
	mcpID string
	token *oauth2.Token
}

func TestCatalogEntryConnectionDoesNotSelectOrCreateServer(t *testing.T) {
	for _, existingServer := range []bool{false, true} {
		t.Run(map[bool]string{false: "unconnected", true: "previously connected"}[existingServer], func(t *testing.T) {
			entry := &v1.MCPServerCatalogEntry{Name: "default-entry", Namespace: system.DefaultNamespace}
			client := newVMCPTestStorage(entry)
			if existingServer {
				require.NoError(t, client.Create(t.Context(), &v1.MCPServer{
					Name:      "ms1existing",
					Namespace: system.DefaultNamespace,
					Spec: v1.MCPServerSpec{
						UserID:                    "7",
						MCPServerCatalogEntryName: entry.Name,
					},
				}))
			}
			manager := &SessionManager{storageClient: client}
			_, _, _, err := manager.ServerForActionWithConnectID(t.Context(), entry.Name, &kuser.DefaultInfo{UID: "7"})
			require.ErrorContains(t, err, "invalid MCP connection ID")
			var servers v1.MCPServerList
			require.NoError(t, client.List(t.Context(), &servers))
			require.Len(t, servers.Items, map[bool]int{false: 0, true: 1}[existingServer])
			var instances v1.MCPServerInstanceList
			require.NoError(t, client.List(t.Context(), &instances))
			require.Empty(t, instances.Items)
		})
	}
}

func TestCatalogNameForServerWhenSourceEntryIsDeleted(t *testing.T) {
	const entryID = "default-everything-c001b50cc6rtk"

	tests := []struct {
		name                string
		server              v1.MCPServer
		entryExists         bool
		failOnEntryMissing  bool
		expectedCatalogName string
		expectError         bool
	}{
		{
			name: "shared vMCP component keeps its catalog when the entry is gone",
			server: v1.MCPServer{
				Spec: v1.MCPServerSpec{
					MCPCatalogID:              system.DefaultCatalog,
					MCPServerCatalogEntryName: entryID,
					VMCPID:                    "vmcp1-test",
					VMCPComponentID:           "component-1",
				},
			},
			entryExists:         false,
			failOnEntryMissing:  false,
			expectedCatalogName: system.DefaultCatalog,
			expectError:         false,
		},
		{
			name: "shared vMCP component keeps its catalog when reached through an instance",
			server: v1.MCPServer{
				Spec: v1.MCPServerSpec{
					MCPCatalogID:              system.DefaultCatalog,
					MCPServerCatalogEntryName: entryID,
					VMCPID:                    "vmcp1-test",
					VMCPComponentID:           "component-1",
				},
			},
			entryExists:         false,
			failOnEntryMissing:  true,
			expectedCatalogName: system.DefaultCatalog,
			expectError:         false,
		},
		{
			name: "dedicated vMCP component falls back to the default catalog",
			server: v1.MCPServer{
				Spec: v1.MCPServerSpec{
					MCPServerCatalogEntryName: entryID,
					VMCPInstanceID:            "vmcpi1-test",
					VMCPComponentID:           "component-1",
				},
			},
			entryExists:         false,
			failOnEntryMissing:  false,
			expectedCatalogName: system.DefaultCatalog,
			expectError:         false,
		},
		{
			name: "dedicated vMCP component falls back when the entry must exist",
			server: v1.MCPServer{
				Spec: v1.MCPServerSpec{
					MCPServerCatalogEntryName: entryID,
					VMCPInstanceID:            "vmcpi1-test",
					VMCPComponentID:           "component-1",
				},
			},
			entryExists:         false,
			failOnEntryMissing:  true,
			expectedCatalogName: system.DefaultCatalog,
			expectError:         false,
		},
		{
			name: "dedicated vMCP component keeps the workspace scope it recorded",
			server: v1.MCPServer{
				Spec: v1.MCPServerSpec{
					MCPServerCatalogEntryName: entryID,
					VMCPInstanceID:            "vmcpi1-test",
					VMCPComponentID:           "component-1",
				},
				Status: v1.MCPServerStatus{MCPCatalogID: "puw1-test"},
			},
			entryExists:         false,
			failOnEntryMissing:  false,
			expectedCatalogName: "puw1-test",
			expectError:         false,
		},
		{
			name: "standalone server still fails when the entry is gone",
			server: v1.MCPServer{
				Spec: v1.MCPServerSpec{
					MCPServerCatalogEntryName: entryID,
					UserID:                    "user-1",
				},
			},
			entryExists:        false,
			failOnEntryMissing: false,
			expectError:        true,
		},
		{
			// A reconciled standalone server has its catalog recorded on status, but it is
			// garbage collected along with its entry, so it must not resolve without one.
			name: "standalone server with a recorded catalog still fails",
			server: v1.MCPServer{
				Spec: v1.MCPServerSpec{
					MCPServerCatalogEntryName: entryID,
					UserID:                    "user-1",
				},
				Status: v1.MCPServerStatus{MCPCatalogID: system.DefaultCatalog},
			},
			entryExists:        false,
			failOnEntryMissing: false,
			expectError:        true,
		},
		{
			name: "admin catalog server with a known catalog still fails",
			server: v1.MCPServer{
				Spec: v1.MCPServerSpec{
					MCPCatalogID:              system.DefaultCatalog,
					MCPServerCatalogEntryName: entryID,
				},
			},
			entryExists:        false,
			failOnEntryMissing: false,
			expectError:        true,
		},
		{
			name: "existing entry supplies the catalog name",
			server: v1.MCPServer{
				Spec: v1.MCPServerSpec{
					MCPServerCatalogEntryName: entryID,
					VMCPInstanceID:            "vmcpi1-test",
					VMCPComponentID:           "component-1",
				},
			},
			entryExists:         true,
			failOnEntryMissing:  false,
			expectedCatalogName: "other-catalog",
			expectError:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(storagescheme.Scheme)
			if tt.entryExists {
				builder = builder.WithObjects(&v1.MCPServerCatalogEntry{
					Name:      entryID,
					Namespace: system.DefaultNamespace,
					Spec:      v1.MCPServerCatalogEntrySpec{MCPCatalogName: "other-catalog"},
				})
			}

			manager := SessionManager{storageClient: builder.Build()}
			catalogName, err := manager.catalogNameForServer(t.Context(), tt.server, tt.failOnEntryMissing)
			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedCatalogName, catalogName)
		})
	}
}

func (s *recordingContainerOAuthStore) ForUserAndMCP(_ string, mcpID, _ string) TokenStorage {
	s.mcpID = mcpID
	return fixedContainerTokenStore{token: s.token}
}

func TestAddExtractedEnvVarsPreservesRemoteConfig(t *testing.T) {
	server := &v1.MCPServer{Spec: v1.MCPServerSpec{Manifest: types.MCPServerManifest{
		Runtime:      types.RuntimeRemote,
		RemoteConfig: &types.RemoteRuntimeConfig{URL: "https://${EXISTING}.example.com/${DETECTED}"},
		Config:       []types.MCPConfig{{Name: "Existing", Key: "EXISTING", Required: true, Usage: types.Header}},
	}}}
	addExtractedEnvVars(server)
	require.ElementsMatch(t, []types.MCPConfig{
		{Name: "Existing", Key: "EXISTING", Required: true, Usage: types.Header},
		{Name: "DETECTED", Key: "DETECTED", Description: "Automatically detected variable", Required: true, Sensitive: true, Usage: types.Env},
	}, server.Spec.Manifest.Config)
}

func TestAllowMissingConfigInjectsContainerOAuthUsingResolvedInstanceID(t *testing.T) {
	const (
		serverID   = "ms1-shared-container"
		instanceID = "msi1-user-container"
		userID     = "user-1"
	)
	container := &types.ContainerizedRuntimeConfig{
		Image: "example/container:latest",
		OAuth: &types.ContainerOAuthConfig{
			Provider: types.ContainerOAuthProviderMicrosoftEntra, AuthorityEnv: "INSTANCE", TenantIDEnv: "TENANT",
			ClientIDEnv: "CLIENT", ClientSecretEnv: "SECRET", Scopes: []string{"api://${CLIENT}/Mcp.Tools.ReadWrite"},
		},
	}
	server := &v1.MCPServer{
		Name: serverID, Namespace: system.DefaultNamespace,
		Spec: v1.MCPServerSpec{
			Manifest: types.MCPServerManifest{
				Runtime: types.RuntimeContainerized, ContainerizedConfig: container,
				Config: []types.MCPConfig{
					{Key: "INSTANCE", Usage: types.Env, Value: "https://login.microsoftonline.com/"},
					{Key: "TENANT", Usage: types.Env, Value: "tenant"},
					{Key: "CLIENT", Usage: types.Env, Value: "client"},
					{Key: "SECRET", Usage: types.Env, Value: "secret"},
				},
			},
		},
	}
	instance := &v1.MCPServerInstance{
		Name: instanceID, Namespace: system.DefaultNamespace,
		Spec: v1.MCPServerInstanceSpec{MCPServerName: serverID, UserID: userID},
	}
	storage := fake.NewClientBuilder().WithScheme(storagescheme.Scheme).WithObjects(server, instance).Build()
	services, err := storageservices.New(storageservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	database, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, database.AutoMigrate())
	gatewayClient := gateway.New(t.Context(), database, storage, nil, nil, nil, nil, time.Hour, 10, 90, 90, 90, true)
	t.Cleanup(func() { require.NoError(t, gatewayClient.Close()) })
	tokens := &recordingContainerOAuthStore{token: &oauth2.Token{AccessToken: "instance-access", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	manager := &SessionManager{
		backend:          &policyRecordingBackend{},
		storageClient:    storage,
		gatewayClient:    gatewayClient,
		globalTokenStore: tokens,
		baseURL:          "https://obot.example",
	}

	connectID, _, config, missing, err := manager.ServerForActionWithConnectIDAllowMissingConfig(context.Background(), instanceID, &kuser.DefaultInfo{UID: userID})
	require.NoError(t, err)
	require.Empty(t, missing)
	require.Equal(t, instanceID, connectID)
	require.Equal(t, instanceID, config.MCPServerInstanceID)
	require.Equal(t, instanceID, tokens.mcpID)
	require.Equal(t, []string{"Authorization"}, config.PassthroughHeaderNames)
	require.Equal(t, []string{"Bearer instance-access"}, config.PassthroughHeaderValues)
}
