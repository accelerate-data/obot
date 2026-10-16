package client

// Fork-only guarantee (VD-4889, restored by VD-6903): an MCP OAuth credential
// change reconciles the owning MCPServer under a namespace-qualified key, and a
// multi-user MCPServerInstance ID resolves to the server it points at. Kept in
// its own file so an upstream sync cannot drop these tests by merging over a
// shared one.

import (
	"context"
	"testing"
	"time"

	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	"github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storagescheme "github.com/obot-platform/obot/pkg/storage/scheme"
	sservices "github.com/obot-platform/obot/pkg/storage/services"
	"github.com/obot-platform/obot/pkg/system"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	triggerTestInstance = system.MCPServerInstancePrefix + "abc"
	triggerTestServer   = system.MCPServerPrefix + "def"
	triggerTestUser     = "user-1"
	triggerTestURL      = "https://mcp.example/api"
)

type recordedControllerTrigger struct {
	gvk schema.GroupVersionKind
	key string
}

type recordingControllerBackend struct {
	triggers []recordedControllerTrigger
}

func (r *recordingControllerBackend) Trigger(_ context.Context, gvk schema.GroupVersionKind, key string, _ time.Duration) error {
	r.triggers = append(r.triggers, recordedControllerTrigger{gvk: gvk, key: key})
	return nil
}

// newTriggerTestClient constructs the client through New, the entry point
// production uses, so the trigger under test is the one New wires rather than a
// test-installed stand-in.
func newTriggerTestClient(t *testing.T, backend *recordingControllerBackend) *Client {
	t.Helper()
	services, err := sservices.New(sservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate())
	storageClient := clientfake.NewClientBuilder().
		WithScheme(storagescheme.Scheme).
		WithObjects(&v1.MCPServerInstance{
			Name:      triggerTestInstance,
			Namespace: system.DefaultNamespace,
			Spec:      v1.MCPServerInstanceSpec{UserID: triggerTestUser, MCPServerName: triggerTestServer},
		}).
		Build()
	return New(t.Context(), db, storageClient, nil, backend, nil, nil, time.Hour, 1, 0, 0, 0, false)
}

func wantOwningServerTriggers(t *testing.T, got []recordedControllerTrigger, serverName string) {
	t.Helper()
	require.NotEmpty(t, got, "no reconcile was enqueued")
	for _, trigger := range got {
		require.Equal(t, recordedControllerTrigger{
			gvk: v1.SchemeGroupVersion.WithKind("MCPServer"),
			key: system.DefaultNamespace + "/" + serverName,
		}, trigger)
	}
}

// Every credential mutation reconciles the owning MCPServer. A multi-user
// change carries the MCPServerInstance ID; instances have no status and no OAuth
// handlers, so the reconcile has to land on the server the instance points at.
// The deletes run after a successful write, which is the path that once returned
// before reaching the trigger.
func TestMCPOAuthTokenChangeTriggersOwningServerNamespacedKey(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(c *Client, mcpID string) error
	}{
		{
			name: "replace",
			mutate: func(c *Client, mcpID string) error {
				return c.ReplaceMCPOAuthToken(t.Context(), triggerTestUser, mcpID, triggerTestURL, "", &oauth2.Config{ClientID: "client"}, &oauth2.Token{AccessToken: "token"})
			},
		},
		{
			name: "delete for URL",
			mutate: func(c *Client, mcpID string) error {
				return c.DeleteMCPOAuthTokenForURL(t.Context(), triggerTestUser, mcpID, triggerTestURL)
			},
		},
		{
			name: "delete for user",
			mutate: func(c *Client, mcpID string) error {
				return c.DeleteMCPOAuthTokens(t.Context(), triggerTestUser, mcpID)
			},
		},
		{
			name: "delete for all users",
			mutate: func(c *Client, mcpID string) error {
				return c.DeleteMCPOAuthTokenForAllUsers(t.Context(), mcpID)
			},
		},
	}
	targets := []struct {
		name  string
		mcpID string
	}{
		{
			name:  "server",
			mcpID: triggerTestServer,
		},
		{
			name:  "instance",
			mcpID: triggerTestInstance,
		},
	}
	for _, target := range targets {
		for _, mutation := range mutations {
			t.Run(target.name+"/"+mutation.name, func(t *testing.T) {
				backend := &recordingControllerBackend{}
				c := newTriggerTestClient(t, backend)

				require.NoError(t, mutation.mutate(c, target.mcpID))

				wantOwningServerTriggers(t, backend.triggers, triggerTestServer)
			})
		}
	}
}

// Static OAuth credential cleanup notifies the deployment identifiers it purged,
// which for a multi-user deployment are MCPServerInstance IDs.
func TestStaticOAuthCredentialCleanupTriggersOwningServerOfInstanceGrant(t *testing.T) {
	const entryName = "catalog-entry-1"
	backend := &recordingControllerBackend{}
	c := newTriggerTestClient(t, backend)
	require.NoError(t, c.db.WithContext(t.Context()).Create(&types.MCPOAuthToken{
		MCPID:            triggerTestInstance,
		UserID:           triggerTestUser,
		CatalogEntryName: entryName,
	}).Error)

	_, err := c.DeleteMCPStaticOAuthCredentialGeneration(t.Context(), entryName, "generation", triggerTestInstance)

	require.NoError(t, err)
	wantOwningServerTriggers(t, backend.triggers, triggerTestServer)
}

func TestNewWithoutControllerBackendLeavesTriggerUnset(t *testing.T) {
	services, err := sservices.New(sservices.Config{DSN: "sqlite://:memory:"})
	require.NoError(t, err)
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)

	c := New(t.Context(), db, nil, nil, nil, nil, nil, time.Hour, 1, 0, 0, 0, false)

	require.Nil(t, c.mcpOAuthTokenTrigger)
}
