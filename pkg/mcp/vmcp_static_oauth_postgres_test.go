package mcp

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaydb "github.com/obot-platform/obot/pkg/gateway/db"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storageservices "github.com/obot-platform/obot/pkg/storage/services"
	"github.com/obot-platform/obot/pkg/system"
	vmcpconfig "github.com/obot-platform/obot/pkg/vmcp"
	"github.com/stretchr/testify/require"
)

func TestVMCPStaticOAuthFenceSupportsMoreComponentsThanPostgresLockPool(t *testing.T) {
	dsn := os.Getenv("OBOT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set OBOT_TEST_POSTGRES_DSN to run PostgreSQL lock-pool regression")
	}
	admin, err := storageservices.New(storageservices.Config{DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.DB.SQLDB.Close()) })
	schema := fmt.Sprintf("vmcp_static_claim_%d", time.Now().UnixNano())
	require.NoError(t, admin.DB.DB.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() { require.NoError(t, admin.DB.DB.Exec("DROP SCHEMA "+schema+" CASCADE").Error) })
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	services, err := storageservices.New(storageservices.Config{DSN: parsed.String()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, services.DB.SQLDB.Close()) })
	db, err := gatewaydb.New(services.DB.DB, services.DB.SQLDB, true)
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate())
	storage := newVMCPTestStorage()
	client := gateway.New(t.Context(), db, storage, nil, nil, nil, nil, time.Hour, 10, 90, 90, 90, true)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	vmcp := staticOAuthVMCPForClaim()
	component := vmcp.Spec.Manifest.Components[0]
	vmcp.Spec.Manifest.Components = nil
	// The dedicated advisory lock pool allows five connections. Six static
	// components previously consumed six separate lock connections plus catalog.
	for i := range 6 {
		next := *component.DeepCopy()
		next.ID = fmt.Sprintf("component-%d", i)
		next.MCPServerCatalogEntryID = fmt.Sprintf("entry-%d", i)
		vmcp.Spec.Manifest.Components = append(vmcp.Spec.Manifest.Components, next)
		require.NoError(t, storage.Create(t.Context(), &v1.MCPServerCatalogEntry{Name: next.MCPServerCatalogEntryID, Namespace: vmcp.Namespace, Spec: v1.MCPServerCatalogEntrySpec{Manifest: next.CatalogEntry.Manifest}}))
		require.NoError(t, client.UpsertCredential(t.Context(), gatewaytypes.Credential{Context: system.MCPOAuthCredentialName(next.MCPServerCatalogEntryID), Name: system.StaticOAuthCredentialName, Secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret", "GENERATION": "proved", "MCP_URL": next.CatalogEntry.Manifest.RemoteConfig.FixedURL}}))
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	release, err := vmcpconfig.LockOAuthCredentials(ctx, client, storage, vmcp.Namespace, vmcp.Spec.Manifest.Components, true)
	require.NoError(t, err, "one vMCP must not exhaust its own credential-lock pool")
	release()
}
