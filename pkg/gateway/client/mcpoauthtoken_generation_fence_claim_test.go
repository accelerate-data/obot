package client

// Fork-only guarantee (fork #37, restored by VD-6903): a catalog OAuth grant is
// written only while the entry, its URL, and the exact static credential generation
// the authorization started with are all still current, and the write is serialized
// against credential rotation and clearing. Kept in its own file so an upstream sync
// cannot drop these tests by merging over a shared one.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	apitypes "github.com/obot-platform/obot/apiclient/types"
	gwtypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	storagescheme "github.com/obot-platform/obot/pkg/storage/scheme"
	"github.com/obot-platform/obot/pkg/system"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	fenceTestEntry = "catalog-entry-1"
	fenceTestMCPID = "mcp-instance-1"
	fenceTestURL   = "https://mcp.example/api"
	fenceTestUser  = "user-1"
)

// newFenceTestClient backs fenceTestMCPID with fenceTestEntry, which serves
// fenceTestURL and requires static OAuth when staticOAuthRequired is set.
func newFenceTestClient(t *testing.T, staticOAuthRequired bool) *Client {
	t.Helper()
	c := newTestClient(t)
	c.storageClient = clientfake.NewClientBuilder().
		WithScheme(storagescheme.Scheme).
		WithObjects(
			&v1.MCPServerInstance{
				Namespace: system.DefaultNamespace, Name: fenceTestMCPID,
				Spec: v1.MCPServerInstanceSpec{MCPServerCatalogEntryName: fenceTestEntry},
			},
			&v1.MCPServerCatalogEntry{
				Namespace: system.DefaultNamespace, Name: fenceTestEntry,
				Spec: v1.MCPServerCatalogEntrySpec{Manifest: apitypes.MCPServerCatalogEntryManifest{
					RemoteConfig: &apitypes.RemoteCatalogConfig{FixedURL: fenceTestURL, StaticOAuthRequired: staticOAuthRequired},
				}},
			},
		).
		Build()
	return c
}

func seedFenceTestCredential(t *testing.T, c *Client, entryName string, secrets map[string]string) {
	t.Helper()
	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    system.StaticOAuthCredentialName,
		Secrets: secrets,
	}); err != nil {
		t.Fatalf("seed catalog OAuth credential: %v", err)
	}
}

func fenceTestSecrets(clientID, clientSecret, generation string) map[string]string {
	return map[string]string{"CLIENT_ID": clientID, "CLIENT_SECRET": clientSecret, "MCP_URL": fenceTestURL, "GENERATION": generation}
}

func writeFencedTestGrant(ctx context.Context, c *Client, mcpID, entryName, clientID, clientSecret, accessToken string) error {
	return c.ReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(ctx, fenceTestUser, mcpID, fenceTestURL, "", entryName, "generation-1",
		&oauth2.Config{ClientID: clientID, ClientSecret: clientSecret},
		&oauth2.Token{AccessToken: accessToken})
}

func requireNoFenceTestGrant(t *testing.T, c *Client) {
	t.Helper()
	if _, err := c.GetMCPOAuthToken(t.Context(), fenceTestUser, fenceTestMCPID, fenceTestURL); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("stale grant was persisted: %v", err)
	}
}

func requireStaleFencedWriteRejected(t *testing.T, c *Client) {
	t.Helper()
	if err := writeFencedTestGrant(t.Context(), c, fenceTestMCPID, fenceTestEntry, "client-1", "secret-1", "stale-access"); !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
		t.Fatalf("stale write error = %v, want catalog credential changed", err)
	}
	requireNoFenceTestGrant(t, c)
}

func TestReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(t *testing.T) {
	t.Run("matching current app persists grant with fence identity", func(t *testing.T) {
		c := newFenceTestClient(t, true)
		seedFenceTestCredential(t, c, fenceTestEntry, fenceTestSecrets("client-1", "secret-1", "generation-1"))

		if err := writeFencedTestGrant(t.Context(), c, fenceTestMCPID, fenceTestEntry, "client-1", "secret-1", "access-1"); err != nil {
			t.Fatalf("persist matching OAuth grant: %v", err)
		}
		stored, err := c.GetMCPOAuthToken(t.Context(), fenceTestUser, fenceTestMCPID, fenceTestURL)
		if err != nil {
			t.Fatalf("load persisted OAuth grant: %v", err)
		}
		if stored.CatalogEntryName != fenceTestEntry || stored.CatalogCredentialGeneration != "generation-1" || stored.AccessToken != "access-1" {
			t.Fatalf("stored grant = entry %q generation %q access token %q", stored.CatalogEntryName, stored.CatalogCredentialGeneration, stored.AccessToken)
		}
	})

	t.Run("same client ID with rotated secret rejects stale grant", func(t *testing.T) {
		c := newFenceTestClient(t, true)
		seedFenceTestCredential(t, c, fenceTestEntry, fenceTestSecrets("client-1", "secret-2", "generation-1"))
		requireStaleFencedWriteRejected(t, c)
	})

	t.Run("same-value replacement generation rejects stale grant", func(t *testing.T) {
		c := newFenceTestClient(t, true)
		seedFenceTestCredential(t, c, fenceTestEntry, fenceTestSecrets("client-1", "secret-1", "generation-2"))
		requireStaleFencedWriteRejected(t, c)
	})

	t.Run("clear rejects stale grant when credential no longer exists", func(t *testing.T) {
		requireStaleFencedWriteRejected(t, newFenceTestClient(t, true))
	})

	t.Run("server reassignment rejects a grant captured for the old entry", func(t *testing.T) {
		c := newFenceTestClient(t, true)
		seedFenceTestCredential(t, c, fenceTestEntry, fenceTestSecrets("client-1", "secret-1", "generation-1"))
		var instance v1.MCPServerInstance
		if err := c.storageClient.Get(t.Context(), kclient.ObjectKey{Namespace: system.DefaultNamespace, Name: fenceTestMCPID}, &instance); err != nil {
			t.Fatalf("get MCP instance: %v", err)
		}
		instance.Spec.MCPServerCatalogEntryName = "catalog-entry-2"
		if err := c.storageClient.Update(t.Context(), &instance); err != nil {
			t.Fatalf("reassign MCP instance: %v", err)
		}
		requireStaleFencedWriteRejected(t, c)
	})

	t.Run("catalog URL change rejects a grant captured for the old URL", func(t *testing.T) {
		c := newFenceTestClient(t, true)
		seedFenceTestCredential(t, c, fenceTestEntry, fenceTestSecrets("client-1", "secret-1", "generation-1"))
		var entry v1.MCPServerCatalogEntry
		if err := c.storageClient.Get(t.Context(), kclient.ObjectKey{Namespace: system.DefaultNamespace, Name: fenceTestEntry}, &entry); err != nil {
			t.Fatalf("get catalog entry: %v", err)
		}
		entry.Spec.Manifest.RemoteConfig.FixedURL = "https://new-mcp.example/api"
		if err := c.storageClient.Update(t.Context(), &entry); err != nil {
			t.Fatalf("change catalog URL: %v", err)
		}
		requireStaleFencedWriteRejected(t, c)
	})

	// A rotation or clear holding the credential lock must finish before the
	// queued callback validates, so the callback sees the new state and refuses.
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, c *Client)
	}{
		{name: "rotation winning the lock prevents old grant resurrection", mutate: func(t *testing.T, c *Client) {
			t.Helper()
			seedFenceTestCredential(t, c, fenceTestEntry, fenceTestSecrets("client-1", "secret-2", "generation-2"))
		}},
		{name: "clear winning the lock prevents old grant resurrection", mutate: func(t *testing.T, c *Client) {
			t.Helper()
			if _, err := c.DeleteCredential(t.Context(), system.MCPOAuthCredentialName(fenceTestEntry), system.StaticOAuthCredentialName); err != nil {
				t.Fatalf("clear catalog credential: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newFenceTestClient(t, true)
			seedFenceTestCredential(t, c, fenceTestEntry, fenceTestSecrets("client-1", "secret-1", "generation-1"))
			release, err := c.AcquireCredentialLock(t.Context(), system.MCPOAuthCredentialName(fenceTestEntry))
			if err != nil {
				t.Fatalf("acquire credential lock: %v", err)
			}
			writeResult := make(chan error, 1)
			go func() {
				writeResult <- writeFencedTestGrant(t.Context(), c, fenceTestMCPID, fenceTestEntry, "client-1", "secret-1", "old-app-access")
			}()
			tc.mutate(t, c)
			if err := c.DeleteMCPOAuthTokenForAllUsers(t.Context(), fenceTestMCPID); err != nil {
				t.Fatalf("clear grants: %v", err)
			}
			release()
			if err := <-writeResult; !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
				t.Fatalf("queued write error = %v, want catalog credential changed", err)
			}
			requireNoFenceTestGrant(t, c)
		})
	}

	t.Run("callback winning the lock is cleaned by later rotation", func(t *testing.T) {
		c := newFenceTestClient(t, true)
		seedFenceTestCredential(t, c, fenceTestEntry, fenceTestSecrets("client-1", "secret-1", "generation-1"))
		writeReachedTrigger := make(chan struct{})
		releaseWrite := make(chan struct{})
		var firstTrigger sync.Once
		c.mcpOAuthTokenTrigger = func(context.Context, string) error {
			firstTrigger.Do(func() {
				close(writeReachedTrigger)
				<-releaseWrite
			})
			return nil
		}
		writeResult := make(chan error, 1)
		go func() {
			writeResult <- writeFencedTestGrant(t.Context(), c, fenceTestMCPID, fenceTestEntry, "client-1", "secret-1", "old-app-access")
		}()
		<-writeReachedTrigger

		rotationResult := make(chan error, 1)
		go func() {
			releaseRotation, err := c.AcquireCredentialLock(t.Context(), system.MCPOAuthCredentialName(fenceTestEntry))
			if err != nil {
				rotationResult <- err
				return
			}
			defer releaseRotation()
			if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
				Context: system.MCPOAuthCredentialName(fenceTestEntry),
				Name:    system.StaticOAuthCredentialName,
				Secrets: fenceTestSecrets("client-2", "secret-2", "generation-2"),
			}); err != nil {
				rotationResult <- err
				return
			}
			rotationResult <- c.DeleteMCPOAuthTokenForAllUsers(t.Context(), fenceTestMCPID)
		}()
		close(releaseWrite)
		if err := <-writeResult; err != nil {
			t.Fatalf("callback that won lock failed: %v", err)
		}
		if err := <-rotationResult; err != nil {
			t.Fatalf("rotation after callback: %v", err)
		}
		requireNoFenceTestGrant(t, c)
	})

	t.Run("unrelated entry is not blocked", func(t *testing.T) {
		c := newFenceTestClient(t, true)
		const (
			otherEntry = "catalog-entry-2"
			otherMCPID = "mcp-instance-2"
		)
		if err := c.storageClient.Create(t.Context(), &v1.MCPServerInstance{
			Namespace: system.DefaultNamespace, Name: otherMCPID,
			Spec: v1.MCPServerInstanceSpec{MCPServerCatalogEntryName: otherEntry},
		}); err != nil {
			t.Fatalf("create unrelated MCP instance: %v", err)
		}
		if err := c.storageClient.Create(t.Context(), &v1.MCPServerCatalogEntry{
			Namespace: system.DefaultNamespace, Name: otherEntry,
			Spec: v1.MCPServerCatalogEntrySpec{Manifest: apitypes.MCPServerCatalogEntryManifest{
				RemoteConfig: &apitypes.RemoteCatalogConfig{FixedURL: fenceTestURL},
			}},
		}); err != nil {
			t.Fatalf("create unrelated catalog entry: %v", err)
		}
		seedFenceTestCredential(t, c, otherEntry, fenceTestSecrets("other-client", "other-secret", "generation-1"))
		release, err := c.AcquireCredentialLock(t.Context(), system.MCPOAuthCredentialName(fenceTestEntry))
		if err != nil {
			t.Fatalf("acquire first entry lock: %v", err)
		}
		defer release()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := writeFencedTestGrant(ctx, c, otherMCPID, otherEntry, "other-client", "other-secret", "other-access"); err != nil {
			t.Fatalf("unrelated entry write was blocked: %v", err)
		}
	})
}
