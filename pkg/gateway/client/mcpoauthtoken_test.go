package client

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apitypes "github.com/obot-platform/obot/apiclient/types"
	gwtypes "github.com/obot-platform/obot/pkg/gateway/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/storage/scheme"
	"github.com/obot-platform/obot/pkg/system"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	"k8s.io/apiserver/pkg/storage/value"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(t *testing.T) {
	const (
		entryName = "catalog-entry-1"
		mcpID     = "mcp-instance-1"
		mcpURL    = "https://mcp.example/api"
	)
	newClient := func(t *testing.T) *Client {
		t.Helper()
		c := newTestClient(t)
		c.storageClient = clientfake.NewClientBuilder().
			WithScheme(scheme.Scheme).
			WithObjects(
				&v1.MCPServerInstance{
					Namespace: system.DefaultNamespace, Name: mcpID,
					Spec: v1.MCPServerInstanceSpec{
						MCPServerCatalogEntryName: entryName,
					},
				},
				&v1.MCPServerCatalogEntry{
					Namespace: system.DefaultNamespace, Name: entryName,
					Spec: v1.MCPServerCatalogEntrySpec{Manifest: apitypes.MCPServerCatalogEntryManifest{
						RemoteConfig: &apitypes.RemoteCatalogConfig{FixedURL: mcpURL, StaticOAuthRequired: true},
					}},
				},
			).
			Build()
		return c
	}
	seedCredential := func(t *testing.T, c *Client, clientID, clientSecret string) {
		t.Helper()
		if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
			Context: system.MCPOAuthCredentialName(entryName),
			Name:    "oauth",
			Secrets: map[string]string{"CLIENT_ID": clientID, "CLIENT_SECRET": clientSecret, "MCP_URL": mcpURL, "GENERATION": "generation-1"},
		}); err != nil {
			t.Fatalf("seed catalog OAuth credential: %v", err)
		}
	}

	t.Run("matching current app persists grant with fence identity", func(t *testing.T) {
		c := newClient(t)
		seedCredential(t, c, "client-1", "secret-1")

		err := c.ReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(t.Context(), "user-1", mcpID, mcpURL, "request-1", entryName, "generation-1",
			&oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"},
			&oauth2.Token{AccessToken: "access-1"})
		if err != nil {
			t.Fatalf("persist matching OAuth grant: %v", err)
		}
		stored, err := c.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL)
		if err != nil {
			t.Fatalf("load persisted OAuth grant: %v", err)
		}
		if stored.CatalogEntryName != entryName || stored.AccessToken != "access-1" {
			t.Fatalf("stored grant = entry %q access token %q", stored.CatalogEntryName, stored.AccessToken)
		}
	})

	t.Run("same client ID with rotated secret rejects stale grant", func(t *testing.T) {
		c := newClient(t)
		seedCredential(t, c, "client-1", "secret-2")

		err := c.ReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(t.Context(), "user-1", mcpID, mcpURL, "", entryName, "generation-1",
			&oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"},
			&oauth2.Token{AccessToken: "stale-access"})
		if !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
			t.Fatalf("stale write error = %v, want catalog credential changed", err)
		}
		if _, err := c.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("stale grant was persisted: %v", err)
		}
	})

	t.Run("same-value replacement generation rejects stale grant", func(t *testing.T) {
		c := newClient(t)
		if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
			Context: system.MCPOAuthCredentialName(entryName),
			Name:    "oauth",
			Secrets: map[string]string{"CLIENT_ID": "client-1", "CLIENT_SECRET": "secret-1", "MCP_URL": mcpURL, "GENERATION": "generation-2"},
		}); err != nil {
			t.Fatalf("seed replaced catalog OAuth credential: %v", err)
		}

		err := c.ReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(t.Context(), "user-1", mcpID, mcpURL, "", entryName, "generation-1",
			&oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"},
			&oauth2.Token{AccessToken: "stale-access"})
		if !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
			t.Fatalf("stale generation write error = %v, want catalog credential changed", err)
		}
		if _, err := c.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("stale generation grant was persisted: %v", err)
		}
	})

	t.Run("clear rejects stale grant when credential no longer exists", func(t *testing.T) {
		c := newClient(t)

		err := c.ReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(t.Context(), "user-1", mcpID, mcpURL, "", entryName, "generation-1",
			&oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"},
			&oauth2.Token{AccessToken: "stale-access"})
		if !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
			t.Fatalf("post-clear write error = %v, want catalog credential changed", err)
		}
		if _, err := c.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("post-clear grant was persisted: %v", err)
		}
	})

	t.Run("server reassignment rejects a grant captured for the old entry", func(t *testing.T) {
		c := newClient(t)
		seedCredential(t, c, "client-1", "secret-1")
		var instance v1.MCPServerInstance
		if err := c.storageClient.Get(t.Context(), kclient.ObjectKey{Namespace: system.DefaultNamespace, Name: mcpID}, &instance); err != nil {
			t.Fatalf("get MCP instance: %v", err)
		}
		instance.Spec.MCPServerCatalogEntryName = "catalog-entry-2"
		if err := c.storageClient.Update(t.Context(), &instance); err != nil {
			t.Fatalf("reassign MCP instance: %v", err)
		}

		err := c.ReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(t.Context(), "user-1", mcpID, mcpURL, "", entryName, "generation-1",
			&oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"},
			&oauth2.Token{AccessToken: "stale-access"})
		if !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
			t.Fatalf("reassigned entry write error = %v, want catalog credential changed", err)
		}
	})

	t.Run("catalog URL change rejects a grant captured for the old URL", func(t *testing.T) {
		c := newClient(t)
		seedCredential(t, c, "client-1", "secret-1")
		var entry v1.MCPServerCatalogEntry
		if err := c.storageClient.Get(t.Context(), kclient.ObjectKey{Namespace: system.DefaultNamespace, Name: entryName}, &entry); err != nil {
			t.Fatalf("get catalog entry: %v", err)
		}
		entry.Spec.Manifest.RemoteConfig.FixedURL = "https://new-mcp.example/api"
		if err := c.storageClient.Update(t.Context(), &entry); err != nil {
			t.Fatalf("change catalog URL: %v", err)
		}

		err := c.ReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(t.Context(), "user-1", mcpID, mcpURL, "", entryName, "generation-1",
			&oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"},
			&oauth2.Token{AccessToken: "stale-access"})
		if !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
			t.Fatalf("changed URL write error = %v, want catalog credential changed", err)
		}
	})

	t.Run("rotation winning the lock prevents old grant resurrection", func(t *testing.T) {
		c := newClient(t)
		seedCredential(t, c, "client-1", "secret-1")
		credentialKey := system.MCPOAuthCredentialName(entryName)
		releaseRotation, err := c.AcquireCredentialLock(t.Context(), credentialKey)
		if err != nil {
			t.Fatalf("acquire rotation lock: %v", err)
		}
		writeResult := make(chan error, 1)
		writeStarted := make(chan struct{})
		go func() {
			close(writeStarted)
			writeResult <- c.ReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(t.Context(), "user-1", mcpID, mcpURL, "", entryName, "generation-1",
				&oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"},
				&oauth2.Token{AccessToken: "old-app-access"})
		}()
		<-writeStarted
		seedCredential(t, c, "client-1", "secret-2")
		if err := c.DeleteMCPOAuthTokenForAllUsers(t.Context(), mcpID); err != nil {
			t.Fatalf("clear grants during rotation: %v", err)
		}
		releaseRotation()
		if err := <-writeResult; !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
			t.Fatalf("post-rotation write error = %v, want catalog credential changed", err)
		}
		if _, err := c.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("old-app grant resurrected after rotation: %v", err)
		}
	})

	t.Run("clear winning the lock prevents old grant resurrection", func(t *testing.T) {
		c := newClient(t)
		seedCredential(t, c, "client-1", "secret-1")
		credentialKey := system.MCPOAuthCredentialName(entryName)
		releaseClear, err := c.AcquireCredentialLock(t.Context(), credentialKey)
		if err != nil {
			t.Fatalf("acquire clear lock: %v", err)
		}
		writeResult := make(chan error, 1)
		writeStarted := make(chan struct{})
		go func() {
			close(writeStarted)
			writeResult <- c.ReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(t.Context(), "user-1", mcpID, mcpURL, "", entryName, "generation-1",
				&oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"},
				&oauth2.Token{AccessToken: "old-app-access"})
		}()
		<-writeStarted
		if _, err := c.DeleteCredential(t.Context(), credentialKey, "oauth"); err != nil {
			t.Fatalf("clear catalog credential: %v", err)
		}
		if err := c.DeleteMCPOAuthTokenForAllUsers(t.Context(), mcpID); err != nil {
			t.Fatalf("clear grants: %v", err)
		}
		releaseClear()
		if err := <-writeResult; !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
			t.Fatalf("post-clear write error = %v, want catalog credential changed", err)
		}
		if _, err := c.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("old-app grant resurrected after clear: %v", err)
		}
	})

	t.Run("callback winning the lock is cleaned by later rotation", func(t *testing.T) {
		c := newClient(t)
		seedCredential(t, c, "client-1", "secret-1")
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
			writeResult <- c.ReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(t.Context(), "user-1", mcpID, mcpURL, "", entryName, "generation-1",
				&oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"},
				&oauth2.Token{AccessToken: "old-app-access"})
		}()
		<-writeReachedTrigger

		rotationResult := make(chan error, 1)
		rotationStarted := make(chan struct{})
		go func() {
			close(rotationStarted)
			credentialKey := system.MCPOAuthCredentialName(entryName)
			releaseRotation, err := c.AcquireCredentialLock(t.Context(), credentialKey)
			if err != nil {
				rotationResult <- err
				return
			}
			defer releaseRotation()
			if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
				Context: credentialKey,
				Name:    "oauth",
				Secrets: map[string]string{"CLIENT_ID": "client-2", "CLIENT_SECRET": "secret-2"},
			}); err != nil {
				rotationResult <- err
				return
			}
			rotationResult <- c.DeleteMCPOAuthTokenForAllUsers(t.Context(), mcpID)
		}()
		<-rotationStarted
		close(releaseWrite)
		if err := <-writeResult; err != nil {
			t.Fatalf("callback that won lock failed: %v", err)
		}
		if err := <-rotationResult; err != nil {
			t.Fatalf("rotation after callback: %v", err)
		}
		if _, err := c.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("callback grant survived later rotation: %v", err)
		}
	})

	t.Run("unrelated entry is not blocked", func(t *testing.T) {
		c := newClient(t)
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
				RemoteConfig: &apitypes.RemoteCatalogConfig{FixedURL: mcpURL},
			}},
		}); err != nil {
			t.Fatalf("create unrelated catalog entry: %v", err)
		}
		if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
			Context: system.MCPOAuthCredentialName(otherEntry),
			Name:    "oauth",
			Secrets: map[string]string{"CLIENT_ID": "other-client", "CLIENT_SECRET": "other-secret", "MCP_URL": mcpURL, "GENERATION": "generation-1"},
		}); err != nil {
			t.Fatalf("seed unrelated credential: %v", err)
		}
		release, err := c.AcquireCredentialLock(t.Context(), system.MCPOAuthCredentialName(entryName))
		if err != nil {
			t.Fatalf("acquire first entry lock: %v", err)
		}
		defer release()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := c.ReplaceMCPOAuthTokenWithCatalogCredentialGenerationFence(ctx, "user-1", otherMCPID, mcpURL, "", otherEntry, "generation-1",
			&oauth2.Config{ClientID: "other-client", ClientSecret: "other-secret"},
			&oauth2.Token{AccessToken: "other-access"}); err != nil {
			t.Fatalf("unrelated entry write was blocked: %v", err)
		}
	})

	t.Run("pending state commit rejects and deletes legacy static state", func(t *testing.T) {
		c := newClient(t)
		seedCredential(t, c, "client-1", "secret-1")
		conf := &oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"}
		if err := c.CreateMCPOAuthPendingState(t.Context(), "user-1", mcpID, mcpURL, "request-1", "", "stale-state", "verifier", conf); err != nil {
			t.Fatalf("create stale pending state: %v", err)
		}
		pending, err := c.GetMCPOAuthPendingState(t.Context(), "stale-state")
		if err != nil {
			t.Fatalf("load stale pending state: %v", err)
		}

		err = c.CommitMCPOAuthPendingStateToken(t.Context(), pending, pending.OAuthAuthRequestID, conf, &oauth2.Token{AccessToken: "stale-access"})
		if !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
			t.Fatalf("stale commit error = %v, want catalog credential changed", err)
		}
		if _, err := c.GetMCPOAuthPendingState(t.Context(), "stale-state"); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("stale pending state remains: %v", err)
		}
	})
}

func TestCreateMCPStaticOAuthTestStoresEncryptedPendingProof(t *testing.T) {
	c := newTestClient(t)
	c.encryptionConfig = &encryptionconfig.EncryptionConfiguration{
		Transformers: map[schema.GroupResource]value.Transformer{
			mcpOAuthPendingStateGroupResource: staticOAuthTestTransformer{},
		},
	}
	ctx := t.Context()
	conf := &oauth2.Config{
		ClientID:     "normalized-client-id",
		ClientSecret: "normalized-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://provider.example/authorize",
			TokenURL:  "https://provider.example/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: "https://obot.example/oauth/mcp/callback",
		Scopes:      []string{"channels:read", "chat:write"},
	}

	before := time.Now()
	started, err := c.CreateMCPStaticOAuthTest(ctx, "user-1", "catalog-entry-1", "https://mcp.example/api", "pkce-verifier", conf)
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	after := time.Now()
	if started.CallbackState == "" || started.TestState == "" {
		t.Fatal("expected random callback and test states")
	}
	secondStart, err := c.CreateMCPStaticOAuthTest(ctx, "user-1", "catalog-entry-1", "https://mcp.example/api", "second-verifier", conf)
	if err != nil {
		t.Fatalf("create second static OAuth test: %v", err)
	}
	if secondStart.CallbackState == started.CallbackState || secondStart.TestState == started.TestState {
		t.Fatal("expected independently generated callback and test states")
	}
	if started.CallbackState == started.TestState {
		t.Fatal("callback state must not be reused as the test status token")
	}

	hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(started.CallbackState)))
	var stored gwtypes.MCPOAuthPendingState
	if err := c.db.WithContext(ctx).First(&stored, "hashed_state = ?", hashedState).Error; err != nil {
		t.Fatalf("load stored pending proof: %v", err)
	}
	if stored.HashedState != hashedState {
		t.Fatalf("stored hash = %q, want %q", stored.HashedState, hashedState)
	}
	if stored.State == started.CallbackState || stored.Verifier == "pkce-verifier" || stored.ClientID == conf.ClientID || stored.ClientSecret == conf.ClientSecret {
		t.Fatal("candidate proof data was stored in plaintext")
	}
	if stored.URL == "https://mcp.example/api" || stored.AuthURL == conf.Endpoint.AuthURL || stored.TokenURL == conf.Endpoint.TokenURL || stored.RedirectURL == conf.RedirectURL || stored.Scopes == "channels:read chat:write" {
		t.Fatal("provider-sensitive proof data was stored in plaintext")
	}
	if !stored.Encrypted {
		t.Fatal("expected pending proof to be marked encrypted")
	}

	proof, err := c.GetMCPOAuthPendingState(ctx, started.CallbackState)
	if err != nil {
		t.Fatalf("decrypt stored pending proof: %v", err)
	}
	if proof.State != started.CallbackState || proof.UserID != "user-1" || proof.MCPID != "catalog-entry-1" || proof.URL != "https://mcp.example/api" {
		t.Fatalf("stored proof identity = state %q user %q MCP %q URL %q", proof.State, proof.UserID, proof.MCPID, proof.URL)
	}
	if !proof.StaticOAuthTest {
		t.Fatal("expected static OAuth test marker")
	}
	if proof.Verifier != "pkce-verifier" || proof.ClientID != conf.ClientID || proof.ClientSecret != conf.ClientSecret {
		t.Fatalf("stored proof candidates = verifier %q client ID %q client secret %q", proof.Verifier, proof.ClientID, proof.ClientSecret)
	}
	if proof.AuthURL != conf.Endpoint.AuthURL || proof.TokenURL != conf.Endpoint.TokenURL || proof.AuthStyle != conf.Endpoint.AuthStyle || proof.RedirectURL != conf.RedirectURL || proof.Scopes != "channels:read chat:write" {
		t.Fatalf("stored OAuth config = %+v", proof)
	}
	if proof.StaticOAuthTestStatus != apitypes.MCPStaticOAuthTestStatusPending {
		t.Fatalf("stored status = %q, want pending", proof.StaticOAuthTestStatus)
	}
	if proof.CreatedAt.Before(before) || proof.CreatedAt.After(after) {
		t.Fatalf("created at = %s, want between %s and %s", proof.CreatedAt, before, after)
	}
}

func TestCreateMCPStaticOAuthTestFailsClosedWithoutEncryption(t *testing.T) {
	c := newTestClient(t)
	conf := &oauth2.Config{ClientID: "candidate-client", ClientSecret: "candidate-secret"}

	_, err := c.CreateMCPStaticOAuthTest(t.Context(), "user-1", "catalog-entry-1", "https://mcp.example/api", "verifier", conf)
	if !errors.Is(err, ErrMCPStaticOAuthEncryptionRequired) {
		t.Fatalf("create without encryption error = %v, want encryption required", err)
	}

	var count int64
	if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthPendingState{}).Count(&count).Error; err != nil {
		t.Fatalf("count pending states: %v", err)
	}
	if count != 0 {
		t.Fatalf("unencrypted pending states = %d, want 0", count)
	}
}

func TestEncryptedMCPStaticOAuthTestFailsClosedWhenEncryptionIsRemoved(t *testing.T) {
	c := newTestClient(t)
	started, _ := createStaticOAuthTest(t, c)

	c.encryptionConfig = nil
	if _, err := c.GetMCPStaticOAuthTestStatus(t.Context(), started.TestState, "user-1", "catalog-entry-1"); !errors.Is(err, ErrMCPStaticOAuthEncryptionRequired) {
		t.Fatalf("status without encryption error = %v, want encryption required", err)
	}
	if _, err := c.GetMCPOAuthPendingState(t.Context(), started.CallbackState); !errors.Is(err, ErrMCPStaticOAuthEncryptionRequired) {
		t.Fatalf("callback state without encryption error = %v, want encryption required", err)
	}
}

func TestEncryptedStaticOAuthCredentialFailsClosedWhenEncryptionIsRemoved(t *testing.T) {
	c := newTestClient(t)
	c.encryptionConfig = &encryptionconfig.EncryptionConfiguration{
		Transformers: map[schema.GroupResource]value.Transformer{
			credentialGroupResource: staticOAuthTestTransformer{},
		},
	}
	credentialContext := system.MCPOAuthCredentialName("catalog-entry-1")
	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: credentialContext,
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret"},
	}); err != nil {
		t.Fatalf("seed encrypted credential: %v", err)
	}

	c.encryptionConfig = nil
	if _, err := c.RevealCredential(t.Context(), []string{credentialContext}, "oauth"); err == nil || !strings.Contains(err.Error(), "encryption is not configured") {
		t.Fatalf("reveal without encryption error = %v", err)
	}
}

func TestCommitMCPStaticOAuthCredentialFailsClosedWithoutCredentialEncryption(t *testing.T) {
	c := newTestClient(t)
	c.encryptionConfig = &encryptionconfig.EncryptionConfiguration{
		Transformers: map[schema.GroupResource]value.Transformer{
			mcpOAuthPendingStateGroupResource: staticOAuthTestTransformer{},
		},
	}
	state, conf := createStaticOAuthTest(t, c)
	proof := completeSuccessfulStaticOAuthTest(t, c, state)

	err := c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, false)
	if !errors.Is(err, ErrMCPStaticOAuthEncryptionRequired) {
		t.Fatalf("commit without credential encryption error = %v, want encryption required", err)
	}
	if _, err := c.RevealCredential(t.Context(), []string{system.MCPOAuthCredentialName("catalog-entry-1")}, "oauth"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("unencrypted credential was stored: %v", err)
	}
	if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, false); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
		t.Fatalf("failed commit left proof reusable: %v", err)
	}
}

func TestMCPStaticOAuthTestLifecycleReturnsOnlySafeStatus(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		c := newTestClient(t)
		state, _ := createStaticOAuthTest(t, c)

		result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "catalog-entry-1")
		if err != nil {
			t.Fatalf("read pending status: %v", err)
		}
		assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusPending, "")
		proof, err := c.GetMCPOAuthPendingState(t.Context(), state.CallbackState)
		if err != nil {
			t.Fatalf("read pending proof: %v", err)
		}
		if want := proof.CreatedAt.Add(pendingStateTTL); !result.ExpiresAt.Time.Equal(want) {
			t.Fatalf("pending expiry = %s, want %s", result.ExpiresAt, want)
		}
	})

	for _, tt := range []struct {
		name   string
		userID string
		mcpID  string
	}{
		{name: "wrong caller", userID: "user-2", mcpID: "catalog-entry-1"},
		{name: "wrong entry", userID: "user-1", mcpID: "catalog-entry-2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t)
			state, _ := createStaticOAuthTest(t, c)

			result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, tt.userID, tt.mcpID)
			if !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
				t.Fatalf("read status returned result %+v and error %v, want invalid proof", result, err)
			}
		})
	}

	t.Run("succeeded", func(t *testing.T) {
		c := newTestClient(t)
		state, _ := createStaticOAuthTest(t, c)

		if err := c.CompleteMCPStaticOAuthTest(t.Context(), state.CallbackState, apitypes.MCPStaticOAuthTestStatusSucceeded, ""); err != nil {
			t.Fatalf("complete successful test: %v", err)
		}
		result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "catalog-entry-1")
		if err != nil {
			t.Fatalf("read succeeded status: %v", err)
		}
		assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusSucceeded, "")

		proof, err := c.GetMCPOAuthPendingState(t.Context(), state.CallbackState)
		if err != nil {
			t.Fatalf("read completed proof: %v", err)
		}
		if proof.StaticOAuthTestCompletedAt.IsZero() {
			t.Fatal("expected successful test completion time")
		}
		if want := proof.CreatedAt.Add(pendingStateTTL); !result.ExpiresAt.Time.Equal(want) {
			t.Fatalf("succeeded expiry = %s, want %s", result.ExpiresAt, want)
		}
	})

	t.Run("failed", func(t *testing.T) {
		c := newTestClient(t)
		state, _ := createStaticOAuthTest(t, c)

		if err := c.CompleteMCPStaticOAuthTest(t.Context(), state.CallbackState, apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureTokenExchange); err != nil {
			t.Fatalf("complete failed test: %v", err)
		}
		result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "catalog-entry-1")
		if err != nil {
			t.Fatalf("read failed status: %v", err)
		}
		assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureTokenExchange)
		proof, err := c.GetMCPOAuthPendingState(t.Context(), state.CallbackState)
		if err != nil {
			t.Fatalf("read failed proof: %v", err)
		}
		if want := proof.CreatedAt.Add(pendingStateTTL); !result.ExpiresAt.Time.Equal(want) {
			t.Fatalf("failed expiry = %s, want %s", result.ExpiresAt, want)
		}
	})

	t.Run("expired", func(t *testing.T) {
		c := newTestClient(t)
		state, _ := createStaticOAuthTest(t, c)
		hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state.CallbackState)))
		if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthPendingState{}).
			Where("hashed_state = ?", hashedState).
			Update("created_at", time.Now().Add(-pendingStateTTL-time.Second)).Error; err != nil {
			t.Fatalf("age pending proof: %v", err)
		}

		result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "catalog-entry-1")
		if err != nil {
			t.Fatalf("read expired status: %v", err)
		}
		assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureExpired)
		if result.ExpiresAt.IsZero() || !result.ExpiresAt.Time.Before(time.Now()) {
			t.Fatalf("expired proof expiry = %s, want authoritative past timestamp", result.ExpiresAt)
		}
	})
}

func TestGetMCPStaticOAuthTestStatusTreatsUnknownConsumedAndCleanedProofsAsInvalid(t *testing.T) {
	for _, tt := range []struct {
		name    string
		prepare func(t *testing.T, c *Client) string
	}{
		{
			name: "unknown",
			prepare: func(*testing.T, *Client) string {
				return "unknown-proof"
			},
		},
		{
			name: "consumed",
			prepare: func(t *testing.T, c *Client) string {
				t.Helper()
				state, conf := createStaticOAuthTest(t, c)
				proof := completeSuccessfulStaticOAuthTest(t, c, state)
				if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, false); err != nil {
					t.Fatalf("commit proof: %v", err)
				}
				return state.TestState
			},
		},
		{
			name: "cleaned",
			prepare: func(t *testing.T, c *Client) string {
				t.Helper()
				state, _ := createStaticOAuthTest(t, c)
				if err := c.CleanupExpiredMCPOAuthPendingStates(t.Context(), 0); err != nil {
					t.Fatalf("clean proof: %v", err)
				}
				return state.TestState
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t)
			state := tt.prepare(t, c)
			result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state, "user-1", "catalog-entry-1")
			if !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
				t.Fatalf("status result = %+v, error = %v, want invalid proof", result, err)
			}
		})
	}
}

func TestClaimMCPStaticOAuthTestEnforcesTTLAndExactlyOnce(t *testing.T) {
	t.Run("exactly once", func(t *testing.T) {
		c := newTestClient(t)
		state, conf := createStaticOAuthTest(t, c)

		const attempts = 8
		start := make(chan struct{})
		results := make(chan error, attempts)
		var wg sync.WaitGroup
		for range attempts {
			wg.Go(func() {
				<-start
				proof, err := c.ClaimMCPStaticOAuthTest(t.Context(), state.CallbackState)
				if err == nil && (proof.ClientID != conf.ClientID || proof.ClientSecret != conf.ClientSecret) {
					err = errors.New("claimed proof did not contain the candidate credentials")
				}
				results <- err
			})
		}
		close(start)
		wg.Wait()
		close(results)

		var claimed int
		for err := range results {
			if err == nil {
				claimed++
			} else if !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
				t.Fatalf("claim proof: %v", err)
			}
		}
		if claimed != 1 {
			t.Fatalf("successful claims = %d, want exactly 1", claimed)
		}

		result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "catalog-entry-1")
		if err != nil {
			t.Fatalf("read claimed status: %v", err)
		}
		assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusPending, "")
		// The read side reports a claim with no recorded time as interrupted, so the
		// claim must stamp status and lease timestamp in the same statement.
		if age := time.Since(requireLiveStaticOAuthTestClaim(t, c, state.CallbackState)); age < 0 || age > staticOAuthTestClaimLease {
			t.Fatalf("claim stamp age = %s, want a live stamp within the %s lease", age, staticOAuthTestClaimLease)
		}
	})

	t.Run("expired row remains unclaimed", func(t *testing.T) {
		c := newTestClient(t)
		state, _ := createStaticOAuthTest(t, c)
		hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state.CallbackState)))
		if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthPendingState{}).
			Where("hashed_state = ?", hashedState).
			Update("created_at", time.Now().Add(-pendingStateTTL-time.Second)).Error; err != nil {
			t.Fatalf("age pending proof: %v", err)
		}

		if _, err := c.ClaimMCPStaticOAuthTest(t.Context(), state.CallbackState); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("claim expired proof returned %v, want invalid proof", err)
		}
		if _, err := c.GetMCPOAuthPendingState(t.Context(), state.CallbackState); err != nil {
			t.Fatalf("expired proof should remain until cleanup: %v", err)
		}
	})
}

func TestGetMCPStaticOAuthTestStatusReportsAbandonedClaimAsInterrupted(t *testing.T) {
	for _, tt := range []struct {
		name     string
		ageClaim func(t *testing.T, c *Client, hashedState string)
	}{
		{
			name: "lease expired",
			ageClaim: func(t *testing.T, c *Client, hashedState string) {
				t.Helper()
				if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthPendingState{}).
					Where("hashed_state = ?", hashedState).
					Update("static_o_auth_test_claimed_at", time.Now().Add(-staticOAuthTestClaimLease-time.Second)).Error; err != nil {
					t.Fatalf("age claim: %v", err)
				}
			},
		},
		{
			// A claim recorded before this column existed, or by a process that
			// died before it could stamp one, is by definition abandoned.
			name: "claim without a recorded claim time",
			ageClaim: func(t *testing.T, c *Client, hashedState string) {
				t.Helper()
				if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthPendingState{}).
					Where("hashed_state = ?", hashedState).
					Update("static_o_auth_test_claimed_at", nil).Error; err != nil {
					t.Fatalf("clear claim time: %v", err)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t)
			state, _ := createStaticOAuthTest(t, c)
			if _, err := c.ClaimMCPStaticOAuthTest(t.Context(), state.CallbackState); err != nil {
				t.Fatalf("claim static OAuth test: %v", err)
			}
			hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state.CallbackState)))
			tt.ageClaim(t, c, hashedState)

			result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "catalog-entry-1")
			if err != nil {
				t.Fatalf("read interrupted status: %v", err)
			}
			assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureInterrupted)
		})
	}
}

// An interrupted test is terminal, so the user retries immediately with a fresh test
// rather than waiting out the pending-state TTL.
func TestStaticOAuthTestRetryAfterInterruptedClaimSucceeds(t *testing.T) {
	c := newTestClient(t)
	state, _ := createStaticOAuthTest(t, c)
	if _, err := c.ClaimMCPStaticOAuthTest(t.Context(), state.CallbackState); err != nil {
		t.Fatalf("claim static OAuth test: %v", err)
	}
	hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state.CallbackState)))
	if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthPendingState{}).
		Where("hashed_state = ?", hashedState).
		Update("static_o_auth_test_claimed_at", time.Now().Add(-staticOAuthTestClaimLease-time.Second)).Error; err != nil {
		t.Fatalf("age claim: %v", err)
	}
	result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "catalog-entry-1")
	if err != nil {
		t.Fatalf("read interrupted status: %v", err)
	}
	assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureInterrupted)

	retry, _ := createStaticOAuthTest(t, c)
	if _, err := c.ClaimMCPStaticOAuthTest(t.Context(), retry.CallbackState); err != nil {
		t.Fatalf("claim retried static OAuth test: %v", err)
	}
	if proof := completeSuccessfulStaticOAuthTest(t, c, retry); proof == "" {
		t.Fatal("retried static OAuth test produced no save proof")
	}
}

// The read and the write side share one lease, so a claim still inside it must remain
// completable while one aged past it is already interrupted and must not be completable.
// Wall-clock cannot pin the instant the lease expires, so the cases bracket it instead.
func TestCompleteMCPStaticOAuthTestFencesClaimByLease(t *testing.T) {
	for _, tt := range []struct {
		name      string
		claimedAt any
		wantDone  bool
	}{
		{name: "claim still inside the lease", claimedAt: time.Now().Add(-staticOAuthTestClaimLease / 2), wantDone: true},
		{name: "claim aged past the lease", claimedAt: time.Now().Add(-staticOAuthTestClaimLease - time.Second)},
		{name: "claim without a recorded claim time", claimedAt: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t)
			state, _ := createStaticOAuthTest(t, c)
			if _, err := c.ClaimMCPStaticOAuthTest(t.Context(), state.CallbackState); err != nil {
				t.Fatalf("claim static OAuth test: %v", err)
			}
			hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state.CallbackState)))
			if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthPendingState{}).
				Where("hashed_state = ?", hashedState).
				Update("static_o_auth_test_claimed_at", tt.claimedAt).Error; err != nil {
				t.Fatalf("rewrite claim time: %v", err)
			}

			if tt.wantDone {
				if proof := completeSuccessfulStaticOAuthTest(t, c, state); proof == "" {
					t.Fatal("completion inside the lease produced no save proof")
				}
				return
			}

			if err := c.CompleteMCPStaticOAuthTest(t.Context(), state.CallbackState, apitypes.MCPStaticOAuthTestStatusSucceeded, ""); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
				t.Fatalf("complete abandoned claim returned %v, want invalid test", err)
			}
			result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "catalog-entry-1")
			if err != nil {
				t.Fatalf("read status after rejected completion: %v", err)
			}
			assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusFailed, apitypes.MCPStaticOAuthTestFailureInterrupted)
			if result.Proof != "" {
				t.Fatalf("rejected completion minted a save proof: %+v", result)
			}
		})
	}
}

func TestCompleteMCPStaticOAuthTestRejectsUnsafeFailureCategoryWithoutEchoingIt(t *testing.T) {
	c := newTestClient(t)
	state, conf := createStaticOAuthTest(t, c)
	unsafe := apitypes.MCPStaticOAuthTestFailureCategory("provider body=invalid_grant code=secret-code token=secret-token " + conf.ClientSecret)

	err := c.CompleteMCPStaticOAuthTest(t.Context(), state.CallbackState, apitypes.MCPStaticOAuthTestStatusFailed, unsafe)
	if err == nil {
		t.Fatal("expected unsafe failure category to be rejected")
	}
	for _, sensitive := range []string{conf.ClientID, conf.ClientSecret, "provider body", "secret-code", "secret-token"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatalf("completion error exposed sensitive value %q: %q", sensitive, err)
		}
	}

	result, readErr := c.GetMCPStaticOAuthTestStatus(t.Context(), state.TestState, "user-1", "catalog-entry-1")
	if readErr != nil {
		t.Fatalf("read status after rejected completion: %v", readErr)
	}
	assertStaticOAuthTestResult(t, result, apitypes.MCPStaticOAuthTestStatusPending, "")
}

func TestCommitMCPStaticOAuthCredentialAtomicallyStoresAndConsumesExactProof(t *testing.T) {
	c := newTestClient(t)
	state, conf := createStaticOAuthTest(t, c)
	proof := completeSuccessfulStaticOAuthTest(t, c, state)

	if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, false); err != nil {
		t.Fatalf("commit initial static OAuth credential: %v", err)
	}
	credential, err := c.RevealCredential(t.Context(), []string{system.MCPOAuthCredentialName("catalog-entry-1")}, "oauth")
	if err != nil {
		t.Fatalf("reveal committed credential: %v", err)
	}
	if credential.Secrets["CLIENT_ID"] != conf.ClientID || credential.Secrets["CLIENT_SECRET"] != conf.ClientSecret {
		t.Fatalf("committed credential = %#v", credential.Secrets)
	}
	if credential.Secrets["MCP_URL"] != "https://mcp.example/api" {
		t.Fatalf("committed credential URL = %q", credential.Secrets["MCP_URL"])
	}
	if credential.Secrets["GENERATION"] != hashMCPStaticOAuthValue(proof) {
		t.Fatalf("committed credential generation = %q, want proof receipt", credential.Secrets["GENERATION"])
	}
	if _, err := c.GetMCPOAuthPendingState(t.Context(), state.CallbackState); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("committed proof remained usable: %v", err)
	}
}

func TestCreateMCPOAuthPendingStateRejectsCredentialBoundToAnotherCatalogURL(t *testing.T) {
	c := newTestClient(t)
	const (
		entryName = "catalog-entry-1"
		mcpID     = "server-1"
		oldURL    = "https://old-mcp.example/api"
		newURL    = "https://new-mcp.example/api"
	)
	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    "oauth",
		Secrets: map[string]string{
			"CLIENT_ID":     "client-1",
			"CLIENT_SECRET": "secret-1",
			"MCP_URL":       oldURL,
			"GENERATION":    "generation-1",
		},
	}); err != nil {
		t.Fatalf("seed catalog credential: %v", err)
	}
	conf := &oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"}

	err := c.CreateMCPOAuthPendingState(t.Context(), "user-1", mcpID, newURL, "request-1", entryName, "state-1", "verifier-1", conf)
	if !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
		t.Fatalf("changed catalog URL error = %v, want catalog credential changed", err)
	}
}

func TestCreateMCPOAuthPendingStateRejectsCredentialWithoutCatalogURL(t *testing.T) {
	c := newTestClient(t)
	const entryName = "catalog-entry-1"
	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    "oauth",
		Secrets: map[string]string{
			"CLIENT_ID":     "client-1",
			"CLIENT_SECRET": "secret-1",
			"GENERATION":    "generation-1",
		},
	}); err != nil {
		t.Fatalf("seed credential without provider URL: %v", err)
	}
	conf := &oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"}

	err := c.CreateMCPOAuthPendingState(t.Context(), "user-1", "server-1", "https://mcp.example/api", "request-1", entryName, "state-1", "verifier-1", conf)
	if !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
		t.Fatalf("credential without provider URL error = %v, want catalog credential changed", err)
	}
}

func TestCreateMCPOAuthPendingStateRejectsCredentialWithoutGeneration(t *testing.T) {
	c := newTestClient(t)
	const (
		entryName = "catalog-entry-1"
		mcpURL    = "https://mcp.example/api"
	)
	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    "oauth",
		Secrets: map[string]string{
			"CLIENT_ID":     "client-1",
			"CLIENT_SECRET": "secret-1",
			"MCP_URL":       mcpURL,
		},
	}); err != nil {
		t.Fatalf("seed credential without generation: %v", err)
	}
	conf := &oauth2.Config{ClientID: "client-1", ClientSecret: "secret-1"}

	err := c.CreateMCPOAuthPendingState(t.Context(), "user-1", "server-1", mcpURL, "request-1", entryName, "state-1", "verifier-1", conf)
	if !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
		t.Fatalf("credential without generation error = %v, want catalog credential changed", err)
	}
}

func TestCommitMCPStaticOAuthCredentialConsumesProofBeforeAtomicMutation(t *testing.T) {
	t.Run("mismatched proof never writes", func(t *testing.T) {
		c := newTestClient(t)
		state, conf := createStaticOAuthTest(t, c)
		proof := completeSuccessfulStaticOAuthTest(t, c, state)

		err := c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", "changed-client", conf.ClientSecret, false)
		if !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("mismatched proof error = %v, want invalid proof", err)
		}
		if _, err := c.RevealCredential(t.Context(), []string{system.MCPOAuthCredentialName("catalog-entry-1")}, "oauth"); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("mismatched proof wrote credential: %v", err)
		}
		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, false); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("mismatched attempt left proof reusable: %v", err)
		}
	})

	t.Run("initial commit rejects existing credential and consumes proof", func(t *testing.T) {
		c := newTestClient(t)
		if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
			Context: system.MCPOAuthCredentialName("catalog-entry-1"),
			Name:    "oauth",
			Secrets: map[string]string{"CLIENT_ID": "active-client", "CLIENT_SECRET": "active-secret"},
		}); err != nil {
			t.Fatalf("seed active credential: %v", err)
		}
		state, conf := createStaticOAuthTest(t, c)
		proof := completeSuccessfulStaticOAuthTest(t, c, state)

		err := c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, false)
		if !errors.Is(err, ErrMCPStaticOAuthCredentialExists) {
			t.Fatalf("initial commit error = %v, want credential exists", err)
		}
		credential, revealErr := c.RevealCredential(t.Context(), []string{system.MCPOAuthCredentialName("catalog-entry-1")}, "oauth")
		if revealErr != nil {
			t.Fatalf("reveal active credential: %v", revealErr)
		}
		if credential.Secrets["CLIENT_ID"] != "active-client" || credential.Secrets["CLIENT_SECRET"] != "active-secret" {
			t.Fatalf("active credential changed: %#v", credential.Secrets)
		}
		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, true); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("existing-credential rejection left proof reusable: %v", err)
		}
	})

	t.Run("replacement upsert failure preserves old credential and consumes proof", func(t *testing.T) {
		c := newTestClient(t)
		credentialKey := system.MCPOAuthCredentialName("catalog-entry-1")
		if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
			Context: credentialKey,
			Name:    "oauth",
			Secrets: map[string]string{"CLIENT_ID": "active-client", "CLIENT_SECRET": "active-secret"},
		}); err != nil {
			t.Fatalf("seed active credential: %v", err)
		}
		state, conf := createStaticOAuthTest(t, c)
		proof := completeSuccessfulStaticOAuthTest(t, c, state)
		if err := c.db.WithContext(t.Context()).Exec(`CREATE TRIGGER fail_oauth_credential_update BEFORE UPDATE ON credentials BEGIN SELECT RAISE(FAIL, 'injected credential write failure'); END`).Error; err != nil {
			t.Fatalf("install credential failure trigger: %v", err)
		}

		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, true); err == nil {
			t.Fatal("replacement succeeded despite injected upsert failure")
		}
		if err := c.db.WithContext(t.Context()).Exec(`DROP TRIGGER fail_oauth_credential_update`).Error; err != nil {
			t.Fatalf("remove credential failure trigger: %v", err)
		}
		credential, err := c.RevealCredential(t.Context(), []string{credentialKey}, "oauth")
		if err != nil {
			t.Fatalf("reveal active credential after rollback: %v", err)
		}
		if credential.Secrets["CLIENT_ID"] != "active-client" || credential.Secrets["CLIENT_SECRET"] != "active-secret" {
			t.Fatalf("active credential changed after rollback: %#v", credential.Secrets)
		}
		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, true); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("failed upsert left proof reusable: %v", err)
		}
	})

	t.Run("proof delete failure rolls back replacement", func(t *testing.T) {
		c := newTestClient(t)
		credentialKey := system.MCPOAuthCredentialName("catalog-entry-1")
		if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
			Context: credentialKey,
			Name:    "oauth",
			Secrets: map[string]string{"CLIENT_ID": "active-client", "CLIENT_SECRET": "active-secret"},
		}); err != nil {
			t.Fatalf("seed active credential: %v", err)
		}
		state, conf := createStaticOAuthTest(t, c)
		proof := completeSuccessfulStaticOAuthTest(t, c, state)
		if err := c.db.WithContext(t.Context()).Exec(`CREATE TRIGGER fail_static_proof_delete BEFORE DELETE ON mcpo_auth_pending_states BEGIN SELECT RAISE(FAIL, 'injected proof delete failure'); END`).Error; err != nil {
			t.Fatalf("install proof failure trigger: %v", err)
		}

		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, true); err == nil {
			t.Fatal("replacement succeeded despite injected proof delete failure")
		}
		if err := c.db.WithContext(t.Context()).Exec(`DROP TRIGGER fail_static_proof_delete`).Error; err != nil {
			t.Fatalf("remove proof failure trigger: %v", err)
		}
		credential, err := c.RevealCredential(t.Context(), []string{credentialKey}, "oauth")
		if err != nil {
			t.Fatalf("reveal active credential after rollback: %v", err)
		}
		if credential.Secrets["CLIENT_ID"] != "active-client" || credential.Secrets["CLIENT_SECRET"] != "active-secret" {
			t.Fatalf("credential update survived proof-delete rollback: %#v", credential.Secrets)
		}
		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, true); err != nil {
			t.Fatalf("proof-delete rollback consumed proof: %v", err)
		}
	})

	t.Run("token delete failure rolls back replacement and consumes proof", func(t *testing.T) {
		c := newTestClient(t)
		state, conf := createStaticOAuthTest(t, c)
		proof := completeSuccessfulStaticOAuthTest(t, c, state)
		credentialKey := system.MCPOAuthCredentialName("catalog-entry-1")
		if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
			Context: credentialKey,
			Name:    "oauth",
			Secrets: map[string]string{"CLIENT_ID": "active-client", "CLIENT_SECRET": "active-secret"},
		}); err != nil {
			t.Fatalf("seed active credential: %v", err)
		}
		if err := c.db.WithContext(t.Context()).Create(&gwtypes.MCPOAuthToken{
			MCPID: "instance-1", UserID: "user-1", URL: "https://mcp.example/api",
			CatalogEntryName: "catalog-entry-1", AccessToken: "active-token",
		}).Error; err != nil {
			t.Fatalf("seed active static OAuth token: %v", err)
		}
		if err := c.db.WithContext(t.Context()).Exec(`CREATE TRIGGER fail_static_token_delete BEFORE DELETE ON mcpo_auth_tokens BEGIN SELECT RAISE(FAIL, 'injected token delete failure'); END`).Error; err != nil {
			t.Fatalf("install token failure trigger: %v", err)
		}

		err := c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, true, "instance-1")
		if err == nil {
			t.Fatal("replacement succeeded despite injected token delete failure")
		}
		if err := c.db.WithContext(t.Context()).Exec(`DROP TRIGGER fail_static_token_delete`).Error; err != nil {
			t.Fatalf("remove token failure trigger: %v", err)
		}
		credential, revealErr := c.RevealCredential(t.Context(), []string{credentialKey}, "oauth")
		if revealErr != nil {
			t.Fatalf("reveal active credential after rollback: %v", revealErr)
		}
		if credential.Secrets["CLIENT_ID"] != "active-client" || credential.Secrets["CLIENT_SECRET"] != "active-secret" {
			t.Fatalf("active credential changed after token rollback: %#v", credential.Secrets)
		}
		if _, err := c.GetMCPOAuthToken(t.Context(), "user-1", "instance-1", "https://mcp.example/api"); err != nil {
			t.Fatalf("active token was deleted despite rollback: %v", err)
		}
		if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, true, "instance-1"); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("token-delete rollback left proof reusable: %v", err)
		}
	})
}

func TestCommitMCPStaticOAuthCredentialInvalidatesSiblingProofs(t *testing.T) {
	c := newTestClient(t)
	firstState, conf := createStaticOAuthTest(t, c)
	secondState, _ := createStaticOAuthTest(t, c)
	firstSaveProof := completeSuccessfulStaticOAuthTest(t, c, firstState)
	completeSuccessfulStaticOAuthTest(t, c, secondState)
	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: system.MCPOAuthCredentialName("catalog-entry-1"),
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "active-client", "CLIENT_SECRET": "active-secret"},
	}); err != nil {
		t.Fatalf("seed active credential: %v", err)
	}
	firstProof, err := c.GetMCPOAuthPendingState(t.Context(), firstState.CallbackState)
	if err != nil {
		t.Fatalf("read first proof before replacement: %v", err)
	}
	if !firstProof.StaticOAuthTest || firstProof.StaticOAuthTestStatus != apitypes.MCPStaticOAuthTestStatusSucceeded || firstProof.UserID != "user-1" || firstProof.MCPID != "catalog-entry-1" || firstProof.URL != "https://mcp.example/api" || firstProof.ClientID != conf.ClientID || firstProof.ClientSecret != conf.ClientSecret {
		t.Fatalf("first proof changed before replacement: static=%v status=%q user=%q mcp=%q url=%q clientIDMatch=%v secretMatch=%v", firstProof.StaticOAuthTest, firstProof.StaticOAuthTestStatus, firstProof.UserID, firstProof.MCPID, firstProof.URL, firstProof.ClientID == conf.ClientID, firstProof.ClientSecret == conf.ClientSecret)
	}

	if err := c.commitMCPStaticOAuthCredential(t.Context(), firstSaveProof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, true); err != nil {
		t.Fatalf("commit replacement: %v", err)
	}
	if _, err := c.GetMCPStaticOAuthTestStatus(t.Context(), secondState.TestState, "user-1", "catalog-entry-1"); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
		t.Fatalf("sibling proof status error = %v, want invalid", err)
	}
}

func TestCommitMCPStaticOAuthCredentialAllowsOneConcurrentWinner(t *testing.T) {
	c := newTestClient(t)
	state, conf := createStaticOAuthTest(t, c)
	proof := completeSuccessfulStaticOAuthTest(t, c, state)
	credentialKey := system.MCPOAuthCredentialName("catalog-entry-1")

	const attempts = 8
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() {
			<-start
			release, err := c.AcquireCredentialLock(t.Context(), credentialKey)
			if err != nil {
				results <- err
				return
			}
			defer release()
			results <- c.commitMCPStaticOAuthCredential(t.Context(), proof, "user-1", "catalog-entry-1", "https://mcp.example/api", conf.ClientID, conf.ClientSecret, false)
		})
	}
	close(start)
	wg.Wait()
	close(results)

	var successes int
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
			t.Fatalf("concurrent commit error = %v, want invalid proof", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent commit successes = %d, want exactly 1", successes)
	}
	credential, err := c.RevealCredential(t.Context(), []string{credentialKey}, "oauth")
	if err != nil {
		t.Fatalf("reveal winning credential: %v", err)
	}
	if credential.Secrets["CLIENT_ID"] != conf.ClientID || credential.Secrets["CLIENT_SECRET"] != conf.ClientSecret {
		t.Fatalf("winning credential = %#v", credential.Secrets)
	}
}

func TestCleanupExpiredMCPOAuthPendingStatesRemovesPendingAndCompletedStaticOAuthTests(t *testing.T) {
	c := newTestClient(t)
	pendingState, _ := createStaticOAuthTest(t, c)
	completedState, _ := createStaticOAuthTest(t, c)
	completeSuccessfulStaticOAuthTest(t, c, completedState)

	cutoff := time.Now().Add(-pendingStateTTL - time.Second)
	for _, state := range []MCPStaticOAuthTestStart{pendingState, completedState} {
		hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte(state.CallbackState)))
		if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthPendingState{}).
			Where("hashed_state = ?", hashedState).
			Update("created_at", cutoff).Error; err != nil {
			t.Fatalf("age static OAuth test %q: %v", state, err)
		}
	}

	if err := c.CleanupExpiredMCPOAuthPendingStates(t.Context(), pendingStateTTL); err != nil {
		t.Fatalf("clean up expired pending states: %v", err)
	}
	for _, state := range []MCPStaticOAuthTestStart{pendingState, completedState} {
		if _, err := c.GetMCPOAuthPendingState(t.Context(), state.CallbackState); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("read cleaned up static OAuth test %q: %v", state, err)
		}
	}
}

func TestStaticOAuthCleanupQueriesUseTargetedIndexes(t *testing.T) {
	c := newTestClient(t)
	for _, tt := range []struct {
		name      string
		query     string
		args      []any
		wantIndex string
	}{
		{
			name:      "catalog grants",
			query:     "EXPLAIN QUERY PLAN SELECT mcp_id FROM mcpo_auth_tokens WHERE catalog_entry_name = ?",
			args:      []any{"entry-1"},
			wantIndex: "idx_mcp_oauth_token_catalog_entry",
		},
		{
			name:      "entry proofs",
			query:     "EXPLAIN QUERY PLAN SELECT hashed_state FROM mcpo_auth_pending_states WHERE mcp_id = ? AND static_o_auth_test = ?",
			args:      []any{"entry-1", true},
			wantIndex: "idx_pending_mcp_static_test",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var plan []struct{ Detail string }
			if err := c.db.WithContext(t.Context()).Raw(tt.query, tt.args...).Scan(&plan).Error; err != nil {
				t.Fatalf("explain cleanup query: %v", err)
			}
			if !slices.ContainsFunc(plan, func(row struct{ Detail string }) bool {
				return strings.Contains(row.Detail, tt.wantIndex)
			}) {
				t.Fatalf("query plan %#v did not use %s", plan, tt.wantIndex)
			}
		})
	}
}

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

func TestDeleteMCPOAuthTokenForAllUsersTriggersServerReconciliation(t *testing.T) {
	c := newTestClient(t)
	var triggered []string
	c.mcpOAuthTokenTrigger = func(_ context.Context, mcpID string) error {
		triggered = append(triggered, mcpID)
		return nil
	}
	conf := &oauth2.Config{ClientID: "client", ClientSecret: "secret"}
	if err := c.ReplaceMCPOAuthToken(t.Context(), "user-1", "server-1", "https://mcp.example/api", "", conf, &oauth2.Token{AccessToken: "token"}); err != nil {
		t.Fatalf("seed OAuth token: %v", err)
	}
	if !slices.Equal(triggered, []string{"server-1"}) {
		t.Fatalf("Replace notified %#v, want [server-1]", triggered)
	}
	triggered = nil

	if err := c.DeleteMCPOAuthTokenForAllUsers(t.Context(), "server-1"); err != nil {
		t.Fatalf("delete OAuth tokens: %v", err)
	}
	if !slices.Equal(triggered, []string{"server-1"}) {
		t.Fatalf("Delete notified %#v, want [server-1]", triggered)
	}
}

// A multi-user credential change carries the MCPServerInstance ID, so the
// production trigger wiring has to reconcile the owning MCPServer under a
// namespace-qualified key. Wire the real trigger function, not a stub, so a
// regression in either the kind or the key fails here.
func TestMCPOAuthTokenChangeForInstanceTriggersOwningServerReconciliation(t *testing.T) {
	const (
		instanceName = system.MCPServerInstancePrefix + "abc"
		serverName   = system.MCPServerPrefix + "def"
		userID       = "user-1"
	)

	storageClient := clientfake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(&v1.MCPServerInstance{
			Name: instanceName, Namespace: system.DefaultNamespace,
			Spec: v1.MCPServerInstanceSpec{UserID: userID, MCPServerName: serverName},
		}).
		Build()
	backend := &recordingControllerBackend{}

	// Constructed through the same entry point production uses, so the trigger
	// under test is the one New wires rather than a test-installed stand-in.
	c := New(
		t.Context(), newTestDB(t), storageClient, nil, backend,
		nil, nil, time.Hour, 1, 0, 0, 0, false,
	)

	wantKey := system.DefaultNamespace + "/" + serverName

	if err := c.ReplaceMCPOAuthToken(t.Context(), userID, instanceName, "https://mcp.example/api", "", &oauth2.Config{ClientID: "client", ClientSecret: "secret"}, &oauth2.Token{AccessToken: "token"}); err != nil {
		t.Fatalf("seed OAuth token: %v", err)
	}
	if len(backend.triggers) != 1 || backend.triggers[0].key != wantKey {
		t.Fatalf("Replace triggers = %#v, want one key %s", backend.triggers, wantKey)
	}
	backend.triggers = nil

	if err := c.DeleteMCPOAuthTokenForAllUsers(t.Context(), instanceName); err != nil {
		t.Fatalf("delete OAuth tokens: %v", err)
	}

	if len(backend.triggers) != 1 || backend.triggers[0].key != wantKey {
		t.Fatalf("Delete triggers = %#v, want one key %s", backend.triggers, wantKey)
	}
	if got := backend.triggers[0].gvk; got != v1.SchemeGroupVersion.WithKind("MCPServer") {
		t.Fatalf("triggered kind = %s, want MCPServer", got)
	}
}

// Catalog-entry deletion notifies the deployment identifiers it purged, and for
// a multi-user deployment those are MCPServerInstance IDs. The cleanup path has
// to resolve them to their owner too, or the reconcile is enqueued against a
// kind that has no OAuth handlers.
func TestDeletedCatalogEntryCleanupTriggersTheOwningServerOfAnInstanceGrant(t *testing.T) {
	const (
		entryName    = "catalog-entry-1"
		instanceName = system.MCPServerInstancePrefix + "abc"
		serverName   = system.MCPServerPrefix + "def"
	)

	storageClient := clientfake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(&v1.MCPServerInstance{
			Name: instanceName, Namespace: system.DefaultNamespace,
			Spec: v1.MCPServerInstanceSpec{UserID: "user-1", MCPServerName: serverName},
		}).
		Build()
	backend := &recordingControllerBackend{}
	c := New(
		t.Context(), newTestDB(t), storageClient, nil, backend,
		nil, nil, time.Hour, 1, 0, 0, 0, false,
	)

	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret"},
	}); err != nil {
		t.Fatalf("seed static OAuth credential: %v", err)
	}
	if err := c.db.WithContext(t.Context()).Create(&gwtypes.MCPOAuthToken{
		MCPID: instanceName, UserID: "user-1", CatalogEntryName: entryName,
	}).Error; err != nil {
		t.Fatalf("seed instance OAuth grant: %v", err)
	}

	deleted, err := c.DeleteMCPStaticOAuthStateForDeletedCatalogEntry(t.Context(), entryName, instanceName)
	if err != nil {
		t.Fatalf("purge deleted catalog entry OAuth state: %v", err)
	}
	if !deleted {
		t.Fatal("did not report deleting the static OAuth credential")
	}

	wantKey := system.DefaultNamespace + "/" + serverName
	if len(backend.triggers) == 0 {
		t.Fatal("cleanup enqueued no reconcile")
	}
	for _, got := range backend.triggers {
		if got.key != wantKey {
			t.Fatalf("cleanup triggers = %#v, want every key %s", backend.triggers, wantKey)
		}
		if want := v1.SchemeGroupVersion.WithKind("MCPServer"); got.gvk != want {
			t.Fatalf("triggered kind = %s, want %s", got.gvk, want)
		}
	}
}

func TestDeleteMCPStaticOAuthCredentialPreservesDynamicGrantWithoutStaticCredential(t *testing.T) {
	c := newTestClient(t)
	const (
		entryName = "catalog-entry-1"
		mcpID     = "server-1"
		mcpURL    = "https://mcp.example/api"
	)
	if err := c.ReplaceMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL, "", &oauth2.Config{}, &oauth2.Token{AccessToken: "dynamic-token"}); err != nil {
		t.Fatalf("seed dynamic OAuth grant: %v", err)
	}
	if err := c.db.WithContext(t.Context()).Create(&gwtypes.MCPOAuthToken{
		MCPID: "fenced-grant", UserID: "user-2", CatalogEntryName: entryName,
	}).Error; err != nil {
		t.Fatalf("seed fenced static OAuth grant: %v", err)
	}

	deleted, err := c.DeleteMCPStaticOAuthCredential(t.Context(), entryName, mcpID)
	if err != nil {
		t.Fatalf("clean up absent static OAuth credential: %v", err)
	}
	if deleted {
		t.Fatal("reported deleting a static OAuth credential that did not exist")
	}
	if _, err := c.GetMCPOAuthToken(t.Context(), "user-1", mcpID, mcpURL); err != nil {
		t.Fatalf("dynamic OAuth grant was deleted by static cleanup: %v", err)
	}
	var fencedGrantCount int64
	if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthToken{}).
		Where("mcp_id = ?", "fenced-grant").Count(&fencedGrantCount).Error; err != nil {
		t.Fatalf("count fenced static OAuth grants: %v", err)
	}
	if fencedGrantCount != 0 {
		t.Fatalf("fenced static OAuth grant count = %d, want 0", fencedGrantCount)
	}
}

func TestDeleteMCPStaticOAuthCredentialPreservesDynamicGrantWithStaticCredential(t *testing.T) {
	c := newTestClient(t)
	const (
		entryName = "catalog-entry-1"
		mcpID     = "server-1"
		mcpURL    = "https://mcp.example/api"
	)
	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret"},
	}); err != nil {
		t.Fatalf("seed static OAuth credential: %v", err)
	}
	if err := c.ReplaceMCPOAuthToken(t.Context(), "dynamic-user", mcpID, mcpURL, "", &oauth2.Config{}, &oauth2.Token{AccessToken: "dynamic-token"}); err != nil {
		t.Fatalf("seed dynamic OAuth grant: %v", err)
	}
	if err := c.db.WithContext(t.Context()).Create(&gwtypes.MCPOAuthToken{
		MCPID: "fenced-grant", UserID: "static-user", CatalogEntryName: entryName,
	}).Error; err != nil {
		t.Fatalf("seed fenced static OAuth grant: %v", err)
	}

	deleted, err := c.DeleteMCPStaticOAuthCredential(t.Context(), entryName, mcpID)
	if err != nil {
		t.Fatalf("delete static OAuth credential: %v", err)
	}
	if !deleted {
		t.Fatal("did not report deleting the static OAuth credential")
	}
	if _, err := c.GetMCPOAuthToken(t.Context(), "dynamic-user", mcpID, mcpURL); err != nil {
		t.Fatalf("dynamic OAuth grant was deleted by static cleanup: %v", err)
	}
	var fencedGrantCount int64
	if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthToken{}).
		Where("mcp_id = ?", "fenced-grant").Count(&fencedGrantCount).Error; err != nil {
		t.Fatalf("count fenced static OAuth grants: %v", err)
	}
	if fencedGrantCount != 0 {
		t.Fatalf("fenced static OAuth grant count = %d, want 0", fencedGrantCount)
	}
}

func TestReplaceMCPStaticOAuthCredentialPreservesDynamicGrant(t *testing.T) {
	c := newTestClient(t)
	const (
		entryName = "catalog-entry-1"
		mcpID     = "server-1"
		mcpURL    = "https://mcp.example/api"
	)
	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "old-client", "CLIENT_SECRET": "old-secret"},
	}); err != nil {
		t.Fatalf("seed static OAuth credential: %v", err)
	}
	if err := c.ReplaceMCPOAuthToken(t.Context(), "dynamic-user", mcpID, mcpURL, "", &oauth2.Config{}, &oauth2.Token{AccessToken: "dynamic-token"}); err != nil {
		t.Fatalf("seed dynamic OAuth grant: %v", err)
	}
	if err := c.db.WithContext(t.Context()).Create(&gwtypes.MCPOAuthToken{
		MCPID: "fenced-grant", UserID: "static-user", CatalogEntryName: entryName,
	}).Error; err != nil {
		t.Fatalf("seed fenced static OAuth grant: %v", err)
	}

	started, conf := createStaticOAuthTest(t, c)
	proof := completeSuccessfulStaticOAuthTest(t, c, started)
	if err := c.commitMCPStaticOAuthCredential(
		t.Context(), proof, "user-1", entryName, mcpURL,
		conf.ClientID, conf.ClientSecret, true, mcpID,
	); err != nil {
		t.Fatalf("replace static OAuth credential: %v", err)
	}

	if _, err := c.GetMCPOAuthToken(t.Context(), "dynamic-user", mcpID, mcpURL); err != nil {
		t.Fatalf("dynamic OAuth grant was deleted by credential replacement: %v", err)
	}
	var fencedGrantCount int64
	if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthToken{}).
		Where("mcp_id = ?", "fenced-grant").Count(&fencedGrantCount).Error; err != nil {
		t.Fatalf("count fenced static OAuth grants: %v", err)
	}
	if fencedGrantCount != 0 {
		t.Fatalf("fenced static OAuth grant count = %d, want 0", fencedGrantCount)
	}
}

func TestDeleteMCPStaticOAuthStateForDeletedCatalogEntryPurgesDeploymentGrants(t *testing.T) {
	c := newTestClient(t)
	const entryName = "catalog-entry-1"
	var triggered []string
	c.mcpOAuthTokenTrigger = func(_ context.Context, mcpID string) error {
		triggered = append(triggered, mcpID)
		return nil
	}
	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret"},
	}); err != nil {
		t.Fatalf("seed static OAuth credential: %v", err)
	}
	if err := c.db.WithContext(t.Context()).Create(&[]gwtypes.MCPOAuthToken{
		{MCPID: "fenced-grant", UserID: "static-user", CatalogEntryName: entryName},
		{MCPID: "server-1", UserID: "dynamic-user"},
		{MCPID: "instance-1", UserID: "container-user"},
		{MCPID: "unrelated", UserID: "other-user", CatalogEntryName: "other-entry"},
	}).Error; err != nil {
		t.Fatalf("seed OAuth grants: %v", err)
	}

	deleted, err := c.DeleteMCPStaticOAuthStateForDeletedCatalogEntry(
		t.Context(), entryName, "server-1", "instance-1",
	)
	if err != nil {
		t.Fatalf("purge deleted catalog entry OAuth state: %v", err)
	}
	if !deleted {
		t.Fatal("did not report deleting the static OAuth credential")
	}

	var targetedGrantCount int64
	if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthToken{}).
		Where("catalog_entry_name = ? OR mcp_id IN ?", entryName, []string{"server-1", "instance-1"}).
		Count(&targetedGrantCount).Error; err != nil {
		t.Fatalf("count purged OAuth grants: %v", err)
	}
	if targetedGrantCount != 0 {
		t.Fatalf("targeted OAuth grant count = %d, want 0", targetedGrantCount)
	}
	var unrelatedGrantCount int64
	if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthToken{}).
		Where("mcp_id = ?", "unrelated").Count(&unrelatedGrantCount).Error; err != nil {
		t.Fatalf("count unrelated OAuth grants: %v", err)
	}
	if unrelatedGrantCount != 1 {
		t.Fatalf("unrelated OAuth grant count = %d, want 1", unrelatedGrantCount)
	}
	for _, mcpID := range []string{"fenced-grant", "server-1", "instance-1"} {
		if !slices.Contains(triggered, mcpID) {
			t.Fatalf("reconciliation triggers = %v, missing %q", triggered, mcpID)
		}
	}
}

func TestDeleteMCPStaticOAuthCredentialRetriesCleanupNotificationsAfterRowsAreGone(t *testing.T) {
	c := newTestClient(t)
	const (
		entryName = "catalog-entry-1"
		mcpID     = "server-1"
	)
	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret"},
	}); err != nil {
		t.Fatalf("seed static OAuth credential: %v", err)
	}
	if err := c.db.WithContext(t.Context()).Create(&gwtypes.MCPOAuthToken{
		MCPID: mcpID, UserID: "user-1", CatalogEntryName: entryName,
	}).Error; err != nil {
		t.Fatalf("seed static OAuth grant: %v", err)
	}

	var triggered []string
	failNotification := true
	c.mcpOAuthTokenTrigger = func(_ context.Context, gotMCPID string) error {
		triggered = append(triggered, gotMCPID)
		if failNotification {
			failNotification = false
			return errors.New("injected notification failure")
		}
		return nil
	}

	if _, err := c.DeleteMCPStaticOAuthCredential(t.Context(), entryName, mcpID); err == nil {
		t.Fatal("first delete succeeded despite injected notification failure")
	}
	if _, err := c.DeleteMCPStaticOAuthCredential(t.Context(), entryName, mcpID); err != nil {
		t.Fatalf("retry static OAuth cleanup: %v", err)
	}
	if !slices.Equal(triggered, []string{mcpID, mcpID}) {
		t.Fatalf("cleanup notifications = %v, want retry for %q", triggered, mcpID)
	}
}

func TestDeleteMCPStaticOAuthCredentialGenerationRejectsStaleClear(t *testing.T) {
	c := newTestClient(t)
	const (
		entryName         = "catalog-entry-1"
		mcpID             = "server-1"
		currentGeneration = "generation-2"
	)
	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    "oauth",
		Secrets: map[string]string{
			"CLIENT_ID":     "client",
			"CLIENT_SECRET": "secret",
			"MCP_URL":       "https://mcp.example/api",
			"GENERATION":    currentGeneration,
		},
	}); err != nil {
		t.Fatalf("seed static OAuth credential: %v", err)
	}
	if err := c.db.WithContext(t.Context()).Create(&gwtypes.MCPOAuthToken{
		MCPID: mcpID, UserID: "user-1", CatalogEntryName: entryName,
	}).Error; err != nil {
		t.Fatalf("seed static OAuth grant: %v", err)
	}

	if _, err := c.DeleteMCPStaticOAuthCredentialGeneration(
		t.Context(), entryName, "generation-1", mcpID,
	); !errors.Is(err, ErrMCPOAuthCatalogCredentialChanged) {
		t.Fatalf("stale Clear error = %v, want catalog credential changed", err)
	}
	credential, err := c.RevealCredential(
		t.Context(), []string{system.MCPOAuthCredentialName(entryName)}, "oauth",
	)
	if err != nil {
		t.Fatalf("stale Clear removed current credential: %v", err)
	}
	if credential.Secrets["GENERATION"] != currentGeneration {
		t.Fatalf("current credential changed: %#v", credential.Secrets)
	}
	if _, err := c.GetMCPOAuthToken(t.Context(), "user-1", mcpID, ""); err != nil {
		t.Fatalf("stale Clear removed current grant: %v", err)
	}
}

func TestDeleteMCPStaticOAuthCredentialGenerationPreservesDynamicGrant(t *testing.T) {
	c := newTestClient(t)
	const (
		entryName  = "catalog-entry-1"
		mcpID      = "server-1"
		mcpURL     = "https://mcp.example/api"
		generation = "generation-1"
	)
	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
		Context: system.MCPOAuthCredentialName(entryName),
		Name:    "oauth",
		Secrets: map[string]string{
			"CLIENT_ID": "client", "CLIENT_SECRET": "secret",
			"MCP_URL": mcpURL, "GENERATION": generation,
		},
	}); err != nil {
		t.Fatalf("seed static OAuth credential: %v", err)
	}
	if err := c.ReplaceMCPOAuthToken(t.Context(), "dynamic-user", mcpID, mcpURL, "", &oauth2.Config{}, &oauth2.Token{AccessToken: "dynamic-token"}); err != nil {
		t.Fatalf("seed dynamic OAuth grant: %v", err)
	}
	if err := c.db.WithContext(t.Context()).Create(&gwtypes.MCPOAuthToken{
		MCPID: "fenced-grant", UserID: "static-user", CatalogEntryName: entryName,
	}).Error; err != nil {
		t.Fatalf("seed fenced static OAuth grant: %v", err)
	}

	deleted, err := c.DeleteMCPStaticOAuthCredentialGeneration(t.Context(), entryName, generation, mcpID)
	if err != nil {
		t.Fatalf("delete static OAuth credential generation: %v", err)
	}
	if !deleted {
		t.Fatal("did not report deleting the static OAuth credential generation")
	}
	if _, err := c.GetMCPOAuthToken(t.Context(), "dynamic-user", mcpID, mcpURL); err != nil {
		t.Fatalf("dynamic OAuth grant was deleted by generation clear: %v", err)
	}
	var fencedGrantCount int64
	if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthToken{}).
		Where("mcp_id = ?", "fenced-grant").Count(&fencedGrantCount).Error; err != nil {
		t.Fatalf("count fenced static OAuth grants: %v", err)
	}
	if fencedGrantCount != 0 {
		t.Fatalf("fenced static OAuth grant count = %d, want 0", fencedGrantCount)
	}
}

func TestStaticOAuthMutationOverlappingDynamicGrantPreservesGrant(t *testing.T) {
	const (
		entryName  = "catalog-entry-1"
		mcpID      = "server-1"
		mcpURL     = "https://mcp.example/api"
		generation = "generation-1"
	)

	for _, mutation := range []string{"replacement", "generation clear"} {
		t.Run(mutation, func(t *testing.T) {
			c := newTestClient(t)
			if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
				Context: system.MCPOAuthCredentialName(entryName),
				Name:    "oauth",
				Secrets: map[string]string{
					"CLIENT_ID": "old-client", "CLIENT_SECRET": "old-secret",
					"MCP_URL": mcpURL, "GENERATION": generation,
				},
			}); err != nil {
				t.Fatalf("seed static OAuth credential: %v", err)
			}
			if err := c.db.WithContext(t.Context()).Create(&gwtypes.MCPOAuthToken{
				MCPID: mcpID, UserID: "static-user", CatalogEntryName: entryName,
			}).Error; err != nil {
				t.Fatalf("seed catalog-owned OAuth grant: %v", err)
			}

			var mutate func() error
			switch mutation {
			case "replacement":
				started, conf := createStaticOAuthTest(t, c)
				proof := completeSuccessfulStaticOAuthTest(t, c, started)
				mutate = func() error {
					return c.commitMCPStaticOAuthCredential(
						t.Context(), proof, "user-1", entryName, mcpURL,
						conf.ClientID, conf.ClientSecret, true, mcpID,
					)
				}
			case "generation clear":
				mutate = func() error {
					deleted, err := c.DeleteMCPStaticOAuthCredentialGeneration(
						t.Context(), entryName, generation, mcpID,
					)
					if err == nil && !deleted {
						return errors.New("static OAuth credential generation was not deleted")
					}
					return err
				}
			}

			cleanupCommitted := make(chan struct{})
			releaseCleanup := make(chan struct{})
			var triggerCalls atomic.Int32
			c.mcpOAuthTokenTrigger = func(context.Context, string) error {
				if triggerCalls.Add(1) == 1 {
					close(cleanupCommitted)
					<-releaseCleanup
				}
				return nil
			}

			mutationDone := make(chan error, 1)
			go func() {
				mutationDone <- mutate()
			}()
			select {
			case <-cleanupCommitted:
			case <-time.After(5 * time.Second):
				t.Fatal("static OAuth mutation did not commit")
			}

			dynamicErr := c.ReplaceMCPOAuthToken(
				t.Context(), "dynamic-user", mcpID, mcpURL, "", &oauth2.Config{},
				&oauth2.Token{AccessToken: "dynamic-token"},
			)
			close(releaseCleanup)
			if dynamicErr != nil {
				t.Fatalf("complete overlapping dynamic OAuth grant: %v", dynamicErr)
			}
			if err := <-mutationDone; err != nil {
				t.Fatalf("complete static OAuth %s: %v", mutation, err)
			}

			if _, err := c.GetMCPOAuthToken(t.Context(), "dynamic-user", mcpID, mcpURL); err != nil {
				t.Fatalf("overlapping dynamic OAuth grant was deleted: %v", err)
			}
			var ownedGrantCount int64
			if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthToken{}).
				Where("catalog_entry_name = ?", entryName).Count(&ownedGrantCount).Error; err != nil {
				t.Fatalf("count catalog-owned OAuth grants: %v", err)
			}
			if ownedGrantCount != 0 {
				t.Fatalf("catalog-owned OAuth grant count = %d, want 0", ownedGrantCount)
			}
		})
	}
}

func (c *Client) commitMCPStaticOAuthCredential(ctx context.Context, state, userID, mcpID, mcpURL, clientID, clientSecret string, replace bool, cleanupMCPIDs ...string) error {
	claim, err := c.ClaimMCPStaticOAuthCredentialProof(ctx, state, userID, mcpID, mcpURL, clientID, clientSecret)
	if err != nil {
		return err
	}
	return c.CommitClaimedMCPStaticOAuthCredential(ctx, claim, replace, cleanupMCPIDs...)
}

func completeSuccessfulStaticOAuthTest(t *testing.T, c *Client, started MCPStaticOAuthTestStart) string {
	t.Helper()
	if err := c.CompleteMCPStaticOAuthTest(t.Context(), started.CallbackState, apitypes.MCPStaticOAuthTestStatusSucceeded, ""); err != nil {
		t.Fatalf("complete successful test: %v", err)
	}
	result, err := c.GetMCPStaticOAuthTestStatus(t.Context(), started.TestState, "user-1", "catalog-entry-1")
	if err != nil {
		t.Fatalf("read successful test: %v", err)
	}
	if result.Proof == "" || result.Proof == started.CallbackState || result.Proof == started.TestState {
		t.Fatalf("save proof was not independently minted: %+v", result)
	}
	return result.Proof
}

// requireLiveStaticOAuthTestClaim returns the lease timestamp of a claimed row, failing
// when the claim was recorded without one.
func requireLiveStaticOAuthTestClaim(t *testing.T, c *Client, callbackState string) time.Time {
	t.Helper()
	var pending gwtypes.MCPOAuthPendingState
	if err := c.db.WithContext(t.Context()).
		First(&pending, "hashed_state = ?", fmt.Sprintf("%x", sha256.Sum256([]byte(callbackState)))).Error; err != nil {
		t.Fatalf("read claimed pending state: %v", err)
	}
	if pending.StaticOAuthTestStatus != mcpStaticOAuthTestStatusClaimed {
		t.Fatalf("pending status = %q, want %q", pending.StaticOAuthTestStatus, mcpStaticOAuthTestStatusClaimed)
	}
	if pending.StaticOAuthTestClaimedAt == nil {
		t.Fatal("claim recorded no lease timestamp, so the read side would report a live claim as interrupted")
	}
	return *pending.StaticOAuthTestClaimedAt
}

func createStaticOAuthTest(t *testing.T, c *Client) (MCPStaticOAuthTestStart, *oauth2.Config) {
	t.Helper()
	if c.encryptionConfig == nil {
		c.encryptionConfig = &encryptionconfig.EncryptionConfiguration{
			Transformers: map[schema.GroupResource]value.Transformer{
				mcpOAuthPendingStateGroupResource: staticOAuthTestTransformer{},
				credentialGroupResource:           staticOAuthTestTransformer{},
			},
		}
	}
	conf := &oauth2.Config{
		ClientID:     "candidate-client-id",
		ClientSecret: "candidate-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://provider.example/authorize",
			TokenURL:  "https://provider.example/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: "https://obot.example/oauth/mcp/callback",
	}
	state, err := c.CreateMCPStaticOAuthTest(t.Context(), "user-1", "catalog-entry-1", "https://mcp.example/api", "pkce-verifier", conf)
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	return state, conf
}

func assertStaticOAuthTestResult(t *testing.T, result apitypes.MCPStaticOAuthTestResult, wantStatus apitypes.MCPStaticOAuthTestStatus, wantFailure apitypes.MCPStaticOAuthTestFailureCategory) {
	t.Helper()
	if result.Status != wantStatus || result.FailureCategory != wantFailure {
		t.Fatalf("result = %+v, want status %q failure %q", result, wantStatus, wantFailure)
	}

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

var _ value.Transformer = staticOAuthTestTransformer{}

type staticOAuthTestTransformer struct{}

func (staticOAuthTestTransformer) TransformToStorage(_ context.Context, data []byte, _ value.Context) ([]byte, error) {
	return append([]byte("encrypted:"), data...), nil
}

func (staticOAuthTestTransformer) TransformFromStorage(_ context.Context, data []byte, _ value.Context) ([]byte, bool, error) {
	return data[len("encrypted:"):], false, nil
}

func createDynamicOAuthPendingState(t *testing.T, c *Client, mcpURL, state string) *oauth2.Config {
	t.Helper()
	conf := &oauth2.Config{
		ClientID:     "dynamic-client-id",
		ClientSecret: "dynamic-client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://provider.example/authorize",
			TokenURL:  "https://provider.example/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: "https://obot.example/oauth/mcp/callback",
	}
	if err := c.CreateMCPOAuthPendingState(t.Context(), "user-1", "mcp-instance-1", mcpURL, "request-1", "", state, "pkce-verifier", conf); err != nil {
		t.Fatalf("create pending state: %v", err)
	}
	return conf
}

func TestClaimMCPOAuthPendingStateEnforcesTTLAndExactlyOnce(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mcpURL string
	}{
		{name: "dynamic", mcpURL: "https://mcp.example/api"},
		{name: "container", mcpURL: ContainerOAuthResourcePrefix + "deployment-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("exactly once", func(t *testing.T) {
				c := newTestClient(t)
				conf := createDynamicOAuthPendingState(t, c, tc.mcpURL, "callback-state")

				const attempts = 8
				start := make(chan struct{})
				results := make(chan error, attempts)
				var wg sync.WaitGroup
				for range attempts {
					wg.Go(func() {
						<-start
						ps, err := c.ClaimMCPOAuthPendingState(t.Context(), "callback-state")
						if err == nil && (ps.ClientID != conf.ClientID || ps.Verifier != "pkce-verifier") {
							err = errors.New("claimed state did not contain the stored exchange material")
						}
						results <- err
					})
				}
				close(start)
				wg.Wait()
				close(results)

				var claimed int
				for err := range results {
					if err == nil {
						claimed++
					} else if !errors.Is(err, ErrMCPOAuthPendingStateInvalid) {
						t.Fatalf("claim pending state: %v", err)
					}
				}
				if claimed != 1 {
					t.Fatalf("successful claims = %d, want exactly 1", claimed)
				}
			})

			t.Run("expired row is rejected and left for cleanup", func(t *testing.T) {
				c := newTestClient(t)
				createDynamicOAuthPendingState(t, c, tc.mcpURL, "callback-state")
				hashedState := fmt.Sprintf("%x", sha256.Sum256([]byte("callback-state")))
				if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthPendingState{}).
					Where("hashed_state = ?", hashedState).
					Update("created_at", time.Now().Add(-pendingStateTTL-time.Second)).Error; err != nil {
					t.Fatalf("age pending state: %v", err)
				}

				// Background cleanup has deliberately not run: the cutoff must be
				// enforced by the claim itself.
				if _, err := c.ClaimMCPOAuthPendingState(t.Context(), "callback-state"); !errors.Is(err, ErrMCPOAuthPendingStateInvalid) {
					t.Fatalf("claim expired state returned %v, want invalid state", err)
				}
				ps, err := c.GetMCPOAuthPendingState(t.Context(), "callback-state")
				if err != nil {
					t.Fatalf("expired state should remain until cleanup: %v", err)
				}
				if ps.ClaimedAt != nil {
					t.Fatalf("expired state was claimed at %v, want unclaimed", *ps.ClaimedAt)
				}
			})

			t.Run("unknown state is rejected", func(t *testing.T) {
				c := newTestClient(t)
				if _, err := c.ClaimMCPOAuthPendingState(t.Context(), "never-issued"); !errors.Is(err, ErrMCPOAuthPendingStateInvalid) {
					t.Fatalf("claim unknown state returned %v, want invalid state", err)
				}
			})
		})
	}
}
