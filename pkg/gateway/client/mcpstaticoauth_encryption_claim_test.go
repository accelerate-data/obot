package client

// Fork-only guarantee (fork #37, restored by VD-6903): static OAuth proofs and
// credentials are stored encrypted, and an encrypted row read without its
// transformer fails closed instead of handing ciphertext back as plaintext. Kept in
// its own file so an upstream sync cannot drop these tests by merging over a
// shared one.

import (
	"errors"
	"strings"
	"testing"
	"time"

	apitypes "github.com/obot-platform/obot/apiclient/types"
	gwtypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/system"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	"k8s.io/apiserver/pkg/storage/value"
)

func pendingOnlyStaticOAuthEncryption() *encryptionconfig.EncryptionConfiguration {
	return &encryptionconfig.EncryptionConfiguration{
		Transformers: map[schema.GroupResource]value.Transformer{
			mcpOAuthPendingStateGroupResource: leaseTestTransformer{},
		},
	}
}

func TestCreateMCPStaticOAuthTestStoresEncryptedPendingProof(t *testing.T) {
	c := newTestClient(t)
	c.encryptionConfig = pendingOnlyStaticOAuthEncryption()
	ctx := t.Context()
	conf := staticOAuthTestConfig()
	conf.Scopes = []string{"channels:read", "chat:write"}

	before := time.Now()
	started, err := c.CreateMCPStaticOAuthTest(ctx, leaseTestUser, leaseTestEntry, staticOAuthTestURL, "pkce-verifier", conf)
	if err != nil {
		t.Fatalf("create static OAuth test: %v", err)
	}
	after := time.Now()
	second, err := c.CreateMCPStaticOAuthTest(ctx, leaseTestUser, leaseTestEntry, staticOAuthTestURL, "second-verifier", conf)
	if err != nil {
		t.Fatalf("create second static OAuth test: %v", err)
	}
	if started.CallbackState == "" || started.TestState == "" || started.CallbackState == started.TestState {
		t.Fatalf("callback and test states must be distinct random values: %+v", started)
	}
	if second.CallbackState == started.CallbackState || second.TestState == started.TestState {
		t.Fatal("expected independently generated callback and test states")
	}

	hashedState := hashMCPStaticOAuthValue(started.CallbackState)
	var stored gwtypes.MCPOAuthPendingState
	if err := c.db.WithContext(ctx).First(&stored, "hashed_state = ?", hashedState).Error; err != nil {
		t.Fatalf("load stored pending proof: %v", err)
	}
	if !stored.Encrypted {
		t.Fatal("expected pending proof to be marked encrypted")
	}
	if stored.State == started.CallbackState || stored.Verifier == "pkce-verifier" || stored.ClientID == conf.ClientID || stored.ClientSecret == conf.ClientSecret {
		t.Fatal("candidate proof data was stored in plaintext")
	}
	if stored.URL == staticOAuthTestURL || stored.AuthURL == conf.Endpoint.AuthURL || stored.TokenURL == conf.Endpoint.TokenURL || stored.RedirectURL == conf.RedirectURL || stored.Scopes == "channels:read chat:write" {
		t.Fatal("provider-sensitive proof data was stored in plaintext")
	}

	proof, err := c.GetMCPOAuthPendingState(ctx, started.CallbackState)
	if err != nil {
		t.Fatalf("decrypt stored pending proof: %v", err)
	}
	if proof.State != started.CallbackState || proof.UserID != leaseTestUser || proof.MCPID != leaseTestEntry || proof.URL != staticOAuthTestURL || !proof.StaticOAuthTest {
		t.Fatalf("stored proof identity = %+v", proof)
	}
	if proof.Verifier != "pkce-verifier" || proof.ClientID != conf.ClientID || proof.ClientSecret != conf.ClientSecret {
		t.Fatalf("stored proof candidates = verifier %q client ID %q", proof.Verifier, proof.ClientID)
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

	_, err := c.CreateMCPStaticOAuthTest(t.Context(), leaseTestUser, leaseTestEntry, staticOAuthTestURL, "verifier", &oauth2.Config{ClientID: "candidate-client", ClientSecret: "candidate-secret"})
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
	if _, err := c.GetMCPStaticOAuthTestStatus(t.Context(), started.TestState, leaseTestUser, leaseTestEntry); !errors.Is(err, ErrMCPStaticOAuthEncryptionRequired) {
		t.Fatalf("status without encryption error = %v, want encryption required", err)
	}
	if _, err := c.GetMCPOAuthPendingState(t.Context(), started.CallbackState); !errors.Is(err, ErrMCPStaticOAuthEncryptionRequired) {
		t.Fatalf("callback state without encryption error = %v, want encryption required", err)
	}
}

// A static credential read back as its ciphertext envelope would compare as an
// application with no client ID and no generation, which every fence treats as a
// legitimate value rather than a failure.
func TestEncryptedStaticOAuthCredentialFailsClosedWhenEncryptionIsRemoved(t *testing.T) {
	credentialContext := system.MCPOAuthCredentialName(leaseTestEntry)
	for _, tt := range []struct {
		name       string
		encryption *encryptionconfig.EncryptionConfiguration
	}{
		{name: "no encryption configuration"},
		{name: "no credential transformer", encryption: pendingOnlyStaticOAuthEncryption()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t)
			c.encryptionConfig = staticOAuthTestEncryption()
			if err := c.UpsertCredential(t.Context(), gwtypes.Credential{
				Context: credentialContext,
				Name:    system.StaticOAuthCredentialName,
				Secrets: map[string]string{"CLIENT_ID": "client", "CLIENT_SECRET": "secret", "GENERATION": "generation-1"},
			}); err != nil {
				t.Fatalf("seed encrypted credential: %v", err)
			}

			c.encryptionConfig = tt.encryption
			credential, err := c.RevealCredential(t.Context(), []string{credentialContext}, system.StaticOAuthCredentialName)
			if err == nil || !strings.Contains(err.Error(), "credential is encrypted but") {
				t.Fatalf("reveal without credential encryption = %+v, %v; want fail closed", credential.Secrets, err)
			}
			if _, err := c.ListCredentials(t.Context(), ListCredentialsOptions{CredentialContexts: []string{credentialContext}}); err == nil {
				t.Fatal("list returned an encrypted credential it could not decrypt")
			}
			if _, err := c.DeleteMCPStaticOAuthCredentialGeneration(t.Context(), leaseTestEntry, "generation-1"); err == nil {
				t.Fatal("generation-fenced clear accepted a credential it could not decrypt")
			}
		})
	}
}

// Failing closed applies to encrypted rows only; a credential written without
// encryption stays readable without it.
func TestUnencryptedCredentialReadsWithoutEncryption(t *testing.T) {
	c := newTestClient(t)
	if err := c.UpsertCredential(t.Context(), gwtypes.Credential{Context: "context-1", Name: "plain", Secrets: map[string]string{"KEY": "value"}}); err != nil {
		t.Fatalf("seed plaintext credential: %v", err)
	}
	credential, err := c.RevealCredential(t.Context(), []string{"context-1"}, "plain")
	if err != nil {
		t.Fatalf("reveal plaintext credential: %v", err)
	}
	if credential.Encrypted || credential.Secrets["KEY"] != "value" {
		t.Fatalf("plaintext credential = %+v", credential)
	}
}

func TestCommitMCPStaticOAuthCredentialFailsClosedWithoutCredentialEncryption(t *testing.T) {
	c := newTestClient(t)
	c.encryptionConfig = pendingOnlyStaticOAuthEncryption()
	proof, conf := createStaticOAuthProof(t, c)

	err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, false)
	if !errors.Is(err, ErrMCPStaticOAuthEncryptionRequired) {
		t.Fatalf("commit without credential encryption error = %v, want encryption required", err)
	}
	if _, err := c.RevealCredential(t.Context(), []string{system.MCPOAuthCredentialName(leaseTestEntry)}, system.StaticOAuthCredentialName); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("unencrypted credential was stored: %v", err)
	}
	if err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, false); !errors.Is(err, ErrMCPStaticOAuthTestInvalid) {
		t.Fatalf("failed commit left proof reusable: %v", err)
	}
}
