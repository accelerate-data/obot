package client

// Fork-only guarantee (fork #37, restored by VD-6903): replacing a static OAuth
// application refuses to overwrite an existing application this server cannot
// decrypt, and a grant-cleanup notification that fails names the server whose
// cleanup still needs a retry. Kept in its own file so an upstream sync cannot
// drop these tests by merging over a shared one.

import (
	"context"
	"errors"
	"strings"
	"testing"

	gwtypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/system"
)

func TestReplaceMCPStaticOAuthCredentialCleanupFailureNamesTheServer(t *testing.T) {
	c := newStaticOAuthCommitClient(t)
	seedActiveStaticOAuthCredential(t, c, "generation-1")
	seedStaticOAuthGrant(t, c)
	proof, conf := createStaticOAuthProof(t, c)

	errInjected := errors.New("injected notification failure")
	c.mcpOAuthTokenTrigger = func(_ context.Context, mcpID string) error {
		if mcpID == staticOAuthCommitInstance {
			return errInjected
		}
		return nil
	}

	err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, true, "instance-2", staticOAuthCommitInstance)
	if !errors.Is(err, errInjected) {
		t.Fatalf("replace error = %v, want injected notification failure", err)
	}
	if !strings.Contains(err.Error(), staticOAuthCommitInstance) {
		t.Fatalf("replace error %q does not name the server whose cleanup failed", err)
	}
	if strings.Contains(err.Error(), "instance-2") {
		t.Fatalf("replace error %q names a server whose cleanup succeeded", err)
	}
	// The cleanup failure is reported after commit, so the new application stands.
	if secrets := revealStaticOAuthTestCredential(t, c); secrets["CLIENT_ID"] != conf.ClientID {
		t.Fatalf("replacement was not committed: %#v", secrets)
	}
}

func TestReplaceMCPStaticOAuthCredentialFailsClosedOnUndecryptableExistingCredential(t *testing.T) {
	c := newStaticOAuthCommitClient(t)
	seedActiveStaticOAuthCredential(t, c, "generation-1")
	seedStaticOAuthGrant(t, c)
	proof, conf := createStaticOAuthProof(t, c)

	// Stand in for a row written under a key this server no longer holds.
	const undecryptable = "not-base64-ciphertext!"
	var existing gwtypes.Credential
	if err := c.db.WithContext(t.Context()).Where("context = ? AND name = ?", staticOAuthTestCredentialContext, system.StaticOAuthCredentialName).First(&existing).Error; err != nil {
		t.Fatalf("load existing credential: %v", err)
	}
	existing.Secrets = map[string]string{credentialEncryptedSecretsKey: undecryptable}
	existing.Encrypted = true
	if err := c.db.WithContext(t.Context()).Save(&existing).Error; err != nil {
		t.Fatalf("corrupt existing credential: %v", err)
	}

	err := c.commitMCPStaticOAuthCredential(t.Context(), proof, leaseTestUser, leaseTestEntry, staticOAuthTestURL, conf.ClientID, conf.ClientSecret, true, staticOAuthCommitInstance)
	if err == nil || !strings.Contains(err.Error(), "failed to decrypt existing static OAuth credential") {
		t.Fatalf("replace error = %v, want a decrypt failure", err)
	}

	var stored gwtypes.Credential
	if err := c.db.WithContext(t.Context()).First(&stored, existing.ID).Error; err != nil {
		t.Fatalf("reload existing credential: %v", err)
	}
	if stored.Secrets[credentialEncryptedSecretsKey] != undecryptable {
		t.Fatalf("undecryptable credential was overwritten: %#v", stored.Secrets)
	}
	var grants int64
	if err := c.db.WithContext(t.Context()).Model(&gwtypes.MCPOAuthToken{}).Where("catalog_entry_name = ?", leaseTestEntry).Count(&grants).Error; err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if grants != 1 {
		t.Fatalf("grants = %d, want the existing grant kept when the replace aborts", grants)
	}
}
