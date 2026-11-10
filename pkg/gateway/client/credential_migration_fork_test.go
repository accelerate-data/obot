package client

import (
	"crypto/aes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	"k8s.io/apiserver/pkg/storage/value"
	encryptaes "k8s.io/apiserver/pkg/storage/value/encrypt/aes"
)

func TestMigrateIfNotRunRollsBackMarkerOnFailureAndRunsOnce(t *testing.T) {
	c := newTestClient(t)
	runs := 0
	migration := func(tx *gorm.DB) error {
		runs++
		var markerCount int64
		if err := tx.Model(&gatewaytypes.Migration{}).Where("name = ?", "test_atomic_marker").Count(&markerCount).Error; err != nil {
			return err
		}
		if markerCount != 1 {
			return errors.New("migration marker was not claimed before the migration body")
		}
		if runs == 1 {
			return errors.New("injected migration failure")
		}
		return nil
	}

	if err := c.migrateIfNotRun(t.Context(), "test_atomic_marker", migration); err == nil {
		t.Fatal("migration unexpectedly succeeded")
	}
	if err := c.migrateIfNotRun(t.Context(), "test_atomic_marker", migration); err != nil {
		t.Fatalf("migration retry failed: %v", err)
	}
	if err := c.migrateIfNotRun(t.Context(), "test_atomic_marker", migration); err != nil {
		t.Fatalf("completed migration was not idempotent: %v", err)
	}
	if runs != 2 {
		t.Fatalf("migration body ran %d times, want 2", runs)
	}
}

func TestMigrateUnencryptedCredentialsPreservesAndEncryptsLegacyRows(t *testing.T) {
	c := newTestClient(t)
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("create AES cipher: %v", err)
	}
	transformer, err := encryptaes.NewGCMTransformer(block)
	if err != nil {
		t.Fatalf("create AES-GCM transformer: %v", err)
	}
	c.encryptionConfig = &encryptionconfig.EncryptionConfiguration{
		Transformers: map[schema.GroupResource]value.Transformer{
			credentialGroupResource: transformer,
		},
	}
	legacy := gatewaytypes.Credential{
		Context: "mcp-oauth-entry-1",
		Name:    "oauth",
		Secrets: map[string]string{"CLIENT_ID": "legacy-client", "CLIENT_SECRET": "legacy-secret"},
	}
	if err := c.db.WithContext(t.Context()).Create(&legacy).Error; err != nil {
		t.Fatalf("seed plaintext credential: %v", err)
	}

	if err := c.MigrateUnencryptedCredentials(t.Context()); err != nil {
		t.Fatalf("migrate plaintext credentials: %v", err)
	}
	var stored gatewaytypes.Credential
	if err := c.db.WithContext(t.Context()).First(&stored, legacy.ID).Error; err != nil {
		t.Fatalf("read migrated credential: %v", err)
	}
	encoded, err := json.Marshal(stored.Secrets)
	if err != nil {
		t.Fatalf("marshal stored secrets: %v", err)
	}
	if !stored.Encrypted || strings.Contains(string(encoded), "legacy-client") || strings.Contains(string(encoded), "legacy-secret") {
		t.Fatalf("legacy credential remained plaintext: encrypted=%v secrets=%s", stored.Encrypted, encoded)
	}
	revealed, err := c.RevealCredential(t.Context(), []string{legacy.Context}, legacy.Name)
	if err != nil {
		t.Fatalf("reveal migrated credential: %v", err)
	}
	if revealed.Secrets["CLIENT_ID"] != "legacy-client" || revealed.Secrets["CLIENT_SECRET"] != "legacy-secret" {
		t.Fatalf("migrated credential changed: %#v", revealed.Secrets)
	}
	if err := c.MigrateUnencryptedCredentials(t.Context()); err != nil {
		t.Fatalf("migration was not idempotent: %v", err)
	}
}
