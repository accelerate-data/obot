package client

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/obot-platform/obot/pkg/gateway/types"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/storage/value"
)

const (
	credentialEncryptedSecretsKey = "_obot_encrypted_env"
	credentialLockRetryInterval   = 25 * time.Millisecond
	credentialLockMaxConnections  = 5
	credentialLockMaxIdleConns    = 2
)

var (
	credentialGroupResource = schema.GroupResource{
		Group:    "obot.obot.ai",
		Resource: "credentials",
	}
)

type ListCredentialsOptions struct {
	CredentialContexts []string
	AllContexts        bool
}

type CredentialNotFoundError struct {
	Contexts []string
	Name     string
}

// AcquireCredentialLock serializes operations for one credential key. PostgreSQL
// uses an advisory lock so independent Obot processes share the same lock;
// other databases use a context-aware process-local semaphore.
func (c *Client) AcquireCredentialLock(ctx context.Context, key string) (func(), error) {
	return c.AcquireCredentialLocks(ctx, key)
}

// AcquireCredentialLocks acquires a set of keys on one PostgreSQL connection,
// so a multi-component operation cannot exhaust the dedicated lock pool. Callers
// supply a consistent lock order: catalog mutation fence first, then sorted
// credential keys. Duplicate keys are acquired once. Release is idempotent.
func (c *Client) AcquireCredentialLocks(ctx context.Context, keys ...string) (func(), error) {
	unique := make([]string, 0, len(keys))
	for _, key := range keys {
		if key == "" {
			return nil, fmt.Errorf("credential lock key is required")
		}
		if !slices.Contains(unique, key) {
			unique = append(unique, key)
		}
	}
	if len(unique) == 0 {
		return func() {}, nil
	}
	db := c.db.WithContext(ctx)
	if db.Name() == "postgres" {
		pool, err := c.postgresCredentialLockPool(db)
		if err != nil {
			return nil, err
		}
		return acquirePostgresCredentialLocks(ctx, pool, unique)
	}
	releases := make([]func(), 0, len(unique))
	var once sync.Once
	release := func() {
		once.Do(func() {
			for _, unlock := range slices.Backward(releases) {
				unlock()
			}
		})
	}
	for _, key := range unique {
		unlock, err := c.acquireProcessCredentialLock(ctx, key)
		if err != nil {
			release()
			return nil, err
		}
		releases = append(releases, unlock)
	}
	return release, nil
}

func (c *Client) postgresCredentialLockPool(db *gorm.DB) (*sql.DB, error) {
	c.credentialLockPoolOnce.Do(func() {
		dialector, ok := db.Dialector.(*gormpostgres.Dialector)
		if !ok || dialector.Config == nil || dialector.DSN == "" {
			c.credentialLockPoolErr = fmt.Errorf("failed to determine PostgreSQL credential lock database configuration")
			return
		}
		config, err := pgx.ParseConfig(dialector.DSN)
		if err != nil {
			c.credentialLockPoolErr = fmt.Errorf("failed to parse credential lock database configuration: %w", err)
			return
		}
		c.credentialLockPool = stdlib.OpenDB(*config)
		c.credentialLockPool.SetMaxOpenConns(credentialLockMaxConnections)
		c.credentialLockPool.SetMaxIdleConns(credentialLockMaxIdleConns)
	})
	return c.credentialLockPool, c.credentialLockPoolErr
}

func acquirePostgresCredentialLocks(ctx context.Context, sqlDB *sql.DB, keys []string) (func(), error) {
	for {
		conn, err := sqlDB.Conn(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to reserve credential lock connection: %w", err)
		}
		tx, err := conn.BeginTx(context.WithoutCancel(ctx), nil)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("failed to begin credential lock transaction: %w", err)
		}
		acquired := true
		for _, key := range keys {
			var locked bool
			if err := tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock($1)", credentialLockID(key)).Scan(&locked); err != nil {
				_ = tx.Rollback()
				_ = conn.Close()
				return nil, fmt.Errorf("failed to acquire credential lock: %w", err)
			}
			if !locked {
				acquired = false
				break
			}
		}
		if acquired {
			var release sync.Once
			return func() {
				release.Do(func() {
					_ = tx.Rollback()
					_ = conn.Close()
				})
			}, nil
		}
		_ = tx.Rollback()
		_ = conn.Close()

		timer := time.NewTimer(credentialLockRetryInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func credentialLockID(key string) int64 {
	digest := sha256.Sum256([]byte(key))
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func (c *Client) acquireProcessCredentialLock(ctx context.Context, key string) (func(), error) {
	permitCandidate := make(chan struct{}, 1)
	permitCandidate <- struct{}{}
	permitValue, _ := c.credentialLocks.LoadOrStore(key, permitCandidate)
	permit := permitValue.(chan struct{})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-permit:
	}

	var release sync.Once
	return func() {
		release.Do(func() {
			permit <- struct{}{}
		})
	}, nil
}

// ListCredentials returns the credentials in the given context.
// If AllContexts is true, CredentialContexts is ignored and credentials from all contexts are returned.
// The secrets in the returned credentials are blanked out for security; use RevealCredential to get the secrets for a specific credential.
func (c *Client) ListCredentials(ctx context.Context, opts ListCredentialsOptions) ([]types.Credential, error) {
	var credentials []types.Credential
	if len(opts.CredentialContexts) == 0 && !opts.AllContexts {
		return credentials, nil
	}

	db := c.db.WithContext(ctx)
	if !opts.AllContexts {
		db = db.Where("context IN ?", opts.CredentialContexts)
	}

	if err := db.Find(&credentials).Error; err != nil {
		return nil, fmt.Errorf("failed to list credentials: %w", err)
	}

	for i := range credentials {
		if err := c.decryptCredential(ctx, &credentials[i]); err != nil {
			return nil, fmt.Errorf("failed to decrypt credential: %w", err)
		}
		credentials[i].Secrets = blankCredentialSecrets(credentials[i].Secrets)
	}

	return credentials, nil
}

func (e CredentialNotFoundError) Unwrap() error {
	// This allows errors.Is(err, gorm.ErrRecordNotFound) to work for CredentialNotFoundError.
	return gorm.ErrRecordNotFound
}

func (e CredentialNotFoundError) Error() string {
	return fmt.Sprintf("credential not found: contexts=%v, name=%s", e.Contexts, e.Name)
}

// RevealCredential returns the first credential matching name in the ordered list of contexts.
func (c *Client) RevealCredential(ctx context.Context, contexts []string, name string) (types.Credential, error) {
	var credential types.Credential
	if len(contexts) == 0 {
		return credential, CredentialNotFoundError{Contexts: contexts, Name: name}
	}

	for _, credentialContext := range contexts {
		if err := c.db.WithContext(ctx).Where("context = ? AND name = ?", credentialContext, name).First(&credential).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue
			}
			return credential, err
		}
		if err := c.decryptCredential(ctx, &credential); err != nil {
			return credential, fmt.Errorf("failed to decrypt credential: %w", err)
		}
		return credential, nil
	}

	return credential, CredentialNotFoundError{Contexts: contexts, Name: name}
}

// RevealAuthProviderCredential is RevealCredential for the credential of the auth provider namespace/name, and also
// returns the adapter type of the provider's SCIM connection, or "" when it has none. It reads both in one query, as
// it runs for every request that checks whether the provider is configured.
func (c *Client) RevealAuthProviderCredential(ctx context.Context, contexts []string, namespace, name string) (types.Credential, string, error) {
	if len(contexts) == 0 {
		return types.Credential{}, "", CredentialNotFoundError{Contexts: contexts, Name: name}
	}

	type credentialRow struct {
		types.Credential
		SCIMAdapterType *string
	}
	var rows []credentialRow
	if err := c.db.WithContext(ctx).Model(new(types.Credential)).
		Select("credentials.*, (SELECT adapter_type FROM scim_connections WHERE auth_provider_namespace = ? AND auth_provider_name = ?) AS scim_adapter_type", namespace, name).
		Where("context IN ? AND name = ?", contexts, name).
		Scan(&rows).Error; err != nil {
		return types.Credential{}, "", fmt.Errorf("failed to read the credential of auth provider %s/%s: %w", namespace, name, err)
	}

	// The first context that has the credential wins, as in RevealCredential.
	for _, credentialContext := range contexts {
		i := slices.IndexFunc(rows, func(row credentialRow) bool {
			return row.Context == credentialContext
		})
		if i < 0 {
			continue
		}

		credential := rows[i].Credential
		if err := c.decryptCredential(ctx, &credential); err != nil {
			return types.Credential{}, "", fmt.Errorf("failed to decrypt credential: %w", err)
		}
		var adapterType string
		if rows[i].SCIMAdapterType != nil {
			adapterType = *rows[i].SCIMAdapterType
		}
		return credential, adapterType, nil
	}

	return types.Credential{}, "", CredentialNotFoundError{Contexts: contexts, Name: name}
}

// HasCredential reports whether a credential with name exists in any of contexts. It does not decrypt the credential,
// so it answers even when the credential could not be decrypted.
func (c *Client) HasCredential(ctx context.Context, contexts []string, name string) (bool, error) {
	return hasCredentialTx(c.db.WithContext(ctx), contexts, name)
}

// UpsertCredential creates or replaces a credential identified by context+name.
func (c *Client) UpsertCredential(ctx context.Context, credential types.Credential) error {
	if credential.Context == "" || credential.Name == "" {
		return fmt.Errorf("credential context and name are required")
	}
	if credential.Secrets == nil {
		credential.Secrets = map[string]string{}
	}
	credential.Encrypted = false
	if err := c.encryptCredential(ctx, &credential); err != nil {
		return fmt.Errorf("failed to encrypt credential: %w", err)
	}

	return c.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "context"}, {Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"secrets", "encrypted"}),
	}).Create(&credential).Error
}

// DeleteCredential deletes a credential if it exists and returns whether a credential was deleted.
func (c *Client) DeleteCredential(ctx context.Context, context, name string) (bool, error) {
	result := c.db.WithContext(ctx).Where("context = ? AND name = ?", context, name).Delete(&types.Credential{})
	if result.Error != nil {
		return false, fmt.Errorf("failed to delete credential: %w", result.Error)
	}
	return result.RowsAffected > 0, nil
}

func (c *Client) encryptCredential(ctx context.Context, credential *types.Credential) error {
	if c.encryptionConfig == nil {
		return nil
	}

	transformer := c.encryptionConfig.Transformers[credentialGroupResource]
	if transformer == nil {
		return nil
	}

	secretsJSON, err := json.Marshal(credential.Secrets)
	if err != nil {
		return fmt.Errorf("failed to marshal secrets: %w", err)
	}

	b, err := transformer.TransformToStorage(ctx, secretsJSON, credentialDataCtx(credential))
	if err != nil {
		return err
	}

	credential.Secrets = map[string]string{
		credentialEncryptedSecretsKey: base64.StdEncoding.EncodeToString(b),
	}
	credential.Encrypted = true
	return nil
}

func (c *Client) decryptCredential(ctx context.Context, credential *types.Credential) error {
	if !credential.Encrypted {
		return nil
	}
	// An encrypted row read without its transformer must fail rather than hand the
	// ciphertext envelope back as the credential's secrets: callers compare those
	// secrets against client IDs and generations, and an empty match is not "no
	// credential".
	if c.encryptionConfig == nil {
		return fmt.Errorf("credential is encrypted but encryption is not configured")
	}
	if len(credential.Secrets) != 1 {
		return fmt.Errorf("credential is encrypted but its encrypted secrets are malformed")
	}

	transformer := c.encryptionConfig.Transformers[credentialGroupResource]
	if transformer == nil {
		return fmt.Errorf("credential is encrypted but no credential transformer is configured")
	}

	encryptedSecrets := credential.Secrets[credentialEncryptedSecretsKey]
	if encryptedSecrets == "" {
		return fmt.Errorf("encrypted secrets is missing")
	}

	decoded, err := base64.StdEncoding.DecodeString(encryptedSecrets)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted secrets: %w", err)
	}

	out, _, err := transformer.TransformFromStorage(ctx, decoded, credentialDataCtx(credential))
	if err != nil {
		return err
	}

	var secrets map[string]string
	if err := json.Unmarshal(out, &secrets); err != nil {
		return fmt.Errorf("failed to unmarshal secrets: %w", err)
	}

	credential.Secrets = secrets
	return nil
}

func credentialDataCtx(credential *types.Credential) value.Context {
	return value.DefaultContext(fmt.Sprintf("%s///%s", credential.Name, credential.Context))
}

func blankCredentialSecrets(secrets map[string]string) map[string]string {
	if len(secrets) == 0 {
		return secrets
	}
	blank := make(map[string]string, len(secrets))
	for key := range secrets {
		blank[key] = ""
	}
	return blank
}

func hasCredentialTx(tx *gorm.DB, contexts []string, name string) (bool, error) {
	if len(contexts) == 0 {
		return false, nil
	}

	var count int64
	if err := tx.Model(new(types.Credential)).Where("context IN ? AND name = ?", contexts, name).Count(&count).Error; err != nil {
		return false, fmt.Errorf("failed to check for credential %s: %w", name, err)
	}
	return count > 0, nil
}
