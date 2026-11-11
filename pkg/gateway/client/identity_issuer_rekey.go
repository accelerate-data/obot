package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/hash"
	"github.com/obot-platform/obot/pkg/system"
	"gorm.io/gorm"
)

const (
	// identityIssuerBindingMigrationName names the re-key of generic OAuth identities from a bare subject to a subject
	// bound to the configured issuer.
	identityIssuerBindingMigrationName = "identity_issuer_binding"

	// genericOAuthIssuerSecret is the credential secret that holds the generic OAuth provider's configured issuer.
	genericOAuthIssuerSecret = "OBOT_GENERIC_OAUTH_AUTH_PROVIDER_ISSUER"

	identityIssuerBindingBatchSize = 500
)

var (
	// ErrGenericOAuthIssuerNotConfigured reports that the backfill cannot run yet, because the generic OAuth auth
	// provider has no issuer configured.
	ErrGenericOAuthIssuerNotConfigured = errors.New("the generic OAuth auth provider has no issuer configured")
)

// rekeyIdentityTx moves the stored identity to the provider user ID newProviderUserID. The encryption context includes
// the key, so the identity is decrypted with the old key and encrypted again with the new one. It reports false, and
// writes nothing, when the identity no longer has its old key or an identity already has the new one.
func (c *Client) rekeyIdentityTx(ctx context.Context, tx *gorm.DB, stored types.Identity, newProviderUserID string) (bool, error) {
	newHash := hash.String(newProviderUserID)
	var taken int64
	if err := tx.Model(new(types.Identity)).
		Where("auth_provider_namespace = ? AND auth_provider_name = ? AND hashed_provider_user_id = ?", stored.AuthProviderNamespace, stored.AuthProviderName, newHash).
		Count(&taken).Error; err != nil {
		return false, fmt.Errorf("failed to check for an identity with the issuer-bound key: %w", err)
	}
	if taken > 0 {
		return false, nil
	}

	rekeyed := stored
	if err := c.decryptStoredIdentity(ctx, &rekeyed); err != nil {
		return false, err
	}
	rekeyed.ProviderUserID = newProviderUserID
	rekeyed.HashedProviderUserID = newHash
	if err := c.encryptIdentity(ctx, &rekeyed); err != nil {
		return false, fmt.Errorf("failed to encrypt identity: %w", err)
	}
	columns := identityEncryptedColumns(&rekeyed)
	columns["hashed_provider_user_id"] = newHash
	result := tx.Model(new(types.Identity)).
		Where("auth_provider_namespace = ? AND auth_provider_name = ? AND hashed_provider_user_id = ?", stored.AuthProviderNamespace, stored.AuthProviderName, stored.HashedProviderUserID).
		UpdateColumns(columns)
	if result.Error != nil {
		return false, fmt.Errorf("failed to re-key the identity: %w", result.Error)
	}
	return result.RowsAffected > 0, nil
}

// legacyIssuerSubjectTx reports the subject of the issuer-bound providerUserID when an identity keyed on that bare
// subject, which predates issuer binding, may still be resolved by it. That holds only for the generic OAuth provider,
// only until the backfill has run, and only for the configured issuer: the backfill would bind such an identity to that
// issuer, so no other issuer may claim it, before or after.
func (c *Client) legacyIssuerSubjectTx(ctx context.Context, tx *gorm.DB, providerName, providerUserID string) (string, bool, error) {
	if providerName != types.GenericOAuthAuthProviderName {
		return "", false, nil
	}
	issuer, subject, ok := types.ParseQualifiedProviderUserID(providerUserID)
	if !ok {
		return "", false, nil
	}
	if done, err := c.identityIssuerBindingDone(tx); err != nil || done {
		return "", false, err
	}
	configured, err := c.configuredGenericOAuthIssuer(ctx, tx)
	if err != nil {
		return "", false, err
	}
	if configured == "" || configured != issuer {
		return "", false, nil
	}
	return subject, true, nil
}

// claimLegacyIssuerIdentityTx binds a generic OAuth identity keyed on the bare subject to the sign-in's issuer, and
// reads it into id, under the condition of legacyIssuerSubjectTx. The caller found no identity with the issuer-bound
// key before calling, so when that key exists after the re-key, whether this re-key or a concurrent one (the backfill,
// or a sign-in with the same issuer and subject) created it, the sign-in resolves to that identity rather than
// creating a new user.
func (c *Client) claimLegacyIssuerIdentityTx(ctx context.Context, tx *gorm.DB, id *types.Identity) (bool, error) {
	subject, ok, err := c.legacyIssuerSubjectTx(ctx, tx, id.AuthProviderName, id.ProviderUserID)
	if err != nil || !ok {
		return false, err
	}

	var legacy []types.Identity
	if err := tx.Where("auth_provider_namespace = ? AND auth_provider_name = ? AND hashed_provider_user_id = ?", id.AuthProviderNamespace, id.AuthProviderName, hash.String(subject)).
		Limit(1).Find(&legacy).Error; err != nil {
		return false, fmt.Errorf("failed to look up the identity keyed on the subject: %w", err)
	}
	if len(legacy) > 0 {
		if _, err := c.rekeyIdentityTx(ctx, tx, legacy[0], id.ProviderUserID); err != nil {
			return false, err
		}
	}

	var claimed []types.Identity
	if err := tx.Where("auth_provider_namespace = ? AND auth_provider_name = ? AND hashed_provider_user_id = ?", id.AuthProviderNamespace, id.AuthProviderName, id.HashedProviderUserID).
		Limit(1).Find(&claimed).Error; err != nil {
		return false, fmt.Errorf("failed to read the re-keyed identity: %w", err)
	}
	if len(claimed) == 0 {
		return false, nil
	}
	groups := id.AuthProviderGroups
	*id = claimed[0]
	id.AuthProviderGroups = groups
	return true, nil
}

// legacyIssuerIdentityTx reads into id the generic OAuth identity keyed on the bare subject of the issuer-bound
// providerUserID, under the condition of legacyIssuerSubjectTx but without re-keying it. It returns
// gorm.ErrRecordNotFound when that condition does not hold or no such identity exists.
func (c *Client) legacyIssuerIdentityTx(ctx context.Context, tx *gorm.DB, providerNamespace, providerName, providerUserID string, id *types.Identity) error {
	subject, ok, err := c.legacyIssuerSubjectTx(ctx, tx, providerName, providerUserID)
	if err != nil {
		return err
	}
	if !ok {
		return gorm.ErrRecordNotFound
	}
	return tx.Where("auth_provider_namespace = ? AND auth_provider_name = ? AND hashed_provider_user_id = ?", providerNamespace, providerName, hash.String(subject)).
		First(id).Error
}

func (c *Client) identityIssuerBindingDone(tx *gorm.DB) (bool, error) {
	var migrations int64
	if err := tx.Model(new(types.Migration)).Where("name = ?", identityIssuerBindingMigrationName).Count(&migrations).Error; err != nil {
		return false, fmt.Errorf("failed to check the issuer binding of identities: %w", err)
	}
	return migrations > 0, nil
}

// BackfillIdentityIssuerBinding binds every generic OAuth identity keyed on a bare subject to the configured issuer,
// once, so existing users keep their accounts. When no issuer is configured it records nothing and returns
// ErrGenericOAuthIssuerNotConfigured, so the caller keeps retrying and the backfill runs as soon as an issuer is
// configured, binding the legacy identities to that first issuer.
func (c *Client) BackfillIdentityIssuerBinding(ctx context.Context) error {
	issuer, err := c.configuredGenericOAuthIssuer(ctx, c.db.WithContext(ctx))
	if err != nil {
		return err
	}
	if issuer == "" {
		if done, err := c.identityIssuerBindingDone(c.db.WithContext(ctx)); err != nil || done {
			return err
		}
		return ErrGenericOAuthIssuerNotConfigured
	}
	return c.migrateIfNotRun(ctx, identityIssuerBindingMigrationName, func(tx *gorm.DB) error {
		return c.backfillIdentityIssuerBinding(ctx, tx, issuer)
	})
}

func (c *Client) configuredGenericOAuthIssuer(ctx context.Context, db *gorm.DB) (string, error) {
	name := types.GenericOAuthAuthProviderName
	cred, err := c.revealCredential(ctx, db, []string{name, system.GenericAuthProviderCredentialContext}, name)
	if err != nil && !errors.As(err, &CredentialNotFoundError{}) {
		return "", fmt.Errorf("failed to reveal the credential of auth provider %q: %w", name, err)
	}
	return types.NormalizeIssuer(cred.Secrets[genericOAuthIssuerSecret]), nil
}

func (c *Client) backfillIdentityIssuerBinding(ctx context.Context, tx *gorm.DB, issuer string) error {
	var (
		after            *types.Identity
		scanned, rekeyed int
	)
	for {
		query := tx.Where("auth_provider_name = ?", types.GenericOAuthAuthProviderName).
			Order("auth_provider_namespace, hashed_provider_user_id").
			Limit(identityIssuerBindingBatchSize)
		if after != nil {
			query = query.Where("(auth_provider_namespace, hashed_provider_user_id) > (?, ?)", after.AuthProviderNamespace, after.HashedProviderUserID)
		}
		var identities []types.Identity
		if err := query.Find(&identities).Error; err != nil {
			return fmt.Errorf("failed to list generic OAuth identities: %w", err)
		}
		if len(identities) == 0 {
			break
		}
		last := identities[len(identities)-1]
		after = &last

		for _, stored := range identities {
			decrypted := stored
			if err := c.decryptStoredIdentity(ctx, &decrypted); err != nil {
				return fmt.Errorf("identity %s/%s/%s: %w", stored.AuthProviderNamespace, stored.AuthProviderName, stored.HashedProviderUserID, err)
			}
			if _, _, qualified := types.ParseQualifiedProviderUserID(decrypted.ProviderUserID); qualified || decrypted.ProviderUserID == "" {
				continue
			}
			ok, err := c.rekeyIdentityTx(ctx, tx, stored, types.QualifyProviderUserID(issuer, decrypted.ProviderUserID))
			if err != nil {
				return err
			}
			if ok {
				rekeyed++
			} else {
				slog.Warn("Left a generic OAuth identity keyed on its bare subject, because another identity already has the issuer-bound key",
					"namespace", stored.AuthProviderNamespace, "hashedProviderUserID", stored.HashedProviderUserID)
			}
		}

		scanned += len(identities)
		if len(identities) < identityIssuerBindingBatchSize {
			break
		}
	}
	if scanned > 0 {
		slog.Info("Bound generic OAuth identities to the configured issuer", "scanned", scanned, "rekeyed", rekeyed)
	}
	return nil
}
