package client

import (
	"context"
	"fmt"

	"github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/hash"
)

// GatewayTokenSignIn returns the subject and issuer that a gateway token of the given user signs in with. A generic
// OAuth sign-in is keyed on its issuer, and a gateway token records only the subject, so the issuer comes from the
// identity of the token's own user that has the token's subject. An identity its re-key bound to an issuer gives that
// issuer, and the configured issuer is never used for it, so repointing the provider at another identity provider
// cannot move a token to another user's identity. An identity still keyed on the bare subject gives the configured
// issuer only while the re-key can still bind it there: before the backfill has run, and while no other identity has
// that issuer-bound key. The issuer is empty, and the sign-in is then refused, when the user has no such identity, when
// its identities with that subject are bound to more than one issuer, or when a bare identity cannot be bound. For any
// other provider the issuer is empty and the subject is the token's provider user ID.
func (c *Client) GatewayTokenSignIn(ctx context.Context, userID uint, providerNamespace, providerName, providerUserID string) (subject, issuer string, err error) {
	if providerName != types.GenericOAuthAuthProviderName {
		return providerUserID, "", nil
	}
	if issuer, subject, ok := types.ParseQualifiedProviderUserID(providerUserID); ok {
		return subject, issuer, nil
	}

	identities, err := c.FindIdentitiesForUserAndProvider(ctx, userID, providerName, providerNamespace)
	if err != nil {
		return "", "", fmt.Errorf("failed to find the identities of the token's user: %w", err)
	}
	var (
		boundIssuers = map[string]struct{}{}
		bare         bool
	)
	for _, id := range identities {
		if types.ProviderSubject(id.ProviderUserID) != providerUserID {
			continue
		}
		if issuer, _, ok := types.ParseQualifiedProviderUserID(id.ProviderUserID); ok {
			boundIssuers[issuer] = struct{}{}
		} else {
			bare = true
		}
	}
	switch {
	case len(boundIssuers) == 1:
		for issuer := range boundIssuers {
			return providerUserID, issuer, nil
		}
	case len(boundIssuers) > 1 || !bare:
		return providerUserID, "", nil
	}

	issuer, err = c.bareIdentityIssuer(ctx, providerNamespace, providerName, providerUserID)
	return providerUserID, issuer, err
}

// bareIdentityIssuer returns the configured issuer that the re-key would bind an identity keyed on the bare subject to,
// or an empty issuer when it no longer can: the backfill has run, no issuer is configured, or another identity already
// has the issuer-bound key, so that key belongs to someone else.
func (c *Client) bareIdentityIssuer(ctx context.Context, providerNamespace, providerName, subject string) (string, error) {
	db := c.db.WithContext(ctx)
	if done, err := c.identityIssuerBindingDone(db); err != nil || done {
		return "", err
	}
	issuer, err := c.configuredGenericOAuthIssuer(ctx, db)
	if err != nil || issuer == "" {
		return "", err
	}
	var taken int64
	if err := db.Model(new(types.Identity)).
		Where("auth_provider_namespace = ? AND auth_provider_name = ? AND hashed_provider_user_id = ?", providerNamespace, providerName, hash.String(types.QualifyProviderUserID(issuer, subject))).
		Count(&taken).Error; err != nil {
		return "", fmt.Errorf("failed to check for an identity with the issuer-bound key: %w", err)
	}
	if taken > 0 {
		return "", nil
	}
	return issuer, nil
}
