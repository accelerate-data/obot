package client

import (
	"context"
	"fmt"

	"github.com/obot-platform/obot/pkg/gateway/types"
)

// GatewayTokenSignIn returns the subject and issuer that a gateway token of the given user signs in with. A generic
// OAuth sign-in is keyed on its issuer, and a gateway token records only the subject, so the issuer comes from the
// identity of the token's own user: the one its re-key bound it to, or, while that identity is still keyed on the bare
// subject, the configured issuer the re-key will bind it to. The configured issuer is never used for an identity that
// is already bound, so repointing the provider at another identity provider cannot move a token to another user's
// identity. The issuer is empty when the user has no identity with the token's subject, and the sign-in is then
// refused. For any other provider the issuer is empty and the subject is the token's provider user ID.
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
	for _, id := range identities {
		if types.ProviderSubject(id.ProviderUserID) != providerUserID {
			continue
		}
		if issuer, _, ok := types.ParseQualifiedProviderUserID(id.ProviderUserID); ok {
			return providerUserID, issuer, nil
		}
		issuer, err := c.configuredGenericOAuthIssuer(ctx, c.db.WithContext(ctx))
		return providerUserID, issuer, err
	}
	return providerUserID, "", nil
}
