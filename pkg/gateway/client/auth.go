package client

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	types2 "github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/principal"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

// UserLimit describes the maximum number of users an installation may have.
// Maximum is ignored when Unlimited is true.
type UserLimit struct {
	Maximum   int64
	Unlimited bool
}

// UserLimitProvider resolves the current license-derived user limit.
type UserLimitProvider interface {
	UserLimit(context.Context) (UserLimit, error)
}

type UserDecorator struct {
	next              authenticator.Request
	client            *Client
	userLimitProvider UserLimitProvider
}

func NewUserDecorator(next authenticator.Request, client *Client, userLimitProvider UserLimitProvider) *UserDecorator {
	return &UserDecorator{
		next:              next,
		client:            client,
		userLimitProvider: userLimitProvider,
	}
}

func (u UserDecorator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	resp, ok, err := u.next.AuthenticateRequest(req)
	if err != nil {
		return nil, false, err
	} else if !ok {
		return nil, false, nil
	}

	var (
		gatewayUser  *types.User
		authGroupIDs []string
	)
	if authProviderNamespace, authProviderName := cmp.Or(resp.User.GetExtra()["auth_provider_namespace"]...), cmp.Or(resp.User.GetExtra()["auth_provider_name"]...); authProviderNamespace != "" && authProviderName != "" {
		identity := &types.Identity{
			Email:                 cmp.Or(resp.User.GetExtra()["email"]...),
			AuthProviderName:      authProviderName,
			AuthProviderNamespace: authProviderNamespace,
			ProviderUsername:      resp.User.GetName(),
		}
		providerUserID, err := signInProviderUserID(authProviderName, resp.User)
		if err != nil {
			return nil, false, err
		}
		identity.ProviderUserID = providerUserID

		userLimit, err := u.resolveUserLimit(req.Context())
		if err != nil {
			return nil, false, err
		}

		gatewayUser, err = u.client.EnsureIdentity(req.Context(), identity, req.Header.Get("X-Obot-User-Timezone"), userLimit)
		if err != nil {
			if _, ok := errors.AsType[*types2.ErrHTTP](err); ok {
				return nil, false, err
			}
			if _, ok := errors.AsType[*FetchUserGroupsError](err); ok {
				return nil, false, err
			}
			if _, ok := errors.AsType[*UserAccessDeniedError](err); ok {
				// Such as a sign-in that SCIM has not provisioned, once SCIM is enforced for the auth provider.
				return nil, false, err
			}
			// The user could not be read, so their status is unknown.
			return nil, false, &UserAccessLookupError{
				Err: err,
			}
		}

		authGroupIDs = identity.GetAuthProviderGroupIDs()
	} else {
		return nil, false, nil
	}

	extra := resp.User.GetExtra()
	extra["auth_provider_groups"] = authGroupIDs
	// The admission check denies the request unless the user is active. The status comes from the user row that
	// EnsureIdentity just read, and replaces anything the auth provider supplied.
	principal.RecordUserStatus(extra, gatewayUser.Status())

	// Resolve effective role by merging individual + group roles
	effectiveRole, err := u.client.ResolveUserEffectiveRole(req.Context(), gatewayUser, authGroupIDs)
	if err != nil {
		// Log error but don't fail authentication - fall back to individual role
		slog.Warn("failed to resolve effective role for user", "userID", gatewayUser.ID, "error", err)
		effectiveRole = gatewayUser.Role
	}

	extra["obot_groups"] = effectiveRole.Groups()

	resp.User = &user.DefaultInfo{
		Name:   gatewayUser.Username,
		UID:    fmt.Sprintf("%d", gatewayUser.ID),
		Extra:  extra,
		Groups: effectiveRole.Groups(),
	}
	return resp, true, nil
}

func (u UserDecorator) resolveUserLimit(ctx context.Context) (UserLimit, error) {
	userLimit, err := u.userLimitProvider.UserLimit(ctx)
	if err != nil {
		return UserLimit{}, fmt.Errorf("failed to resolve user limit: %w", err)
	}

	if !userLimit.Unlimited && userLimit.Maximum <= 0 {
		return UserLimit{}, fmt.Errorf("invalid user limit %d", userLimit.Maximum)
	}

	return userLimit, nil
}

// signInProviderUserID returns the provider user ID that a sign-in's identity is keyed on. A generic OAuth sign-in
// binds its subject to the issuer that vouched for it, because the issuer is admin-configurable and a subject is only
// unique within one issuer: without the binding, repointing the provider at another identity provider would let a
// colliding subject sign in as an existing user. A generic OAuth sign-in that names no issuer is refused rather than
// keyed on its bare subject, which would resolve to an identity no issuer is bound to.
func signInProviderUserID(authProviderName string, u user.Info) (string, error) {
	if authProviderName != types.GenericOAuthAuthProviderName {
		return u.GetUID(), nil
	}
	issuer := types.NormalizeIssuer(cmp.Or(u.GetExtra()["auth_provider_issuer"]...))
	if issuer == "" {
		return "", types2.NewErrHTTP(http.StatusUnauthorized, "the generic OAuth auth provider did not report the issuer of this sign-in")
	}
	return types.QualifyProviderUserID(issuer, u.GetUID()), nil
}
