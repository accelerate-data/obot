package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/obot-platform/obot/pkg/auth"
	"github.com/obot-platform/obot/pkg/gateway/client"
	"github.com/obot-platform/obot/pkg/gateway/server/dispatcher"
	"gorm.io/gorm"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

type gatewayTokenReview struct {
	gatewayClient *client.Client
	dispatcher    *dispatcher.Dispatcher
}

func NewGatewayTokenReviewer(gatewayClient *client.Client, dispatcher *dispatcher.Dispatcher) authenticator.Request {
	return &gatewayTokenReview{
		gatewayClient: gatewayClient,
		dispatcher:    dispatcher,
	}
}

func (g *gatewayTokenReview) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	bearer := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	if bearer == "" {
		bearer = req.Header.Get("X-API-Key")
		if bearer == "" {
			return nil, false, nil
		}
	}

	u, namespace, name, providerUserID, groupIDs, err := g.gatewayClient.UserFromToken(req.Context(), bearer)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}

	if err := populateContext(req, g.dispatcher, namespace, name); err != nil {
		return nil, false, err
	}

	subject, issuer, err := g.gatewayClient.GatewayTokenSignIn(req.Context(), u.ID, namespace, name, providerUserID)
	if err != nil {
		return nil, false, err
	}
	extra := map[string][]string{
		"email":                   {u.Email},
		"auth_provider_namespace": {namespace},
		"auth_provider_name":      {name},
		"auth_provider_groups":    groupIDs,
	}
	if issuer != "" {
		extra["auth_provider_issuer"] = []string{issuer}
	}

	return &authenticator.Response{
		User: &user.DefaultInfo{
			Name:  u.Username,
			UID:   subject,
			Extra: extra,
		},
	}, true, nil
}

func populateContext(req *http.Request, dispatcher *dispatcher.Dispatcher, namespace, name string) error {
	providerURL, err := dispatcher.URLForAuthProvider(req.Context(), namespace, name)
	if err != nil {
		return err
	}
	groupIDPrefix, err := dispatcher.GroupIDPrefixForAuthProvider(req.Context(), namespace, name)
	if err != nil {
		return err
	}

	// Store provider metadata in context for later group fetching and validation.
	ctx := auth.ContextWithProviderURL(req.Context(), providerURL.String())
	ctx = auth.ContextWithProviderGroupIDPrefix(ctx, groupIDPrefix)
	*req = *req.WithContext(ctx)

	return nil
}
