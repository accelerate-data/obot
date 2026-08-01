package handlers

import (
	"encoding/json"
	"errors"
	"strings"

	nmcp "github.com/obot-platform/nanobot/pkg/mcp"
	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	gatewayclient "github.com/obot-platform/obot/pkg/gateway/client"
	"github.com/obot-platform/obot/pkg/mcp"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"golang.org/x/oauth2"
)

func (h *MCPCatalogHandler) verifyOAuthCredentialTestAccess(req api.Context) (*v1.MCPServerCatalogEntry, error) {
	entry, err := verifyOAuthCredentialAccess(req, req.PathValue("catalog_id"), req.PathValue("workspace_id"), req.PathValue("entry_id"))
	if err != nil {
		return nil, err
	}
	if entry.Spec.Manifest.Runtime != types.RuntimeRemote ||
		entry.Spec.Manifest.ServerUserType != types.ServerUserTypeMultiUser ||
		entry.Spec.Manifest.RemoteConfig == nil ||
		strings.TrimSpace(entry.Spec.Manifest.RemoteConfig.FixedURL) == "" {
		return nil, types.NewErrBadRequest("static OAuth verification requires a multi-user remote entry with a fixed URL")
	}
	return entry, nil
}

// StartOAuthCredentialTest discovers the provider metadata and starts a real static OAuth authorization-code flow.
func (h *MCPCatalogHandler) StartOAuthCredentialTest(req api.Context) error {
	entry, err := h.verifyOAuthCredentialTestAccess(req)
	if err != nil {
		return err
	}

	var candidate types.MCPServerOAuthCredentialTestRequest
	if err := req.Read(&candidate); err != nil {
		return err
	}
	candidate.ClientID = strings.TrimSpace(candidate.ClientID)
	candidate.ClientSecret = strings.TrimSpace(candidate.ClientSecret)
	if candidate.ClientID == "" || candidate.ClientSecret == "" {
		return types.NewErrBadRequest("clientID and clientSecret are required")
	}

	fixedURL := strings.TrimSpace(entry.Spec.Manifest.RemoteConfig.FixedURL)
	if err := mcp.ValidateRemoteMCPURL(req.Context(), fixedURL, h.remoteURLValidationConfig); err != nil {
		return types.NewErrBadRequest("remote MCP URL is not allowed")
	}
	callbackURL := system.MCPOAuthCallbackURL(h.serverURL)
	metadata, err := nmcp.GetOAuthMetadataWithBlockingConfig(req.Context(), nmcp.Server{BaseURL: fixedURL}, "Obot Static OAuth Test", callbackURL,
		!h.remoteURLValidationConfig.AllowLocalhostMCP,
		!h.remoteURLValidationConfig.AllowPrivateIPMCP,
		!h.remoteURLValidationConfig.AllowLinkLocalMCP,
	)
	if err != nil {
		return types.NewErrBadRequest("failed to discover OAuth metadata")
	}

	var authorizationServer nmcp.AuthorizationServerMetadata
	if len(metadata.AuthorizationServerMetadata) == 0 || json.Unmarshal(metadata.AuthorizationServerMetadata, &authorizationServer) != nil || authorizationServer.AuthorizationEndpoint == "" || authorizationServer.TokenEndpoint == "" {
		return types.NewErrBadRequest("OAuth provider metadata is incomplete")
	}
	var registration nmcp.ClientRegistrationMetadata
	if len(metadata.ClientRegistration) > 0 && json.Unmarshal(metadata.ClientRegistration, &registration) != nil {
		return types.NewErrBadRequest("OAuth provider metadata is incomplete")
	}

	conf := &oauth2.Config{
		ClientID:     candidate.ClientID,
		ClientSecret: candidate.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   authorizationServer.AuthorizationEndpoint,
			TokenURL:  authorizationServer.TokenEndpoint,
			AuthStyle: staticOAuthAuthStyle(registration.TokenEndpointAuthMethod),
		},
		RedirectURL: callbackURL,
	}
	if registration.Scope != "" {
		conf.Scopes = strings.Fields(registration.Scope)
	}

	verifier := oauth2.GenerateVerifier()
	state, err := h.gatewayClient.CreateMCPStaticOAuthTest(req.Context(), req.User.GetUID(), entry.Name, fixedURL, verifier, conf)
	if err != nil {
		return errors.New("failed to create static OAuth credential test")
	}
	oauthURL, err := nmcp.AuthCodeURL(conf, authorizationServer.AuthorizationEndpoint, fixedURL, state, verifier)
	if err != nil {
		return errors.New("failed to create static OAuth authorization URL")
	}
	return req.Write(types.MCPServerOAuthCredentialTestStart{State: state, OAuthURL: oauthURL})
}

// GetOAuthCredentialTest returns only the caller- and entry-bound safe verification status.
func (h *MCPCatalogHandler) GetOAuthCredentialTest(req api.Context) error {
	entry, err := h.verifyOAuthCredentialTestAccess(req)
	if err != nil {
		return err
	}
	var statusRequest types.MCPServerOAuthCredentialTestStatusRequest
	if err := req.Read(&statusRequest); err != nil {
		return err
	}
	statusRequest.State = strings.TrimSpace(statusRequest.State)
	if statusRequest.State == "" {
		return types.NewErrBadRequest("state is required")
	}
	result, err := h.gatewayClient.GetMCPStaticOAuthTestStatus(req.Context(), statusRequest.State, req.User.GetUID(), entry.Name)
	if errors.Is(err, gatewayclient.ErrMCPStaticOAuthTestInvalid) {
		return types.NewErrBadRequest("invalid or expired OAuth credential test")
	} else if err != nil {
		return errors.New("failed to get static OAuth credential test")
	}
	return req.Write(result)
}

func staticOAuthAuthStyle(method string) oauth2.AuthStyle {
	switch method {
	case "client_secret_basic", "":
		return oauth2.AuthStyleInHeader
	case "client_secret_post":
		return oauth2.AuthStyleInParams
	default:
		return oauth2.AuthStyleAutoDetect
	}
}
