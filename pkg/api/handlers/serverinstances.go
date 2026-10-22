package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/obot-platform/obot/pkg/accesscontrolrule"
	kuser "k8s.io/apiserver/pkg/authentication/user"

	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	"github.com/obot-platform/obot/pkg/mcp"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// MCPInstanceResolver resolves an MCP server instance ID to the server and
// config needed for an OAuth check. Satisfied by *mcp.SessionManager.
type MCPInstanceResolver interface {
	ServerForActionWithConnectIDAllowMissingConfig(ctx context.Context, id string, user kuser.Info) (string, v1.MCPServer, mcp.ServerConfig, []string, error)
}

type ServerInstancesHandler struct {
	acrHelper         *accesscontrolrule.Helper
	mcpOAuthChecker   MCPOAuthChecker
	mcpSessionManager MCPInstanceResolver
	serverURL         string
	completionURL     string
}

func NewServerInstancesHandler(acrHelper *accesscontrolrule.Helper, mcpOAuthChecker MCPOAuthChecker, mcpSessionManager MCPInstanceResolver, serverURL, completionURL string) *ServerInstancesHandler {
	return &ServerInstancesHandler{
		acrHelper:         acrHelper,
		mcpOAuthChecker:   mcpOAuthChecker,
		mcpSessionManager: mcpSessionManager,
		serverURL:         serverURL,
		completionURL:     completionURL,
	}
}

func (h *ServerInstancesHandler) ListServerInstances(req api.Context) error {
	var (
		instances v1.MCPServerInstanceList
		err       error
	)
	if (req.UserIsAdmin() || req.UserIsAuditor()) && req.URL.Query().Get("all") == "true" {
		err = req.List(&instances)
	} else {
		err = req.List(&instances, kclient.MatchingFields{
			"spec.userID": req.User.GetUID(),
		})
	}
	if err != nil {
		return err
	}

	convertedInstances := make([]types.MCPServerInstance, 0, len(instances.Items))
	for _, instance := range instances.Items {
		// Hide template and component instances from user list view
		if instance.Spec.Template || instance.Spec.CompositeName != "" || instance.Spec.VMCPInstanceID != "" {
			continue
		}

		cred, err := mcpServerInstanceCredEnv(req, instance)
		if err != nil {
			return fmt.Errorf("failed to get credentials for instance %s: %w", instance.Name, err)
		}

		convertedInstances = append(convertedInstances, ConvertMCPServerInstance(instance, cred))
	}

	return req.Write(types.MCPServerInstanceList{
		Items: convertedInstances,
	})
}

func (h *ServerInstancesHandler) GetServerInstance(req api.Context) error {
	var instance v1.MCPServerInstance
	if err := req.Get(&instance, req.PathValue("mcp_server_instance_id")); err != nil {
		return err
	}

	credEnv, err := mcpServerInstanceCredEnv(req, instance)
	if err != nil {
		return err
	}

	return req.Write(ConvertMCPServerInstance(instance, credEnv))
}

func (h *ServerInstancesHandler) ClearOAuthCredentials(req api.Context) error {
	var mcpServerInstance v1.MCPServerInstance
	if err := req.Get(&mcpServerInstance, req.PathValue("mcp_server_instance_id")); err != nil {
		return err
	}

	if err := req.GatewayClient.DeleteMCPOAuthTokens(req.Context(), req.User.GetUID(), mcpServerInstance.Name); err != nil {
		return fmt.Errorf("failed to delete OAuth credentials: %v", err)
	}

	req.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *ServerInstancesHandler) GetOAuthURL(req api.Context) error {
	u, err := h.oauthURLForInstance(req)
	if err != nil {
		return err
	}

	return req.Write(map[string]string{"oauthURL": u})
}

func (h *ServerInstancesHandler) RedirectOAuthURL(req api.Context) error {
	u, err := h.oauthURLForInstance(req)
	if err != nil {
		return err
	}
	if u == "" {
		http.Redirect(req.ResponseWriter, req.Request, MCPOAuthCompletionRedirect(h.completionURL, url.Values{
			"flow":   {"instance"},
			"status": {"success"},
			"mcp_id": {req.PathValue("mcp_server_instance_id")},
		}), http.StatusFound)
		return nil
	}

	http.Redirect(req.ResponseWriter, req.Request, u, http.StatusFound)
	return nil
}

func (h *ServerInstancesHandler) oauthURLForInstance(req api.Context) (string, error) {
	var instance v1.MCPServerInstance
	if err := req.Get(&instance, req.PathValue("mcp_server_instance_id")); err != nil {
		return "", err
	}
	if instance.Spec.UserID != req.User.GetUID() {
		return "", types.NewErrNotFound("MCP server instance not found")
	}

	// allowMissingConfig: report OAuth state even when the instance is not yet
	// fully configured (e.g. required headers unset) so the probe never 500s on
	// a half-set-up instance. For remote catalog servers (NeedsURL=false) this
	// is identical to the strict path.
	_, server, serverConfig, _, err := h.mcpSessionManager.ServerForActionWithConnectIDAllowMissingConfig(req.Context(), instance.Name, req.User)
	if err != nil {
		return "", fmt.Errorf("failed to resolve MCP server instance: %w", err)
	}

	u, err := h.mcpOAuthChecker.CheckForMCPAuth(req, server, serverConfig, req.User.GetUID(), instance.Name, "")
	if err != nil {
		return "", fmt.Errorf("failed to get OAuth URL: %w", err)
	}

	return u, nil
}

func ConvertMCPServerInstance(instance v1.MCPServerInstance, credEnv map[string]string) types.MCPServerInstance {
	missingHeaders := mcpServerInstanceMissingHeaders(instance, credEnv)

	return types.MCPServerInstance{
		Metadata:                MetadataFrom(&instance),
		Configured:              len(missingHeaders) == 0,
		MissingRequiredHeaders:  missingHeaders,
		UserID:                  instance.Spec.UserID,
		MCPServerID:             instance.Spec.MCPServerName,
		MCPCatalogID:            instance.Spec.MCPCatalogName,
		MCPServerCatalogEntryID: instance.Spec.MCPServerCatalogEntryName,
		PowerUserWorkspaceID:    instance.Spec.PowerUserWorkspaceID,
		Config:                  instance.Spec.Config,
	}
}

func mcpServerInstanceCredEnv(req api.Context, instance v1.MCPServerInstance) (map[string]string, error) {
	cred, err := req.GatewayClient.RevealCredential(req.Context(), []string{MCPServerInstanceCredentialContext(instance)}, instance.Name)
	if err != nil {
		if errors.As(err, &gateway.CredentialNotFoundError{}) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find credential: %w", err)
	}

	return cred.Secrets, nil
}

func MCPServerInstanceCredentialContext(instance v1.MCPServerInstance) string {
	return fmt.Sprintf("%s-%s", instance.Spec.UserID, instance.Name)
}

func mcpServerInstanceMissingHeaders(instance v1.MCPServerInstance, credEnv map[string]string) []string {
	if instance.Spec.Config == nil {
		return nil
	}

	var missingHeaders []string

	for _, header := range instance.Spec.Config {
		val := credEnv[header.Key]
		if (val == "" || !mcp.ConfigurationOptionValueValid(header.ToHeader(), credEnv)) && (header.Required || val != "") {
			missingHeaders = append(missingHeaders, header.Key)
		}
	}

	return missingHeaders
}

func (h *ServerInstancesHandler) ListServerInstancesForServer(req api.Context) error {
	catalogID := req.PathValue("catalog_id")
	workspaceID := req.PathValue("workspace_id")
	serverID := req.PathValue("mcp_server_id")

	// First, verify the server exists and belongs to the correct scope
	var server v1.MCPServer
	if err := req.Get(&server, serverID); err != nil {
		return err
	}

	// Verify server belongs to the requested scope
	if catalogID != "" && server.Spec.MCPCatalogID != catalogID {
		return types.NewErrNotFound("MCP server not found")
	} else if workspaceID != "" && server.Spec.PowerUserWorkspaceID != workspaceID {
		return types.NewErrNotFound("MCP server not found")
	}

	// List instances for this specific server
	var instances v1.MCPServerInstanceList
	if err := req.List(&instances, kclient.MatchingFields{
		"spec.mcpServerName": serverID,
	}); err != nil {
		return err
	}

	convertedInstances := make([]types.MCPServerInstance, 0, len(instances.Items))
	for _, instance := range instances.Items {
		// Hide component instances
		if instance.Spec.CompositeName != "" || instance.Spec.VMCPInstanceID != "" {
			continue
		}
		credEnv, err := mcpServerInstanceCredEnv(req, instance)
		if err != nil {
			return err
		}
		convertedInstances = append(convertedInstances, ConvertMCPServerInstance(instance, credEnv))
	}

	return req.Write(types.MCPServerInstanceList{
		Items: convertedInstances,
	})
}
