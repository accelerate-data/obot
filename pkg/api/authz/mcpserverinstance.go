package authz

import (
	"net/http"
	"slices"

	"github.com/obot-platform/nah/pkg/router"
	"github.com/obot-platform/obot/apiclient/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
)

func (a *Authorizer) checkMCPServerInstance(req *http.Request, resources *Resources, u User) (bool, error) {
	if resources.MCPServerInstanceID == "" {
		return true, nil
	}

	var mcpServerInstance v1.MCPServerInstance
	if err := a.get(req.Context(), router.Key(system.DefaultNamespace, resources.MCPServerInstanceID), &mcpServerInstance); err != nil {
		return false, err
	}

	if mcpServerInstance.Spec.UserID == u.GetUID() {
		return true, nil
	}

	// Studio's user offboarding deletes a departing user's instances with an
	// administrator service token, because the user can no longer act. Only the
	// delete of the instance itself is opened to administrators: reading,
	// configuring or revealing another user's instance stays owner-only.
	return isAdminInstanceDelete(req, resources.MCPServerInstanceID, u), nil
}

func isAdminInstanceDelete(req *http.Request, instanceID string, u User) bool {
	return req.Method == http.MethodDelete &&
		req.URL.Path == "/api/mcp-server-instances/"+instanceID &&
		slices.Contains(u.GetGroups(), types.GroupAdmin)
}
