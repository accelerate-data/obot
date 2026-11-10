package oidcjwt_test

// Fork-only guarantee (fork #37, restored by VD-6903): default-catalog OAuth
// credential routes admit only the owner group, so an admin role mapped from an
// OIDC JWT is refused. Kept in its own file so an upstream sync cannot drop these
// tests by merging over a shared one.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIntegration_OwnerRoleReachesOwnerOnlyCatalogOAuthEndpoint(t *testing.T) {
	path := "/api/mcp-catalogs/default/entries/slack/oauth-credentials"
	code, _ := runPathWithRoles(t, path, []string{"owner"})
	require.Equal(t, http.StatusOK, code)
	code, _ = runPathWithRoles(t, path, []string{"admin"})
	require.Equal(t, http.StatusForbidden, code)
}
