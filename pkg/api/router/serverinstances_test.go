package router

import (
	"testing"

	"github.com/obot-platform/obot/pkg/api"
	"github.com/obot-platform/obot/pkg/api/handlers"
)

type recordingRouteRegistrar struct {
	patterns []string
}

func (r *recordingRouteRegistrar) HandleFunc(pattern string, _ api.HandlerFunc) {
	r.patterns = append(r.patterns, pattern)
}

func TestRegisterServerInstanceOAuthRoutes(t *testing.T) {
	registrar := &recordingRouteRegistrar{}

	registerServerInstanceOAuthRoutes(registrar, &handlers.ServerInstancesHandler{})

	want := []string{
		"GET /api/mcp-server-instances/{mcp_server_instance_id}/oauth-url",
		"GET /api/mcp-server-instances/{mcp_server_instance_id}/oauth-redirect",
	}
	if len(registrar.patterns) != len(want) {
		t.Fatalf("registered patterns = %v, want %v", registrar.patterns, want)
	}
	for i := range want {
		if registrar.patterns[i] != want[i] {
			t.Errorf("registered pattern %d = %q, want %q", i, registrar.patterns[i], want[i])
		}
	}
}
