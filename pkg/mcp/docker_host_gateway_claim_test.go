package mcp

// Fork-only guarantee (fork #23, restored by VD-6903): every MCP server container maps host.docker.internal to the host gateway, so a remote MCP server published on the host stays reachable on native Linux dockerd. Kept in its own file so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"slices"
	"testing"

	"github.com/moby/moby/api/types/container"
)

func TestNewMCPServerHostConfigMapsHostDockerInternal(t *testing.T) {
	hc := newMCPServerHostConfig("8099/tcp", nil, container.Resources{})

	// The shim (and other MCP server containers) must be able to reach services
	// published on the host via host.docker.internal, matching how Obot's own
	// container is reached. Without this mapping, a remote MCP server whose URL
	// resolves to host.docker.internal is unreachable from the shim on native
	// Linux dockerd (Docker Desktop injects it automatically, masking the bug).
	if !slices.Contains(hc.ExtraHosts, "host.docker.internal:host-gateway") {
		t.Fatalf("ExtraHosts = %v, want it to contain host.docker.internal:host-gateway", hc.ExtraHosts)
	}
}
