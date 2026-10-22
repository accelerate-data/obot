package mcp

// Fork-only guarantee (fork #11, restored by VD-6903): an explicitly configured MCP child-container network (OBOT_MCP_DOCKER_NETWORK) always wins over the auto-detected one, and "bridge" is used only when neither is set. Kept in its own file so an upstream sync cannot drop these tests by merging over a shared one.

import (
	"testing"
)

func TestChooseMCPNetwork(t *testing.T) {
	if got := chooseMCPNetwork("vibedata-local-default", "some-autodetected"); got != "vibedata-local-default" {
		t.Fatalf("explicit option should win, got %q", got)
	}
	if got := chooseMCPNetwork("", "auto-net"); got != "auto-net" {
		t.Fatalf("auto-detected should be used when option empty, got %q", got)
	}
	if got := chooseMCPNetwork("", ""); got != "bridge" {
		t.Fatalf("default should be bridge, got %q", got)
	}
}
