package handlers

import (
	"net/url"
	"testing"
)

func TestMCPOAuthCompletionRedirect(t *testing.T) {
	q := url.Values{"flow": {"instance"}, "status": {"success"}, "mcp_id": {"ms1-abc"}}
	if got := MCPOAuthCompletionRedirect("", q); got != "/auth/oauth/complete" {
		t.Fatalf("unset base must keep Obot page, got %q", got)
	}
	if got := MCPOAuthCompletionRedirect("/auth/mcp-oauth/complete", q); got != "/auth/mcp-oauth/complete?flow=instance&mcp_id=ms1-abc&status=success" {
		t.Fatalf("got %q", got)
	}
	if got := MCPOAuthCompletionRedirect("/auth/mcp-oauth/complete", nil); got != "/auth/mcp-oauth/complete" {
		t.Fatalf("got %q", got)
	}
}
