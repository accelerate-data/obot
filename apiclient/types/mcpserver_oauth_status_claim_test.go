package types

// Fork-only guarantee (fork #37, restored by VD-6903): an MCP server reports an
// explicit missingOAuthCredentials=false, so clients can tell "configured" apart
// from an older server that never sends the field. Kept in its own file so an
// upstream sync cannot drop these tests by merging over a shared one.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMCPServerSerializesExplicitOAuthCredentialStatus(t *testing.T) {
	encoded, err := json.Marshal(MCPServer{MissingOAuthCredentials: false})
	if err != nil {
		t.Fatalf("marshal MCP server: %v", err)
	}
	if !strings.Contains(string(encoded), `"missingOAuthCredentials":false`) {
		t.Fatalf("MCP server omitted explicit OAuth credential status: %s", encoded)
	}
}
