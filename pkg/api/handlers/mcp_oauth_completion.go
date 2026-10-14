package handlers

import "net/url"

const defaultMCPOAuthCompletionPath = "/auth/oauth/complete"

// MCPOAuthCompletionRedirect keeps Obot's own completion page when the
// deployment configures no destination, so non-Studio installs are unaffected.
func MCPOAuthCompletionRedirect(base string, q url.Values) string {
	if base == "" {
		return defaultMCPOAuthCompletionPath
	}
	if len(q) == 0 {
		return base
	}
	return base + "?" + q.Encode()
}
