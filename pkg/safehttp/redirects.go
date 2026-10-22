package safehttp

import (
	"fmt"
	"net/http"
)

// RejectRedirects is an http.Client CheckRedirect policy that refuses every
// redirect. The error names only the target host, so a redirected request's
// credentials never reach a log or an API response.
func RejectRedirects(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("refusing to follow redirect to %s", req.URL.Host)
}

// NoRedirects returns a copy of httpClient that rejects every redirect. Clients
// that carry credentials, such as OAuth token exchange and refresh, use it so an
// authorization code, PKCE verifier, refresh token, or client secret is never
// replayed to another origin. The source client is often shared with transports
// that still follow redirects, so it is cloned rather than mutated.
func NoRedirects(httpClient *http.Client) *http.Client {
	if httpClient == nil {
		return nil
	}
	clone := *httpClient
	clone.CheckRedirect = RejectRedirects
	return &clone
}
