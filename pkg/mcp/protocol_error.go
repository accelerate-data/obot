package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxProtocolErrorBody = 8 << 10
)

var (
	bearerCredential        = regexp.MustCompile(`(?i)\bBearer\s+(?:"[^"]*"|'[^']*'|[^\s,;"}]+)`)
	authorizationCredential = regexp.MustCompile(`(?i)\b(?:proxy-)?authorization\s*[:=]\s*(?:(?:Basic|Bearer|Digest|ApiKey|Token)\s+)?(?:"[^"]*"|'[^']*'|[^\s,;"}]+)`)
	namedCredential         = regexp.MustCompile(`(?i)\b((?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|secret|password|api[_-]?key|client[_-]?secret|cookie|set[_-]?cookie)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;"&}]+)`)
	jsonCredential          = regexp.MustCompile(`(?i)("(?:authorization|credential|nonce|signature|access_token|refresh_token|id_token|token|secret|password|api_key|client_secret|cookie|set-cookie)"\s*:\s*")(?:(?:\\.)|[^"\\])*"`)
	cookieHeader            = regexp.MustCompile(`(?i)\b(?:set-cookie|cookie)\s*[:=]\s*[^;=\s]+=(?:"[^"]*"|'[^']*'|[^;\s]+)(?:;\s*[^;=\s]+=(?:"[^"]*"|'[^']*'|[^;\s]+))*`)
	oauthQueryCredential    = regexp.MustCompile(`(?i)([?&](?:code|state)=)[^\s&#;,]+`)
	urlUserInfo             = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@`)
	privateKeyBlock         = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	runtimeCredential       = regexp.MustCompile(`\bvd_(?:iat|pat|org|svc)_[A-Za-z0-9_.-]+\b`)
	slackCredential         = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)
)

type protocolErrorTransport struct {
	base http.RoundTripper
}

type replayBody struct {
	io.Reader
	io.Closer
}

// The MCP SDK rejects JSON-RPC responses with a null ID, even when the
// server's HTTP error body contains an actionable error. Give it a valid ID
// and redact the message before the SDK exposes it through API errors or logs.
func withSafeProtocolErrors(client *http.Client) *http.Client {
	wrapped := *client
	base := wrapped.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	wrapped.Transport = protocolErrorTransport{base: base}
	return &wrapped
}

func (t protocolErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil || (resp.StatusCode >= 200 && resp.StatusCode < 300) || resp.Body == nil {
		return resp, err
	}

	prefix, readErr := io.ReadAll(io.LimitReader(resp.Body, maxProtocolErrorBody+1))
	if readErr != nil || len(prefix) > maxProtocolErrorBody {
		_ = resp.Body.Close()
		message := "MCP server error response exceeds 8192 bytes; diagnostic omitted"
		if readErr != nil {
			message = "MCP server error response could not be read; diagnostic omitted"
		}
		body, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      0,
			"error": map[string]any{
				"code":    -32603,
				"message": message,
			},
		})
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Type", "application/json")
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return resp, nil
	}

	updated := safeProtocolErrorBody(prefix)
	if updated == nil {
		resp.Body = &replayBody{Reader: bytes.NewReader(prefix), Closer: resp.Body}
		return resp, nil
	}
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(updated))
	resp.ContentLength = int64(len(updated))
	resp.Header.Set("Content-Length", strconv.Itoa(len(updated)))
	return resp, nil
}

func safeProtocolErrorBody(body []byte) []byte {
	var envelope struct {
		Version string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Version != "2.0" ||
		len(envelope.ID) == 0 || strings.TrimSpace(envelope.Error.Message) == "" {
		return nil
	}
	nullID := bytes.Equal(bytes.TrimSpace(envelope.ID), []byte("null"))

	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return nil
	}
	var errorFields map[string]json.RawMessage
	if json.Unmarshal(fields["error"], &errorFields) != nil {
		return nil
	}
	message := privateKeyBlock.ReplaceAllString(envelope.Error.Message, "[REDACTED]")
	message = urlUserInfo.ReplaceAllString(message, "${1}[REDACTED]@")
	message = oauthQueryCredential.ReplaceAllString(message, "${1}[REDACTED]")
	message = jsonCredential.ReplaceAllString(message, `${1}[REDACTED]"`)
	message = cookieHeader.ReplaceAllString(message, "Cookie: [REDACTED]")
	message = authorizationCredential.ReplaceAllString(message, "Authorization: [REDACTED]")
	message = namedCredential.ReplaceAllString(message, "${1}[REDACTED]")
	message = bearerCredential.ReplaceAllString(message, "Bearer [REDACTED]")
	message = runtimeCredential.ReplaceAllString(message, "[REDACTED]")
	message = slackCredential.ReplaceAllString(message, "[REDACTED]")
	for len(message) > 512 {
		_, size := utf8.DecodeLastRuneInString(message)
		message = message[:len(message)-size]
	}
	if !nullID && message == envelope.Error.Message {
		return nil
	}
	encodedMessage, _ := json.Marshal(message)
	errorFields["message"] = encodedMessage
	fields["error"], _ = json.Marshal(errorFields)
	if nullID {
		fields["id"] = json.RawMessage("0")
	}
	updated, err := json.Marshal(fields)
	if err != nil {
		return nil
	}
	return updated
}
